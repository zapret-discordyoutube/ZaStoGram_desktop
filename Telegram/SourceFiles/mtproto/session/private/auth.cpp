/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/session/private/session_private.h"

#include "core/version.h"
#include "mtproto/auth/mtproto_bound_key_creator.h"
#include "mtproto/details/mtproto_dcenter.h"
#include "mtproto/protocol/mtproto_dump_to_text.h"
#include "mtproto/details/mtproto_rsa_public_key.h"
#include "mtproto/proxy/connection_broker.h"
#include "mtproto/proxy/control_plane.h"
#include "mtproto/proxy/diagnostics.h"
#include "mtproto/proxy/transport_policy.h"
#include "mtproto/session/session.h"
#include "mtproto/protocol/mtproto_response.h"
#include "mtproto/config/mtproto_dc_options.h"
#include "mtproto/transport/connection_abstract.h"
#include "base/options.h"
#include "base/random.h"
#include "base/qthelp_url.h"
#include "base/openssl_help.h"
#include "base/unixtime.h"

#include "base/platform/base_platform_info.h"

#include <ksandbox.h>
#include <zlib.h>

namespace MTP {
namespace details {
namespace {

constexpr auto kTemporaryExpiresIn = TimeId(86400);
constexpr auto kBindKeyAdditionalExpiresTimeout = TimeId(30);
constexpr auto kKeyOldEnoughForDestroy = 60 * crl::time(1000);

} // namespace

SessionPrivate::HandleResult SessionPrivate::handleBindResponse(
		mtpMsgId requestMsgId,
		const mtpBuffer &response) {
	if (!_authState.keyCreator || !_authState.bindMsgId || _authState.bindMsgId != requestMsgId) {
		return HandleResult::Ignored;
	}
	_authState.bindMsgId = 0;

	const auto result = _authState.keyCreator->handleBindResponse(response);
	switch (result) {
	case DcKeyBindState::Success:
		if (!_sessionState.data->releaseKeyCreationOnDone(
			_sessionState.encryptionKey,
			base::take(_authState.keyCreator)->bindPersistentKey())) {
			return HandleResult::DestroyTemporaryKey;
		}
		logMtprotoEvent(
			ProxyDiagnosticsPhase::MtpKeyReady,
			ProxyDiagnosticsSeverity::Info,
			u"temporary key bound (id %1)"_q.arg(_sessionState.keyId));
		_sessionState.data->queueNeedToResumeAndSend();
		return HandleResult::Success;
	case DcKeyBindState::DefinitelyDestroyed:
		if (destroyOldEnoughPersistentKey()) {
			logMtprotoEvent(
				ProxyDiagnosticsPhase::MtpBindFailed,
				ProxyDiagnosticsSeverity::Warning,
				u"bind failed, persistent key destroyed on server"_q);
			return HandleResult::DestroyTemporaryKey;
		}
		[[fallthrough]];
	case DcKeyBindState::Failed:
		logMtprotoEvent(
			ProxyDiagnosticsPhase::MtpBindFailed,
			ProxyDiagnosticsSeverity::Warning,
			u"temporary key bind failed"_q);
		_sessionState.data->queueNeedToResumeAndSend();
		return HandleResult::Success;
	}
	Unexpected("Result of BoundKeyCreator::handleBindResponse.");
}

void SessionPrivate::checkAuthKey() {
	logMtprotoEvent(
		ProxyDiagnosticsPhase::MtpTransportReady,
		ProxyDiagnosticsSeverity::Info,
		u"transport ready via %1, handshake %2ms, key id %3"_q
			.arg(_connectionState.connection ? _connectionState.connection->tag() : u"none"_q)
			.arg(_connectionState.connection ? _connectionState.connection->pingTime() : 0)
			.arg(_sessionState.keyId));
	if (_sessionState.keyId) {
		authKeyChecked();
	} else if (_delegate->isKeysDestroyer()) {
		applyAuthKey(_sessionState.data->getPersistentKey());
	} else {
		applyAuthKey(_sessionState.data->getTemporaryKey(
			TemporaryKeyTypeByDcType(_currentDcType)));
	}
}

void SessionPrivate::updateAuthKey() {
	if (_delegate->isKeysDestroyer() || _authState.keyCreator || !_connectionState.connection) {
		return;
	}

	DEBUG_LOG(("AuthKey Info: Connection updating key from Session, dc %1"
		).arg(_shiftedDcId));
	applyAuthKey(_sessionState.data->getTemporaryKey(
		TemporaryKeyTypeByDcType(_currentDcType)));
}

void SessionPrivate::setCurrentKeyId(uint64 newKeyId) {
	if (_sessionState.keyId == newKeyId) {
		return;
	}
	_sessionState.keyId = newKeyId;

	DEBUG_LOG(("MTP Info: auth key id set to id %1").arg(newKeyId));
	changeSessionId();
}

void SessionPrivate::applyAuthKey(AuthKeyPtr &&encryptionKey) {
	_sessionState.encryptionKey = std::move(encryptionKey);
	const auto newKeyId = _sessionState.encryptionKey ? _sessionState.encryptionKey->keyId() : 0;
	if (_sessionState.keyId) {
		if (_sessionState.keyId == newKeyId) {
			return;
		}
		setCurrentKeyId(0);
		DEBUG_LOG(("MTP Info: auth_key id for dc %1 changed, restarting..."
			).arg(_shiftedDcId));
		if (_connectionState.connection) {
			restart();
		}
		return;
	}
	if (!_connectionState.connection) {
		return;
	}
	setCurrentKeyId(newKeyId);
	DEBUG_LOG(("AuthKey Info: Connection update key from Session, "
		"dc %1 result: %2"
		).arg(_shiftedDcId
		).arg(Logs::mb(&_sessionState.keyId, sizeof(_sessionState.keyId)).str()));
	if (_sessionState.keyId) {
		return authKeyChecked();
	}

	if (_delegate->isKeysDestroyer()) {
		// We are here to destroy an old key, so we're done.
		LOG(("MTP Error: No key %1 in updateAuthKey() for destroying."
			).arg(_shiftedDcId));
		_delegate->keyWasPossiblyDestroyed(_shiftedDcId);
	} else if (noMediaKeyWithExistingRegularKey()) {
		DEBUG_LOG(("AuthKey Info: No key in updateAuthKey() for media, "
			"but someone has created regular, trying to acquire."));
		const auto dcType = tryAcquireKeyCreation();
		if (_authState.keyCreator && dcType != _currentDcType) {
			DEBUG_LOG(("AuthKey Info: "
				"Dc type changed for creation, restarting."));
			restart();
			return;
		}
	}
	if (_authState.keyCreator) {
		DEBUG_LOG(("AuthKey Info: No key in updateAuthKey(), creating."));
		logMtprotoEvent(
			ProxyDiagnosticsPhase::MtpKeyCreating,
			ProxyDiagnosticsSeverity::Info,
			u"no auth key, starting key creation"_q);
		_authState.keyCreator->start(
			BareDcId(_shiftedDcId),
			getProtocolDcId(),
			_connectionState.connection.get(),
			&_delegate->dcOptions());
	} else {
		DEBUG_LOG(("AuthKey Info: No key in updateAuthKey(), "
			"but someone is creating already, waiting."));
		logMtprotoEvent(
			ProxyDiagnosticsPhase::MtpKeyCreating,
			ProxyDiagnosticsSeverity::Info,
			u"no auth key, waiting for creation by another session"_q);
	}
}

bool SessionPrivate::noMediaKeyWithExistingRegularKey() const {
	return (TemporaryKeyTypeByDcType(_currentDcType)
			== TemporaryKeyType::MediaCluster)
		&& _sessionState.data->getTemporaryKey(TemporaryKeyType::Regular);
}

bool SessionPrivate::destroyOldEnoughPersistentKey() {
	Expects(_authState.keyCreator != nullptr);

	const auto key = _authState.keyCreator->bindPersistentKey();
	Assert(key != nullptr);

	const auto created = key->creationTime();
	if (created > 0 && crl::now() - created < kKeyOldEnoughForDestroy) {
		return false;
	}
	const auto instance = _instance;
	const auto delegate = _delegate;
	const auto shiftedDcId = _shiftedDcId;
	const auto keyId = key->keyId();
	InvokeQueued(instance, [=] {
		delegate->keyDestroyedOnServer(shiftedDcId, keyId);
	});
	return true;
}

DcType SessionPrivate::tryAcquireKeyCreation() {
	if (_authState.keyCreator) {
		return _currentDcType;
	} else if (_delegate->isKeysDestroyer()) {
		return _realDcType;
	}

	const auto acquired = _sessionState.data->acquireKeyCreation(_realDcType);
	if (acquired == CreatingKeyType::None) {
		return _realDcType;
	}

	using Result = DcKeyResult;
	using Error = DcKeyError;
	auto delegate = BoundKeyCreator::Delegate();
	delegate.unboundReady = [=](base::expected<Result, Error> result) {
		if (!result) {
			releaseKeyCreationOnFail();
			if (result.error() == Error::UnknownPublicKey) {
				if (_realDcType == DcType::Cdn) {
					LOG(("Warning: CDN public RSA key not found"));
					requestCDNConfig();
					return;
				}
				LOG(("AuthKey Error: could not choose public RSA key"));
			}
			restart();
			return;
		}
		DEBUG_LOG(("AuthKey Info: unbound key creation succeed, "
			"ids: (%1, %2) server salts: (%3, %4)"
			).arg(result->temporaryKey
				? result->temporaryKey->keyId()
				: 0
			).arg(result->persistentKey
				? result->persistentKey->keyId()
				: 0
			).arg(result->temporaryServerSalt
			).arg(result->persistentServerSalt));

		_sessionState.sessionSalt = result->temporaryServerSalt;
		result->temporaryKey->setExpiresAt(base::unixtime::now()
			+ kTemporaryExpiresIn
			+ kBindKeyAdditionalExpiresTimeout);
		if (_realDcType != DcType::Cdn) {
			auto key = result->persistentKey
				? std::move(result->persistentKey)
				: _sessionState.data->getPersistentKey();
			if (!key) {
				releaseKeyCreationOnFail();
				restart();
				return;
			}
			_authState.keyCreator->bind(std::move(key));
		}
		applyAuthKey(std::move(result->temporaryKey));
		if (_realDcType == DcType::Cdn) {
			_authState.keyCreator = nullptr;
			if (!_sessionState.data->releaseCdnKeyCreationOnDone(_sessionState.encryptionKey)) {
				restart();
			} else {
				_sessionState.data->queueNeedToResumeAndSend();
			}
		}
	};
	delegate.sentSome = [=](uint64 size) {
		onSentSome(size);
	};
	delegate.receivedSome = [=] {
		onReceivedSome();
	};

	auto request = DcKeyRequest();
	request.persistentNeeded = (acquired == CreatingKeyType::Persistent);
	request.temporaryExpiresIn = kTemporaryExpiresIn;
	_authState.keyCreator = std::make_unique<BoundKeyCreator>(
		request,
		std::move(delegate));
	const auto forceUseRegular = (_realDcType == DcType::MediaCluster)
		&& (acquired != CreatingKeyType::TemporaryMediaCluster);
	return forceUseRegular ? DcType::Regular : _realDcType;
}

void SessionPrivate::authKeyChecked() {
	connect(_connectionState.connection, &AbstractConnection::receivedData, [=] {
		handleReceived();
	});

	logMtprotoEvent(
		ProxyDiagnosticsPhase::MtpKeyReady,
		ProxyDiagnosticsSeverity::Info,
		u"auth key ready (id %1), %2"_q
			.arg(_sessionState.keyId)
			.arg(_sessionState.sessionSalt
				? u"session connected"_q
				: u"requesting server salt"_q));

	if (_sessionState.sessionSalt && setState(ConnectedState)) {
		resendAll();
	} // else receive salt in bad_server_salt first, then try to send all the requests

	_requestState.pingIdToSend = base::RandomValue<uint64>(); // get server_salt
	_sessionState.data->queueNeedToResumeAndSend();
}

void SessionPrivate::destroyTemporaryKey() {
	if (_delegate->isKeysDestroyer()) {
		LOG(("MTP Info: -404 error received in destroyer %1, assuming key was destroyed.").arg(_shiftedDcId));
		logMtprotoEvent(
			ProxyDiagnosticsPhase::MtpKeyDestroyed,
			ProxyDiagnosticsSeverity::Info,
			u"key destroyer confirmed key gone"_q);
		_delegate->keyWasPossiblyDestroyed(_shiftedDcId);
		return;
	}
	LOG(("MTP Info: -404 error received in %1 with temporary key, assuming it was destroyed.").arg(_shiftedDcId));
	logMtprotoEvent(
		ProxyDiagnosticsPhase::MtpKeyDestroyed,
		ProxyDiagnosticsSeverity::Warning,
		u"temporary key (id %1) assumed destroyed by server, recreating"_q
			.arg(_sessionState.keyId));
	releaseKeyCreationOnFail();
	if (_sessionState.encryptionKey) {
		_sessionState.data->destroyTemporaryKey(_sessionState.encryptionKey->keyId());
	}
	applyAuthKey(nullptr);
	restart();
}

void SessionPrivate::clearUnboundKeyCreator() {
	if (_authState.keyCreator) {
		_authState.keyCreator->stop();
	}
}

void SessionPrivate::releaseKeyCreationOnFail() {
	if (!_authState.keyCreator) {
		return;
	}
	_authState.keyCreator = nullptr;
	_sessionState.data->releaseKeyCreationOnFail();
}

} // namespace details
} // namespace MTP

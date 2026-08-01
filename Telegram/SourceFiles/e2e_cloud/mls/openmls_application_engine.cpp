/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "e2e_cloud/mls/openmls_application_engine.h"

#include "e2e_cloud/identity/account_identity.h"
#include "e2e_cloud/mls/openmls_bridge.h"
#include "e2e_cloud/storage/persistent_mls_state.h"

#include <algorithm>
#include <array>
#include <utility>

namespace E2ECloud {
namespace {

inline constexpr auto kRequestHashMagic = std::array<std::uint8_t, 8>{
	'T', 'D', 'E', '2', 'E', 'S', 'E', 'A',
};
inline constexpr auto kMaximumApplicationPlaintextSize = 1024 * 1024;

void AppendUint16(QByteArray &result, std::uint16_t value) {
	result.append(char(value >> 8));
	result.append(char(value));
}

void AppendUint32(QByteArray &result, std::uint32_t value) {
	result.append(char(value >> 24));
	result.append(char(value >> 16));
	result.append(char(value >> 8));
	result.append(char(value));
}

template <typename Array>
void AppendArray(QByteArray &result, const Array &value) {
	result.append(
		reinterpret_cast<const char*>(value.data()),
		int(value.size()));
}

void Cleanse(QByteArray &value) {
	std::fill_n(value.data(), value.size(), char(0));
}

[[nodiscard]] bool ValidContext(const OpenMlsClientContext &context) {
	return context.conversationId
		&& context.accountId
		&& context.clientId
		&& context.telegramPeerIdBinding;
}

} // namespace

QByteArray OpenMlsEngineId() {
	return QByteArray("openmls-0.8.1-0e99bc88-rustcrypto-v1");
}

OpenMlsBootstrapResult InitializeOpenMlsCreator(
		const OpenMlsClientContext &context,
		const OpenMlsBridge &bridge,
		const MlsContextCodecV1 &contextCodec,
		PersistentMlsStateStore &store) {
	if (!ValidContext(context)) {
		return {
			.status = OpenMlsBootstrapStatus::InvalidContext,
			.roster = {},
		};
	} else if (!store.loaded()) {
		return {
			.status = OpenMlsBootstrapStatus::StoreNotLoaded,
			.roster = {},
		};
	} else if (store.conversationId() != context.conversationId) {
		return {
			.status = OpenMlsBootstrapStatus::InvalidContext,
			.roster = {},
		};
	} else if (store.revision()) {
		return {
			.status = OpenMlsBootstrapStatus::StoreNotEmpty,
			.roster = {},
		};
	} else if (!bridge.compatible()) {
		return {
			.status = OpenMlsBootstrapStatus::BridgeIncompatible,
			.roster = {},
		};
	}
	const auto credential = contextCodec.encodeCredential({
		.conversationId = context.conversationId,
		.accountId = context.accountId,
		.clientId = context.clientId,
	});
	if (!credential) {
		return {
			.status = OpenMlsBootstrapStatus::InvalidContext,
			.roster = {},
		};
	}
	const auto groupId = QByteArray(
		reinterpret_cast<const char*>(context.conversationId.bytes.data()),
		context.conversationId.bytes.size());
	auto created = bridge.createGroup(*credential, groupId);
	if (created.status != OpenMlsBridgeStatus::Ok
		|| created.epoch
		|| created.state.isEmpty()
		|| created.roster.isEmpty()) {
		Cleanse(created.state);
		return {
			.status = OpenMlsBootstrapStatus::BridgeFailure,
			.roster = {},
		};
	}
	auto roster = std::move(created.roster);
	const auto committed = store.initialize(
		OpenMlsEngineId(),
		std::move(created.state));
	if (committed != MlsStateCommitResult::Committed) {
		return {
			.status = OpenMlsBootstrapStatus::PersistenceFailure,
			.roster = {},
		};
	}
	return {
		.status = OpenMlsBootstrapStatus::Initialized,
		.roster = std::move(roster),
	};
}

OpenMlsApplicationEngine::OpenMlsApplicationEngine(
		OpenMlsClientContext context,
		const OpenMlsBridge &bridge,
		const MlsContextCodecV1 &contextCodec,
		const EnvelopeCodec &envelopeCodec,
		const Sha256Provider &sha256,
		PersistentMlsStateStore &store)
: _context(context)
, _bridge(bridge)
, _contextCodec(contextCodec)
, _envelopeCodec(envelopeCodec)
, _sha256(sha256)
, _store(store) {
}

bool OpenMlsApplicationEngine::ready() const {
	return validContext()
		&& _bridge.compatible()
		&& _store.loaded()
		&& _store.conversationId() == _context.conversationId
		&& _store.engineId() == OpenMlsEngineId()
		&& _store.revision()
		&& !_store.engineState().isEmpty();
}

std::optional<EncodedEnvelope>
OpenMlsApplicationEngine::protectIdempotently(
		const MlsSealRequest &request) {
	if (!ready()
		|| request.conversationId != _context.conversationId
		|| !request.objectId
		|| request.plaintext.isEmpty()
		|| request.plaintext.size() > kMaximumApplicationPlaintextSize) {
		return std::nullopt;
	}
	const auto aad = _contextCodec.encodeAad({
		.conversationId = request.conversationId,
		.objectKind = ObjectKind::MlsApplication,
		.senderAccountId = _context.accountId,
		.senderClientId = _context.clientId,
		.telegramPeerIdBinding = _context.telegramPeerIdBinding,
		.objectId = request.objectId,
		.context = request.authenticatedData,
	});
	if (!aad) {
		return std::nullopt;
	}
	const auto hash = requestHash(request, *aad);
	if (!hash) {
		return std::nullopt;
	}
	if (const auto existing = _store.receipt(request.objectId)) {
		return (existing->requestHash == *hash)
			? std::optional<EncodedEnvelope>(existing->envelope)
			: std::nullopt;
	}
	const auto baseRevision = _store.revision();
	auto sealed = _bridge.seal(
		_store.engineState(),
		*aad,
		request.plaintext);
	if (sealed.status != OpenMlsBridgeStatus::Ok
		|| sealed.state.isEmpty()
		|| sealed.message.isEmpty()) {
		Cleanse(sealed.state);
		return std::nullopt;
	}
	const auto payloadHash = _sha256.digest(sealed.message);
	if (!payloadHash) {
		Cleanse(sealed.state);
		return std::nullopt;
	}
	const auto encoded = _envelopeCodec.encode({
		.conversationId = request.conversationId,
		.objectKind = ObjectKind::MlsApplication,
		.senderAccountId = _context.accountId,
		.senderClientId = _context.clientId,
		.telegramPeerIdBinding = _context.telegramPeerIdBinding,
		.epochOrGeneration = sealed.epoch,
		.objectId = request.objectId,
		.payloadHash = payloadHash,
		.payload = std::move(sealed.message),
		.authenticationData = *aad,
	});
	if (!encoded) {
		Cleanse(sealed.state);
		return std::nullopt;
	}
	const auto receipt = MlsOperationReceipt{
		.objectId = request.objectId,
		.requestHash = *hash,
		.envelope = *encoded,
	};
	const auto committed = _store.commit({
		.baseRevision = baseRevision,
		.engineState = std::move(sealed.state),
		.receipt = receipt,
		.inboundApplication = std::nullopt,
		.removalTombstone = std::nullopt,
	});
	if (committed == MlsStateCommitResult::Committed) {
		return encoded;
	} else if (committed == MlsStateCommitResult::AlreadyCommitted) {
		const auto existing = _store.receipt(request.objectId);
		return (existing && existing->requestHash == *hash)
			? std::optional<EncodedEnvelope>(existing->envelope)
			: std::nullopt;
	}
	return std::nullopt;
}

bool OpenMlsApplicationEngine::acknowledgeUploaded(ObjectId objectId) {
	return ready() && _store.acknowledgeReceipt(objectId);
}

bool OpenMlsApplicationEngine::validContext() const {
	return ValidContext(_context);
}

std::optional<Digest> OpenMlsApplicationEngine::requestHash(
		const MlsSealRequest &request,
		const QByteArray &encodedAad) const {
	if (encodedAad.isEmpty()
		|| request.plaintext.isEmpty()
		|| request.plaintext.size() > kMaximumApplicationPlaintextSize) {
		return std::nullopt;
	}
	auto input = QByteArray();
	input.reserve(
		8 + 2 + 4 + encodedAad.size() + 4 + request.plaintext.size());
	AppendArray(input, kRequestHashMagic);
	AppendUint16(input, 1);
	AppendUint32(input, std::uint32_t(encodedAad.size()));
	input.append(encodedAad);
	AppendUint32(input, std::uint32_t(request.plaintext.size()));
	input.append(request.plaintext);
	const auto result = _sha256.digest(input);
	Cleanse(input);
	return result ? std::optional<Digest>(result) : std::nullopt;
}

OpenMlsEnvelopeAuthenticator::OpenMlsEnvelopeAuthenticator(
		const MlsContextCodecV1 &contextCodec,
		const Sha256Provider &sha256)
: _contextCodec(contextCodec)
, _sha256(sha256) {
}

bool OpenMlsEnvelopeAuthenticator::authenticate(
		const TransportEnvelope &envelope) const {
	if (envelope.objectKind != ObjectKind::MlsApplication
		|| envelope.payload.isEmpty()
		|| envelope.payloadHash != _sha256.digest(envelope.payload)) {
		return false;
	}
	const auto aad = _contextCodec.decodeAad(envelope.authenticationData);
	return aad
		&& aad->conversationId == envelope.conversationId
		&& aad->objectKind == envelope.objectKind
		&& aad->senderAccountId == envelope.senderAccountId
		&& aad->senderClientId == envelope.senderClientId
		&& aad->telegramPeerIdBinding == envelope.telegramPeerIdBinding
		&& aad->objectId == envelope.objectId;
}

OpenMlsApplicationInboundApplier::OpenMlsApplicationInboundApplier(
		OpenMlsClientContext context,
		const OpenMlsBridge &bridge,
		const MlsContextCodecV1 &contextCodec,
		const Sha256Provider &sha256,
		PersistentMlsStateStore &store)
: _context(context)
, _bridge(bridge)
, _contextCodec(contextCodec)
, _sha256(sha256)
, _store(store) {
}

bool OpenMlsApplicationInboundApplier::ready() const {
	return validContext()
		&& _bridge.compatible()
		&& _store.loaded()
		&& _store.conversationId() == _context.conversationId
		&& _store.engineId() == OpenMlsEngineId()
		&& _store.revision()
		&& !_store.engineState().isEmpty();
}

InboundApplyResult OpenMlsApplicationInboundApplier::apply(
		const TransportEnvelope &envelope) {
	const auto authenticator = OpenMlsEnvelopeAuthenticator(
		_contextCodec,
		_sha256);
	if (!ready()
		|| envelope.conversationId != _context.conversationId
		|| envelope.telegramPeerIdBinding
			!= _context.telegramPeerIdBinding
		|| !authenticator.authenticate(envelope)) {
		return InboundApplyResult::Rejected;
	}
	if (const auto existing = _store.inboundApplication(envelope.objectId)) {
		return (existing->payloadHash == envelope.payloadHash)
			? InboundApplyResult::Applied
			: InboundApplyResult::ForkDetected;
	}
	const auto aad = _contextCodec.decodeAad(envelope.authenticationData);
	const auto baseRevision = _store.revision();
	auto processed = _bridge.process(
		_store.engineState(),
		envelope.payload);
	if (processed.status != OpenMlsBridgeStatus::Ok) {
		Cleanse(processed.state);
		Cleanse(processed.plaintext);
		switch (processed.status) {
		case OpenMlsBridgeStatus::CryptoError:
			return InboundApplyResult::Deferred;
		case OpenMlsBridgeStatus::InvalidState:
		case OpenMlsBridgeStatus::Panic:
			return InboundApplyResult::ForkDetected;
		default:
			return InboundApplyResult::Rejected;
		}
	}
	const auto credential = _contextCodec.decodeCredential(
		processed.senderCredential);
	if (!aad
		|| processed.kind != OpenMlsContentKind::Application
		|| processed.senderIndex == kOpenMlsNonMemberSender
		|| processed.epoch != envelope.epochOrGeneration
		|| processed.state.isEmpty()
		|| processed.plaintext.isEmpty()
		|| processed.authenticatedData != envelope.authenticationData
		|| processed.roster.isEmpty()
		|| !credential
		|| credential->conversationId != envelope.conversationId
		|| credential->accountId != envelope.senderAccountId
		|| credential->clientId != envelope.senderClientId) {
		Cleanse(processed.state);
		Cleanse(processed.plaintext);
		return InboundApplyResult::Rejected;
	}
	const auto committed = _store.commit({
		.baseRevision = baseRevision,
		.engineState = std::move(processed.state),
		.receipt = std::nullopt,
		.inboundApplication = MlsInboundApplication{
			.objectId = envelope.objectId,
			.payloadHash = envelope.payloadHash,
			.epoch = processed.epoch,
			.senderAccountId = envelope.senderAccountId,
			.senderClientId = envelope.senderClientId,
			.senderLeafIndex = processed.senderIndex,
			.plaintext = std::move(processed.plaintext),
			.context = aad->context,
		},
		.removalTombstone = std::nullopt,
	});
	switch (committed) {
	case MlsStateCommitResult::Committed:
	case MlsStateCommitResult::AlreadyCommitted:
		return InboundApplyResult::Applied;
	case MlsStateCommitResult::RevisionConflict:
	case MlsStateCommitResult::PersistenceFailed:
		return InboundApplyResult::Deferred;
	default:
		return InboundApplyResult::ForkDetected;
	}
}

InboundRecoveryResult OpenMlsApplicationInboundApplier::recover(
		const TransportEnvelope &envelope) const {
	if (!ready()
		|| envelope.conversationId != _context.conversationId
		|| envelope.telegramPeerIdBinding
			!= _context.telegramPeerIdBinding) {
		return InboundRecoveryResult::Unknown;
	}
	const auto existing = _store.inboundApplication(envelope.objectId);
	if (!existing) {
		return InboundRecoveryResult::NotApplied;
	}
	const auto aad = _contextCodec.decodeAad(envelope.authenticationData);
	return (aad
		&& existing->payloadHash == envelope.payloadHash
		&& existing->epoch == envelope.epochOrGeneration
		&& existing->senderAccountId == envelope.senderAccountId
		&& existing->senderClientId == envelope.senderClientId
		&& existing->context == aad->context)
		? InboundRecoveryResult::Applied
		: InboundRecoveryResult::Unknown;
}

const std::vector<MlsInboundApplication>
		&OpenMlsApplicationInboundApplier::pendingApplications() const {
	return _store.inboundApplications();
}

std::optional<MlsInboundApplication>
OpenMlsApplicationInboundApplier::application(ObjectId objectId) const {
	return _store.inboundApplication(objectId);
}

bool OpenMlsApplicationInboundApplier::acknowledgeDelivered(
		ObjectId objectId) {
	return ready() && _store.acknowledgeInboundApplication(objectId);
}

bool OpenMlsApplicationInboundApplier::validContext() const {
	return ValidContext(_context);
}

} // namespace E2ECloud

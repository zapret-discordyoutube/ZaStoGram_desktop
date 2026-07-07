/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/session_private.h"

#include "core/version.h"
#include "mtproto/details/mtproto_binary.h"
#include "mtproto/details/mtproto_bound_key_creator.h"
#include "mtproto/details/mtproto_dcenter.h"
#include "mtproto/details/mtproto_dump_to_text.h"
#include "mtproto/details/mtproto_rsa_public_key.h"
#include "mtproto/proxy/connection_broker.h"
#include "mtproto/proxy/control_plane.h"
#include "mtproto/proxy/diagnostics.h"
#include "mtproto/proxy/transport_policy.h"
#include "mtproto/session.h"
#include "mtproto/mtproto_response.h"
#include "mtproto/mtproto_dc_options.h"
#include "mtproto/connection_abstract.h"
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

constexpr auto kIntSize = static_cast<int>(sizeof(mtpPrime));
constexpr auto kMaxMessageLength = 16 * 1024 * 1024;
constexpr auto kSentContainerLives = 600 * crl::time(1000);
constexpr auto kAckSendWaiting = 10 * crl::time(1000);
constexpr auto kFastRequestDuration = crl::time(500);

auto SyncTimeRequestDuration = kFastRequestDuration;

[[nodiscard]] QString LogIdsVector(const QVector<MTPlong> &ids) {
	if (!ids.size()) return "[]";
	auto idsStr = QString("[%1").arg(ids.cbegin()->v);
	for (const auto &id : ids) {
		idsStr += QString(", %2").arg(id.v);
	}
	return idsStr + "]";
}

[[nodiscard]] bool ConstTimeIsDifferent(
		const void *a,
		const void *b,
		size_t size) {
	const auto ca = bytes::make_span(static_cast<const bytes::type*>(a), size);
	const auto cb = bytes::make_span(static_cast<const bytes::type*>(b), size);
	volatile auto different = false;
	for (auto i = size_t(0); i != size; ++i) {
		different = different | (ca[i] != cb[i]);
	}
	return different;
}

} // namespace

void SessionPrivate::clearOldContainers() {
	auto resent = false;
	auto nextTimeout = kSentContainerLives;
	const auto now = crl::now();
	const auto checkTime = now - kSentContainerLives;
	for (auto i = _requestState.sentContainers.begin(); i != _requestState.sentContainers.end();) {
		if (i->second.sent <= checkTime) {
			DEBUG_LOG(("MTP Info: Removing old container with resending %1, "
				"sent: %2, now: %3, current unixtime: %4"
				).arg(i->first
				).arg(i->second.sent
				).arg(now
				).arg(base::unixtime::now()));

			const auto ids = std::move(i->second.messages);
			i = _requestState.sentContainers.erase(i);

			resent = resent || !ids.empty();
			for (const auto innerMsgId : ids) {
				resend(innerMsgId, -1);
			}
		} else {
			nextTimeout = std::min(i->second.sent - checkTime, nextTimeout);
			++i;
		}
	}
	if (resent) {
		_sessionState.data->queueNeedToResumeAndSend();
	}
	if (nextTimeout < kSentContainerLives) {
		_timing.clearOldContainersTimer.callOnce(nextTimeout);
	} else if (!_timing.clearOldContainersTimer.isActive()) {
		_timing.clearOldContainersTimer.callEach(nextTimeout);
	}
}

void SessionPrivate::handleReceived() {
	Expects(_sessionState.encryptionKey != nullptr);

	onReceivedSome();

	while (!_connectionState.connection->received().empty()) {
		auto intsBuffer = std::move(_connectionState.connection->received().front());
		_connectionState.connection->received().pop_front();

		constexpr auto kExternalHeaderIntsCount = 6U; // 2 auth_key_id, 4 msg_key
		constexpr auto kEncryptedHeaderIntsCount = 8U; // 2 salt, 2 session, 2 msg_id, 1 seq_no, 1 length
		constexpr auto kMinimalEncryptedIntsCount = kEncryptedHeaderIntsCount + 4U; // + 1 data + 3 padding
		constexpr auto kMinimalIntsCount = kExternalHeaderIntsCount + kMinimalEncryptedIntsCount;
		auto intsCount = uint32(intsBuffer.size());
		auto ints = intsBuffer.constData();
		if ((intsCount < kMinimalIntsCount) || (intsCount > kMaxMessageLength / kIntSize)) {
			LOG(("TCP Error: bad message received, len %1").arg(intsCount * kIntSize));
			return restart();
		}
		const auto receivedKeyId = binary::Read<uint64>(
			bytes::make_span(intsBuffer));
		if (_sessionState.keyId != receivedKeyId) {
			LOG(("TCP Error: bad auth_key_id %1 instead of %2 received").arg(_sessionState.keyId).arg(receivedKeyId));
			return restart();
		}

		constexpr auto kMinPaddingSize = 12U;
		constexpr auto kMaxPaddingSize = 1024U;

		auto encryptedInts = ints + kExternalHeaderIntsCount;
		auto encryptedIntsCount = (intsCount - kExternalHeaderIntsCount) & ~0x03U;
		auto encryptedBytesCount = encryptedIntsCount * kIntSize;
		auto decryptedBuffer = QByteArray(encryptedBytesCount, Qt::Uninitialized);
		auto msgKey = binary::ReadAt<MTPint128>(
			bytes::make_span(intsBuffer),
			2 * kIntSize);

		aesIgeDecrypt(encryptedInts, decryptedBuffer.data(), encryptedBytesCount, _sessionState.encryptionKey, msgKey);

		auto decrypted = mtpBuffer(encryptedIntsCount);
		binary::Copy(
			bytes::make_span(decrypted),
			bytes::make_span(decryptedBuffer.constData(), encryptedBytesCount));
		const auto decryptedBytes = bytes::make_span(decrypted);
		auto serverSalt = binary::ReadAt<uint64>(decryptedBytes, 0);
		auto session = binary::ReadAt<uint64>(decryptedBytes, 2 * kIntSize);
		auto msgId = binary::ReadAt<uint64>(decryptedBytes, 4 * kIntSize);
		auto seqNo = binary::ReadAt<uint32>(decryptedBytes, 6 * kIntSize);
		auto needAck = ((seqNo & 0x01) != 0);
		auto messageLength = binary::ReadAt<uint32>(
			decryptedBytes,
			7 * kIntSize);
		auto fullDataLength = kEncryptedHeaderIntsCount * kIntSize + messageLength; // Without padding.

		// Can underflow, but it is an unsigned type, so we just check the range later.
		auto paddingSize = static_cast<uint32>(encryptedBytesCount) - static_cast<uint32>(fullDataLength);

		std::array<uchar, 32> sha256Buffer = { { 0 } };

		SHA256_CTX msgKeyLargeContext;
		SHA256_Init(&msgKeyLargeContext);
		SHA256_Update(&msgKeyLargeContext, _sessionState.encryptionKey->partForMsgKey(false), 32);
		SHA256_Update(&msgKeyLargeContext, decrypted.constData(), encryptedBytesCount);
		SHA256_Final(sha256Buffer.data(), &msgKeyLargeContext);

		constexpr auto kMsgKeyShift = 8U;
		if (ConstTimeIsDifferent(&msgKey, sha256Buffer.data() + kMsgKeyShift, sizeof(msgKey))) {
			LOG(("TCP Error: bad SHA256 hash after aesDecrypt in message"));
			return restart();
		}

		if ((messageLength > kMaxMessageLength)
			|| (messageLength & 0x03)
			|| (paddingSize < kMinPaddingSize)
			|| (paddingSize > kMaxPaddingSize)) {
			LOG(("TCP Error: bad msg_len received %1, data size: %2").arg(messageLength).arg(encryptedBytesCount));
			return restart();
		}

		if (Logs::DebugEnabled()) {
			_connectionState.connection->logInfo(u"Decrypted message %1,%2,%3 is %4 len"_q
				.arg(msgId)
				.arg(seqNo)
				.arg(Logs::b(needAck))
				.arg(fullDataLength));
		}

		if (session != _sessionState.sessionId) {
			LOG(("MTP Error: bad server session received"));
			return restart();
		}

		const auto serverTime = int32(msgId >> 32);
		const auto isReply = ((msgId & 0x03) == 1);
		if (!isReply && ((msgId & 0x03) != 3)) {
			LOG(("MTP Error: bad msg_id %1 in message received").arg(msgId));

			return restart();
		}

		const auto clientTime = base::unixtime::now();
		const auto badTime = (serverTime > clientTime + 60)
			|| (serverTime + 300 < clientTime);
		if (badTime) {
			DEBUG_LOG(("MTP Info: bad server time from msg_id: %1, my time: %2").arg(serverTime).arg(clientTime));
		}

		bool wasConnected = (getState() == ConnectedState);
		if (serverSalt != _sessionState.sessionSalt) {
			if (!badTime) {
				DEBUG_LOG(("MTP Info: other salt received... received: %1, my salt: %2, updating...").arg(serverSalt).arg(_sessionState.sessionSalt));
				_sessionState.sessionSalt = serverSalt;

				if (setState(ConnectedState, ConnectingState)) {
					resendAll();
				}
			} else {
				DEBUG_LOG(("MTP Info: other salt received... received: %1, my salt: %2").arg(serverSalt).arg(_sessionState.sessionSalt));
			}
		} else {
			serverSalt = 0; // dont pass to handle method, so not to lock in setSalt()
		}

		if (needAck) _requestState.ackData.push_back(MTP_long(msgId));

		auto res = HandleResult::Success; // if no need to handle, then succeed
		auto from = decrypted.constData() + kEncryptedHeaderIntsCount;
		auto end = from + (messageLength / kIntSize);
		auto sfrom = from - (SerializedRequest::kMessageBodyPosition
			- SerializedRequest::kMessageIdPosition);
		MTP_LOG(_shiftedDcId, ("Recv: ")
			+ DumpToText(sfrom, end)
			+ QString(" (dc:%1,key:%2,session:%3)"
			).arg(AbstractConnection::ProtocolDcDebugId(getProtocolDcId())
			).arg(_sessionState.encryptionKey->keyId()
			).arg(_sessionState.sessionId));

		const auto registered = _requestState.receivedIds.registerMsgId(
			msgId,
			needAck);
		if (registered == ReceivedIdsManager::Result::Success) {
			res = handleOneReceived(from, end, msgId, {
				.outerMsgId = msgId,
				.serverSalt = serverSalt,
				.serverTime = serverTime,
				.badTime = badTime,
			});
		} else if (registered == ReceivedIdsManager::Result::TooOld) {
			res = HandleResult::ResetSession;
		}
		_requestState.receivedIds.shrink();

		// send acks
		if (const auto toAckSize = _requestState.ackData.size()) {
			DEBUG_LOG(("MTP Info: will send %1 acks, ids: %2").arg(toAckSize).arg(LogIdsVector(_requestState.ackData)));
			_sessionState.data->queueSendAnything(kAckSendWaiting);
		}

		auto lock = QReadLocker(_sessionState.data->haveReceivedMutex());
		const auto tryToReceive = !_sessionState.data->haveReceivedMessages().empty();
		lock.unlock();

		if (tryToReceive) {
			DEBUG_LOG(("MTP Info: queueTryToReceive() - need to parse in another thread, %1 messages.").arg(_sessionState.data->haveReceivedMessages().size()));
			_sessionState.data->queueTryToReceive();
		}

		if (res != HandleResult::Success && res != HandleResult::Ignored) {
			if (res == HandleResult::DestroyTemporaryKey) {
				destroyTemporaryKey();
			} else if (res == HandleResult::ResetSession) {
				_sessionState.needReset = true;
			}
			return restart();
		}
		_timing.retryTimeout = 1; // reset restart() timer

		if (!_connectionState.mtprotoDataReceived) {
			_connectionState.mtprotoDataReceived = true;
			_connectionState.mtprotoSilentTimeouts = 0;
			if (_connectionState.proxyMigrationScout) {
				_connectionState.proxyMigrationScout = false;
				_instance->proxyMigrationSucceeded(_connectionState.proxyGeneration);
			}
			logMtprotoEvent(
				ProxyDiagnosticsPhase::MtpFirstDataReceived,
				ProxyDiagnosticsSeverity::Info,
				u"first mtproto payload received"_q);
			if (!MtProxy::EndpointEmpty(_connectionState.mtproxyEndpoint)) {
				ProxyControlPlane::ReportMtproxySuccess({
					.endpoint = _connectionState.mtproxyEndpoint,
					.use = _connectionState.mtproxyUse,
					.proxyGeneration = _connectionState.mtproxyAttempt.proxyGeneration,
					.attemptId = _connectionState.mtproxyAttempt.attemptId,
					.proxyEpoch = _connectionState.mtproxyAttempt.proxyEpoch,
					.successEpoch = _connectionState.mtproxyAttempt.successEpoch,
					.attemptStartedAt = _connectionState.mtproxyAttemptStartedAt,
					.scope = MtProxy::SuccessScope::Relay,
				});
			}
		}

		_connectionState.startedConnectingAt = crl::time(0);

		if (!wasConnected) {
			if (getState() == ConnectedState) {
				_sessionState.data->queueNeedToResumeAndSend();
			}
		}
	}
	if (_connectionState.connection->serviceRequestNeeded(
			AbstractConnection::TransportServiceRequest::HttpWait)) {
		_sessionState.data->queueSendAnything();
	}
}

SessionPrivate::HandleResult SessionPrivate::handleOneReceived(
		const mtpPrime *from,
		const mtpPrime *end,
		uint64 msgId,
		OuterInfo info) {
	Expects(from < end);

	switch (mtpTypeId(*from)) {

	case mtpc_gzip_packed:
		return handleGzipPacked(from, end, msgId, info);

	case mtpc_msg_container:
		return handleMsgContainer(from, end, msgId, info);

	case mtpc_msgs_ack:
		return handleMsgsAck(from, end, msgId, info);

	case mtpc_bad_msg_notification:
		return handleBadMsgNotification(from, end, msgId, info);

	case mtpc_bad_server_salt:
		return handleBadServerSalt(from, end, msgId, info);

	case mtpc_msgs_state_info:
		return handleMsgsStateInfo(from, end, msgId, info);

	case mtpc_msgs_all_info:
		return handleMsgsAllInfo(from, end, msgId, info);

	case mtpc_msg_detailed_info:
		return handleMsgDetailedInfo(from, end, msgId, info);

	case mtpc_msg_new_detailed_info:
		return handleMsgNewDetailedInfo(from, end, msgId, info);

	case mtpc_rpc_result:
		return handleRpcResult(from, end, msgId, info);

	case mtpc_new_session_created:
		return handleNewSessionCreated(from, end, msgId, info);

	case mtpc_pong:
		return handlePong(from, end, msgId, info);

	}

	return handleUpdates(from, end, msgId, info);
}

SessionPrivate::HandleResult SessionPrivate::handleGzipPacked(
		const mtpPrime *from,
		const mtpPrime *end,
		uint64 msgId,
		OuterInfo info) {
	DEBUG_LOG(("Message Info: gzip container"));
	mtpBuffer response = ungzip(++from, end);
	if (response.empty()) {
		return HandleResult::RestartConnection;
	}
	return handleOneReceived(response.data(), response.data() + response.size(), msgId, info);
}

SessionPrivate::HandleResult SessionPrivate::handleMsgContainer(
		const mtpPrime *from,
		const mtpPrime *end,
		uint64 msgId,
		OuterInfo info) {
	if (++from >= end) {
		return HandleResult::ParseError;
	}

	const mtpPrime *otherEnd;
	const auto msgsCount = (uint32)*(from++);
	DEBUG_LOG(("Message Info: container received, count: %1").arg(msgsCount));
	for (uint32 i = 0; i < msgsCount; ++i) {
		if (from + 4 >= end) {
			return HandleResult::ParseError;
		}
		otherEnd = from + 4;

		MTPlong inMsgId;
		if (!inMsgId.read(from, otherEnd)) {
			return HandleResult::ParseError;
		}
		bool isReply = ((inMsgId.v & 0x03) == 1);
		if (!isReply && ((inMsgId.v & 0x03) != 3)) {
			LOG(("Message Error: bad msg_id %1 in contained message received").arg(inMsgId.v));
			return HandleResult::RestartConnection;
		}

		MTPint inSeqNo;
		if (!inSeqNo.read(from, otherEnd)) {
			return HandleResult::ParseError;
		}
		MTPint bytes;
		if (!bytes.read(from, otherEnd)) {
			return HandleResult::ParseError;
		}
		if ((bytes.v & 0x03) || bytes.v < 4) {
			LOG(("Message Error: bad length %1 of contained message received").arg(bytes.v));
			return HandleResult::RestartConnection;
		}

		bool needAck = (inSeqNo.v & 0x01);
		if (needAck) _requestState.ackData.push_back(inMsgId);

		DEBUG_LOG(("Message Info: message from container, msg_id: %1, needAck: %2").arg(inMsgId.v).arg(Logs::b(needAck)));

		otherEnd = from + (bytes.v >> 2);
		if (otherEnd > end) {
			return HandleResult::ParseError;
		}

		auto res = HandleResult::Success; // if no need to handle, then succeed
		const auto registered = _requestState.receivedIds.registerMsgId(
			inMsgId.v,
			needAck);
		if (registered == ReceivedIdsManager::Result::Success) {
			res = handleOneReceived(from, otherEnd, inMsgId.v, info);
			info.badTime = false;
		} else if (registered == ReceivedIdsManager::Result::TooOld) {
			res = HandleResult::ResetSession;
		}
		if (res != HandleResult::Success) {
			return res;
		}

		from = otherEnd;
	}
	return HandleResult::Success;
}

SessionPrivate::HandleResult SessionPrivate::handleMsgsAck(
		const mtpPrime *from,
		const mtpPrime *end,
		uint64 msgId,
		OuterInfo info) {
	MTPMsgsAck msg;
	if (!msg.read(from, end)) {
		return HandleResult::ParseError;
	}
	const auto &ids = msg.c_msgs_ack().vmsg_ids().v;
	DEBUG_LOG(("Message Info: acks received, ids: %1"
		).arg(LogIdsVector(ids)));
	if (ids.isEmpty()) {
		return info.badTime ? HandleResult::Ignored : HandleResult::Success;
	}

	if (info.badTime) {
		if (!requestsFixTimeSalt(ids, info)) {
			return HandleResult::Ignored;
		}
	} else {
		correctUnixtimeByFastRequest(ids, info.serverTime);
	}
	requestsAcked(ids);
	return HandleResult::Success;
}

SessionPrivate::HandleResult SessionPrivate::handleBadMsgNotification(
		const mtpPrime *from,
		const mtpPrime *end,
		uint64 msgId,
		OuterInfo info) {
	MTPBadMsgNotification msg;
	if (!msg.read(from, end)) {
		return HandleResult::ParseError;
	}
	const auto &data(msg.c_bad_msg_notification());
	LOG(("Message Info: bad message notification received (error_code %3) for msg_id = %1, seq_no = %2").arg(data.vbad_msg_id().v).arg(data.vbad_msg_seqno().v).arg(data.verror_code().v));

	const auto resendId = data.vbad_msg_id().v;
	const auto errorCode = data.verror_code().v;
	if (false
		|| errorCode == 16
		|| errorCode == 17
		|| errorCode == 32
		|| errorCode == 33
		|| errorCode == 64) { // can handle
		const auto needResend = false
			|| (errorCode == 16) // bad msg_id
			|| (errorCode == 17) // bad msg_id
			|| (errorCode == 64); // bad container
		if (errorCode == 64) { // bad container!
			if (Logs::DebugEnabled()) {
				const auto i = _requestState.sentContainers.find(resendId);
				if (i == _requestState.sentContainers.end()) {
					LOG(("Message Error: Container not found!"));
				} else {
					auto idsList = QStringList();
					for (const auto innerMsgId : i->second.messages) {
						idsList.push_back(QString::number(innerMsgId));
					}
					LOG(("Message Info: bad container received! messages: %1").arg(idsList.join(',')));
				}
			}
		}

		if (!wasSent(resendId)) {
			DEBUG_LOG(("Message Error: "
				"such message was not sent recently %1").arg(resendId));
			return info.badTime
				? HandleResult::Ignored
				: HandleResult::Success;
		}

		if (needResend) { // bad msg_id or bad container
			if (info.serverSalt) {
				_sessionState.sessionSalt = info.serverSalt;
			}

			correctUnixtimeWithBadLocal(info.serverTime);

			DEBUG_LOG(("Message Info: unixtime updated, now %1, resending in container...").arg(info.serverTime));

			resend(resendId);
		} else { // must create new session, because msg_id and msg_seqno are inconsistent
			if (info.badTime) {
				if (info.serverSalt) {
					_sessionState.sessionSalt = info.serverSalt;
				}
				correctUnixtimeWithBadLocal(info.serverTime);
				info.badTime = false;
			}
			if (_authState.bindMsgId) {
				LOG(("Message Info: bad message notification received"
					" while binding temp key, restarting."));
				return HandleResult::RestartConnection;
			}
			LOG(("Message Info: bad message notification received, msgId %1, error_code %2").arg(data.vbad_msg_id().v).arg(errorCode));
			return HandleResult::ResetSession;
		}
	} else { // fatal (except 48, but it must not get here)
		const auto badMsgId = mtpMsgId(data.vbad_msg_id().v);
		const auto requestId = wasSent(resendId);
		if (_authState.bindMsgId) {
			LOG(("Message Error: fatal bad message notification received"
				" while binding temp key, restarting."));
			return HandleResult::RestartConnection;
		} else if (requestId) {
			LOG(("Message Error: "
				"fatal bad message notification received, "
				"msgId %1, error_code %2, requestId: %3"
				).arg(badMsgId
				).arg(errorCode
				).arg(requestId));
			auto reply = mtpBuffer();
			MTPRpcError(MTP_rpc_error(
				MTP_int(500),
				MTP_string("PROTOCOL_ERROR")
			)).write(reply);

			// Save rpc_error for processing in the main thread.
			QWriteLocker locker(_sessionState.data->haveReceivedMutex());
			_sessionState.data->haveReceivedMessages().push_back({
				.reply = std::move(reply),
				.outerMsgId = info.outerMsgId,
				.requestId = requestId,
			});
		} else {
			DEBUG_LOG(("Message Error: "
				"such message was not sent recently %1").arg(badMsgId));
		}
		return info.badTime
			? HandleResult::Ignored
			: HandleResult::Success;
	}
	return HandleResult::Success;
}

SessionPrivate::HandleResult SessionPrivate::handleBadServerSalt(
		const mtpPrime *from,
		const mtpPrime *end,
		uint64 msgId,
		OuterInfo info) {
	MTPBadMsgNotification msg;
	if (!msg.read(from, end)) {
		return HandleResult::ParseError;
	}
	const auto &data = msg.c_bad_server_salt();
	DEBUG_LOG(("Message Info: bad server salt received (error_code %4) for msg_id = %1, seq_no = %2, new salt: %3").arg(data.vbad_msg_id().v).arg(data.vbad_msg_seqno().v).arg(data.vnew_server_salt().v).arg(data.verror_code().v));

	const auto resendId = data.vbad_msg_id().v;
	if (!wasSent(resendId)) {
		DEBUG_LOG(("Message Error: such message was not sent recently %1").arg(resendId));
		return (info.badTime ? HandleResult::Ignored : HandleResult::Success);
	}

	_sessionState.sessionSalt = data.vnew_server_salt().v;

	// Don't force time update here.
	base::unixtime::update(info.serverTime);

	if (_authState.bindMsgId) {
		LOG(("Message Info: bad_server_salt received while binding temp key, restarting."));
		return HandleResult::RestartConnection;
	}

	if (setState(ConnectedState, ConnectingState)) {
		resendAll();
	}

	info.badTime = false;

	DEBUG_LOG(("Message Info: unixtime updated, now %1, server_salt updated, now %2, resending...").arg(info.serverTime).arg(info.serverSalt));
	resend(resendId);
	return HandleResult::Success;
}

SessionPrivate::HandleResult SessionPrivate::handleMsgsStateInfo(
		const mtpPrime *from,
		const mtpPrime *end,
		uint64 msgId,
		OuterInfo info) {
	MTPMsgsStateInfo msg;
	if (!msg.read(from, end)) {
		return HandleResult::ParseError;
	}
	auto &data = msg.c_msgs_state_info();

	auto reqMsgId = data.vreq_msg_id().v;
	auto &states = data.vinfo().v;

	DEBUG_LOG(("Message Info: msg state received, msgId %1, reqMsgId: %2, HEX states %3").arg(msgId).arg(reqMsgId).arg(Logs::mb(states.data(), states.length()).str()));
	const auto i = _requestState.stateAndResendRequests.find(reqMsgId);
	if (i == _requestState.stateAndResendRequests.end()) {
		DEBUG_LOG(("Message Error: such message was not sent recently %1").arg(reqMsgId));
		return info.badTime
			? HandleResult::Ignored
			: HandleResult::Success;
	}
	if (info.badTime) {
		if (info.serverSalt) {
			_sessionState.sessionSalt = info.serverSalt; // requestsFixTimeSalt with no lookup
		}
		correctUnixtimeWithBadLocal(info.serverTime);

		DEBUG_LOG(("Message Info: unixtime updated from mtpc_msgs_state_info, now %1").arg(info.serverTime));

		info.badTime = false;
	}
	const auto originalRequest = i->second;
	Assert(originalRequest->size() > 8);

	requestsAcked(QVector<MTPlong>(1, MTP_long(reqMsgId)), true);

	const auto originalBody = originalRequest.bodyPrimes();
	auto rFrom = originalBody.data();
	const auto rEnd = rFrom + originalBody.size();
	if (mtpTypeId(*rFrom) == mtpc_msgs_state_req) {
		MTPMsgsStateReq request;
		if (!request.read(rFrom, rEnd)) {
			LOG(("Message Error: could not parse sent msgs_state_req"));
			return HandleResult::ParseError;
		}
		handleMsgsStates(request.c_msgs_state_req().vmsg_ids().v, states);
	} else {
		MTPMsgResendReq request;
		if (!request.read(rFrom, rEnd)) {
			LOG(("Message Error: could not parse sent msgs_resend_req"));
			return HandleResult::ParseError;
		}
		handleMsgsStates(request.c_msg_resend_req().vmsg_ids().v, states);
	}
	return HandleResult::Success;
}

SessionPrivate::HandleResult SessionPrivate::handleMsgsAllInfo(
		const mtpPrime *from,
		const mtpPrime *end,
		uint64 msgId,
		OuterInfo info) {
	if (info.badTime) {
		DEBUG_LOG(("Message Info: skipping with bad time..."));
		return HandleResult::Ignored;
	}

	MTPMsgsAllInfo msg;
	if (!msg.read(from, end)) {
		return HandleResult::ParseError;
	}
	auto &data = msg.c_msgs_all_info();
	auto &ids = data.vmsg_ids().v;
	auto &states = data.vinfo().v;

	DEBUG_LOG(("Message Info: msgs all info received, msgId %1, reqMsgIds: %2, states %3").arg(
		QString::number(msgId),
		LogIdsVector(ids),
		Logs::mb(states.data(), states.length()).str()));

	handleMsgsStates(ids, states);
	return HandleResult::Success;
}

SessionPrivate::HandleResult SessionPrivate::handleMsgDetailedInfo(
		const mtpPrime *from,
		const mtpPrime *end,
		uint64 msgId,
		OuterInfo info) {
	MTPMsgDetailedInfo msg;
	if (!msg.read(from, end)) {
		return HandleResult::ParseError;
	}
	const auto &data(msg.c_msg_detailed_info());

	DEBUG_LOG(("Message Info: msg detailed info, sent msgId %1, answerId %2, status %3, bytes %4").arg(data.vmsg_id().v).arg(data.vanswer_msg_id().v).arg(data.vstatus().v).arg(data.vbytes().v));

	QVector<MTPlong> ids(1, data.vmsg_id());
	if (info.badTime) {
		if (requestsFixTimeSalt(ids, info)) {
			info.badTime = false;
		} else {
			DEBUG_LOG(("Message Info: error, such message was not sent recently %1").arg(data.vmsg_id().v));
			return HandleResult::Ignored;
		}
	}
	requestsAcked(ids);

	const auto resMsgId = data.vanswer_msg_id();
	if (_requestState.receivedIds.lookup(resMsgId.v) != ReceivedIdsManager::State::NotFound) {
		_requestState.ackData.push_back(resMsgId);
	} else {
		DEBUG_LOG(("Message Info: answer message %1 was not received, requesting...").arg(resMsgId.v));
		_requestState.resendData.push_back(resMsgId);
	}
	return HandleResult::Success;
}

SessionPrivate::HandleResult SessionPrivate::handleMsgNewDetailedInfo(
		const mtpPrime *from,
		const mtpPrime *end,
		uint64 msgId,
		OuterInfo info) {
	if (info.badTime) {
		DEBUG_LOG(("Message Info: skipping msg_new_detailed_info with bad time..."));
		return HandleResult::Ignored;
	}
	MTPMsgDetailedInfo msg;
	if (!msg.read(from, end)) {
		return HandleResult::ParseError;
	}
	const auto &data(msg.c_msg_new_detailed_info());

	DEBUG_LOG(("Message Info: msg new detailed info, answerId %2, status %3, bytes %4").arg(data.vanswer_msg_id().v).arg(data.vstatus().v).arg(data.vbytes().v));

	const auto resMsgId = data.vanswer_msg_id();
	if (_requestState.receivedIds.lookup(resMsgId.v) != ReceivedIdsManager::State::NotFound) {
		_requestState.ackData.push_back(resMsgId);
	} else {
		DEBUG_LOG(("Message Info: answer message %1 was not received, requesting...").arg(resMsgId.v));
		_requestState.resendData.push_back(resMsgId);
	}
	return HandleResult::Success;
}

SessionPrivate::HandleResult SessionPrivate::handleRpcResult(
		const mtpPrime *from,
		const mtpPrime *end,
		uint64 msgId,
		OuterInfo info) {
	if (from + 3 > end) {
		return HandleResult::ParseError;
	}
	auto response = mtpBuffer();

	MTPlong reqMsgId;
	if (!reqMsgId.read(++from, end)) {
		return HandleResult::ParseError;
	}
	const auto requestMsgId = reqMsgId.v;

	DEBUG_LOG(("RPC Info: response received for %1, queueing...").arg(requestMsgId));

	QVector<MTPlong> ids(1, reqMsgId);
	if (info.badTime) {
		if (requestsFixTimeSalt(ids, info)) {
			info.badTime = false;
		} else {
			DEBUG_LOG(("Message Info: error, such message was not sent recently %1").arg(requestMsgId));
			return HandleResult::Ignored;
		}
	}

	mtpTypeId typeId = from[0];
	if (typeId == mtpc_gzip_packed) {
		DEBUG_LOG(("RPC Info: gzip container"));
		response = ungzip(++from, end);
		if (response.empty()) {
			return HandleResult::RestartConnection;
		}
		typeId = response[0];
	} else {
		response.resize(end - from);
		binary::Copy(
			bytes::make_span(response),
			bytes::make_span(from, end - from));
	}
	if (typeId == mtpc_rpc_error) {
		if (IsDestroyedTemporaryKeyError(response)) {
			return HandleResult::DestroyTemporaryKey;
		}
		// An error could be some RPC_CALL_FAIL or other error inside
		// the initConnection, so we're not sure yet that it was inited.
		// Wait till a good response is received.
	} else {
		_sessionState.data->notifyConnectionInited(*_sessionState.options);
	}
	requestsAcked(ids, true);

	const auto bindResult = handleBindResponse(requestMsgId, response);
	if (bindResult != HandleResult::Ignored) {
		return bindResult;
	}
	const auto requestId = wasSent(requestMsgId);
	if (requestId && requestId != mtpRequestId(0xFFFFFFFF)) {
		// Save rpc_result for processing in the main thread.
		QWriteLocker locker(_sessionState.data->haveReceivedMutex());
		_sessionState.data->haveReceivedMessages().push_back({
			.reply = std::move(response),
			.outerMsgId = info.outerMsgId,
			.requestId = requestId,
		});
	} else {
		DEBUG_LOG(("RPC Info: requestId not found for msgId %1").arg(requestMsgId));
	}
	return HandleResult::Success;
}

SessionPrivate::HandleResult SessionPrivate::handleNewSessionCreated(
		const mtpPrime *from,
		const mtpPrime *end,
		uint64 msgId,
		OuterInfo info) {
	const mtpPrime *start = from;
	MTPNewSession msg;
	if (!msg.read(from, end)) {
		return HandleResult::ParseError;
	}
	const auto &data(msg.c_new_session_created());

	if (info.badTime) {
		if (requestsFixTimeSalt(QVector<MTPlong>(1, data.vfirst_msg_id()), info)) {
			info.badTime = false;
		} else {
			DEBUG_LOG(("Message Info: error, such message was not sent recently %1").arg(data.vfirst_msg_id().v));
			return HandleResult::Ignored;
		}
	}

	DEBUG_LOG(("Message Info: new server session created, unique_id %1, first_msg_id %2, server_salt %3").arg(data.vunique_id().v).arg(data.vfirst_msg_id().v).arg(data.vserver_salt().v));
	_sessionState.sessionSalt = data.vserver_salt().v;

	mtpMsgId firstMsgId = data.vfirst_msg_id().v;
	QVector<quint64> toResend;
	{
		QReadLocker locker(_sessionState.data->haveSentMutex());
		const auto &haveSent = _sessionState.data->haveSentMap();
		toResend.reserve(haveSent.size());
		for (const auto &[msgId, request] : haveSent) {
			if (msgId >= firstMsgId) {
				break;
			} else if (request->requestId) {
				toResend.push_back(msgId);
			}
		}
	}
	for (const auto msgId : toResend) {
		resend(msgId, 10);
	}

	mtpBuffer update(from - start);
	if (from > start) {
		binary::Copy(
			bytes::make_span(update),
			bytes::make_span(start, from - start));
	}

	// Notify main process about new session - need to get difference.
	QWriteLocker locker(_sessionState.data->haveReceivedMutex());
	_sessionState.data->haveReceivedMessages().push_back({
		.reply = update,
		.outerMsgId = info.outerMsgId,
	});
	return HandleResult::Success;
}

SessionPrivate::HandleResult SessionPrivate::handlePong(
		const mtpPrime *from,
		const mtpPrime *end,
		uint64 msgId,
		OuterInfo info) {
	MTPPong msg;
	if (!msg.read(from, end)) {
		return HandleResult::ParseError;
	}
	const auto &data(msg.c_pong());
	DEBUG_LOG(("Message Info: pong received, msg_id: %1, ping_id: %2").arg(data.vmsg_id().v).arg(data.vping_id().v));

	if (!wasSent(data.vmsg_id().v)) {
		DEBUG_LOG(("Message Error: such msg_id %1 ping_id %2 was not sent recently").arg(data.vmsg_id().v).arg(data.vping_id().v));
		return HandleResult::Ignored;
	}
	if (data.vping_id().v == _requestState.pingId) {
		if (_requestState.pingSentTime) {
			reportPingTime(crl::now() - base::take(_requestState.pingSentTime));
		}
		_requestState.pingId = 0;
	} else {
		DEBUG_LOG(("Message Info: just pong..."));
	}

	QVector<MTPlong> ids(1, data.vmsg_id());
	if (info.badTime) {
		if (requestsFixTimeSalt(ids, info)) {
			info.badTime = false;
		} else {
			return HandleResult::Ignored;
		}
	}
	requestsAcked(ids, true);
	return HandleResult::Success;
}

SessionPrivate::HandleResult SessionPrivate::handleUpdates(
		const mtpPrime *from,
		const mtpPrime *end,
		uint64 msgId,
		OuterInfo info) {
	if (info.badTime) {
		DEBUG_LOG(("Message Error: bad time in updates cons, must create new session"));
		return HandleResult::ResetSession;
	}

	if (_currentDcType == DcType::Regular) {
		mtpBuffer update(end - from);
		if (end > from) {
			binary::Copy(
				bytes::make_span(update),
				bytes::make_span(from, end - from));
		}

		// Notify main process about the new updates.
		QWriteLocker locker(_sessionState.data->haveReceivedMutex());
		_sessionState.data->haveReceivedMessages().push_back({
			.reply = update,
			.outerMsgId = info.outerMsgId,
		});
	} else {
		LOG(("Message Error: unexpected updates in dcType: %1"
			).arg(static_cast<int>(_currentDcType)));
	}

	return HandleResult::Success;
}

mtpBuffer SessionPrivate::ungzip(const mtpPrime *from, const mtpPrime *end) const {
	mtpBuffer result; // * 4 because of mtpPrime type
	result.resize(0);

	MTPstring packed;
	if (!packed.read(from, end)) { // read packed string as serialized mtp string type
		LOG(("RPC Error: could not read gziped bytes."));
		return result;
	}
	uint32 packedLen = packed.v.size(), unpackedChunk = packedLen;

	z_stream stream;
	stream.zalloc = 0;
	stream.zfree = 0;
	stream.opaque = 0;
	stream.avail_in = 0;
	stream.next_in = 0;
	int res = inflateInit2(&stream, 16 + MAX_WBITS);
	if (res != Z_OK) {
		LOG(("RPC Error: could not init zlib stream, code: %1").arg(res));
		return result;
	}
	stream.avail_in = packedLen;
	stream.next_in = reinterpret_cast<Bytef*>(packed.v.data());

	stream.avail_out = 0;
	while (!stream.avail_out) {
		result.resize(result.size() + unpackedChunk);
		stream.avail_out = unpackedChunk * sizeof(mtpPrime);
		stream.next_out = (Bytef*)&result[result.size() - unpackedChunk];
		int res = inflate(&stream, Z_NO_FLUSH);
		if (res != Z_OK && res != Z_STREAM_END) {
			inflateEnd(&stream);
			LOG(("RPC Error: could not unpack gziped data, code: %1").arg(res));
			DEBUG_LOG(("RPC Error: bad gzip: %1").arg(Logs::mb(packed.v.constData(), packedLen).str()));
			return mtpBuffer();
		}
	}
	if (stream.avail_out & 0x03) {
		uint32 badSize = result.size() * sizeof(mtpPrime) - stream.avail_out;
		LOG(("RPC Error: bad length of unpacked data %1").arg(badSize));
		DEBUG_LOG(("RPC Error: bad unpacked data %1").arg(Logs::mb(result.data(), badSize).str()));
		return mtpBuffer();
	}
	result.resize(result.size() - (stream.avail_out >> 2));
	inflateEnd(&stream);
	if (!result.size()) {
		LOG(("RPC Error: bad length of unpacked data 0"));
	}
	return result;
}

bool SessionPrivate::requestsFixTimeSalt(const QVector<MTPlong> &ids, const OuterInfo &info) {
	for (const auto &id : ids) {
		if (wasSent(id.v)) {
			// Found such msg_id in recent acked or in recent sent requests.
			if (info.serverSalt) {
				_sessionState.sessionSalt = info.serverSalt;
			}
			correctUnixtimeWithBadLocal(info.serverTime);
			return true;
		}
	}
	return false;
}

void SessionPrivate::correctUnixtimeByFastRequest(
		const QVector<MTPlong> &ids,
		TimeId serverTime) {
	const auto now = crl::now();

	QReadLocker locker(_sessionState.data->haveSentMutex());
	const auto &haveSent = _sessionState.data->haveSentMap();
	for (const auto &id : ids) {
		const auto i = haveSent.find(id.v);
		if (i == haveSent.end()) {
			continue;
		}
		const auto duration = (now - i->second->lastSentTime);
		if (duration < 0 || duration > SyncTimeRequestDuration) {
			continue;
		}
		locker.unlock();

		SyncTimeRequestDuration = duration;
		base::unixtime::update(serverTime);
		return;
	}
}

void SessionPrivate::correctUnixtimeWithBadLocal(TimeId serverTime) {
	SyncTimeRequestDuration = kFastRequestDuration;
	base::unixtime::update(serverTime, true);
}

void SessionPrivate::requestsAcked(const QVector<MTPlong> &ids, bool byResponse) {
	DEBUG_LOG(("Message Info: requests acked, ids %1").arg(LogIdsVector(ids)));

	QVector<MTPlong> toAckMore;
	{
		QWriteLocker locker2(_sessionState.data->haveSentMutex());
		auto &haveSent = _sessionState.data->haveSentMap();

		for (const auto &wrappedMsgId : ids) {
			const auto msgId = wrappedMsgId.v;
			if (const auto i = _requestState.sentContainers.find(msgId); i != end(_requestState.sentContainers)) {
				DEBUG_LOG(("Message Info: container ack received, msgId %1").arg(msgId));
				const auto &list = i->second.messages;
				toAckMore.reserve(toAckMore.size() + list.size());
				for (const auto msgId : list) {
					toAckMore.push_back(MTP_long(msgId));
				}
				_requestState.sentContainers.erase(i);
				continue;
			}
			if (const auto i = _requestState.stateAndResendRequests.find(msgId); i != end(_requestState.stateAndResendRequests)) {
				_requestState.stateAndResendRequests.erase(i);
				continue;
			}
			if (const auto i = haveSent.find(msgId); i != end(haveSent)) {
				const auto requestId = i->second->requestId;

				if (!byResponse && _instance->hasCallback(requestId)) {
					DEBUG_LOG(("Message Info: ignoring ACK for msgId %1 because request %2 requires a response").arg(msgId).arg(requestId));
					continue;
				}
				haveSent.erase(i);

				_requestState.ackedIds.emplace(msgId, requestId);
				continue;
			}
			DEBUG_LOG(("Message Info: msgId %1 was not found in recent sent, while acking requests, searching in resend...").arg(msgId));
			if (const auto i = _requestState.resendingIds.find(msgId); i != end(_requestState.resendingIds)) {
				const auto requestId = i->second;

				if (!byResponse && _instance->hasCallback(requestId)) {
					DEBUG_LOG(("Message Info: ignoring ACK for msgId %1 because request %2 requires a response").arg(msgId).arg(requestId));
					continue;
				}
				_requestState.resendingIds.erase(i);

				QWriteLocker locker4(_sessionState.data->toSendMutex());
				auto &toSend = _sessionState.data->toSendMap();
				const auto j = toSend.find(requestId);
				if (j == end(toSend)) {
					DEBUG_LOG(("Message Info: msgId %1 was found in recent resent, requestId %2 was not found in prepared to send").arg(msgId).arg(requestId));
					continue;
				}
				if (j->second->requestId != requestId) {
					DEBUG_LOG(("Message Error: for msgId %1 found resent request, requestId %2, contains requestId %3").arg(msgId).arg(requestId).arg(j->second->requestId));
				} else {
					DEBUG_LOG(("Message Info: acked msgId %1 that was prepared to resend, requestId %2").arg(msgId).arg(requestId));
				}

				_requestState.ackedIds.emplace(msgId, j->second->requestId);

				toSend.erase(j);
				continue;
			}
			DEBUG_LOG(("Message Info: msgId %1 was not found in recent resent either").arg(msgId));
		}
	}

	auto ackedCount = _requestState.ackedIds.size();
	if (ackedCount > kIdsBufferSize) {
		DEBUG_LOG(("Message Info: removing some old acked sent msgIds %1").arg(ackedCount - kIdsBufferSize));
		while (ackedCount-- > kIdsBufferSize) {
			_requestState.ackedIds.erase(_requestState.ackedIds.begin());
		}
	}

	if (toAckMore.size()) {
		requestsAcked(toAckMore);
	}
}

void SessionPrivate::handleMsgsStates(const QVector<MTPlong> &ids, const QByteArray &states) {
	const auto idsCount = ids.size();
	if (!idsCount) {
		DEBUG_LOG(("Message Info: void ids vector in handleMsgsStates()"));
		return;
	}
	if (states.size() != idsCount) {
		LOG(("Message Error: got less states than required ids count."));
		return;
	}

	auto acked = QVector<MTPlong>();
	acked.reserve(idsCount);
	for (auto i = 0; i != idsCount; ++i) {
		const auto state = states[i];
		const auto requestMsgId = ids[i].v;
		{
			QReadLocker locker(_sessionState.data->haveSentMutex());
			if (!_sessionState.data->haveSentMap().contains(requestMsgId)) {
				DEBUG_LOG(("Message Info: state was received for msgId %1, but request is not found, looking in resent requests...").arg(requestMsgId));
				const auto reqIt = _requestState.resendingIds.find(requestMsgId);
				if (reqIt != _requestState.resendingIds.cend()) {
					if ((state & 0x07) != 0x04) { // was received
						DEBUG_LOG(("Message Info: state was received for msgId %1, state %2, already resending in container").arg(requestMsgId).arg((int32)state));
					} else {
						DEBUG_LOG(("Message Info: state was received for msgId %1, state %2, ack, cancelling resend").arg(requestMsgId).arg((int32)state));
						acked.push_back(MTP_long(requestMsgId)); // will remove from resend in requestsAcked
					}
				} else {
					DEBUG_LOG(("Message Info: msgId %1 was not found in recent resent either").arg(requestMsgId));
				}
				continue;
			}
		}
		if ((state & 0x07) != 0x04) { // was received
			DEBUG_LOG(("Message Info: state was received for msgId %1, state %2, resending in container").arg(requestMsgId).arg((int32)state));
			resend(requestMsgId, 10);
		} else {
			DEBUG_LOG(("Message Info: state was received for msgId %1, state %2, ack").arg(requestMsgId).arg((int32)state));
			acked.push_back(MTP_long(requestMsgId));
		}
	}
	requestsAcked(acked);
}

void SessionPrivate::clearSpecialMsgId(mtpMsgId msgId) {
	if (msgId == _requestState.pingMsgId) {
		_requestState.pingMsgId = 0;
		_requestState.pingId = 0;
		_requestState.pingSentTime = 0;
	} else if (msgId == _authState.bindMsgId) {
		_authState.bindMsgId = 0;
	}
}

void SessionPrivate::resend(mtpMsgId msgId, crl::time msCanWait) {
	const auto guard = gsl::finally([&] {
		clearSpecialMsgId(msgId);
		if (msCanWait >= 0) {
			_sessionState.data->queueSendAnything(msCanWait);
		}
	});

	if (const auto i = _requestState.sentContainers.find(msgId); i != end(_requestState.sentContainers)) {
		DEBUG_LOG(("Message Info: resending container, msgId %1").arg(msgId));
		const auto ids = std::move(i->second.messages);
		_requestState.sentContainers.erase(i);

		for (const auto innerMsgId : ids) {
			resend(innerMsgId, -1);
		}
		return;
	}
	auto lock = QWriteLocker(_sessionState.data->haveSentMutex());
	auto &haveSent = _sessionState.data->haveSentMap();
	auto i = haveSent.find(msgId);
	if (i == haveSent.end()) {
		return;
	}
	auto request = i->second;
	haveSent.erase(i);
	lock.unlock();

	request->lastSentTime = crl::now();
	request->forceSendInContainer = true;
	_requestState.resendingIds.emplace(msgId, request->requestId);
	{
		QWriteLocker locker(_sessionState.data->toSendMutex());
		_sessionState.data->toSendMap().emplace(request->requestId, request);
	}
}

void SessionPrivate::resendAll() {
	auto lock = QWriteLocker(_sessionState.data->haveSentMutex());
	auto haveSent = base::take(_sessionState.data->haveSentMap());
	lock.unlock();
	{
		auto lock = QWriteLocker(_sessionState.data->toSendMutex());
		auto &toSend = _sessionState.data->toSendMap();
		const auto now = crl::now();
		for (auto &[msgId, request] : haveSent) {
			const auto requestId = request->requestId;
			request->lastSentTime = now;
			request->forceSendInContainer = true;
			_requestState.resendingIds.emplace(msgId, requestId);
			toSend.emplace(requestId, std::move(request));
		}
	}

	_sessionState.data->queueSendAnything();
}

mtpRequestId SessionPrivate::wasSent(mtpMsgId msgId) const {
	if (msgId == _requestState.pingMsgId || msgId == _authState.bindMsgId) {
		return mtpRequestId(0xFFFFFFFF);
	}
	if (const auto i = _requestState.resendingIds.find(msgId); i != end(_requestState.resendingIds)) {
		return i->second;
	}
	if (const auto i = _requestState.ackedIds.find(msgId); i != end(_requestState.ackedIds)) {
		return i->second;
	}
	if (const auto i = _requestState.sentContainers.find(msgId); i != end(_requestState.sentContainers)) {
		return mtpRequestId(0xFFFFFFFF);
	}

	{
		QReadLocker locker(_sessionState.data->haveSentMutex());
		const auto &haveSent = _sessionState.data->haveSentMap();
		const auto i = haveSent.find(msgId);
		if (i != haveSent.end()) {
			return i->second->requestId
				? i->second->requestId
				: mtpRequestId(0xFFFFFFFF);
		}
	}
	return 0;
}

} // namespace details
} // namespace MTP

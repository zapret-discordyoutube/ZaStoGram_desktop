/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/session/private/session_private.h"

#include "core/version.h"
#include "mtproto/protocol/mtproto_binary.h"
#include "mtproto/auth/mtproto_bound_key_creator.h"
#include "mtproto/details/mtproto_dcenter.h"
#include "mtproto/protocol/mtproto_dump_to_text.h"
#include "mtproto/details/mtproto_rsa_public_key.h"
#include "mtproto/session/session.h"
#include "mtproto/protocol/mtproto_response.h"
#include "mtproto/config/mtproto_dc_options.h"
#include "mtproto/transport/connection_abstract.h"
#include "base/options.h"
#include "base/random.h"
#include "base/qthelp_url.h"
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

} // namespace

void SessionMessageHandler::clearOldContainers() {
	auto resent = false;
	auto nextTimeout = kSentContainerLives;
	const auto now = crl::now();
	const auto checkTime = now - kSentContainerLives;
	for (auto i = _owner->_requestState.sentContainers.begin(); i != _owner->_requestState.sentContainers.end();) {
		if (i->second.sent <= checkTime) {
			DEBUG_LOG(("MTP Info: Removing old container with resending %1, "
				"sent: %2, now: %3, current unixtime: %4"
				).arg(i->first
				).arg(i->second.sent
				).arg(now
				).arg(base::unixtime::now()));

			const auto ids = std::move(i->second.messages);
			i = _owner->_requestState.sentContainers.erase(i);

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
		_owner->_sessionState.data->queueNeedToResumeAndSend();
	}
	if (nextTimeout < kSentContainerLives) {
		_owner->_transport._timing.clearOldContainersTimer.callOnce(nextTimeout);
	} else if (!_owner->_transport._timing.clearOldContainersTimer.isActive()) {
		_owner->_transport._timing.clearOldContainersTimer.callEach(nextTimeout);
	}
}

void SessionMessageHandler::handleReceived() {
	Expects(_owner->_sessionState.encryptionKey != nullptr);

	_owner->_transport.onReceivedSome();

	while (!_owner->_transport._state.connection->received().empty()) {
		auto intsBuffer = std::move(_owner->_transport._state.connection->received().front());
		_owner->_transport._state.connection->received().pop_front();

		constexpr auto kExternalHeaderIntsCount = 6U; // 2 auth_key_id, 4 msg_key
		constexpr auto kEncryptedHeaderIntsCount = 8U; // 2 salt, 2 session, 2 msg_id, 1 seq_no, 1 length
		constexpr auto kMinimalEncryptedIntsCount = kEncryptedHeaderIntsCount + 4U; // + 1 data + 3 padding
		constexpr auto kMinimalIntsCount = kExternalHeaderIntsCount + kMinimalEncryptedIntsCount;
		auto intsCount = uint32(intsBuffer.size());
		auto ints = intsBuffer.constData();
		if ((intsCount < kMinimalIntsCount) || (intsCount > kMaxMessageLength / kIntSize)) {
			LOG(("TCP Error: bad message received, len %1").arg(intsCount * kIntSize));
			return _owner->restart();
		}
		const auto receivedKeyId = binary::Read<uint64>(
			bytes::make_span(intsBuffer));
		if (_owner->_sessionState.keyId != receivedKeyId) {
			LOG(("TCP Error: bad auth_key_id %1 instead of %2 received").arg(_owner->_sessionState.keyId).arg(receivedKeyId));
			return _owner->restart();
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

		aesIgeDecrypt(encryptedInts, decryptedBuffer.data(), encryptedBytesCount, _owner->_sessionState.encryptionKey, msgKey);

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

		if (!_owner->_sessionState.encryptionKey->validateMsgKey(
				msgKey,
				bytes::make_span(decrypted),
				false)) {
			LOG(("TCP Error: bad SHA256 hash after aesDecrypt in message"));
			return _owner->restart();
		}

		if ((messageLength > kMaxMessageLength)
			|| (messageLength & 0x03)
			|| (paddingSize < kMinPaddingSize)
			|| (paddingSize > kMaxPaddingSize)) {
			LOG(("TCP Error: bad msg_len received %1, data size: %2").arg(messageLength).arg(encryptedBytesCount));
			return _owner->restart();
		}

		if (Logs::DebugEnabled()) {
			_owner->_transport._state.connection->logInfo(u"Decrypted message %1,%2,%3 is %4 len"_q
				.arg(msgId)
				.arg(seqNo)
				.arg(Logs::b(needAck))
				.arg(fullDataLength));
		}

		if (session != _owner->_sessionState.sessionId) {
			LOG(("MTP Error: bad server session received"));
			return _owner->restart();
		}

		const auto serverTime = int32(msgId >> 32);
		const auto isReply = ((msgId & 0x03) == 1);
		if (!isReply && ((msgId & 0x03) != 3)) {
			LOG(("MTP Error: bad msg_id %1 in message received").arg(msgId));

			return _owner->restart();
		}

		const auto clientTime = base::unixtime::now();
		const auto badTime = (serverTime > clientTime + 60)
			|| (serverTime + 300 < clientTime);
		if (badTime) {
			DEBUG_LOG(("MTP Info: bad server time from msg_id: %1, my time: %2").arg(serverTime).arg(clientTime));
		}

		bool wasConnected = (_owner->getState() == ConnectedState);
		if (serverSalt != _owner->_sessionState.sessionSalt) {
			if (!badTime) {
				DEBUG_LOG(("MTP Info: other salt received... received: %1, my salt: %2, updating...").arg(serverSalt).arg(_owner->_sessionState.sessionSalt));
				_owner->_sessionState.sessionSalt = serverSalt;

				if (_owner->setState(ConnectedState, ConnectingState)) {
					resendAll();
				}
			} else {
				DEBUG_LOG(("MTP Info: other salt received... received: %1, my salt: %2").arg(serverSalt).arg(_owner->_sessionState.sessionSalt));
			}
		} else {
			serverSalt = 0; // dont pass to handle method, so not to lock in setSalt()
		}

		if (needAck) _owner->_requestState.ackData.push_back(MTP_long(msgId));

		auto res = HandleResult::Success; // if no need to handle, then succeed
		auto from = decrypted.constData() + kEncryptedHeaderIntsCount;
		auto end = from + (messageLength / kIntSize);
		auto sfrom = from - (SerializedRequest::kMessageBodyPosition
			- SerializedRequest::kMessageIdPosition);
		MTP_LOG(_owner->_shiftedDcId, ("Recv: ")
			+ DumpToText(sfrom, end)
			+ QString(" (dc:%1,key:%2,session:%3)"
			).arg(AbstractConnection::ProtocolDcDebugId(_owner->getProtocolDcId())
			).arg(_owner->_sessionState.encryptionKey->keyId()
			).arg(_owner->_sessionState.sessionId));

		const auto registered = _owner->_requestState.receivedIds.registerMsgId(
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
		_owner->_requestState.receivedIds.shrink();

		// send acks
		if (const auto toAckSize = _owner->_requestState.ackData.size()) {
			DEBUG_LOG(("MTP Info: will send %1 acks, ids: %2").arg(toAckSize).arg(LogIdsVector(_owner->_requestState.ackData)));
			_owner->_sessionState.data->queueSendAnything(kAckSendWaiting);
		}

		auto lock = QReadLocker(_owner->_sessionState.data->haveReceivedMutex());
		const auto tryToReceive = !_owner->_sessionState.data->haveReceivedMessages().empty();
		lock.unlock();

		if (tryToReceive) {
			DEBUG_LOG(("MTP Info: queueTryToReceive() - need to parse in another thread, %1 messages.").arg(_owner->_sessionState.data->haveReceivedMessages().size()));
			_owner->_sessionState.data->queueTryToReceive();
		}

		if (res != HandleResult::Success && res != HandleResult::Ignored) {
			if (res == HandleResult::DestroyTemporaryKey) {
				_owner->destroyTemporaryKey();
			} else if (res == HandleResult::ResetSession) {
				_owner->_sessionState.needReset = true;
			}
			return _owner->restart();
		}
		_owner->_transport._timing.retryTimeout = 1; // reset _owner->restart() timer

		if (!_owner->_transport._state.mtprotoDataReceived) {
			_owner->_transport._state.mtprotoDataReceived = true;
			_owner->_transport._state.mtprotoSilentTimeouts = 0;
			if (_owner->_transport._state.proxyMigrationScout) {
				_owner->_transport._state.proxyMigrationScout = false;
				_owner->_delegate->proxyMigrationSucceeded(
					_owner->_transport._state.proxyGeneration);
			}
			_owner->logMtprotoEvent(
				ProxyDiagnosticsPhase::MtpFirstDataReceived,
				ProxyDiagnosticsSeverity::Info,
				u"first mtproto payload received"_q);
			_owner->_proxyPort->reportFirstMtprotoPayload(
				_owner->_transport.currentProxyAttempt());
		}

		_owner->_transport._state.startedConnectingAt = crl::time(0);

		if (!wasConnected) {
			if (_owner->getState() == ConnectedState) {
				_owner->_sessionState.data->queueNeedToResumeAndSend();
			}
		}
	}
	if (_owner->_transport._state.connection->serviceRequestNeeded(
			AbstractConnection::TransportServiceRequest::HttpWait)) {
		_owner->_sessionState.data->queueSendAnything();
	}
}

SessionMessageHandler::HandleResult SessionMessageHandler::handleOneReceived(
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

SessionMessageHandler::HandleResult SessionMessageHandler::handleGzipPacked(
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

SessionMessageHandler::HandleResult SessionMessageHandler::handleMsgContainer(
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
		if (needAck) _owner->_requestState.ackData.push_back(inMsgId);

		DEBUG_LOG(("Message Info: message from container, msg_id: %1, needAck: %2").arg(inMsgId.v).arg(Logs::b(needAck)));

		otherEnd = from + (bytes.v >> 2);
		if (otherEnd > end) {
			return HandleResult::ParseError;
		}

		auto res = HandleResult::Success; // if no need to handle, then succeed
		const auto registered = _owner->_requestState.receivedIds.registerMsgId(
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

SessionMessageHandler::HandleResult SessionMessageHandler::handleMsgsAck(
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

SessionMessageHandler::HandleResult SessionMessageHandler::handleBadMsgNotification(
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
				const auto i = _owner->_requestState.sentContainers.find(resendId);
				if (i == _owner->_requestState.sentContainers.end()) {
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

		if (!_owner->wasSent(resendId)) {
			DEBUG_LOG(("Message Error: "
				"such message was not sent recently %1").arg(resendId));
			return info.badTime
				? HandleResult::Ignored
				: HandleResult::Success;
		}

		if (needResend) { // bad msg_id or bad container
			if (info.serverSalt) {
				_owner->_sessionState.sessionSalt = info.serverSalt;
			}

			correctUnixtimeWithBadLocal(info.serverTime);

			DEBUG_LOG(("Message Info: unixtime updated, now %1, resending in container...").arg(info.serverTime));

			resend(resendId);
		} else { // must create new session, because msg_id and msg_seqno are inconsistent
			if (info.badTime) {
				if (info.serverSalt) {
					_owner->_sessionState.sessionSalt = info.serverSalt;
				}
				correctUnixtimeWithBadLocal(info.serverTime);
				info.badTime = false;
			}
			if (_owner->_authState.bindMsgId) {
				LOG(("Message Info: bad message notification received"
					" while binding temp key, restarting."));
				return HandleResult::RestartConnection;
			}
			LOG(("Message Info: bad message notification received, msgId %1, error_code %2").arg(data.vbad_msg_id().v).arg(errorCode));
			return HandleResult::ResetSession;
		}
	} else { // fatal (except 48, but it must not get here)
		const auto badMsgId = mtpMsgId(data.vbad_msg_id().v);
		const auto requestId = _owner->wasSent(resendId);
		if (_owner->_authState.bindMsgId) {
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
			QWriteLocker locker(_owner->_sessionState.data->haveReceivedMutex());
			_owner->_sessionState.data->haveReceivedMessages().push_back({
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

SessionMessageHandler::HandleResult SessionMessageHandler::handleBadServerSalt(
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
	if (!_owner->wasSent(resendId)) {
		DEBUG_LOG(("Message Error: such message was not sent recently %1").arg(resendId));
		return (info.badTime ? HandleResult::Ignored : HandleResult::Success);
	}

	_owner->_sessionState.sessionSalt = data.vnew_server_salt().v;

	// Don't force time update here.
	base::unixtime::update(info.serverTime);

	if (_owner->_authState.bindMsgId) {
		LOG(("Message Info: bad_server_salt received while binding temp key, restarting."));
		return HandleResult::RestartConnection;
	}

	if (_owner->setState(ConnectedState, ConnectingState)) {
		resendAll();
	}

	info.badTime = false;

	DEBUG_LOG(("Message Info: unixtime updated, now %1, server_salt updated, now %2, resending...").arg(info.serverTime).arg(info.serverSalt));
	resend(resendId);
	return HandleResult::Success;
}

SessionMessageHandler::HandleResult SessionMessageHandler::handleMsgsStateInfo(
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
	const auto i = _owner->_requestState.stateAndResendRequests.find(reqMsgId);
	if (i == _owner->_requestState.stateAndResendRequests.end()) {
		DEBUG_LOG(("Message Error: such message was not sent recently %1").arg(reqMsgId));
		return info.badTime
			? HandleResult::Ignored
			: HandleResult::Success;
	}
	if (info.badTime) {
		if (info.serverSalt) {
			_owner->_sessionState.sessionSalt = info.serverSalt; // requestsFixTimeSalt with no lookup
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

SessionMessageHandler::HandleResult SessionMessageHandler::handleMsgsAllInfo(
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

SessionMessageHandler::HandleResult SessionMessageHandler::handleMsgDetailedInfo(
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
	if (_owner->_requestState.receivedIds.lookup(resMsgId.v) != ReceivedIdsManager::State::NotFound) {
		_owner->_requestState.ackData.push_back(resMsgId);
	} else {
		DEBUG_LOG(("Message Info: answer message %1 was not received, requesting...").arg(resMsgId.v));
		_owner->_requestState.resendData.push_back(resMsgId);
	}
	return HandleResult::Success;
}

SessionMessageHandler::HandleResult SessionMessageHandler::handleMsgNewDetailedInfo(
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
	if (_owner->_requestState.receivedIds.lookup(resMsgId.v) != ReceivedIdsManager::State::NotFound) {
		_owner->_requestState.ackData.push_back(resMsgId);
	} else {
		DEBUG_LOG(("Message Info: answer message %1 was not received, requesting...").arg(resMsgId.v));
		_owner->_requestState.resendData.push_back(resMsgId);
	}
	return HandleResult::Success;
}

SessionMessageHandler::HandleResult SessionMessageHandler::handleRpcResult(
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
		_owner->_sessionState.data->notifyConnectionInited(*_owner->_sessionState.options);
	}
	requestsAcked(ids, true);

	const auto bindResult = handleBindResponse(requestMsgId, response);
	if (bindResult != HandleResult::Ignored) {
		return bindResult;
	}
	const auto requestId = _owner->wasSent(requestMsgId);
	if (requestId && requestId != mtpRequestId(0xFFFFFFFF)) {
		// Save rpc_result for processing in the main thread.
		QWriteLocker locker(_owner->_sessionState.data->haveReceivedMutex());
		_owner->_sessionState.data->haveReceivedMessages().push_back({
			.reply = std::move(response),
			.outerMsgId = info.outerMsgId,
			.requestId = requestId,
		});
	} else {
		DEBUG_LOG(("RPC Info: requestId not found for msgId %1").arg(requestMsgId));
	}
	return HandleResult::Success;
}

SessionMessageHandler::HandleResult SessionMessageHandler::handleNewSessionCreated(
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
	_owner->_sessionState.sessionSalt = data.vserver_salt().v;

	mtpMsgId firstMsgId = data.vfirst_msg_id().v;
	QVector<quint64> toResend;
	{
		QReadLocker locker(_owner->_sessionState.data->haveSentMutex());
		const auto &haveSent = _owner->_sessionState.data->haveSentMap();
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
	QWriteLocker locker(_owner->_sessionState.data->haveReceivedMutex());
	_owner->_sessionState.data->haveReceivedMessages().push_back({
		.reply = update,
		.outerMsgId = info.outerMsgId,
	});
	return HandleResult::Success;
}

SessionMessageHandler::HandleResult SessionMessageHandler::handlePong(
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

	if (!_owner->wasSent(data.vmsg_id().v)) {
		DEBUG_LOG(("Message Error: such msg_id %1 ping_id %2 was not sent recently").arg(data.vmsg_id().v).arg(data.vping_id().v));
		return HandleResult::Ignored;
	}
	if (data.vping_id().v == _owner->_requestState.pingId) {
		if (_owner->_requestState.pingSentTime) {
			_owner->reportPingTime(crl::now() - base::take(_owner->_requestState.pingSentTime));
		}
		_owner->_requestState.pingId = 0;
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

SessionMessageHandler::HandleResult SessionMessageHandler::handleUpdates(
		const mtpPrime *from,
		const mtpPrime *end,
		uint64 msgId,
		OuterInfo info) {
	if (info.badTime) {
		DEBUG_LOG(("Message Error: bad time in updates cons, must create new session"));
		return HandleResult::ResetSession;
	}

	if (_owner->_currentDcType == DcType::Regular) {
		mtpBuffer update(end - from);
		if (end > from) {
			binary::Copy(
				bytes::make_span(update),
				bytes::make_span(from, end - from));
		}

		// Notify main process about the new updates.
		QWriteLocker locker(_owner->_sessionState.data->haveReceivedMutex());
		_owner->_sessionState.data->haveReceivedMessages().push_back({
			.reply = update,
			.outerMsgId = info.outerMsgId,
		});
	} else {
		LOG(("Message Error: unexpected updates in dcType: %1"
			).arg(static_cast<int>(_owner->_currentDcType)));
	}

	return HandleResult::Success;
}

mtpBuffer SessionMessageHandler::ungzip(const mtpPrime *from, const mtpPrime *end) const {
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

bool SessionMessageHandler::requestsFixTimeSalt(const QVector<MTPlong> &ids, const OuterInfo &info) {
	for (const auto &id : ids) {
		if (_owner->wasSent(id.v)) {
			// Found such msg_id in recent acked or in recent sent requests.
			if (info.serverSalt) {
				_owner->_sessionState.sessionSalt = info.serverSalt;
			}
			correctUnixtimeWithBadLocal(info.serverTime);
			return true;
		}
	}
	return false;
}

void SessionMessageHandler::correctUnixtimeByFastRequest(
		const QVector<MTPlong> &ids,
		TimeId serverTime) {
	const auto now = crl::now();

	QReadLocker locker(_owner->_sessionState.data->haveSentMutex());
	const auto &haveSent = _owner->_sessionState.data->haveSentMap();
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

void SessionMessageHandler::correctUnixtimeWithBadLocal(TimeId serverTime) {
	SyncTimeRequestDuration = kFastRequestDuration;
	base::unixtime::update(serverTime, true);
}

void SessionMessageHandler::requestsAcked(const QVector<MTPlong> &ids, bool byResponse) {
	DEBUG_LOG(("Message Info: requests acked, ids %1").arg(LogIdsVector(ids)));

	QVector<MTPlong> toAckMore;
	auto resentAcked = std::vector<std::pair<mtpMsgId, mtpRequestId>>();
	{
		QWriteLocker locker2(_owner->_sessionState.data->haveSentMutex());
		auto &haveSent = _owner->_sessionState.data->haveSentMap();

		for (const auto &wrappedMsgId : ids) {
			const auto msgId = wrappedMsgId.v;
			if (const auto i = _owner->_requestState.sentContainers.find(msgId); i != end(_owner->_requestState.sentContainers)) {
				DEBUG_LOG(("Message Info: container ack received, msgId %1").arg(msgId));
				const auto &list = i->second.messages;
				toAckMore.reserve(toAckMore.size() + list.size());
				for (const auto msgId : list) {
					toAckMore.push_back(MTP_long(msgId));
				}
				_owner->_requestState.sentContainers.erase(i);
				continue;
			}
			if (const auto i = _owner->_requestState.stateAndResendRequests.find(msgId); i != end(_owner->_requestState.stateAndResendRequests)) {
				_owner->_requestState.stateAndResendRequests.erase(i);
				continue;
			}
			if (const auto i = haveSent.find(msgId); i != end(haveSent)) {
				const auto requestId = i->second->requestId;

				if (!byResponse && _owner->_delegate->hasCallback(requestId)) {
					DEBUG_LOG(("Message Info: ignoring ACK for msgId %1 because request %2 requires a response").arg(msgId).arg(requestId));
					continue;
				}
				haveSent.erase(i);

				_owner->_requestState.ackedIds.emplace(msgId, requestId);
				continue;
			}
			DEBUG_LOG(("Message Info: msgId %1 was not found in recent sent, while acking requests, searching in resend...").arg(msgId));
			if (const auto i = _owner->_requestState.resendingIds.find(msgId); i != end(_owner->_requestState.resendingIds)) {
				const auto requestId = i->second;

				if (!byResponse && _owner->_delegate->hasCallback(requestId)) {
					DEBUG_LOG(("Message Info: ignoring ACK for msgId %1 because request %2 requires a response").arg(msgId).arg(requestId));
					continue;
				}
				_owner->_requestState.resendingIds.erase(i);
				resentAcked.emplace_back(msgId, requestId);
				continue;
			}
			DEBUG_LOG(("Message Info: msgId %1 was not found in recent resent either").arg(msgId));
		}
	}
	for (const auto &[msgId, requestId] : resentAcked) {
		const auto request = _owner->_sessionState.data->takeToSendRequest(requestId);
		if (!request) {
			DEBUG_LOG(("Message Info: msgId %1 was found in recent resent, requestId %2 was not found in prepared to send").arg(msgId).arg(requestId));
			continue;
		}
		if ((*request)->requestId != requestId) {
			DEBUG_LOG(("Message Error: for msgId %1 found resent request, requestId %2, contains requestId %3").arg(msgId).arg(requestId).arg((*request)->requestId));
		} else {
			DEBUG_LOG(("Message Info: acked msgId %1 that was prepared to resend, requestId %2").arg(msgId).arg(requestId));
		}
		_owner->_requestState.ackedIds.emplace(msgId, (*request)->requestId);
	}

	auto ackedCount = _owner->_requestState.ackedIds.size();
	if (ackedCount > kIdsBufferSize) {
		DEBUG_LOG(("Message Info: removing some old acked sent msgIds %1").arg(ackedCount - kIdsBufferSize));
		while (ackedCount-- > kIdsBufferSize) {
			_owner->_requestState.ackedIds.erase(_owner->_requestState.ackedIds.begin());
		}
	}

	if (toAckMore.size()) {
		requestsAcked(toAckMore);
	}
}

void SessionMessageHandler::handleMsgsStates(const QVector<MTPlong> &ids, const QByteArray &states) {
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
			QReadLocker locker(_owner->_sessionState.data->haveSentMutex());
			if (!_owner->_sessionState.data->haveSentMap().contains(requestMsgId)) {
				DEBUG_LOG(("Message Info: state was received for msgId %1, but request is not found, looking in resent requests...").arg(requestMsgId));
				const auto reqIt = _owner->_requestState.resendingIds.find(requestMsgId);
				if (reqIt != _owner->_requestState.resendingIds.cend()) {
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

void SessionMessageHandler::clearSpecialMsgId(mtpMsgId msgId) {
	if (msgId == _owner->_requestState.pingMsgId) {
		_owner->_requestState.pingMsgId = 0;
		_owner->_requestState.pingId = 0;
		_owner->_requestState.pingSentTime = 0;
	} else if (msgId == _owner->_authState.bindMsgId) {
		_owner->_authState.bindMsgId = 0;
	}
}

void SessionMessageHandler::resend(mtpMsgId msgId, crl::time msCanWait) {
	const auto guard = gsl::finally([&] {
		clearSpecialMsgId(msgId);
		if (msCanWait >= 0) {
			_owner->_sessionState.data->queueSendAnything(msCanWait);
		}
	});

	if (const auto i = _owner->_requestState.sentContainers.find(msgId); i != end(_owner->_requestState.sentContainers)) {
		DEBUG_LOG(("Message Info: resending container, msgId %1").arg(msgId));
		const auto ids = std::move(i->second.messages);
		_owner->_requestState.sentContainers.erase(i);

		for (const auto innerMsgId : ids) {
			resend(innerMsgId, -1);
		}
		return;
	}
	const auto sent = _owner->_sessionState.data->takeSentRequest(msgId);
	if (!sent) {
		return;
	}
	auto request = sent->request;

	request->lastSentTime = crl::now();
	request->forceSendInContainer = true;
	_owner->_requestState.resendingIds.emplace(msgId, request->requestId);
	_owner->_sessionState.data->enqueueResentRequest(request);
}

void SessionMessageHandler::resendAll() {
	auto haveSent = _owner->_sessionState.data->takeAllSentRequests();
	const auto now = crl::now();
	for (auto &sent : haveSent) {
		const auto requestId = sent.request->requestId;
		sent.request->lastSentTime = now;
		sent.request->forceSendInContainer = true;
		_owner->_requestState.resendingIds.emplace(sent.msgId, requestId);
		_owner->_sessionState.data->enqueueResentRequest(sent.request);
	}

	_owner->_sessionState.data->queueSendAnything();
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

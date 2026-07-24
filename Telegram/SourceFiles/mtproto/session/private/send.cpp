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
#include "mtproto/proxy/diagnostics.h"
#include "mtproto/proxy/transport_policy.h"
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
constexpr auto kPingDelayDisconnect = 60;
constexpr auto kPingSendAfter = 30 * crl::time(1000);
constexpr auto kPingSendAfterForce = 45 * crl::time(1000);
constexpr auto kCheckSentRequestTimeout = 10 * crl::time(1000);
constexpr auto kSendStateRequestWaiting = crl::time(1000);
constexpr auto kCutContainerOnSize = 16 * 1024;

[[nodiscard]] ProxyDiagnosticsDirection FileDiagnosticsDirection(
		FileTransferDirection direction) {
	switch (direction) {
	case FileTransferDirection::Download:
		return ProxyDiagnosticsDirection::Download;
	case FileTransferDirection::Upload:
		return ProxyDiagnosticsDirection::Upload;
	}
	Unexpected("File transfer direction.");
}

[[nodiscard]] ProxyConnectionUse FileDiagnosticsUse(
		FileTransferDirection direction) {
	switch (direction) {
	case FileTransferDirection::Download:
		return ProxyConnectionUse::Media;
	case FileTransferDirection::Upload:
		return ProxyConnectionUse::Upload;
	}
	Unexpected("File transfer direction.");
}

[[nodiscard]] ProxyDiagnosticsRpcKind FileDiagnosticsRpcKind(
		FileTransferRpcKind kind) {
	switch (kind) {
	case FileTransferRpcKind::GetFile:
		return ProxyDiagnosticsRpcKind::GetFile;
	case FileTransferRpcKind::GetWebFile:
		return ProxyDiagnosticsRpcKind::GetWebFile;
	case FileTransferRpcKind::GetCdnFile:
		return ProxyDiagnosticsRpcKind::GetCdnFile;
	case FileTransferRpcKind::GetCdnFileHashes:
		return ProxyDiagnosticsRpcKind::GetCdnFileHashes;
	case FileTransferRpcKind::ReuploadCdnFile:
		return ProxyDiagnosticsRpcKind::ReuploadCdnFile;
	case FileTransferRpcKind::SaveFilePart:
		return ProxyDiagnosticsRpcKind::SaveFilePart;
	case FileTransferRpcKind::SaveBigFilePart:
		return ProxyDiagnosticsRpcKind::SaveBigFilePart;
	}
	Unexpected("File transfer RPC kind.");
}

[[nodiscard]] ProxyDiagnosticsEvent FileDiagnosticsEvent(
		const FileTransferRequestTag::Trace &trace,
		ProxyDiagnosticsTransition transition) {
	auto event = ProxyDiagnosticsEvent();
	event.source = ProxyDiagnosticsSource::MTP;
	event.phase = ProxyDiagnosticsPhase::FileRpc;
	event.attempt.traceId = trace.traceOrdinal;
	event.attempt.use = FileDiagnosticsUse(trace.direction);
	event.transition = transition;
	event.direction = FileDiagnosticsDirection(trace.direction);
	event.rpcKind = FileDiagnosticsRpcKind(trace.rpcKind);
	event.laneOrdinal = trace.laneOrdinal;
	event.requestOrdinal = trace.requestOrdinal;
	event.firstInLane = trace.firstInLane;
	return event;
}

void ReportFileTransferSent(
		not_null<RuntimeEnvironment*> runtime,
		SessionProxyPort &proxyPort,
		const std::vector<SerializedRequest> &requests) {
	auto events = std::vector<ProxyDiagnosticsEvent>();
	events.reserve(requests.size());
	const auto now = crl::now();
	for (const auto &request : requests) {
		const auto trace = request->fileTransferTag->trace;
		QMutexLocker lock(&trace->mutex);
		const auto resent = (trace->successfulSendCount > 0);
		if (!resent) {
			trace->firstSentAt = now;
		}
		trace->lastSentAt = now;
		++trace->successfulSendCount;
		if (trace->firstInLane || resent) {
			auto event = FileDiagnosticsEvent(
				*trace,
				resent
					? ProxyDiagnosticsTransition::Resent
					: ProxyDiagnosticsTransition::Sent);
			event.sendCount = trace->successfulSendCount;
			events.push_back(std::move(event));
		}
	}
	for (auto &event : events) {
		proxyPort.writeDiagnosticsEvent(runtime, std::move(event));
	}
}

[[nodiscard]] QString ComputeAppVersion() {
#if defined Q_OS_WIN && defined Q_PROCESSOR_X86_64
	const auto arch = u" x64"_q;
#elif (defined Q_OS_WIN && defined Q_PROCESSOR_X86_32) || defined Q_PROCESSOR_X86_64
	const auto arch = QString();
#else
	const auto arch = ' ' + QSysInfo::buildCpuArchitecture();
#endif
	return QString::fromLatin1(AppVersionStr) + arch + ([] {
#if defined OS_MAC_STORE
		return u" Mac App Store"_q;
#elif defined OS_WIN_STORE
		return u" Microsoft Store"_q;
#else
		return KSandbox::isFlatpak()
			? u" Flatpak"_q
			: KSandbox::isSnap()
			? u" Snap"_q
			: QString();
#endif
	})();
}

constexpr auto kInnerHeaderPrimes = SerializedRequest::kMessageIdInts
	+ SerializedRequest::kSeqNoInts
	+ SerializedRequest::kMessageLengthInts;
constexpr auto kInnerLengthOffset = kInnerHeaderPrimes - 1;
constexpr auto kInvokeAfterPrimes = 3;

void AddInnerMessageLength(
		SerializedRequest &request,
		int messageStart,
		int addedPrimes) {
	(*request)[messageStart + kInnerLengthOffset] += addedPrimes * kIntSize;
}

void AddOuterContainerLength(
		SerializedRequest &request,
		int messageStart,
		int addedPrimes) {
	if (messageStart != SerializedRequest::kMessageIdPosition) {
		(*request)[SerializedRequest::kMessageLengthPosition] += addedPrimes
			* kIntSize;
	}
}

void AppendInnerHeader(
		SerializedRequest &to,
		const SerializedRequest &from) {
	binary::AppendPrimes(
		*to,
		from.innerMessagePrimes().subspan(0, kInnerHeaderPrimes));
}

void AppendMessageWithPrefix(
		SerializedRequest &to,
		const SerializedRequest &from,
		gsl::span<const mtpPrime> prefix) {
	const auto start = to->size();
	AppendInnerHeader(to, from);
	if (!prefix.empty()) {
		AddInnerMessageLength(to, start, prefix.size());
		binary::AppendPrimes(*to, prefix);
	}
	to.appendBodyFrom(from);
}

void AppendContainerMessage(
		SerializedRequest &to,
		const SerializedRequest &from) {
	to.appendInnerMessageFrom(from);
}

void AppendInvokeWithLayer(
		SerializedRequest &to,
		const SerializedRequest &from,
		gsl::span<const mtpPrime> layerPrefix) {
	AppendMessageWithPrefix(to, from, layerPrefix);
}

void AppendInvokeAfter(
		SerializedRequest &to,
		const SerializedRequest &from,
		const base::flat_map<mtpMsgId, SerializedRequest> &haveSent,
		gsl::span<const mtpPrime> bodyPrefix = {}) {
	const auto afterId = from->after ? from->after.getMsgId() : mtpMsgId();
	const auto wrapAfter = afterId && haveSent.contains(afterId);
	const auto start = to->size();
	AppendInnerHeader(to, from);
	if (!bodyPrefix.empty()) {
		AddInnerMessageLength(to, start, bodyPrefix.size());
		binary::AppendPrimes(*to, bodyPrefix);
	}
	if (wrapAfter) {
		AddInnerMessageLength(to, start, kInvokeAfterPrimes);
		AddOuterContainerLength(to, start, kInvokeAfterPrimes);
		to->push_back(mtpPrime(mtpc_invokeAfterMsg));
		binary::AppendBytes(*to, binary::AsBytes(&afterId));
	}
	to.appendBodyFrom(from);
}

} // namespace

void SessionPrivate::checkSentRequests() {
	const auto now = crl::now();
	const auto checkTime = now - kCheckSentRequestTimeout;
	if (_authState.bindMsgId && _authState.bindMessageSent < checkTime) {
		DEBUG_LOG(("MTP Info: "
			"Request state while key is not bound, restarting."));
		restart();
		_transport.scheduleCheckSentRequests(kCheckSentRequestTimeout);
		return;
	}
	auto requesting = false;
	auto nextTimeout = kCheckSentRequestTimeout;
	{
		QReadLocker locker(_sessionState.data->haveSentMutex());
		auto &haveSent = _sessionState.data->haveSentMap();
		for (const auto &[msgId, request] : haveSent) {
			if (request->lastSentTime <= checkTime) {
				// Need to check state.
				request->lastSentTime = now;
				if (_requestState.stateData.emplace(msgId).second) {
					requesting = true;
				}
			} else {
				nextTimeout = std::min(request->lastSentTime - checkTime, nextTimeout);
			}
		}
	}
	if (requesting) {
		_sessionState.data->queueSendAnything(kSendStateRequestWaiting);
	}
	if (nextTimeout < kCheckSentRequestTimeout) {
		_transport.scheduleCheckSentRequests(nextTimeout);
	}
}

mtpMsgId SessionPrivate::prepareToSend(
		SerializedRequest &request,
		mtpMsgId currentLastId,
		bool forceNewMsgId) {
	Expects(request->size() > 8);

	if (const auto msgId = request.getMsgId()) {
		// resending this request
		const auto i = _requestState.resendingIds.find(msgId);
		if (i != _requestState.resendingIds.cend()) {
			_requestState.resendingIds.erase(i);
		}

		return (forceNewMsgId || msgId > currentLastId)
			? replaceMsgId(request, currentLastId)
			: msgId;
	}
	request.setMsgId(currentLastId);
	request.setSeqNo(nextRequestSeqNumber(request.needAck()));
	if (request->requestId) {
		MTP_LOG(_shiftedDcId, ("[r%1] msg_id 0 -> %2").arg(request->requestId).arg(currentLastId));
	}
	return currentLastId;
}

mtpMsgId SessionPrivate::replaceMsgId(SerializedRequest &request, mtpMsgId newId) {
	Expects(request->size() > 8);

	const auto oldMsgId = request.getMsgId();
	if (oldMsgId == newId) {
		return newId;
	}
	// haveSentMutex() was locked in tryToSend()
	auto &haveSent = _sessionState.data->haveSentMap();

	while (_requestState.resendingIds.contains(newId)
		|| _requestState.ackedIds.contains(newId)
		|| haveSent.contains(newId)) {
		newId = base::unixtime::mtproto_msg_id();
	}

	MTP_LOG(_shiftedDcId, ("[r%1] msg_id %2 -> %3"
		).arg(request->requestId
		).arg(oldMsgId
		).arg(newId));

	const auto i = _requestState.resendingIds.find(oldMsgId);
	if (i != _requestState.resendingIds.end()) {
		const auto requestId = i->second;
		_requestState.resendingIds.erase(i);
		_requestState.resendingIds.emplace(newId, requestId);
	}

	const auto j = _requestState.ackedIds.find(oldMsgId);
	if (j != _requestState.ackedIds.end()) {
		const auto requestId = j->second;
		_requestState.ackedIds.erase(j);
		_requestState.ackedIds.emplace(newId, requestId);
	}

	const auto k = haveSent.find(oldMsgId);
	if (k != haveSent.end()) {
		const auto request = k->second;
		haveSent.erase(k);
		haveSent.emplace(newId, request);
	}
	for (auto &[msgId, container] : _requestState.sentContainers) {
		for (auto &innerMsgId : container.messages) {
			if (innerMsgId == oldMsgId) {
				innerMsgId = newId;
			}
		}
	}
	request.setMsgId(newId);
	request.setSeqNo(nextRequestSeqNumber(request.needAck()));
	return newId;
}

mtpMsgId SessionPrivate::RegisterSentRequest(
		base::flat_map<mtpMsgId, SerializedRequest> &haveSent,
		SerializedRequest &request,
		mtpMsgId msgId) {
	Expects(request->size() > 8);

	while (true) {
		if (haveSent.emplace(msgId, request).second) {
			return msgId;
		}
		const auto oldMsgId = request.getMsgId();
		do {
			msgId = base::unixtime::mtproto_msg_id();
		} while (_requestState.resendingIds.contains(msgId)
			|| _requestState.ackedIds.contains(msgId)
			|| haveSent.contains(msgId));

		MTP_LOG(_shiftedDcId, ("[r%1] msg_id %2 -> %3"
			).arg(request->requestId
			).arg(oldMsgId
			).arg(msgId));

		const auto i = _requestState.resendingIds.find(oldMsgId);
		if (i != _requestState.resendingIds.end()) {
			const auto requestId = i->second;
			_requestState.resendingIds.erase(i);
			_requestState.resendingIds.emplace(msgId, requestId);
		}

		const auto j = _requestState.ackedIds.find(oldMsgId);
		if (j != _requestState.ackedIds.end()) {
			const auto requestId = j->second;
			_requestState.ackedIds.erase(j);
			_requestState.ackedIds.emplace(msgId, requestId);
		}

		for (auto &entry : _requestState.sentContainers) {
			for (auto &innerMsgId : entry.second.messages) {
				if (innerMsgId == oldMsgId) {
					innerMsgId = msgId;
				}
			}
		}
		request.setMsgId(msgId);
		request.setSeqNo(nextRequestSeqNumber(request.needAck()));
	}
}

mtpMsgId SessionPrivate::placeToContainer(
		SerializedRequest &toSendRequest,
		mtpMsgId &bigMsgId,
		bool forceNewMsgId,
		SerializedRequest &req) {
	const auto msgId = prepareToSend(req, bigMsgId, forceNewMsgId);
	if (msgId >= bigMsgId) {
		bigMsgId = base::unixtime::mtproto_msg_id();
	}

	AppendContainerMessage(toSendRequest, req);

	return msgId;
}

void SessionPrivate::tryToSend() {
	DEBUG_LOG(("MTP Info: tryToSend for dc %1.").arg(_shiftedDcId));
	if (!_transport.connection()) {
		DEBUG_LOG(("MTP Info: not yet connected in dc %1.").arg(_shiftedDcId));
		return;
	} else if (!_sessionState.keyId) {
		DEBUG_LOG(("MTP Info: not yet with auth key in dc %1.").arg(_shiftedDcId));
		return;
	}

	const auto needsLayer = !_sessionState.data->connectionInited();
	const auto state = getState();
	const auto sendOnlyFirstPing = (state != ConnectedState);
	const auto sendAll = !sendOnlyFirstPing && !_authState.keyCreator;
	const auto isMainSession = (GetDcIdShift(_shiftedDcId) == 0);
	if (sendOnlyFirstPing && !_requestState.pingIdToSend) {
		DEBUG_LOG(("MTP Info: dc %1 not sending, waiting for Connected state, state: %2").arg(_shiftedDcId).arg(state));
		return; // just do nothing, if is not connected yet
	} else if (isMainSession
		&& !sendOnlyFirstPing
		&& !_requestState.pingIdToSend
		&& !_requestState.pingId
		&& _requestState.pingSendAt <= crl::now()) {
		_requestState.pingIdToSend = base::RandomValue<mtpPingId>();
	}
	const auto forceNewMsgId = sendAll && markSessionAsStarted();
	if (forceNewMsgId && _authState.keyCreator) {
		_authState.keyCreator->restartBinder();
	}

	auto pingRequest = SerializedRequest();
	auto ackRequest = SerializedRequest();
	auto resendRequest = SerializedRequest();
	auto stateRequest = SerializedRequest();
	auto httpWaitRequest = SerializedRequest();
	auto bindDcKeyRequest = SerializedRequest();
	if (_requestState.pingIdToSend) {
		if (sendOnlyFirstPing || !isMainSession) {
			DEBUG_LOG(("MTP Info: sending ping, ping_id: %1"
				).arg(_requestState.pingIdToSend));
			pingRequest = SerializedRequest::Serialize(MTPPing(
				MTP_long(_requestState.pingIdToSend)
			));
		} else {
			DEBUG_LOG(("MTP Info: sending ping_delay_disconnect, "
				"ping_id: %1").arg(_requestState.pingIdToSend));
			pingRequest = SerializedRequest::Serialize(MTPPing_delay_disconnect(
				MTP_long(_requestState.pingIdToSend),
				MTP_int(kPingDelayDisconnect)));
			_transport.schedulePing(kPingSendAfterForce);
		}
		_requestState.pingSendAt = pingRequest->lastSentTime + kPingSendAfter;
		_requestState.pingId = base::take(_requestState.pingIdToSend);
		_requestState.pingSentTime = crl::now();
	} else if (!sendAll) {
		DEBUG_LOG(("MTP Info: dc %1 sending only service or bind."
			).arg(_shiftedDcId));
	} else {
		DEBUG_LOG(("MTP Info: dc %1 trying to send after ping, state: %2"
			).arg(_shiftedDcId
			).arg(state));
	}

	if (!sendOnlyFirstPing) {
		if (!_requestState.ackData.isEmpty()) {
			ackRequest = SerializedRequest::Serialize(MTPMsgsAck(
				MTP_msgs_ack(MTP_vector<MTPlong>(
					base::take(_requestState.ackData)))));
		}
		if (!_requestState.resendData.isEmpty()) {
			resendRequest = SerializedRequest::Serialize(MTPMsgResendReq(
				MTP_msg_resend_req(MTP_vector<MTPlong>(
					base::take(_requestState.resendData)))));
		}
		if (!_requestState.stateData.empty()) {
			auto ids = QVector<MTPlong>();
			ids.reserve(_requestState.stateData.size());
			for (const auto id : base::take(_requestState.stateData)) {
				ids.push_back(MTP_long(id));
			}
			stateRequest = SerializedRequest::Serialize(MTPMsgsStateReq(
				MTP_msgs_state_req(MTP_vector<MTPlong>(ids))));
		}
		if (_transport.serviceRequest()
			== AbstractConnection::TransportServiceRequest::HttpWait) {
			httpWaitRequest = SerializedRequest::Serialize(MTPHttpWait(
				MTP_http_wait(MTP_int(100), MTP_int(30), MTP_int(25000))));
		}
		if (!_authState.bindMsgId && _authState.keyCreator && _authState.keyCreator->readyToBind()) {
			bindDcKeyRequest = _authState.keyCreator->prepareBindRequest(
				_sessionState.encryptionKey,
				_sessionState.sessionId);

			// This is a special request with msgId used inside the message
			// body, so it is prepared already with a msgId and we place
			// seqNo for it manually here.
			bindDcKeyRequest.setSeqNo(
				nextRequestSeqNumber(bindDcKeyRequest.needAck()));
		}
	}

	MTPInitConnection<SerializedRequest> initWrapper;
	int32 initSizeInInts = 0;
	if (needsLayer) {
		Assert(_sessionState.options != nullptr);
		const auto systemLangCode = _sessionState.options->systemLangCode;
		const auto cloudLangCode = _sessionState.options->cloudLangCode;
		const auto langPackName = _sessionState.options->langPackName;
		const auto deviceModel = (_currentDcType == DcType::Cdn)
			? "n/a"
			: _delegate->deviceModel();
		const auto systemVersion = (_currentDcType == DcType::Cdn)
			? "n/a"
			: _delegate->systemVersion();
		const auto appVersion = ComputeAppVersion();
		const auto proxyType = _sessionState.options->proxy.type;
		const auto mtprotoProxy = (proxyType == ProxyData::Type::Mtproto);
		const auto clientProxyFields = mtprotoProxy
			? MTP_inputClientProxy(
				MTP_string(_sessionState.options->proxy.host),
				MTP_int(_sessionState.options->proxy.port))
			: MTPInputClientProxy();
		using Flag = MTPInitConnection<SerializedRequest>::Flag;
		initWrapper = MTPInitConnection<SerializedRequest>(
			MTP_flags(Flag::f_params
				| (mtprotoProxy ? Flag::f_proxy : Flag(0))),
			MTP_int(ApiId),
			MTP_string(deviceModel),
			MTP_string(systemVersion),
			MTP_string(appVersion),
			MTP_string(systemLangCode),
			MTP_string(langPackName),
			MTP_string(cloudLangCode),
			clientProxyFields,
			MTP_jsonObject(prepareInitParams()),
			SerializedRequest());
		initSizeInInts = (tl::count_length(initWrapper) >> 2) + 2;
	}

	auto needAnyResponse = false;
	auto toSendBatch = sendAll
		? _sessionState.data->takeToSendBatch(kCutContainerOnSize)
		: SessionData::ToSendBatch();
	auto &toSend = toSendBatch.requests;
	const auto someSkipped = toSendBatch.someSkipped;
	auto fileTransferRequests = std::vector<SerializedRequest>();
	fileTransferRequests.reserve(toSend.size());
	for (const auto &entry : toSend) {
		const auto &request = entry.second;
		if (request->fileTransferTag) {
			fileTransferRequests.push_back(request);
		}
	}
	SerializedRequest toSendRequest;

	auto scheduleCheckSentRequests = false;
	auto totalSending = int(toSend.size());
	const auto sendingCount = totalSending;
	if (pingRequest) ++totalSending;
	if (ackRequest) ++totalSending;
	if (resendRequest) ++totalSending;
	if (stateRequest) ++totalSending;
	if (httpWaitRequest) ++totalSending;
	if (bindDcKeyRequest) ++totalSending;

	if (!totalSending) {
		return;
	}

	const auto first = pingRequest
		? pingRequest
		: ackRequest
		? ackRequest
		: resendRequest
		? resendRequest
		: stateRequest
		? stateRequest
		: httpWaitRequest
		? httpWaitRequest
		: bindDcKeyRequest
		? bindDcKeyRequest
		: toSend.front().second;
	if (totalSending == 1 && !first->forceSendInContainer) {
		toSendRequest = first;

		const auto msgId = prepareToSend(
			toSendRequest,
			base::unixtime::mtproto_msg_id(),
			forceNewMsgId && !bindDcKeyRequest);
		if (bindDcKeyRequest) {
			_authState.bindMsgId = msgId;
			_authState.bindMessageSent = crl::now();
			needAnyResponse = true;
		} else if (pingRequest) {
			_requestState.pingMsgId = msgId;
			needAnyResponse = true;
		} else if (stateRequest || resendRequest) {
			_requestState.stateAndResendRequests.emplace(
				msgId,
				stateRequest ? stateRequest : resendRequest);
			needAnyResponse = true;
		}

		if (toSendRequest->requestId) {
			if (toSendRequest.needAck()) {
				toSendRequest->lastSentTime = crl::now();

				QWriteLocker locker(_sessionState.data->haveSentMutex());
				auto &haveSent = _sessionState.data->haveSentMap();
				RegisterSentRequest(haveSent, toSendRequest, msgId);
				scheduleCheckSentRequests = true;

				const auto wrapLayer = needsLayer && toSendRequest->needsLayer;
				if (toSendRequest->after) {
					const auto toSendSize = tl::count_length(toSendRequest) >> 2;
					auto wrappedRequest = SerializedRequest::Prepare(
						toSendSize,
						toSendSize + 3);
					wrappedRequest->resize(
						SerializedRequest::kMessageIdPosition);
					AppendInvokeAfter(
						wrappedRequest,
						toSendRequest,
						haveSent);
					toSendRequest = std::move(wrappedRequest);
				}
				if (wrapLayer) {
					const auto noWrapSize = (tl::count_length(toSendRequest) >> 2);
					const auto toSendSize = noWrapSize + initSizeInInts;
					auto wrappedRequest = SerializedRequest::Prepare(toSendSize);
					auto layerPrefix = mtpBuffer();
					layerPrefix.reserve(initSizeInInts);
					layerPrefix.push_back(mtpc_invokeWithLayer);
					layerPrefix.push_back(kCurrentLayer);
					initWrapper.write<mtpBuffer>(layerPrefix);
					wrappedRequest->resize(
						SerializedRequest::kMessageIdPosition);
					AppendInvokeWithLayer(
						wrappedRequest,
						toSendRequest,
						gsl::make_span(layerPrefix));
					toSendRequest = std::move(wrappedRequest);
				}

				needAnyResponse = true;
			} else {
				_requestState.ackedIds.emplace(msgId, toSendRequest->requestId);
			}
		}
	} else {
		bool willNeedInit = false;
		uint32 containerSize = 1 + 1;
		if (pingRequest) containerSize += pingRequest.messageSize();
		if (ackRequest) containerSize += ackRequest.messageSize();
		if (resendRequest) containerSize += resendRequest.messageSize();
		if (stateRequest) containerSize += stateRequest.messageSize();
		if (httpWaitRequest) containerSize += httpWaitRequest.messageSize();
		if (bindDcKeyRequest) containerSize += bindDcKeyRequest.messageSize();
		for (const auto &[requestId, request] : toSend) {
			containerSize += request.messageSize();
			if (needsLayer && request->needsLayer) {
				containerSize += initSizeInInts;
				willNeedInit = true;
			}
		}
		mtpBuffer initSerialized;
		if (willNeedInit) {
			initSerialized.reserve(initSizeInInts);
			initSerialized.push_back(mtpc_invokeWithLayer);
			initSerialized.push_back(kCurrentLayer);
			initWrapper.write<mtpBuffer>(initSerialized);
		}
		toSendRequest = SerializedRequest::Prepare(
			containerSize,
			containerSize + 3 * sendingCount);
		toSendRequest->push_back(mtpc_msg_container);
		toSendRequest->push_back(totalSending);

		auto bigMsgId = base::unixtime::mtproto_msg_id();

		QWriteLocker locker(_sessionState.data->haveSentMutex());
		auto &haveSent = _sessionState.data->haveSentMap();

		auto sentIdsWrap = SentContainer();
		sentIdsWrap.sent = crl::now();
		sentIdsWrap.messages.reserve(totalSending);

		if (bindDcKeyRequest) {
			_authState.bindMsgId = placeToContainer(
				toSendRequest,
				bigMsgId,
				false,
				bindDcKeyRequest);
			_authState.bindMessageSent = crl::now();
			sentIdsWrap.messages.push_back(_authState.bindMsgId);
			needAnyResponse = true;
		}
		if (pingRequest) {
			_requestState.pingMsgId = placeToContainer(
				toSendRequest,
				bigMsgId,
				forceNewMsgId,
				pingRequest);
			sentIdsWrap.messages.push_back(_requestState.pingMsgId);
			needAnyResponse = true;
		}

		for (auto &[requestId, request] : toSend) {
			const auto msgId = prepareToSend(
				request,
				bigMsgId,
				forceNewMsgId);
			if (msgId >= bigMsgId) {
				bigMsgId = base::unixtime::mtproto_msg_id();
			}
			bool added = false;
			if (request->requestId) {
				if (request.needAck()) {
					request->lastSentTime = crl::now();
					const auto registeredMsgId = RegisterSentRequest(
						haveSent,
						request,
						msgId);
					const auto requestNeedsLayer = needsLayer
						&& request->needsLayer;
					if (request->after) {
						AppendInvokeAfter(
							toSendRequest,
							request,
							haveSent,
							requestNeedsLayer
								? gsl::make_span(initSerialized)
								: gsl::span<const mtpPrime>());
						added = true;
					} else if (requestNeedsLayer) {
						AppendInvokeWithLayer(
							toSendRequest,
							request,
							gsl::make_span(initSerialized));
						added = true;
					}

					sentIdsWrap.messages.push_back(registeredMsgId);
					scheduleCheckSentRequests = true;
					needAnyResponse = true;
				} else {
					_requestState.ackedIds.emplace(msgId, request->requestId);
				}
			}
			if (!added) {
				AppendContainerMessage(toSendRequest, request);
			}
		}

		if (stateRequest) {
			const auto msgId = placeToContainer(
				toSendRequest,
				bigMsgId,
				forceNewMsgId,
				stateRequest);
			_requestState.stateAndResendRequests.emplace(msgId, stateRequest);
			needAnyResponse = true;
		}
		if (resendRequest) {
			const auto msgId = placeToContainer(
				toSendRequest,
				bigMsgId,
				forceNewMsgId,
				resendRequest);
			_requestState.stateAndResendRequests.emplace(msgId, resendRequest);
			needAnyResponse = true;
		}
		if (ackRequest) {
			placeToContainer(
				toSendRequest,
				bigMsgId,
				forceNewMsgId,
				ackRequest);
		}
		if (httpWaitRequest) {
			placeToContainer(
				toSendRequest,
				bigMsgId,
				forceNewMsgId,
				httpWaitRequest);
		}

		const auto containerMsgId = prepareToSend(
			toSendRequest,
			bigMsgId,
			forceNewMsgId);
		_requestState.sentContainers.emplace(
			containerMsgId,
			std::move(sentIdsWrap));
	}
	if (scheduleCheckSentRequests
		&& !_transport.checkSentRequestsTimerActive()) {
		_transport.scheduleCheckSentRequests(kCheckSentRequestTimeout);
	}
	if (sendSecureRequest(std::move(toSendRequest), needAnyResponse)) {
		ReportFileTransferSent(_runtime, *_proxyPort, fileTransferRequests);
	}
	if (someSkipped) {
		InvokeQueued(this, [=] {
			tryToSend();
		});
	}
}

void SessionPrivate::sendPingByTimer() {
	if (_requestState.pingId) {
		// _pingSendAt: when to send next ping (lastPingAt + kPingSendAfter)
		// could be equal to zero.
		const auto now = crl::now();
		const auto mustSendTill = _requestState.pingSendAt
			+ kPingSendAfterForce
			- kPingSendAfter;
		if (mustSendTill < now + 1000) {
			LOG(("Could not send ping for some seconds, restarting..."));
			logMtprotoEvent(
				ProxyDiagnosticsPhase::MtpPingTimeout,
				ProxyDiagnosticsSeverity::Warning,
				u"ping unanswered for too long, restarting"_q);
			return restart();
		} else {
			_transport.schedulePing(mustSendTill - now);
		}
	} else {
		_sessionState.data->queueNeedToResumeAndSend();
	}
}

void SessionPrivate::sendPingForce() {
	DEBUG_LOG(("MTP Info: send ping force for dcWithShift %1.").arg(_shiftedDcId));
	if (!_requestState.pingId) {
		_requestState.pingSendAt = 0;
		DEBUG_LOG(("Will send ping!"));
		tryToSend();
	}
}

bool SessionPrivate::sendSecureRequest(
		SerializedRequest &&request,
		bool needAnyResponse) {
	request.addPadding(false);

	uint32 fullSize = request->size();
	if (fullSize < 9) {
		return false;
	}

	auto messageSize = request.messageSize();
	if (messageSize < 5 || fullSize < messageSize + 4) {
		return false;
	}

	request.setSalt(_sessionState.sessionSalt);
	request.setSessionId(_sessionState.sessionId);

	auto from = request.innerMessagePrimes().data();
	MTP_LOG(_shiftedDcId, ("Send: ")
		+ DumpToText(from, from + messageSize)
		+ QString(" (dc:%1,key:%2,session:%3)"
		).arg(AbstractConnection::ProtocolDcDebugId(getProtocolDcId())
		).arg(_sessionState.encryptionKey->keyId()
		).arg(_sessionState.sessionId));

	const auto msgKey = _sessionState.encryptionKey->countMsgKey(
		bytes::make_span(request->constData(), fullSize),
		true);

	auto packet = _transport.prepareSecurePacket(
		_sessionState.keyId,
		msgKey,
		fullSize);
	const auto prefix = packet.size();
	packet.resize(prefix + fullSize);

	aesIgeEncrypt(
		request->constData(),
		&packet[prefix],
		fullSize * sizeof(mtpPrime),
		_sessionState.encryptionKey,
		msgKey);

	DEBUG_LOG(("MTP Info: sending request, size: %1, num: %2, time: %3").arg(fullSize + 6).arg((*request)[4]).arg((*request)[5]));

	_transport.sendData(
		std::move(packet),
		{ .keyId = _sessionState.keyId });

	if (needAnyResponse) {
		onSentSome((prefix + fullSize) * sizeof(mtpPrime));
	}

	return true;
}

} // namespace details
} // namespace MTP

/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "mtproto/core_types.h"

#include <crl/crl_time.h>

#include <memory>
#include <optional>

#include <QtCore/QMutex>

namespace MTP {
namespace details {

class RequestData;
class SerializedRequest;

enum class FileTransferDirection {
	Download,
	Upload,
};

enum class FileTransferRpcKind {
	GetFile,
	GetWebFile,
	GetCdnFile,
	GetCdnFileHashes,
	ReuploadCdnFile,
	SaveFilePart,
	SaveBigFilePart,
};

struct FileTransferRequestTag {
	struct Trace {
		Trace(
			FileTransferDirection direction,
			FileTransferRpcKind rpcKind,
			uint64 traceOrdinal,
			uint64 laneOrdinal,
			uint64 requestOrdinal,
			bool firstInLane)
		: direction(direction)
		, rpcKind(rpcKind)
		, traceOrdinal(traceOrdinal)
		, laneOrdinal(laneOrdinal)
		, requestOrdinal(requestOrdinal)
		, firstInLane(firstInLane) {
		}

		QMutex mutex;
		FileTransferDirection direction;
		FileTransferRpcKind rpcKind;
		uint64 traceOrdinal = 0;
		uint64 laneOrdinal = 0;
		uint64 requestOrdinal = 0;
		crl::time enqueuedAt = 0;
		crl::time firstSentAt = 0;
		crl::time lastSentAt = 0;
		crl::time terminalAt = 0;
		uint64 acceptedBytes = 0;
		uint64 acknowledgedBytes = 0;
		int successfulSendCount = 0;
		bool queueEventEmitted = false;
		bool terminalEventEmitted = false;
		bool slowEventEmitted = false;
		bool firstInLane = false;
	};

	FileTransferRequestTag(
		FileTransferDirection direction,
		FileTransferRpcKind rpcKind,
		uint64 traceOrdinal,
		uint64 laneOrdinal,
		uint64 requestOrdinal,
		bool firstInLane)
	: trace(std::make_shared<Trace>(
		direction,
		rpcKind,
		traceOrdinal,
		laneOrdinal,
		requestOrdinal,
		firstInLane)) {
	}

	std::shared_ptr<Trace> trace;
};

class RequestConstructHider {
	struct Tag {};
	friend class RequestData;
	friend class SerializedRequest;
};

class SerializedRequest {
public:
	SerializedRequest() = default;

	static constexpr auto kSaltInts = 2;
	static constexpr auto kSessionIdInts = 2;
	static constexpr auto kSessionIdPosition = kSaltInts;
	static constexpr auto kMessageIdPosition = kSaltInts + kSessionIdInts;
	static constexpr auto kMessageIdInts = 2;
	static constexpr auto kSeqNoPosition = kMessageIdPosition
		+ kMessageIdInts;
	static constexpr auto kSeqNoInts = 1;
	static constexpr auto kMessageLengthPosition = kSeqNoPosition
		+ kSeqNoInts;
	static constexpr auto kMessageLengthInts = 1;
	static constexpr auto kMessageBodyPosition = kMessageLengthPosition
		+ kMessageLengthInts;

	static SerializedRequest Prepare(uint32 size, uint32 reserveSize = 0);

	template <
		typename Request,
		typename = std::enable_if_t<tl::is_boxed_v<Request>>>
		static SerializedRequest Serialize(const Request &request);

	// For template MTP requests and MTPBoxed instantiation.
	template <typename Accumulator>
	void write(Accumulator &to) const {
		if (const auto size = sizeInBytes()) {
			tl::Writer<Accumulator>::PutBytes(to, dataInBytes(), size);
		}
	}

	RequestData *operator->() const;
	RequestData &operator*() const;
	explicit operator bool() const;

	void setMsgId(mtpMsgId msgId);
	[[nodiscard]] mtpMsgId getMsgId() const;
	void setSalt(uint64 salt);
	void setSessionId(uint64 sessionId);

	void setSeqNo(uint32 seqNo);
	[[nodiscard]] uint32 getSeqNo() const;

	void addPadding(bool forAuthKeyInner);
	[[nodiscard]] uint32 messageSize() const;
	[[nodiscard]] gsl::span<const mtpPrime> innerMessagePrimes() const;
	[[nodiscard]] gsl::span<const mtpPrime> bodyPrimes() const;
	void appendInnerMessageFrom(const SerializedRequest &from);
	void appendBodyFrom(const SerializedRequest &from);

	[[nodiscard]] bool needAck() const;

	using ResponseType = void; // don't know real response type =(

private:
	explicit SerializedRequest(const RequestConstructHider::Tag &);

	[[nodiscard]] size_t sizeInBytes() const;
	[[nodiscard]] const void *dataInBytes() const;

	std::shared_ptr<RequestData> _data;

};

class RequestData : public mtpBuffer {
public:
	explicit RequestData(const RequestConstructHider::Tag &) {
	}

	SerializedRequest after;
	crl::time lastSentTime = 0;
	mtpRequestId requestId = 0;
	bool needsLayer = false;
	bool forceSendInContainer = false;
	std::optional<FileTransferRequestTag> fileTransferTag;

};

template <typename Request, typename>
SerializedRequest SerializedRequest::Serialize(const Request &request) {
	const auto requestSize = tl::count_length(request) >> 2;
	auto serialized = Prepare(requestSize);
	request.template write<mtpBuffer>(*serialized);
	return serialized;
}

} // namespace details
} // namespace MTP

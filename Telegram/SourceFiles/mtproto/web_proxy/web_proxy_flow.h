/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "base/basic_types.h"

#include <array>
#include <deque>
#include <map>
#include <optional>

// Flow policy of the WEB proxy carrier, kept free of Qt objects and
// threads so that it can be tested on its own.
//
// Every MTProto connection through a WEB proxy is one stream, and all of
// them share a single carrier: one bridge page that forwards frames to the
// relay through one HTTPS or WebSocket pipe. The relay keeps one FIFO per
// direction for the whole carrier, so whatever the client hands over first
// is delivered first. Left alone, a media download or a file upload puts
// megabytes in front of the one reply a chat is waiting for, and every
// session then declares its own stream dead after a few seconds of
// silence - all at once, over a pipe that was working the whole time.
//
// The policy has three parts:
// - uplink: interactive frames go first, bulk streams share what is left
//   round-robin in frame-sized chunks, and upload bytes that the relay has
//   not yet written to its backend are capped, so the page queue never holds
//   more than a bounded amount of bulk data in front of a chat request;
// - downlink: the relay may only read a backend while it holds our credit,
//   so download streams get a small credit instead of the full protocol
//   window, and what they do not get stays in the backend's TCP buffers
//   instead of in the shared FIFO in front of interactive replies;
// - liveness: a stream is declared dead by what the carrier knows about it,
//   not by a per-stream timer that cannot tell "queued" from "lost".

namespace MTP::WebProxy {

enum class StreamClass : uchar {
	Interactive,
	Download,
	Upload,
};
inline constexpr auto kStreamClassCount = 3;

[[nodiscard]] const char *StreamClassName(StreamClass value);

struct UplinkLimits {
	int frameSize = 64 * 1024;

	// Upload bytes handed to the carrier and not yet credited back by the
	// relay. This is what can sit in front of an interactive frame in the
	// shared uplink queue.
	int64 uploadInFlight = 1024 * 1024;

	// Interactive and download frames are tiny, but a steady stream of them
	// must not stop uploads forever: after this many of them in a row while
	// an upload was eligible, one upload frame goes out.
	int priorityBurst = 16;
};

struct UplinkGrant {
	uint32 streamId = 0;
	int maxBytes = 0;
};

struct UplinkStats {
	std::array<int, kStreamClassCount> streams = {};
	std::array<int, kStreamClassCount> ready = {};
	int64 uploadInFlight = 0;
};

class UplinkScheduler final {
public:
	explicit UplinkScheduler(UplinkLimits limits = {});

	void add(uint32 streamId, StreamClass streamClass);
	void remove(uint32 streamId);
	void clear();

	// The stream has data and send credit. Idempotent.
	void markReady(uint32 streamId);

	// Picks the next stream to write one frame for and removes it from the
	// ready set; mark it ready again if it still has data after the write.
	[[nodiscard]] std::optional<UplinkGrant> next();

	void sent(uint32 streamId, int bytes);
	void acknowledged(uint32 streamId, int64 bytes);

	[[nodiscard]] UplinkStats stats() const;
	[[nodiscard]] bool uploadBlocked() const;
	[[nodiscard]] const UplinkLimits &limits() const {
		return _limits;
	}

private:
	struct Entry {
		StreamClass streamClass = StreamClass::Interactive;
		int64 inFlight = 0;
		bool ready = false;
	};

	[[nodiscard]] bool hasReady(StreamClass streamClass);
	[[nodiscard]] std::optional<uint32> popReady(StreamClass streamClass);

	UplinkLimits _limits;
	std::map<uint32, Entry> _streams;
	std::array<std::deque<uint32>, kStreamClassCount> _ready;
	int64 _uploadInFlight = 0;
	int _uploadSkipped = 0;

};

struct DownlinkLimits {
	int64 streamWindow = 4 * 1024 * 1024;

	// Credit shared by all download streams: the most media that can be
	// queued in the relay's downlink FIFO in front of an interactive reply.
	int64 downloadBudget = 2 * 1024 * 1024;
	int64 downloadMin = 256 * 1024;
	int64 downloadMax = 1024 * 1024;
};

// How much credit the relay should hold for a stream of this class.
[[nodiscard]] int64 DownlinkCreditTarget(
	const DownlinkLimits &limits,
	StreamClass streamClass,
	int downloadStreams);

// How much of the credit consumed by the reader and not yet returned may be
// returned now, given how much the relay already holds.
[[nodiscard]] int64 DownlinkCreditRelease(
	int64 relayCredit,
	int64 withheld,
	int64 target);

struct CarrierHealth {
	bool connected = false;

	// Any frame from the relay.
	int64 lastDownlinkAt = 0;

	// Any credit from the relay: our uplink bytes reached its backends.
	int64 lastCreditAt = 0;

	// Bytes written to the carrier and not yet credited, all streams.
	int64 unackedBytes = 0;

	// When unackedBytes last became non-zero.
	int64 outstandingSince = 0;
};

struct StreamHealth {
	bool open = false;

	// Waiting in the client, not yet handed to the carrier.
	int64 queuedBytes = 0;

	// Handed to the carrier, not yet written to the backend by the relay.
	int64 unackedBytes = 0;

	int64 lastReceivedAt = 0;

	// When everything this stream sent last reached the backend.
	int64 deliveredAt = 0;
};

struct LivenessLimits {
	// Outstanding uplink bytes and not a single frame from the relay for
	// this long: the carrier itself is stuck.
	int64 carrierStall = 20'000;

	// The request reached the backend and the downlink is empty, yet no
	// reply: nothing is queued ahead of it, the stream is dead.
	int64 quietReply = 8'000;

	// The request reached the backend and the downlink is busy with other
	// streams, yet no reply for this long: dead as well.
	int64 busyReply = 30'000;

	// Absolute bound for one wait, whatever the carrier reports.
	int64 maxWait = 64'000;

	// Frames from the relay within this long mean the downlink is busy.
	int64 busyWindow = 2'000;

	int64 recheck = 2'000;
};

enum class ReceiveVerdict : uchar {
	Wait,
	Fail,
};

enum class ReceiveReason : uchar {
	StreamClosed,
	CarrierDown,
	MaxWait,
	CarrierStalled,
	Queued,
	ReplyQueued,
	ReplyPending,
	ReplyMissing,
	ReplyTimeout,
};

struct ReceiveDecision {
	ReceiveVerdict verdict = ReceiveVerdict::Fail;
	ReceiveReason reason = ReceiveReason::StreamClosed;
	int64 waitMore = 0;
};

[[nodiscard]] const char *ReceiveReasonName(ReceiveReason reason);

[[nodiscard]] bool CarrierStalled(
	int64 now,
	const CarrierHealth &carrier,
	const LivenessLimits &limits);

// Called when a session saw no MTProto data for its usual receive timeout.
// Wait means the reply is plausibly still queued in a carrier that makes
// progress; a stalled carrier is recovered by the carrier itself, once for
// all of its streams, so the stream waits for that as well.
[[nodiscard]] ReceiveDecision DecideReceiveWait(
	int64 now,
	int64 waitStartedAt,
	const CarrierHealth &carrier,
	const StreamHealth &stream,
	const LivenessLimits &limits);

} // namespace MTP::WebProxy

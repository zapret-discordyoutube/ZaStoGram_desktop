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
//   not yet written to its backend are capped by a window, so the page
//   queue never holds more than a bounded amount of bulk data in front of
//   a chat request;
// - downlink: the relay may only read a backend while it holds our credit,
//   so download streams share a credit budget instead of the full protocol
//   window each, and what they do not get stays in the backend's TCP
//   buffers instead of in the shared FIFO in front of interactive replies;
// - both the upload window and the download budget adapt: they track the
//   bandwidth-delay product the carrier actually delivers plus a small
//   queue allowance, and shrink when chat replies start to wait in line;
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
	// shared uplink queue. The carrier moves it with AdaptiveWindow.
	int64 uploadInFlight = 1024 * 1024;

	// Upload frames are cut to a quarter of the in-flight cap, but not
	// below this: on a slow uplink a 64 KiB frame alone is a long wait
	// for whatever is queued behind it.
	int minUploadFrame = 16 * 1024;

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

	void setUploadInFlight(int64 bytes);

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
	// The carrier moves it with AdaptiveWindow.
	int64 downloadBudget = 2 * 1024 * 1024;

	// Bounds of one stream's share.
	int64 downloadMin = 128 * 1024;
	int64 downloadMax = 4 * 1024 * 1024;
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

// A window sized by the bandwidth-delay product the carrier delivers.
//
// Everything the carrier holds in flight waits in one FIFO in front of the
// next chat request: the bridge page's queue, the WebSocket, TCP and the
// relay's queue. So the window is kept at
//
//     window = rate * (baseRtt + targetDelay)
//
// once per interval, where rate is what was delivered in it (credited back
// by the relay for the uplink, received for the downlink) and baseRtt is
// the lowest frame round trip over the last minutes: one bandwidth-delay
// product to keep the pipe full plus targetDelay worth of queue. While the
// window is the limit the delivered rate is window / loop round trip, so
// the target is above the window until the queue reaches targetDelay and
// below it after. The upload window and the download budget share one
// loop (a download's credit goes up behind uploads, an upload's credit
// comes down behind media), so together they settle where both queues sum
// to targetDelay: what a chat request waits behind, both ways.
//
// The base must be the path without a queue, and a flow that keeps its
// queue at targetDelay never shows it by itself: a minimum over a short
// history would soon take the standing queue for the base and the window
// would run away. So, like BBR's ProbeRTT, the carrier drains both windows
// for a round trip every few seconds (FlowSample::probing); those samples
// refresh the base, and the history only has to outlive the probe period.
struct AdaptiveWindowLimits {
	int64 initial = 1024 * 1024;
	int64 min = 64 * 1024;
	int64 max = 8 * 1024 * 1024;

	// Queueing delay (ms) the flow may add in front of interactive traffic.
	int64 targetDelay = 100;

	// Without any delay sample the window may still grow when it is the
	// limit, but only up to this.
	int64 blindMax = 2 * 1024 * 1024;

	// The base round trip is the minimum of per-bucket minimums over the
	// history (ms), so it follows a real path change within minutes.
	int64 baseBucket = 10'000;
	int64 baseHistory = 60'000;

	int64 maxGrowthPercent = 200;
	int64 shrinkPercent = 75;
};

struct FlowSample {
	int64 now = 0;
	int64 interval = 0;

	// Delivered in the interval: credited back (uplink) or received
	// (downlink).
	int64 bytes = 0;

	// Demand was held back by the window during the interval.
	bool windowLimited = false;

	// Lowest round trip measured in the interval.
	std::optional<int64> delay;

	// The interval overlapped a drain for measuring the base: its delay
	// counts, its rate and limits do not.
	bool probing = false;

	// Queueing (ms) another flow on the same loop is allowed on top of
	// targetDelay: with upload and download both busy each keeps its own
	// share instead of the two squeezing each other into one.
	int64 extraDelay = 0;
};

class AdaptiveWindow final {
public:
	explicit AdaptiveWindow(AdaptiveWindowLimits limits);

	void update(const FlowSample &sample);

	// The loop is slowed by a queue this flow does not own (e.g. the
	// relay's downlink flooded by new streams' initial credit): only the
	// base is tracked, the window stays. Growing it to cover the credit in
	// transit cannot tell that transit from this flow's own queue.
	void hold(const FlowSample &sample);

	void reset();

	[[nodiscard]] int64 window() const {
		return _window;
	}
	[[nodiscard]] int64 rate() const { // Bytes per second, smoothed.
		return _rate;
	}
	[[nodiscard]] int64 target() const {
		return _target;
	}
	[[nodiscard]] std::optional<int64> baseDelay() const;
	[[nodiscard]] std::optional<int64> lastDelay() const {
		return _lastDelay;
	}
	[[nodiscard]] int shrinks() const {
		return _shrinks;
	}
	[[nodiscard]] const AdaptiveWindowLimits &limits() const {
		return _limits;
	}

private:
	void noteDelay(int64 now, std::optional<int64> delay);

	AdaptiveWindowLimits _limits;
	std::deque<std::pair<int64, int64>> _base; // (bucket, min delay)
	std::optional<int64> _lastDelay;
	int64 _window = 0;
	int64 _target = 0;
	int64 _rate = 0;
	int _shrinks = 0;

};

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

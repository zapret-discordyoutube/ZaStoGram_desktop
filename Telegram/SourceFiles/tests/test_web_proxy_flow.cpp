/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/web_proxy/web_proxy_flow.h"

#include <cstdio>
#include <vector>

namespace {

using namespace MTP::WebProxy;

int Failures = 0;

void Check(bool condition, const char *message) {
	if (!condition) {
		std::fprintf(stderr, "FAIL: %s\n", message);
		++Failures;
	}
}

[[nodiscard]] std::vector<uint32> Drain(
		UplinkScheduler &scheduler,
		int count,
		bool keepReady) {
	auto result = std::vector<uint32>();
	for (auto i = 0; i != count; ++i) {
		const auto grant = scheduler.next();
		if (!grant) {
			break;
		}
		result.push_back(grant->streamId);
		if (keepReady) {
			scheduler.markReady(grant->streamId);
		}
	}
	return result;
}

void TestInteractiveFirst() {
	auto scheduler = UplinkScheduler();
	scheduler.add(1, StreamClass::Upload);
	scheduler.add(2, StreamClass::Download);
	scheduler.add(3, StreamClass::Interactive);
	scheduler.markReady(1);
	scheduler.markReady(2);
	scheduler.markReady(3);
	const auto order = Drain(scheduler, 3, false);
	Check(order == std::vector<uint32>{ 3, 2, 1 },
		"interactive, then download, then upload");
	Check(!scheduler.next().has_value(), "nothing left after draining");
}

void TestRoundRobinWithinClass() {
	auto scheduler = UplinkScheduler();
	scheduler.add(10, StreamClass::Upload);
	scheduler.add(11, StreamClass::Upload);
	scheduler.add(12, StreamClass::Upload);
	scheduler.markReady(10);
	scheduler.markReady(11);
	scheduler.markReady(12);
	const auto order = Drain(scheduler, 6, true);
	Check(order == std::vector<uint32>{ 10, 11, 12, 10, 11, 12 },
		"bulk streams of one class share the carrier round-robin");
}

void TestMarkReadyIdempotent() {
	auto scheduler = UplinkScheduler();
	scheduler.add(1, StreamClass::Interactive);
	scheduler.markReady(1);
	scheduler.markReady(1);
	scheduler.markReady(1);
	Check(Drain(scheduler, 5, false).size() == 1,
		"a stream is queued once however often it is marked ready");
	scheduler.markReady(99);
	Check(!scheduler.next().has_value(), "unknown streams are ignored");
}

void TestUploadCap() {
	auto limits = UplinkLimits();
	limits.frameSize = 64;
	limits.uploadInFlight = 160;
	auto scheduler = UplinkScheduler(limits);
	scheduler.add(1, StreamClass::Upload);
	scheduler.markReady(1);

	auto grant = scheduler.next();
	Check(grant && grant->maxBytes == 64, "first upload frame is full");
	scheduler.sent(1, 64);
	scheduler.markReady(1);
	grant = scheduler.next();
	Check(grant && grant->maxBytes == 64, "second upload frame is full");
	scheduler.sent(1, 64);
	scheduler.markReady(1);
	grant = scheduler.next();
	Check(grant && grant->maxBytes == 32, "third frame is cut to the cap");
	scheduler.sent(1, 32);
	scheduler.markReady(1);
	Check(!scheduler.next().has_value(), "upload stops at the cap");
	Check(scheduler.uploadBlocked(), "a ready upload at the cap is blocked");
	Check(scheduler.stats().uploadInFlight == 160, "in-flight accounting");

	scheduler.acknowledged(1, 100);
	Check(!scheduler.uploadBlocked(), "credit unblocks uploads");
	grant = scheduler.next();
	Check(grant && grant->maxBytes == 64, "credit reopens the upload");

	// Interactive traffic is never capped by bulk bytes in flight.
	scheduler.sent(1, 64);
	scheduler.add(2, StreamClass::Interactive);
	scheduler.markReady(2);
	grant = scheduler.next();
	Check(grant && grant->streamId == 2 && grant->maxBytes == 64,
		"interactive frames pass a full upload cap");

	// Credit beyond what was sent is not counted twice.
	scheduler.acknowledged(1, 1'000'000);
	Check(scheduler.stats().uploadInFlight == 0,
		"acknowledgement is clamped to what was sent");

	// Removing an upload stream releases its share of the cap.
	scheduler.sent(1, 150);
	scheduler.remove(1);
	Check(scheduler.stats().uploadInFlight == 0,
		"removed stream releases its in-flight bytes");
}

void TestUploadFramesFollowTheCap() {
	auto limits = UplinkLimits();
	limits.uploadInFlight = 64 * 1024;
	auto scheduler = UplinkScheduler(limits);
	scheduler.add(1, StreamClass::Upload);
	scheduler.markReady(1);
	auto grant = scheduler.next();
	Check(grant && grant->maxBytes == limits.minUploadFrame,
		"a small cap cuts upload frames down to the minimum");
	scheduler.setUploadInFlight(4 * 1024 * 1024);
	scheduler.markReady(1);
	grant = scheduler.next();
	Check(grant && grant->maxBytes == limits.frameSize,
		"a large cap sends full frames");
	scheduler.add(2, StreamClass::Interactive);
	scheduler.setUploadInFlight(64 * 1024);
	scheduler.markReady(2);
	grant = scheduler.next();
	Check(grant && grant->maxBytes == limits.frameSize,
		"interactive frames are never cut");
}

void TestDownloadNotCapped() {
	auto limits = UplinkLimits();
	limits.frameSize = 64;
	limits.uploadInFlight = 64;
	auto scheduler = UplinkScheduler(limits);
	scheduler.add(1, StreamClass::Upload);
	scheduler.add(2, StreamClass::Download);
	scheduler.markReady(1);
	auto grant = scheduler.next();
	scheduler.sent(1, 64);
	scheduler.markReady(1);
	scheduler.markReady(2);
	grant = scheduler.next();
	Check(grant && grant->streamId == 2,
		"download requests are not held back by the upload cap");
	scheduler.sent(2, 64);
	scheduler.markReady(2);
	grant = scheduler.next();
	Check(grant && grant->streamId == 2, "download stays eligible");
}

void TestNoUploadStarvation() {
	auto limits = UplinkLimits();
	limits.priorityBurst = 4;
	auto scheduler = UplinkScheduler(limits);
	scheduler.add(1, StreamClass::Interactive);
	scheduler.add(2, StreamClass::Upload);
	scheduler.markReady(1);
	scheduler.markReady(2);
	auto uploads = 0;
	auto interactive = 0;
	for (auto i = 0; i != 20; ++i) {
		const auto grant = scheduler.next();
		if (!grant) {
			break;
		}
		(grant->streamId == 2 ? uploads : interactive) += 1;
		scheduler.markReady(grant->streamId);
	}
	Check(uploads == 4, "one upload frame per burst of interactive frames");
	Check(interactive == 16, "interactive keeps the rest");
}

void TestStaleIdsSkipped() {
	auto scheduler = UplinkScheduler();
	scheduler.add(1, StreamClass::Interactive);
	scheduler.add(2, StreamClass::Interactive);
	scheduler.markReady(1);
	scheduler.markReady(2);
	scheduler.remove(1);
	const auto grant = scheduler.next();
	Check(grant && grant->streamId == 2, "removed streams are skipped");
	scheduler.clear();
	Check(!scheduler.next().has_value(), "clear forgets everything");
	const auto stats = scheduler.stats();
	Check(stats.streams[0] == 0 && stats.uploadInFlight == 0,
		"clear resets statistics");
}

void TestDownlinkCredit() {
	const auto limits = DownlinkLimits();
	Check(DownlinkCreditTarget(limits, StreamClass::Interactive, 5)
		== limits.streamWindow, "interactive streams keep the full window");
	Check(DownlinkCreditTarget(limits, StreamClass::Upload, 5)
		== limits.streamWindow, "upload streams keep the full window");
	Check(DownlinkCreditTarget(limits, StreamClass::Download, 1)
		== limits.downloadBudget, "a lone download gets the whole budget");
	Check(DownlinkCreditTarget(limits, StreamClass::Download, 4)
		== limits.downloadBudget / 4, "downloads share the budget");
	Check(DownlinkCreditTarget(limits, StreamClass::Download, 100)
		== limits.downloadMin, "a share never drops below the minimum");
	Check(DownlinkCreditTarget(limits, StreamClass::Download, 0)
		== limits.downloadBudget, "zero streams does not divide by zero");
	auto big = limits;
	big.downloadBudget = 64 * 1024 * 1024;
	Check(DownlinkCreditTarget(big, StreamClass::Download, 1)
		== limits.downloadMax, "a share never exceeds the per-stream max");

	// The relay still holds the initial window: nothing is returned.
	Check(DownlinkCreditRelease(4 * 1024 * 1024, 65536, 512 * 1024) == 0,
		"credit is withheld while the relay holds more than the target");
	// Below the target: return what is missing, limited by what we hold.
	Check(DownlinkCreditRelease(100 * 1024, 1024 * 1024, 512 * 1024)
		== 412 * 1024, "credit is topped up to the target");
	Check(DownlinkCreditRelease(0, 1000, 512 * 1024) == 1000,
		"only consumed credit can be returned");
	Check(DownlinkCreditRelease(0, 0, 512 * 1024) == 0,
		"nothing consumed, nothing returned");
	// Full target (interactive): everything consumed goes back at once.
	Check(DownlinkCreditRelease(
		4 * 1024 * 1024 - 5000,
		5000,
		4 * 1024 * 1024) == 5000,
		"interactive credit is returned in full");
}

[[nodiscard]] CarrierHealth Healthy(int64 now) {
	return {
		.connected = true,
		.lastDownlinkAt = now - 100,
		.lastCreditAt = now - 100,
		.unackedBytes = 0,
		.outstandingSince = 0,
	};
}

void TestCarrierStall() {
	const auto limits = LivenessLimits();
	const auto now = int64(1'000'000);
	auto carrier = Healthy(now);
	Check(!CarrierStalled(now, carrier, limits), "healthy carrier");

	carrier.unackedBytes = 1000;
	carrier.outstandingSince = now - 100'000;
	carrier.lastCreditAt = now - 100'000;
	carrier.lastDownlinkAt = now - 1'000;
	Check(!CarrierStalled(now, carrier, limits),
		"downlink progress keeps the carrier alive");

	carrier.lastDownlinkAt = now - 25'000;
	Check(CarrierStalled(now, carrier, limits),
		"no progress with bytes outstanding is a stall");

	carrier.unackedBytes = 0;
	Check(!CarrierStalled(now, carrier, limits),
		"an idle carrier with nothing outstanding is not stalled");

	carrier.unackedBytes = 1000;
	carrier.outstandingSince = now - 1'000;
	Check(!CarrierStalled(now, carrier, limits),
		"freshly outstanding bytes are not a stall yet");

	carrier.outstandingSince = now - 100'000;
	carrier.connected = false;
	Check(!CarrierStalled(now, carrier, limits),
		"a disconnected carrier is down, not stalled");
}

void TestReceiveWait() {
	const auto limits = LivenessLimits();
	const auto now = int64(1'000'000);
	const auto started = now - 4'000;
	auto carrier = Healthy(now);
	auto stream = StreamHealth{ .open = true };

	auto decision = DecideReceiveWait(now, started, carrier, stream, limits);
	Check(decision.verdict == ReceiveVerdict::Wait
		&& decision.reason == ReceiveReason::ReplyQueued,
		"a busy downlink may still carry the reply");

	stream.queuedBytes = 1000;
	carrier.lastDownlinkAt = now - 10'000;
	decision = DecideReceiveWait(now, started, carrier, stream, limits);
	Check(decision.verdict == ReceiveVerdict::Wait
		&& decision.reason == ReceiveReason::Queued,
		"a request still queued in the client is waited for");

	stream.queuedBytes = 0;
	stream.unackedBytes = 1000;
	decision = DecideReceiveWait(now, started, carrier, stream, limits);
	Check(decision.verdict == ReceiveVerdict::Wait
		&& decision.reason == ReceiveReason::Queued,
		"a request not yet credited by the relay is waited for");

	// Delivered, quiet downlink, but not for long enough yet.
	stream.unackedBytes = 0;
	stream.deliveredAt = now - 3'000;
	carrier.lastDownlinkAt = now - 3'000;
	decision = DecideReceiveWait(now, started, carrier, stream, limits);
	Check(decision.verdict == ReceiveVerdict::Wait
		&& decision.reason == ReceiveReason::ReplyPending
		&& decision.waitMore == limits.quietReply - 3'000,
		"a quiet reply gets the rest of its quiet budget");

	// Delivered, and the whole downlink has been quiet: no reply coming.
	stream.deliveredAt = now - 9'000;
	carrier.lastDownlinkAt = now - 9'000;
	decision = DecideReceiveWait(now, now - 9'500, carrier, stream, limits);
	Check(decision.verdict == ReceiveVerdict::Fail
		&& decision.reason == ReceiveReason::ReplyMissing,
		"a delivered request on a quiet carrier without a reply fails");

	// Downlink busy with others for too long.
	carrier.lastDownlinkAt = now - 100;
	stream.deliveredAt = now - 31'000;
	decision = DecideReceiveWait(now, now - 31'000, carrier, stream, limits);
	Check(decision.verdict == ReceiveVerdict::Fail
		&& decision.reason == ReceiveReason::ReplyTimeout,
		"a busy carrier does not excuse an unbounded wait");

	// Received something recently: the reply budget restarts from there.
	stream.lastReceivedAt = now - 1'000;
	decision = DecideReceiveWait(now, now - 31'000, carrier, stream, limits);
	Check(decision.verdict == ReceiveVerdict::Wait,
		"recent data for this stream restarts its reply budget");

	// Absolute bound.
	stream.queuedBytes = 1000;
	decision = DecideReceiveWait(
		now,
		now - limits.maxWait,
		carrier,
		stream,
		limits);
	Check(decision.verdict == ReceiveVerdict::Fail
		&& decision.reason == ReceiveReason::MaxWait,
		"no wait is longer than the absolute bound");

	decision = DecideReceiveWait(
		now,
		now - limits.maxWait + 500,
		carrier,
		stream,
		limits);
	Check(decision.verdict == ReceiveVerdict::Wait
		&& decision.waitMore == 500,
		"a wait never extends past the absolute bound");

	// Carrier states.
	stream.queuedBytes = 0;
	carrier.connected = false;
	decision = DecideReceiveWait(now, started, carrier, stream, limits);
	Check(decision.verdict == ReceiveVerdict::Fail
		&& decision.reason == ReceiveReason::CarrierDown,
		"a lost carrier fails the stream");

	carrier = Healthy(now);
	stream.open = false;
	decision = DecideReceiveWait(now, started, carrier, stream, limits);
	Check(decision.verdict == ReceiveVerdict::Fail
		&& decision.reason == ReceiveReason::StreamClosed,
		"a closed stream fails");

	stream.open = true;
	carrier.unackedBytes = 5000;
	carrier.outstandingSince = now - 50'000;
	carrier.lastCreditAt = now - 50'000;
	carrier.lastDownlinkAt = now - 50'000;
	decision = DecideReceiveWait(now, started, carrier, stream, limits);
	Check(decision.verdict == ReceiveVerdict::Wait
		&& decision.reason == ReceiveReason::CarrierStalled,
		"a stalled carrier is recovered once by the carrier, not per stream");
}

// A path with a bottleneck of `capacity` bytes per second and a base round
// trip of `baseRtt` ms, fed as the carrier would feed it: everything above
// one bandwidth-delay product waits in the queue.
struct Path {
	int64 capacity = 0;
	int64 baseRtt = 0;

	[[nodiscard]] int64 queueDelay(int64 window) const {
		const auto bdp = capacity * baseRtt / 1000;
		return (window > bdp) ? ((window - bdp) * 1000 / capacity) : 0;
	}
	[[nodiscard]] FlowSample sample(
			int64 now,
			int64 interval,
			int64 window,
			bool limited = true) const {
		const auto rtt = baseRtt + queueDelay(window);
		const auto rate = std::min(window * 1000 / rtt, capacity);
		auto result = FlowSample();
		result.now = now;
		result.interval = interval;
		result.bytes = rate * interval / 1000;
		result.windowLimited = limited;
		result.delay = rtt;
		return result;
	}
};

[[nodiscard]] FlowSample Sample(
		int64 now,
		int64 interval,
		int64 bytes,
		bool limited,
		std::optional<int64> delay) {
	auto result = FlowSample();
	result.now = now;
	result.interval = interval;
	result.bytes = bytes;
	result.windowLimited = limited;
	result.delay = delay;
	return result;
}

void TestAdaptiveGrowsOnFreePath() {
	auto window = AdaptiveWindow(AdaptiveWindowLimits());
	const auto start = window.window();
	const auto path = Path{ .capacity = 20 * 1024 * 1024, .baseRtt = 100 };
	auto now = int64(1000);
	for (auto i = 0; i != 80; ++i) {
		now += 200;
		window.update(path.sample(now, 200, window.window()));
	}
	// Settles where the queue it builds is the 100 ms target:
	// 20 MiB/s * (100 ms + 100 ms) = 4 MiB.
	Check(window.window() > start, "a free path grows the window");
	Check(window.window() >= 3 * 1024 * 1024
		&& window.window() <= 5 * 1024 * 1024,
		"the window settles where queueing meets the target");
	Check(path.queueDelay(window.window()) <= 150,
		"what waits in front of a chat stays near the target delay");

	auto fast = AdaptiveWindow(AdaptiveWindowLimits());
	const auto wide = Path{ .capacity = 200 * 1024 * 1024, .baseRtt = 100 };
	now = 1000;
	auto steps = 0;
	while (fast.window() < fast.limits().max && steps < 40) {
		now += 200;
		fast.update(wide.sample(now, 200, fast.window()));
		++steps;
	}
	Check(fast.window() == fast.limits().max,
		"a wide path reaches the upper bound");
	Check(steps <= 6, "growth is multiplicative, not additive");
}

void TestAdaptiveShrinksWhenQueueGrows() {
	auto limits = AdaptiveWindowLimits();
	limits.initial = 8 * 1024 * 1024;
	auto window = AdaptiveWindow(limits);
	// A slow uplink: 400 KB/s at 60 ms. 8 MiB in flight means 20 s of
	// queue in front of every chat request.
	const auto path = Path{ .capacity = 400 * 1000, .baseRtt = 60 };
	auto now = int64(1000);
	// The first frames of a burst see the empty path.
	window.update(Sample(now, 200, 80'000, false, 60));
	auto first = int64(0);
	for (auto i = 0; i != 60; ++i) {
		now += 200;
		window.update(path.sample(now, 200, window.window()));
		if (!i) {
			first = window.window();
		}
	}
	Check(first >= limits.initial / 2,
		"one interval shrinks the window at most by half");
	Check(window.window() <= 128 * 1024,
		"a queue far beyond the target shrinks the window to the floor");
	Check(path.queueDelay(window.window()) <= 250,
		"after shrinking chats wait a fraction of a second, not seconds");
	Check(window.shrinks() > 0, "shrinks are counted");
	Check(window.baseDelay() == 60,
		"a standing queue does not raise the base round trip "
		"within the history");
}

void TestAdaptiveIgnoresIdleFlow() {
	auto window = AdaptiveWindow(AdaptiveWindowLimits());
	const auto start = window.window();
	auto now = int64(1000);
	for (auto i = 0; i != 30; ++i) {
		now += 200;
		window.update(Sample(now, 200, 1000, false, 80));
	}
	Check(window.window() == start,
		"an application-limited flow neither grows nor drains the window");

	auto blind = AdaptiveWindow(AdaptiveWindowLimits());
	for (auto i = 0; i != 30; ++i) {
		blind.update(Sample(1000 + i * 200, 200, 10'000'000, true, {}));
	}
	Check(blind.window() == blind.limits().blindMax,
		"without delay samples growth stops at the blind cap");
}

void TestAdaptiveSharesDelay() {
	// Upload and download on one loop: the credit for this direction comes
	// back behind the queue the other direction keeps (here 150 ms), which
	// delays the loop but holds none of this direction's bytes.
	const auto capacity = int64(1'500'000);
	const auto base = int64(150);
	const auto other = int64(150);
	const auto run = [&](int64 extra) {
		auto window = AdaptiveWindow(AdaptiveWindowLimits());
		auto now = int64(1000);
		window.update(Sample(now, base, 1, false, base));
		auto rate = int64();
		for (auto i = 0; i != 100; ++i) {
			now += base;
			const auto loop = base + other;
			const auto w = window.window();
			const auto queue = std::max(w - capacity * loop / 1000, int64(0))
				* 1000 / capacity;
			rate = std::min(capacity, w * 1000 / loop);
			auto sample = Sample(now, base, rate * base / 1000, true, loop + queue);
			sample.extraDelay = extra;
			window.update(sample);
		}
		return rate;
	};
	Check(run(0) < capacity * 9 / 10,
		"without a share the other queue starves this direction");
	Check(run(100) >= capacity * 95 / 100,
		"with its share this direction keeps the pipe full");
}

void TestAdaptiveHold() {
	auto window = AdaptiveWindow(AdaptiveWindowLimits());
	window.update(Sample(1000, 100, 1, false, 100));
	const auto before = window.window();
	for (auto i = 0; i != 40; ++i) {
		window.hold(Sample(1100 + i * 100, 100, 50'000, true, 2100));
	}
	Check(window.window() == before,
		"a held window neither grows nor shrinks");
	window.hold(Sample(6000, 100, 1, true, 90));
	Check(window.baseDelay() == 90, "held samples still refresh the base");
}

void TestAdaptiveBaseHistory() {
	auto window = AdaptiveWindow(AdaptiveWindowLimits());
	window.update(Sample(1000, 200, 1, false, 50));
	window.update(Sample(2000, 200, 1, false, 200));
	Check(window.baseDelay() == 50, "the lowest recent round trip is the base");
	window.update(Sample(25'000, 200, 1, false, 200));
	Check(window.baseDelay() == 50, "the base outlives the probe period");
	window.update(Sample(75'000, 200, 1, false, 200));
	Check(window.baseDelay() == 200, "an old base is eventually forgotten");

	// A drained interval feeds the base but moves nothing else.
	auto probe = Sample(76'000, 200, 10'000'000, true, 120);
	probe.probing = true;
	const auto before = window.window();
	window.update(probe);
	Check(window.baseDelay() == 120 && window.window() == before,
		"a probe refreshes the base without touching the window");
	window.reset();
	Check(!window.baseDelay().has_value()
		&& window.window() == window.limits().initial,
		"reset starts over");
}

void TestReasonNames() {
	Check(ReceiveReasonName(ReceiveReason::ReplyMissing)
		== std::string("reply_missing"), "reason names are stable");
	Check(StreamClassName(StreamClass::Upload) == std::string("upload"),
		"class names are stable");
}

} // namespace

int main(int, char *[]) {
	TestInteractiveFirst();
	TestRoundRobinWithinClass();
	TestMarkReadyIdempotent();
	TestUploadCap();
	TestUploadFramesFollowTheCap();
	TestDownloadNotCapped();
	TestNoUploadStarvation();
	TestStaleIdsSkipped();
	TestDownlinkCredit();
	TestCarrierStall();
	TestReceiveWait();
	TestAdaptiveGrowsOnFreePath();
	TestAdaptiveShrinksWhenQueueGrows();
	TestAdaptiveIgnoresIdleFlow();
	TestAdaptiveSharesDelay();
	TestAdaptiveHold();
	TestAdaptiveBaseHistory();
	TestReasonNames();
	if (Failures) {
		std::fprintf(stderr, "%d check(s) failed\n", Failures);
		return 1;
	}
	std::printf("test_web_proxy_flow: all checks passed\n");
	return 0;
}

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
		== limits.downloadMax, "a lone download is capped at the max");
	Check(DownlinkCreditTarget(limits, StreamClass::Download, 4)
		== limits.downloadBudget / 4, "downloads share the budget");
	Check(DownlinkCreditTarget(limits, StreamClass::Download, 100)
		== limits.downloadMin, "a share never drops below the minimum");
	Check(DownlinkCreditTarget(limits, StreamClass::Download, 0)
		== limits.downloadMax, "zero streams does not divide by zero");

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
	TestDownloadNotCapped();
	TestNoUploadStarvation();
	TestStaleIdsSkipped();
	TestDownlinkCredit();
	TestCarrierStall();
	TestReceiveWait();
	TestReasonNames();
	if (Failures) {
		std::fprintf(stderr, "%d check(s) failed\n", Failures);
		return 1;
	}
	std::printf("test_web_proxy_flow: all checks passed\n");
	return 0;
}

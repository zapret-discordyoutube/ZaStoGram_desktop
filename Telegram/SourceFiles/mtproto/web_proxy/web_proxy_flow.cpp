/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/web_proxy/web_proxy_flow.h"

#include <algorithm>

namespace MTP::WebProxy {
namespace {

[[nodiscard]] std::size_t Index(StreamClass value) {
	return std::size_t(value);
}

} // namespace

const char *StreamClassName(StreamClass value) {
	switch (value) {
	case StreamClass::Interactive: return "interactive";
	case StreamClass::Download: return "download";
	case StreamClass::Upload: return "upload";
	}
	return "interactive";
}

UplinkScheduler::UplinkScheduler(UplinkLimits limits)
: _limits(limits) {
}

void UplinkScheduler::add(uint32 streamId, StreamClass streamClass) {
	remove(streamId);
	_streams.emplace(streamId, Entry{ .streamClass = streamClass });
}

void UplinkScheduler::remove(uint32 streamId) {
	const auto i = _streams.find(streamId);
	if (i == end(_streams)) {
		return;
	}
	if (i->second.streamClass == StreamClass::Upload) {
		_uploadInFlight -= i->second.inFlight;
	}
	// A stale id may stay in its ready queue; popReady() skips it.
	_streams.erase(i);
}

void UplinkScheduler::clear() {
	_streams.clear();
	for (auto &queue : _ready) {
		queue.clear();
	}
	_uploadInFlight = 0;
	_uploadSkipped = 0;
}

void UplinkScheduler::markReady(uint32 streamId) {
	const auto i = _streams.find(streamId);
	if (i == end(_streams) || i->second.ready) {
		return;
	}
	i->second.ready = true;
	_ready[Index(i->second.streamClass)].push_back(streamId);
}

bool UplinkScheduler::hasReady(StreamClass streamClass) {
	auto &queue = _ready[Index(streamClass)];
	while (!queue.empty()) {
		const auto i = _streams.find(queue.front());
		if (i != end(_streams)
			&& i->second.ready
			&& i->second.streamClass == streamClass) {
			return true;
		}
		queue.pop_front();
	}
	return false;
}

std::optional<uint32> UplinkScheduler::popReady(StreamClass streamClass) {
	if (!hasReady(streamClass)) {
		return std::nullopt;
	}
	auto &queue = _ready[Index(streamClass)];
	const auto streamId = queue.front();
	queue.pop_front();
	_streams[streamId].ready = false;
	return streamId;
}

std::optional<UplinkGrant> UplinkScheduler::next() {
	const auto uploadRoom = _limits.uploadInFlight - _uploadInFlight;
	const auto uploadEligible = (uploadRoom > 0)
		&& hasReady(StreamClass::Upload);
	const auto preferUpload = uploadEligible
		&& (_uploadSkipped >= _limits.priorityBurst);
	const auto order = preferUpload
		? std::array{
			StreamClass::Upload,
			StreamClass::Interactive,
			StreamClass::Download,
		}
		: std::array{
			StreamClass::Interactive,
			StreamClass::Download,
			StreamClass::Upload,
		};
	for (const auto streamClass : order) {
		const auto upload = (streamClass == StreamClass::Upload);
		if (upload && !uploadEligible) {
			continue;
		}
		const auto streamId = popReady(streamClass);
		if (!streamId) {
			continue;
		}
		if (upload) {
			_uploadSkipped = 0;
		} else if (uploadEligible) {
			++_uploadSkipped;
		}
		const auto uploadFrame = std::min<int64>(
			_limits.frameSize,
			std::max<int64>(
				_limits.uploadInFlight / 4,
				_limits.minUploadFrame));
		const auto maxBytes = upload
			? int(std::min(uploadFrame, uploadRoom))
			: _limits.frameSize;
		return UplinkGrant{ .streamId = *streamId, .maxBytes = maxBytes };
	}
	return std::nullopt;
}

void UplinkScheduler::sent(uint32 streamId, int bytes) {
	const auto i = _streams.find(streamId);
	if (i == end(_streams) || bytes <= 0) {
		return;
	}
	i->second.inFlight += bytes;
	if (i->second.streamClass == StreamClass::Upload) {
		_uploadInFlight += bytes;
	}
}

void UplinkScheduler::acknowledged(uint32 streamId, int64 bytes) {
	const auto i = _streams.find(streamId);
	if (i == end(_streams) || bytes <= 0) {
		return;
	}
	const auto acked = std::min(i->second.inFlight, bytes);
	i->second.inFlight -= acked;
	if (i->second.streamClass == StreamClass::Upload) {
		_uploadInFlight -= acked;
	}
}

void UplinkScheduler::setUploadInFlight(int64 bytes) {
	_limits.uploadInFlight = std::max(bytes, int64(_limits.frameSize));
}

UplinkStats UplinkScheduler::stats() const {
	auto result = UplinkStats{ .uploadInFlight = _uploadInFlight };
	for (const auto &[streamId, entry] : _streams) {
		++result.streams[Index(entry.streamClass)];
		if (entry.ready) {
			++result.ready[Index(entry.streamClass)];
		}
	}
	return result;
}

bool UplinkScheduler::uploadBlocked() const {
	if (_uploadInFlight < _limits.uploadInFlight) {
		return false;
	}
	return std::any_of(begin(_streams), end(_streams), [](const auto &pair) {
		return pair.second.ready
			&& pair.second.streamClass == StreamClass::Upload;
	});
}

int64 DownlinkCreditTarget(
		const DownlinkLimits &limits,
		StreamClass streamClass,
		int downloadStreams) {
	if (streamClass != StreamClass::Download) {
		return limits.streamWindow;
	}
	const auto share = limits.downloadBudget
		/ std::max(downloadStreams, 1);
	return std::min(
		std::clamp(share, limits.downloadMin, limits.downloadMax),
		limits.streamWindow);
}

int64 DownlinkCreditRelease(
		int64 relayCredit,
		int64 withheld,
		int64 target) {
	return std::clamp(target - relayCredit, int64(0), std::max(withheld, int64(0)));
}

AdaptiveWindow::AdaptiveWindow(AdaptiveWindowLimits limits)
: _limits(limits)
, _window(std::clamp(limits.initial, limits.min, limits.max))
, _target(_window) {
}

void AdaptiveWindow::reset() {
	_base.clear();
	_lastDelay = std::nullopt;
	_window = std::clamp(_limits.initial, _limits.min, _limits.max);
	_target = _window;
	_rate = 0;
}

std::optional<int64> AdaptiveWindow::baseDelay() const {
	if (_base.empty()) {
		return std::nullopt;
	}
	auto result = _base.front().second;
	for (const auto &[bucket, value] : _base) {
		result = std::min(result, value);
	}
	return result;
}

void AdaptiveWindow::noteDelay(int64 now, std::optional<int64> delay) {
	if (!delay || *delay < 0) {
		return;
	}
	_lastDelay = delay;
	const auto bucket = now / _limits.baseBucket;
	if (!_base.empty() && _base.back().first == bucket) {
		_base.back().second = std::min(_base.back().second, *delay);
	} else {
		_base.emplace_back(bucket, *delay);
	}
	const auto buckets = _limits.baseHistory / _limits.baseBucket;
	while (!_base.empty() && bucket - _base.front().first >= buckets) {
		_base.pop_front();
	}
}

void AdaptiveWindow::hold(const FlowSample &sample) {
	noteDelay(sample.now, sample.delay);
}

void AdaptiveWindow::update(const FlowSample &sample) {
	if (sample.interval <= 0) {
		return;
	}
	const auto now = sample.now;
	if (!sample.probing) {
		const auto rate = sample.bytes * 1000 / sample.interval;
		_rate = _rate ? ((_rate + rate) / 2) : rate;
	}

	noteDelay(now, sample.delay);
	if (!sample.windowLimited || sample.probing) {
		// An idle or application-limited flow says nothing about the
		// path; keep the window for the next burst. A drained one only
		// says what the base is.
		return;
	}
	const auto clampWindow = [&](int64 value) {
		return std::clamp(value, _limits.min, _limits.max);
	};
	const auto base = baseDelay();
	if (!base) {
		// Nothing tells how much is queued: grow cautiously, never past
		// blindMax.
		if (_window < _limits.blindMax) {
			_window = std::min(
				clampWindow(_window * _limits.maxGrowthPercent / 100),
				std::max(_limits.blindMax, _limits.min));
		}
		return;
	}
	// While the window is the limit, rate == window / loop round trip.
	// Below the target the loop runs at the base round trip and the target
	// comes out above the window; once a queue builds, the loop round trip
	// grows past base + targetDelay and the target drops below it.
	_target = clampWindow(_rate
		* (*base + _limits.targetDelay + sample.extraDelay)
		/ 1000);
	if (_target > _window) {
		_window = std::min(
			_target,
			clampWindow(_window * _limits.maxGrowthPercent / 100));
	} else if (_target < _window) {
		_window = std::max(
			_target,
			clampWindow(_window * _limits.shrinkPercent / 100));
		++_shrinks;
	}
}

const char *ReceiveReasonName(ReceiveReason reason) {
	switch (reason) {
	case ReceiveReason::StreamClosed: return "stream_closed";
	case ReceiveReason::CarrierDown: return "carrier_down";
	case ReceiveReason::MaxWait: return "max_wait";
	case ReceiveReason::CarrierStalled: return "carrier_stalled";
	case ReceiveReason::Queued: return "request_queued";
	case ReceiveReason::ReplyQueued: return "reply_queued";
	case ReceiveReason::ReplyPending: return "reply_pending";
	case ReceiveReason::ReplyMissing: return "reply_missing";
	case ReceiveReason::ReplyTimeout: return "reply_timeout";
	}
	return "unknown";
}

bool CarrierStalled(
		int64 now,
		const CarrierHealth &carrier,
		const LivenessLimits &limits) {
	if (!carrier.connected || carrier.unackedBytes <= 0) {
		return false;
	}
	const auto progress = std::max({
		carrier.outstandingSince,
		carrier.lastCreditAt,
		carrier.lastDownlinkAt,
	});
	return (now - progress) >= limits.carrierStall;
}

ReceiveDecision DecideReceiveWait(
		int64 now,
		int64 waitStartedAt,
		const CarrierHealth &carrier,
		const StreamHealth &stream,
		const LivenessLimits &limits) {
	const auto fail = [](ReceiveReason reason) {
		return ReceiveDecision{
			.verdict = ReceiveVerdict::Fail,
			.reason = reason,
		};
	};
	if (!stream.open) {
		return fail(ReceiveReason::StreamClosed);
	} else if (!carrier.connected) {
		return fail(ReceiveReason::CarrierDown);
	}
	const auto waited = now - waitStartedAt;
	if (waited >= limits.maxWait) {
		return fail(ReceiveReason::MaxWait);
	}
	const auto left = limits.maxWait - waited;
	const auto wait = [&](ReceiveReason reason, int64 delay) {
		return ReceiveDecision{
			.verdict = ReceiveVerdict::Wait,
			.reason = reason,
			.waitMore = std::clamp(delay, int64(1), left),
		};
	};
	if (CarrierStalled(now, carrier, limits)) {
		// The carrier watchdog tears every stream down at once; failing
		// here first would only reopen streams on the stuck carrier.
		return wait(ReceiveReason::CarrierStalled, limits.recheck);
	} else if (stream.queuedBytes > 0 || stream.unackedBytes > 0) {
		// The request itself has not reached the backend yet, and the
		// carrier is moving (otherwise it would be stalled above).
		return wait(ReceiveReason::Queued, limits.recheck);
	}
	const auto replyFrom = std::max({
		stream.deliveredAt,
		stream.lastReceivedAt,
		waitStartedAt,
	});
	const auto silent = now - replyFrom;
	if (silent >= limits.busyReply) {
		return fail(ReceiveReason::ReplyTimeout);
	}
	const auto downlinkIdle = now - carrier.lastDownlinkAt;
	if (downlinkIdle < limits.busyWindow) {
		return wait(ReceiveReason::ReplyQueued, limits.recheck);
	}
	// Nothing is arriving at all, so nothing can be queued in front of the
	// reply: count the time both the request and the downlink were idle.
	const auto quiet = std::min(silent, downlinkIdle);
	if (quiet >= limits.quietReply) {
		return fail(ReceiveReason::ReplyMissing);
	}
	return wait(ReceiveReason::ReplyPending, limits.quietReply - quiet);
}

} // namespace MTP::WebProxy

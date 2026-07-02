/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "chat_helpers/picker_animation_scheduler.h"

#include "base/algorithm.h"

#include <QtWidgets/QWidget>

#include <algorithm>

namespace ChatHelpers {
namespace {

constexpr auto kRepaintTick = crl::time(33);
constexpr auto kColdStartTick = crl::time(50);
constexpr auto kMaxClipStartsPerTick = 4;
constexpr auto kMaxVectorStartsPerTick = 8;

} // namespace

PickerAnimationScheduler::PickerAnimationScheduler()
: _repaintTimer([=] { flushRepaints(); }) {
}

void PickerAnimationScheduler::setActive(bool active) {
	if (_active == active) {
		return;
	}
	_active = active;
	if (!active) {
		_dirty.clear();
		_repaintTimer.cancel();
	}
}

bool PickerAnimationScheduler::active() const {
	return _active;
}

int PickerAnimationScheduler::retentionTop(
		int visibleTop,
		int visibleBottom) const {
	const auto height = std::max(visibleBottom - visibleTop, 0);
	return visibleTop - 2 * height;
}

int PickerAnimationScheduler::retentionBottom(
		int visibleTop,
		int visibleBottom) const {
	const auto height = std::max(visibleBottom - visibleTop, 0);
	return visibleBottom + 2 * height;
}

PickerAnimationLease PickerAnimationScheduler::requestLease(
		PickerAnimationKey key,
		bool visible,
		bool needsStart) {
	const auto now = crl::now();
	const auto admitted = _active && visible;
	return {
		.visible = admitted,
		.canStart = admitted && (!needsStart || consumeStart(key.kind, now)),
		.frameMs = admitted ? now : crl::time(0),
		.nextRepaintDelay = kRepaintTick,
	};
}

void PickerAnimationScheduler::queueRepaint(QWidget *widget, QRect rect) {
	if (!_active || !widget || rect.isEmpty()) {
		return;
	}
	for (auto &entry : _dirty) {
		if (entry.widget == widget) {
			entry.region += rect;
			if (!_repaintTimer.isActive()) {
				_repaintTimer.callOnce(kRepaintTick);
			}
			return;
		}
	}
	_dirty.push_back({ widget, QRegion(rect) });
	if (!_repaintTimer.isActive()) {
		_repaintTimer.callOnce(kRepaintTick);
	}
}

void PickerAnimationScheduler::flushRepaints() {
	auto dirty = base::take(_dirty);
	for (const auto &entry : dirty) {
		if (const auto widget = entry.widget.data()) {
			widget->update(entry.region);
		}
	}
}

bool PickerAnimationScheduler::consumeStart(
		PickerAnimationKind kind,
		crl::time now) {
	refreshColdStartBudget(now);
	auto &left = (kind == PickerAnimationKind::Gif
		|| kind == PickerAnimationKind::StickerWebm)
		? _clipStartsLeft
		: _vectorStartsLeft;
	if (left <= 0) {
		return false;
	}
	--left;
	return true;
}

void PickerAnimationScheduler::refreshColdStartBudget(crl::time now) {
	if (_lastColdStartTick && now < _lastColdStartTick + kColdStartTick) {
		return;
	}
	_lastColdStartTick = now;
	_clipStartsLeft = kMaxClipStartsPerTick;
	_vectorStartsLeft = kMaxVectorStartsPerTick;
}

} // namespace ChatHelpers

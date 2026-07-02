/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "base/timer.h"

#include <QtCore/QPointer>
#include <QtCore/QRect>
#include <QtGui/QRegion>

#include <cstdint>
#include <vector>

class QWidget;

namespace ChatHelpers {

enum class PickerAnimationKind {
	Gif,
	StickerWebm,
	StickerLottie,
	CustomEmoji,
	FooterIcon,
};

struct PickerAnimationKey {
	uintptr_t owner = 0;
	int index = -1;
	PickerAnimationKind kind = PickerAnimationKind::Gif;
};

struct PickerAnimationLease {
	bool visible = false;
	bool canStart = false;
	crl::time frameMs = 0;
	crl::time nextRepaintDelay = 0;
};

class PickerAnimationScheduler final {
public:
	PickerAnimationScheduler();

	void setActive(bool active);
	[[nodiscard]] bool active() const;

	[[nodiscard]] int retentionTop(int visibleTop, int visibleBottom) const;
	[[nodiscard]] int retentionBottom(int visibleTop, int visibleBottom) const;

	[[nodiscard]] PickerAnimationLease requestLease(
		PickerAnimationKey key,
		bool visible);

	void queueRepaint(QWidget *widget, QRect rect);
	void flushRepaints();

private:
	struct DirtyEntry {
		QPointer<QWidget> widget;
		QRegion region;
	};

	bool consumeStart(PickerAnimationKind kind, crl::time now);
	void refreshColdStartBudget(crl::time now);

	bool _active = true;
	crl::time _lastColdStartTick = 0;
	int _clipStartsLeft = 0;
	int _vectorStartsLeft = 0;
	std::vector<DirtyEntry> _dirty;
	base::Timer _repaintTimer;

};

} // namespace ChatHelpers

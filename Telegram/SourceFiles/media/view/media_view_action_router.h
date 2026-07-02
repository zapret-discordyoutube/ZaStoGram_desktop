/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "base/basic_types.h"
#include "base/timer.h"

#include <QtCore/Qt>

#include <optional>

class DocumentData;

namespace Media::View {

enum class Action {
	None,
	TogglePlayback,
	SeekRelative,
	SeekToStart,
	SeekToProgress,
	StepFrame,
	JumpChapter,
	ToggleFullscreen,
};

struct ActionContext {
	int key = 0;
	Qt::KeyboardModifiers modifiers;
	bool autoRepeat = false;
	bool hasStreamed = false;
	bool stories = false;
	bool fullScreenVideo = false;
	bool paused = false;
	bool hasTimestamps = false;
};

struct ActionRequest {
	Action action = Action::None;
	int direction = 0;
	float64 progress = 0.;
	crl::time relative = 0;
};

[[nodiscard]] std::optional<ActionRequest> ResolveAction(
	ActionContext context);

[[nodiscard]] bool ShouldOpenDocumentInMediaView(
	not_null<DocumentData*> document);

} // namespace Media::View

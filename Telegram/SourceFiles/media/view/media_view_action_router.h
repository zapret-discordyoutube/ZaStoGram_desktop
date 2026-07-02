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

enum class OpenRoute {
	None,
	MediaView,
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

struct ActionHandlers {
	Fn<void()> togglePlayback;
	Fn<void(crl::time)> seekRelative;
	Fn<void()> seekToStart;
	Fn<void(float64)> seekToProgress;
	Fn<void(int)> stepFrame;
	Fn<void(int)> jumpChapter;
	Fn<void()> toggleFullscreen;
};

[[nodiscard]] std::optional<ActionRequest> ResolveAction(
	ActionContext context);

[[nodiscard]] bool ExecuteAction(
	const ActionRequest &request,
	const ActionHandlers &handlers);

[[nodiscard]] OpenRoute ResolveOpenRoute(
	not_null<DocumentData*> document);

} // namespace Media::View

/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "media/view/media_view_action_router.h"

#include "data/data_document.h"

namespace Media::View {
namespace {

constexpr auto kSeekTimeMs = crl::time(5000);
constexpr auto kSeekTimeMsLong = crl::time(10000);

[[nodiscard]] bool IsEnterKey(int key) {
	return key == Qt::Key_Enter || key == Qt::Key_Return;
}

} // namespace

std::optional<ActionRequest> ResolveAction(ActionContext context) {
	const auto key = context.key;
	const auto modifiers = context.modifiers;
	const auto ctrl = modifiers.testFlag(Qt::ControlModifier);
	const auto alt = modifiers.testFlag(Qt::AltModifier);

	if (!context.hasStreamed) {
		return std::nullopt;
	} else if (ctrl && key == Qt::Key_Left) {
		return ActionRequest{
			.action = Action::StepFrame,
			.direction = -1,
		};
	} else if (ctrl && key == Qt::Key_Right) {
		return ActionRequest{
			.action = Action::StepFrame,
			.direction = 1,
		};
	} else if (context.paused && key == Qt::Key_Comma) {
		return ActionRequest{
			.action = Action::StepFrame,
			.direction = -1,
		};
	} else if (context.paused && key == Qt::Key_Period) {
		return ActionRequest{
			.action = Action::StepFrame,
			.direction = 1,
		};
	} else if ((alt || ctrl) && IsEnterKey(key)) {
		return ActionRequest{ .action = Action::ToggleFullscreen };
	} else if (key == Qt::Key_K) {
		return ActionRequest{ .action = Action::TogglePlayback };
	} else if (key == Qt::Key_J) {
		return ActionRequest{
			.action = Action::SeekRelative,
			.relative = -kSeekTimeMsLong,
		};
	} else if (key == Qt::Key_L) {
		return ActionRequest{
			.action = Action::SeekRelative,
			.relative = kSeekTimeMsLong,
		};
	} else if (alt
		&& context.hasTimestamps
		&& (key == Qt::Key_Left || key == Qt::Key_Right)) {
		return ActionRequest{
			.action = Action::JumpChapter,
			.direction = (key == Qt::Key_Left) ? -1 : 1,
		};
	} else if (context.fullScreenVideo && !ctrl) {
		if (key == Qt::Key_Escape) {
			return ActionRequest{ .action = Action::ToggleFullscreen };
		} else if (key == Qt::Key_0) {
			return ActionRequest{ .action = Action::SeekToStart };
		} else if (key >= Qt::Key_1 && key <= Qt::Key_9) {
			return ActionRequest{
				.action = Action::SeekToProgress,
				.progress = int(key - Qt::Key_0) / 10.,
			};
		} else if (key == Qt::Key_Left || key == Qt::Key_Right) {
			return ActionRequest{
				.action = Action::SeekRelative,
				.relative = (key == Qt::Key_Left)
					? -kSeekTimeMs
					: kSeekTimeMs,
			};
		}
	}
	return std::nullopt;
}

bool ShouldOpenDocumentInMediaView(not_null<DocumentData*> document) {
	return document->isVideoMessage();
}

} // namespace Media::View

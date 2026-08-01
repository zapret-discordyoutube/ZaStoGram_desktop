/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "base/basic_types.h"
#include "e2e_cloud/core/types.h"

namespace Window {
class SessionController;
} // namespace Window

namespace E2ECloud {

void ShowProtectedGroupList(
	not_null<Window::SessionController*> controller);
void ShowProtectedConversation(
	not_null<Window::SessionController*> controller,
	ConversationId conversationId);

} // namespace E2ECloud

/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "data/data_types.h"

namespace Ui::Menu {
struct MenuCallback;
} // namespace Ui::Menu

namespace Window {
class SessionController;
} // namespace Window

// The actions of one ZaStoGram folder for context menus (folder tabs, the
// folders sidebar, the settings list): edit, chats, subfolder, order,
// synchronization and delete.
void FillLocalFolderMenu(
	const Ui::Menu::MenuCallback &addAction,
	not_null<Window::SessionController*> controller,
	FilterId id);

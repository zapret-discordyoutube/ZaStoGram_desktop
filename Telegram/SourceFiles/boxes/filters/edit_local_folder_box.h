/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "data/data_types.h"

namespace Ui {
class GenericBox;
} // namespace Ui

namespace Window {
class SessionController;
} // namespace Window

// Creates (id == 0, inside the folder `parent`, 0 for the top level) or
// edits one of ZaStoGram's own folders.
void EditLocalFolderBox(
	not_null<Ui::GenericBox*> box,
	not_null<Window::SessionController*> controller,
	FilterId id,
	FilterId parent);

// Chooses the chats added directly to the folder.
void ShowLocalFolderChatsBox(
	not_null<Window::SessionController*> controller,
	FilterId id);

// Asks for confirmation and deletes the folder with all its subfolders.
void DeleteLocalFolder(
	not_null<Window::SessionController*> controller,
	FilterId id,
	Fn<void()> done = nullptr);

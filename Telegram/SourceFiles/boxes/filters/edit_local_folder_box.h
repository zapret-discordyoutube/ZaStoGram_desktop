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

/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

namespace Ui {
class VerticalLayout;
} // namespace Ui

namespace Window {
class SessionController;
} // namespace Window

namespace Settings {

// The list of ZaStoGram's own folders on the Folders page.
void SetupLocalFolders(
	not_null<Window::SessionController*> controller,
	not_null<Ui::VerticalLayout*> container);

} // namespace Settings

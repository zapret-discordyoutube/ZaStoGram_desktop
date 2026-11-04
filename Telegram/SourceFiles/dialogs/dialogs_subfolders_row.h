/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "ui/rp_widget.h"

namespace Ui {
class RoundButton;
} // namespace Ui

namespace Window {
class SessionController;
} // namespace Window

namespace Dialogs {

// The row under the folder tabs for ZaStoGram's nested folders: the path to
// the active folder (to go up) and the subfolders it contains (to go down).
// It is hidden when the active folder is not a ZaStoGram folder, or is a
// top-level one without subfolders.
class SubfoldersRow final : public Ui::RpWidget {
public:
	SubfoldersRow(
		QWidget *parent,
		not_null<Window::SessionController*> controller);

	[[nodiscard]] rpl::producer<bool> shownValue() const {
		return _shown.value();
	}

protected:
	int resizeGetHeight(int newWidth) override;

private:
	void rebuild();

	const not_null<Window::SessionController*> _controller;
	std::vector<std::unique_ptr<Ui::RoundButton>> _buttons;
	rpl::variable<bool> _shown = false;

};

} // namespace Dialogs

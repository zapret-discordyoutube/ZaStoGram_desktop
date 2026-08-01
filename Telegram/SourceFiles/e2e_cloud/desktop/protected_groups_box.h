/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "ui/layers/box_content.h"

namespace Ui {
class FlatLabel;
class PasswordInput;
} // namespace Ui

namespace Window {
class SessionController;
} // namespace Window

namespace E2ECloud {

class ProtectedGroupsBox final : public Ui::BoxContent {
public:
	ProtectedGroupsBox(
		QWidget*,
		not_null<Window::SessionController*> controller);

protected:
	void prepare() override;
	void setInnerFocus() override;
	void resizeEvent(QResizeEvent *event) override;

private:
	void refresh();
	void updateControlsGeometry();
	void submit();
	void showGroupCreation();

	const not_null<Window::SessionController*> _controller;
	object_ptr<Ui::FlatLabel> _status;
	object_ptr<Ui::PasswordInput> _password;
	object_ptr<Ui::PasswordInput> _confirm;
};

} // namespace E2ECloud

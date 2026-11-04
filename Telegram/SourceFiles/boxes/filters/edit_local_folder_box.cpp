/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "boxes/filters/edit_local_folder_box.h"

#include "data/data_chat_filters.h"
#include "data/data_chat_filters_tree.h"
#include "data/data_session.h"
#include "lang/lang_keys.h"
#include "main/main_session.h"
#include "ui/boxes/confirm_box.h"
#include "ui/layers/generic_box.h"
#include "ui/vertical_list.h"
#include "ui/widgets/buttons.h"
#include "ui/widgets/checkbox.h"
#include "ui/widgets/fields/input_field.h"
#include "window/window_session_controller.h"
#include "styles/style_layers.h"
#include "styles/style_window.h"

namespace {

constexpr auto kMaxLocalFolderTitleLength = 64;

} // namespace

void EditLocalFolderBox(
		not_null<Ui::GenericBox*> box,
		not_null<Window::SessionController*> controller,
		FilterId id,
		FilterId parent) {
	const auto session = &controller->session();
	const auto folders = [=]() -> Data::LocalFolders& {
		return session->data().chatsFilters().local();
	};
	const auto existing = id ? folders().find(id) : nullptr;
	if (id && !existing) {
		box->closeBox();
		return;
	}
	box->setTitle(id
		? tr::lng_zsg_folders_edit_title()
		: tr::lng_zsg_folders_new_title());

	const auto name = box->addRow(
		object_ptr<Ui::InputField>(
			box,
			st::windowFilterNameInput,
			Ui::InputField::Mode::SingleLine,
			tr::lng_zsg_folders_name(),
			existing ? existing->title : QString()),
		st::windowFilterNameInputPadding);
	name->setMaxLength(kMaxLocalFolderTitleLength);
	box->setFocusCallback([=] {
		name->setFocusFast();
	});

	const auto sync = box->addRow(
		object_ptr<Ui::Checkbox>(
			box,
			tr::lng_zsg_folders_sync(tr::now),
			existing ? existing->sync : true),
		st::boxRowPadding);

	const auto save = [=] {
		const auto title = name->getLastText().trimmed();
		if (title.isEmpty()) {
			name->showError();
			return;
		}
		auto &local = folders();
		const auto target = id ? id : local.create(title, parent);
		if (!target) {
			box->closeBox();
			return;
		}
		if (id) {
			local.rename(id, title);
		}
		local.setSync(target, sync->checked());
		box->closeBox();
	};
	name->submits() | rpl::on_next(save, name->lifetime());
	box->addButton(tr::lng_settings_save(), save);
	box->addButton(tr::lng_cancel(), [=] { box->closeBox(); });

	if (!id) {
		return;
	}
	Ui::AddSkip(box->verticalLayout());
	const auto subfolder = box->addRow(
		object_ptr<Ui::LinkButton>(
			box,
			tr::lng_zsg_folders_subfolder(tr::now)),
		st::boxRowPadding);
	subfolder->setClickedCallback([=] {
		controller->show(
			Box(EditLocalFolderBox, controller, FilterId(0), id));
	});
	box->addLeftButton(tr::lng_zsg_folders_delete(), [=] {
		const auto folder = folders().find(id);
		if (!folder) {
			return;
		}
		controller->show(Ui::MakeConfirmBox({
			.text = tr::lng_zsg_folders_delete_sure(
				tr::now,
				lt_name,
				folder->title),
			.confirmed = [=](Fn<void()> close) {
				folders().remove(id);
				close();
				box->closeBox();
			},
			.confirmText = tr::lng_box_delete(),
			.confirmStyle = &st::attentionBoxButton,
		}));
	});
}

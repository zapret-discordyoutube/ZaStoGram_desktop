/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "boxes/filters/local_folder_menu.h"

#include "boxes/filters/edit_local_folder_box.h"
#include "data/data_chat_filters.h"
#include "data/data_chat_filters_tree.h"
#include "data/data_session.h"
#include "lang/lang_keys.h"
#include "main/main_session.h"
#include "ui/layers/generic_box.h"
#include "ui/widgets/menu/menu_add_action_callback.h"
#include "window/window_session_controller.h"
#include "styles/style_menu_icons.h"

void FillLocalFolderMenu(
		const Ui::Menu::MenuCallback &addAction,
		not_null<Window::SessionController*> controller,
		FilterId id) {
	const auto session = &controller->session();
	const auto folders = [=]() -> Data::LocalFolders& {
		return session->data().chatsFilters().local();
	};
	const auto folder = folders().find(id);
	if (!folder) {
		return;
	}
	const auto sync = folder->sync;
	const auto parent = folders().parentOf(id);
	const auto siblings = folders().childrenOf(parent);
	const auto i = ranges::find(siblings, id);
	const auto index = (i == siblings.end()) ? -1 : int(i - siblings.begin());

	addAction(
		tr::lng_filters_context_edit(tr::now),
		[=] {
			controller->show(
				Box(EditLocalFolderBox, controller, id, FilterId(0)));
		},
		&st::menuIconEdit);
	addAction(
		tr::lng_zsg_folders_chats(tr::now),
		[=] { ShowLocalFolderChatsBox(controller, id); },
		&st::menuIconShowInFolder);
	addAction(
		tr::lng_zsg_folders_subfolder(tr::now),
		[=] {
			controller->show(
				Box(EditLocalFolderBox, controller, FilterId(0), id));
		},
		&st::menuIconShowInFolder);
	if (index > 0) {
		addAction(
			tr::lng_zsg_folders_move_up(tr::now),
			[=] { folders().moveBy(id, -1); },
			nullptr);
	}
	if (index >= 0 && index + 1 < int(siblings.size())) {
		addAction(
			tr::lng_zsg_folders_move_down(tr::now),
			[=] { folders().moveBy(id, 1); },
			nullptr);
	}
	if (parent) {
		addAction(
			tr::lng_zsg_folders_menu_to_top(tr::now),
			[=] { folders().place(id, FilterId(0), FilterId(0)); },
			nullptr);
	}
	addAction(
		sync
			? tr::lng_zsg_folders_menu_sync_off(tr::now)
			: tr::lng_zsg_folders_menu_sync_on(tr::now),
		[=] { folders().setSync(id, !sync); },
		nullptr);
	addAction({
		.text = tr::lng_zsg_folders_delete(tr::now),
		.handler = [=] { DeleteLocalFolder(controller, id); },
		.icon = &st::menuIconDeleteAttention,
		.isAttention = true,
	});
}

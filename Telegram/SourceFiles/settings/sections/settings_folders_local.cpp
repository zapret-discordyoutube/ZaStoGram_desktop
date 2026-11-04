/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "settings/sections/settings_folders_local.h"

#include "boxes/filters/edit_local_folder_box.h"
#include "data/data_chat_filters.h"
#include "data/data_chat_filters_tree.h"
#include "data/data_session.h"
#include "lang/lang_keys.h"
#include "main/main_session.h"
#include "settings/settings_common.h"
#include "ui/layers/generic_box.h"
#include "ui/vertical_list.h"
#include "ui/widgets/labels.h"
#include "ui/wrap/vertical_layout.h"
#include "window/window_session_controller.h"
#include "styles/palette.h"
#include "styles/style_settings.h"

namespace Settings {

void SetupLocalFolders(
		not_null<Window::SessionController*> controller,
		not_null<Ui::VerticalLayout*> container) {
	const auto session = &controller->session();

	Ui::AddSkip(container);
	Ui::AddSubsectionTitle(container, tr::lng_zsg_folders_title());

	const auto list = container->add(
		object_ptr<Ui::VerticalLayout>(container));
	const auto rebuild = [=] {
		list->clear();
		const auto &local = session->data().chatsFilters().local();
		for (const auto id : local.ids()) {
			const auto folder = local.find(id);
			if (!folder) {
				continue;
			}
			const auto indent = QString(u"      "_q).repeated(local.depth(id));
			const auto count = int(local.peersOf(id).size());
			const auto button = AddButtonWithLabel(
				list,
				rpl::single(indent + folder->title),
				rpl::single(folder->sync
					? tr::lng_zsg_folders_chats_count(
						tr::now,
						lt_count,
						count)
					: (tr::lng_zsg_folders_chats_count(
						tr::now,
						lt_count,
						count) + u" · "_q + tr::lng_zsg_folders_local_only(tr::now))),
				st::settingsButtonNoIcon);
			button->addClickHandler([=] {
				controller->show(
					Box(EditLocalFolderBox, controller, id, FilterId(0)));
			});
		}
		list->resizeToWidth(list->width());
	};
	session->data().chatsFilters().local().changed(
	) | rpl::on_next(rebuild, list->lifetime());
	rebuild();

	const auto create = AddButtonWithIcon(
		container,
		tr::lng_zsg_folders_create(),
		st::settingsButtonActive,
		{ &st::settingsIconAdd, IconType::Round, &st::windowBgActive });
	create->setClickedCallback([=] {
		controller->show(
			Box(EditLocalFolderBox, controller, FilterId(0), FilterId(0)));
	});

	Ui::AddSkip(container);
	Ui::AddDividerText(container, tr::lng_zsg_folders_about());
}

} // namespace Settings

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
#include "ui/widgets/buttons.h"
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
			// Subfolders are marked and indented under their parent.
			const auto depth = local.depth(id);
			const auto title = depth
				? (QString(u"      "_q).repeated(depth - 1)
					+ u"↳ "_q
					+ folder->title)
				: folder->title;
			const auto count = int(local.peersOf(id).size());
			const auto subfolders = int(local.childrenOf(id).size());
			auto label = tr::lng_zsg_folders_chats_count(
				tr::now,
				lt_count,
				count);
			if (subfolders) {
				label += u" · "_q + tr::lng_zsg_folders_subfolders_count(
					tr::now,
					lt_count,
					subfolders);
			}
			if (!folder->sync) {
				label += u" · "_q + tr::lng_zsg_folders_local_only(tr::now);
			}
			const auto button = AddButtonWithLabel(
				list,
				rpl::single(title),
				rpl::single(label),
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

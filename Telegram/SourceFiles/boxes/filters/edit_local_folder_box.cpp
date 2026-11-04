/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "boxes/filters/edit_local_folder_box.h"

#include "boxes/filters/edit_filter_chats_list.h"
#include "boxes/peer_list_box.h"
#include "data/data_chat_filters.h"
#include "data/data_chat_filters_tree.h"
#include "data/data_peer.h"
#include "data/data_session.h"
#include "history/history.h"
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
constexpr auto kNoChatsLimit = 1000000;

void ChooseParentBox(
		not_null<Ui::GenericBox*> box,
		not_null<Window::SessionController*> controller,
		FilterId id) {
	const auto session = &controller->session();
	box->setTitle(tr::lng_zsg_folders_parent());
	const auto &local = session->data().chatsFilters().local();
	const auto group = std::make_shared<Ui::RadiobuttonGroup>(
		int(local.parentOf(id)));
	box->addRow(
		object_ptr<Ui::Radiobutton>(
			box,
			group,
			0,
			tr::lng_zsg_folders_top_level(tr::now),
			st::defaultBoxCheckbox),
		st::boxRowPadding);
	for (const auto candidate : local.ids()) {
		// A folder cannot be moved into itself or into its own subfolders.
		auto inside = false;
		for (auto up = candidate, guard = FilterId(0);
			up && guard < 1000;
			up = local.parentOf(up), ++guard) {
			if (up == id) {
				inside = true;
				break;
			}
		}
		if (inside) {
			continue;
		}
		box->addRow(
			object_ptr<Ui::Radiobutton>(
				box,
				group,
				int(candidate),
				local.pathTitle(candidate),
				st::defaultBoxCheckbox),
			st::boxRowPadding);
	}
	box->addButton(tr::lng_settings_save(), [=] {
		session->data().chatsFilters().local().move(
			id,
			FilterId(group->current()));
		box->closeBox();
	});
	box->addButton(tr::lng_cancel(), [=] { box->closeBox(); });
}

void ShowChatsBox(
		not_null<Window::SessionController*> controller,
		FilterId id) {
	const auto session = &controller->session();
	const auto folder = session->data().chatsFilters().local().find(id);
	if (!folder) {
		return;
	}
	auto peers = base::flat_set<not_null<History*>>();
	for (const auto peerId : folder->own) {
		peers.emplace(session->data().history(peerId));
	}
	auto list = std::make_unique<EditFilterChatsListController>(
		session,
		tr::lng_zsg_folders_pick_title(),
		Data::ChatFilter::Flags(),
		Data::ChatFilter::Flags(),
		peers,
		kNoChatsLimit,
		[] {});
	auto init = [=](not_null<PeerListBox*> box) {
		box->setCloseByOutsideClick(false);
		box->addButton(tr::lng_settings_save(), [=] {
			auto chosen = base::flat_set<PeerId>();
			for (const auto peer : box->collectSelectedRows()) {
				chosen.emplace(peer->id);
			}
			session->data().chatsFilters().local().setChats(id, chosen);
			box->closeBox();
		});
		box->addButton(tr::lng_cancel(), [=] { box->closeBox(); });
	};
	controller->show(Box<PeerListBox>(std::move(list), std::move(init)));
}

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
	const auto parentFolder = (!id && parent) ? folders().find(parent) : nullptr;
	box->setTitle(id
		? tr::lng_zsg_folders_edit_title()
		: parentFolder
		? rpl::single(tr::lng_zsg_folders_new_sub_title(
			tr::now,
			lt_name,
			folders().pathTitle(parent)))
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
		if (!id) {
			// A new folder is empty: offer to fill it right away.
			ShowChatsBox(controller, target);
		}
	};
	name->submits() | rpl::on_next(save, name->lifetime());
	box->addButton(tr::lng_settings_save(), save);
	box->addButton(tr::lng_cancel(), [=] { box->closeBox(); });

	if (!id) {
		return;
	}
	Ui::AddSkip(box->verticalLayout());
	const auto addLink = [&](const QString &text, Fn<void()> callback) {
		const auto link = box->addRow(
			object_ptr<Ui::LinkButton>(box, text),
			st::boxRowPadding);
		link->setClickedCallback(std::move(callback));
	};
	addLink(tr::lng_zsg_folders_chats(tr::now), [=] {
		ShowChatsBox(controller, id);
	});
	const auto parentId = folders().parentOf(id);
	addLink(
		tr::lng_zsg_folders_parent(tr::now)
			+ u": "_q
			+ (parentId
				? folders().pathTitle(parentId)
				: tr::lng_zsg_folders_top_level(tr::now)),
		[=] {
			controller->show(Box(ChooseParentBox, controller, id));
		});
	addLink(tr::lng_zsg_folders_move_up(tr::now), [=] {
		folders().moveBy(id, -1);
	});
	addLink(tr::lng_zsg_folders_move_down(tr::now), [=] {
		folders().moveBy(id, 1);
	});
	addLink(tr::lng_zsg_folders_subfolder(tr::now), [=] {
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

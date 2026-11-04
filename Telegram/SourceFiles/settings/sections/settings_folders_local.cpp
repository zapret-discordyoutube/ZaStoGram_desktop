/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "settings/sections/settings_folders_local.h"

#include "base/event_filter.h"
#include "boxes/filters/edit_local_folder_box.h"
#include "boxes/filters/local_folder_menu.h"
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
#include "ui/widgets/menu/menu_add_action_callback_factory.h"
#include "ui/widgets/popup_menu.h"
#include "ui/wrap/vertical_layout.h"
#include "window/window_session_controller.h"
#include "styles/palette.h"
#include "styles/style_basic.h"
#include "styles/style_menu_icons.h"
#include "styles/style_settings.h"

#include <QtGui/QMouseEvent>
#include <QtGui/QPainter>
#include <QtWidgets/QApplication>

namespace Settings {
namespace {

struct DragRow {
	FilterId id = 0;
	Ui::SettingsButton *button = nullptr;
};

struct ListState {
	std::vector<DragRow> rows;
	FilterId pressed = 0;
	QPoint pressPoint;
	bool dragging = false;
	bool justDragged = false;
	FilterId dragId = 0;
	bool targetValid = false;
	FilterId targetParent = 0;
	FilterId targetBefore = 0;
	Ui::RpWidget *indicator = nullptr;
	base::unique_qptr<Ui::PopupMenu> menu;
};

} // namespace

void SetupLocalFolders(
		not_null<Window::SessionController*> controller,
		not_null<Ui::VerticalLayout*> container) {
	const auto session = &controller->session();

	Ui::AddSkip(container);
	Ui::AddSubsectionTitle(container, tr::lng_zsg_folders_title());

	const auto list = container->add(
		object_ptr<Ui::VerticalLayout>(container));
	const auto state = list->lifetime().make_state<ListState>();

	// The line that shows where the dragged folder will land.
	state->indicator = Ui::CreateChild<Ui::RpWidget>(list.get());
	state->indicator->hide();
	state->indicator->setAttribute(Qt::WA_TransparentForMouseEvents);
	state->indicator->paintRequest(
	) | rpl::on_next([=] {
		auto p = QPainter(state->indicator);
		p.fillRect(state->indicator->rect(), st::windowBgActive);
	}, state->indicator->lifetime());

	// Where would the folder land if it is dropped at this point: on the
	// middle of a row it goes inside that folder, near the top or the bottom
	// edge of a row it goes next to that folder.
	const auto updateTarget = [=](QPoint global) {
		const auto &local = session->data().chatsFilters().local();
		const auto &rows = state->rows;
		state->targetValid = false;
		if (rows.empty()) {
			state->indicator->hide();
			return;
		}
		const auto pos = list->mapFromGlobal(global);
		const auto first = rows.front().button->geometry();
		const auto last = rows.back().button->geometry();
		auto parent = FilterId(0);
		auto before = FilterId(0);
		auto indicatorY = 0;
		auto indicatorDepth = 0;
		if (pos.y() < first.top()) {
			const auto top = local.childrenOf(0);
			before = top.empty() ? FilterId(0) : top.front();
			indicatorY = first.top();
		} else if (pos.y() >= last.bottom()) {
			indicatorY = last.bottom();
		} else {
			auto index = 0;
			for (auto i = 0, count = int(rows.size()); i != count; ++i) {
				const auto geometry = rows[i].button->geometry();
				if (pos.y() >= geometry.top() && pos.y() < geometry.bottom()) {
					index = i;
					break;
				}
			}
			const auto target = rows[index].id;
			const auto geometry = rows[index].button->geometry();
			const auto fraction = float64(pos.y() - geometry.top())
				/ std::max(1, geometry.height());
			if (fraction < 0.28) {
				parent = local.parentOf(target);
				before = target;
				indicatorY = geometry.top();
				indicatorDepth = local.depth(target);
			} else if (fraction > 0.72) {
				parent = local.parentOf(target);
				const auto siblings = local.childrenOf(parent);
				const auto i = ranges::find(siblings, target);
				before = (i != siblings.end() && (i + 1) != siblings.end())
					? *(i + 1)
					: FilterId(0);
				indicatorY = geometry.bottom();
				indicatorDepth = local.depth(target);
			} else {
				parent = target;
				indicatorY = geometry.bottom();
				indicatorDepth = local.depth(target) + 1;
			}
		}
		// A folder cannot go inside itself or inside its own subfolders.
		auto inside = false;
		auto up = parent;
		for (auto guard = 0; up && guard < 1000; ++guard) {
			if (up == state->dragId) {
				inside = true;
				break;
			}
			up = local.parentOf(up);
		}
		if (inside || before == state->dragId) {
			state->indicator->hide();
			return;
		}
		state->targetValid = true;
		state->targetParent = parent;
		state->targetBefore = before;
		const auto indent = indicatorDepth * st::defaultVerticalListSkip * 4;
		const auto thickness = st::lineWidth * 3;
		state->indicator->setGeometry(
			indent,
			indicatorY - thickness / 2,
			std::max(1, list->width() - indent),
			thickness);
		state->indicator->show();
		state->indicator->raise();
	};

	const auto drop = [=] {
		if (!state->dragging) {
			return;
		}
		const auto id = state->dragId;
		const auto valid = state->targetValid;
		const auto parent = state->targetParent;
		const auto before = state->targetBefore;
		state->dragging = false;
		state->indicator->hide();
		if (!valid) {
			return;
		}
		// The rows are rebuilt by the change, so not inside their own event.
		crl::on_main(list.get(), [=] {
			session->data().chatsFilters().local().place(id, parent, before);
		});
	};

	const auto rebuild = [=] {
		state->indicator->hide();
		state->rows.clear();
		state->pressed = 0;
		state->dragging = false;
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
			state->rows.push_back({ id, button.get() });
			button->addClickHandler([=] {
				if (state->justDragged) {
					state->justDragged = false;
					return;
				}
				controller->show(
					Box(EditLocalFolderBox, controller, id, FilterId(0)));
			});
			base::install_event_filter(button, [=](not_null<QEvent*> e) {
				const auto type = e->type();
				if (type == QEvent::MouseButtonPress) {
					const auto mouse = static_cast<QMouseEvent*>(e.get());
					if (mouse->button() == Qt::RightButton) {
						state->menu = base::make_unique_q<Ui::PopupMenu>(
							list.get(),
							st::popupMenuWithIcons);
						FillLocalFolderMenu(
							Ui::Menu::CreateAddActionCallback(state->menu),
							controller,
							id);
						if (!state->menu->empty()) {
							state->menu->popup(QCursor::pos());
						}
						return base::EventFilterResult::Cancel;
					} else if (mouse->button() == Qt::LeftButton) {
						state->pressed = id;
						state->pressPoint = mouse->globalPosition().toPoint();
						state->dragging = false;
						state->justDragged = false;
					}
				} else if (type == QEvent::MouseMove) {
					const auto mouse = static_cast<QMouseEvent*>(e.get());
					if ((mouse->buttons() & Qt::LeftButton)
						&& state->pressed == id) {
						const auto global = mouse->globalPosition().toPoint();
						if (!state->dragging
							&& (global - state->pressPoint).manhattanLength()
								>= QApplication::startDragDistance()) {
							state->dragging = true;
							state->dragId = id;
						}
						if (state->dragging) {
							updateTarget(global);
						}
					}
				} else if (type == QEvent::MouseButtonRelease) {
					if (state->pressed == id) {
						state->pressed = 0;
						if (state->dragging) {
							// The click that follows is not a click.
							state->justDragged = true;
							drop();
						}
					}
				}
				return base::EventFilterResult::Continue;
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

/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "dialogs/dialogs_subfolders_row.h"

#include "data/data_chat_filters.h"
#include "data/data_chat_filters_tree.h"
#include "data/data_session.h"
#include "main/main_session.h"
#include "ui/widgets/buttons.h"
#include "window/window_session_controller.h"
#include "styles/style_basic.h"
#include "styles/style_widgets.h"

namespace Dialogs {

SubfoldersRow::SubfoldersRow(
	QWidget *parent,
	not_null<Window::SessionController*> controller)
: RpWidget(parent)
, _controller(controller) {
	const auto session = &controller->session();
	rpl::merge(
		controller->activeChatsFilter() | rpl::to_empty,
		session->data().chatsFilters().local().changed()
	) | rpl::on_next([=] {
		rebuild();
	}, lifetime());
	rebuild();
}

void SubfoldersRow::rebuild() {
	_buttons.clear();

	const auto controller = _controller;
	const auto &local = controller->session().data().chatsFilters().local();
	const auto active = controller->activeChatsFilterCurrent();
	if (Data::IsLocalFilterId(active) && local.find(active)) {
		auto path = std::vector<FilterId>();
		for (auto id = active, guard = FilterId(0);
			id && guard < 1000;
			id = local.parentOf(id), ++guard) {
			path.insert(path.begin(), id);
		}
		const auto children = local.childrenOf(active);
		if (path.size() > 1 || !children.empty()) {
			const auto add = [&](FilterId id, QString title, bool current) {
				auto button = std::make_unique<Ui::RoundButton>(
					this,
					rpl::single(title),
					current ? st::defaultActiveButton : st::defaultLightButton);
				button->setClickedCallback([=] {
					controller->setActiveChatsFilter(id);
				});
				button->show();
				_buttons.push_back(std::move(button));
			};
			for (const auto id : path) {
				const auto folder = local.find(id);
				if (folder) {
					add(
						id,
						(id == active) ? folder->title : (folder->title + u"  ›"_q),
						(id == active));
				}
			}
			for (const auto id : children) {
				if (const auto folder = local.find(id)) {
					add(id, folder->title, false);
				}
			}
		}
	}
	const auto shown = !_buttons.empty();
	setVisible(shown);
	_shown = shown;
	if (shown && width() > 0) {
		resizeToWidth(width());
	}
}

int SubfoldersRow::resizeGetHeight(int newWidth) {
	if (_buttons.empty()) {
		return 0;
	}
	const auto skip = st::defaultVerticalListSkip;
	auto x = skip;
	auto y = skip;
	auto rowHeight = 0;
	for (const auto &button : _buttons) {
		rowHeight = button->height();
		if (x > skip && x + button->width() + skip > newWidth) {
			x = skip;
			y += rowHeight + skip;
		}
		button->moveToLeft(x, y, newWidth);
		x += button->width() + skip;
	}
	return y + rowHeight + skip;
}

} // namespace Dialogs

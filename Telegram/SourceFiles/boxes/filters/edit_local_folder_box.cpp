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
#include "ui/painter.h"
#include "ui/rp_widget.h"
#include "window/window_session_controller.h"
#include "styles/palette.h"
#include "styles/style_basic.h"
#include "styles/style_layers.h"
#include "styles/style_window.h"

namespace {

constexpr auto kMaxLocalFolderTitleLength = 64;
constexpr auto kNoChatsLimit = 1000000;
constexpr auto kMaxIconLength = 8;

// A few ready icons, any other emoji can be typed or pasted.
const char *const kPresetIcons[] = {
	"📁", "⭐", "❤️", "🔥", "💼", "🏠", "🎮", "🎵",
	"📚", "✈️", "🛒", "💬", "👥", "📢", "🤖", "💰",
	"🎓", "🏋️", "🍕", "🐱", "🔒", "📷", "🧠", "⚡",
};

// A few ready colors, any other one can be typed as #RRGGBB.
const char *const kPresetColors[] = {
	"#e57373", "#f06292", "#ba68c8", "#9575cd", "#7986cb", "#64b5f6",
	"#4dd0e1", "#4db6ac", "#81c784", "#dce775", "#ffb74d", "#a1887f",
};

// The preview of a folder with the ready icons and colors to choose from.
class LookPicker final : public Ui::RpWidget {
public:
	LookPicker(
		QWidget *parent,
		const QString &icon,
		const QString &color,
		const QString &title)
	: RpWidget(parent)
	, _icon(icon)
	, _color(color)
	, _title(title) {
		setMouseTracking(true);
	}

	void setIcon(const QString &icon) {
		if (_icon != icon) {
			_icon = icon;
			update();
		}
	}
	void setColor(const QString &color) {
		if (_color != color) {
			_color = color;
			update();
		}
	}
	void setTitle(const QString &title) {
		if (_title != title) {
			_title = title;
			update();
		}
	}

	[[nodiscard]] rpl::producer<QString> iconPicked() const {
		return _iconPicked.events();
	}
	[[nodiscard]] rpl::producer<QString> colorPicked() const {
		return _colorPicked.events();
	}

protected:
	int resizeGetHeight(int newWidth) override {
		layoutCells(newWidth);
		return _height;
	}

	void paintEvent(QPaintEvent *e) override {
		Painter p(this);
		p.setRenderHint(QPainter::Antialiasing);
		const auto fill = _color.isEmpty()
			? st::windowBgActive->c
			: QColor(_color);

		p.setPen(Qt::NoPen);
		p.setBrush(fill);
		p.drawEllipse(_preview);
		auto big = st::normalFont->f;
		big.setPixelSize(int(_preview.height() * 0.55));
		p.setFont(big);
		p.setPen(QColor(255, 255, 255));
		p.drawText(
			_preview,
			Qt::AlignCenter,
			_icon.isEmpty() ? QString::fromUtf8("📁") : _icon);
		p.setFont(st::semiboldFont);
		p.setPen(st::windowFg);
		const auto textLeft = _preview.right() + st::boxRowPadding.left() / 2;
		p.drawText(
			QRect(textLeft, _preview.top(), width() - textLeft - _pad, _preview.height()),
			Qt::AlignLeft | Qt::AlignVCenter,
			_title.isEmpty() ? tr::lng_zsg_folders_new_title(tr::now) : _title);

		auto small = st::normalFont->f;
		small.setPixelSize(int(_icons.empty() ? 20 : _icons.front().rect.height() * 0.58));
		p.setFont(small);
		for (auto i = 0, count = int(_icons.size()); i != count; ++i) {
			const auto &cell = _icons[i];
			if (_hovered == (i + 1)) {
				p.setPen(Qt::NoPen);
				p.setBrush(st::windowBgOver);
				p.drawRoundedRect(cell.rect, 8, 8);
			}
			if (cell.value == _icon) {
				p.setPen(QPen(st::windowBgActive->c, 2));
				p.setBrush(Qt::NoBrush);
				p.drawRoundedRect(cell.rect.adjusted(1, 1, -1, -1), 8, 8);
			}
			p.setPen(st::windowFg);
			p.drawText(cell.rect, Qt::AlignCenter, cell.value);
		}
		for (auto i = 0, count = int(_colors.size()); i != count; ++i) {
			const auto &cell = _colors[i];
			const auto none = cell.value.isEmpty();
			const auto selected = (cell.value == _color);
			const auto dot = cell.rect.adjusted(4, 4, -4, -4);
			if (none) {
				p.setPen(QPen(st::windowSubTextFg->c, 2));
				p.setBrush(Qt::NoBrush);
				p.drawEllipse(dot);
				p.drawLine(dot.bottomLeft(), dot.topRight());
			} else {
				p.setPen(Qt::NoPen);
				p.setBrush(QColor(cell.value));
				p.drawEllipse(dot);
			}
			if (selected) {
				p.setPen(QPen(st::windowFg->c, 2));
				p.setBrush(Qt::NoBrush);
				p.drawEllipse(cell.rect.adjusted(1, 1, -1, -1));
			}
		}
	}

	void mouseMoveEvent(QMouseEvent *e) override {
		const auto hovered = hitIcon(e->pos());
		const auto over = hovered || hitColor(e->pos()) >= 0;
		if (_hovered != hovered) {
			_hovered = hovered;
			update();
		}
		setCursor(over ? style::cur_pointer : style::cur_default);
	}

	void mousePressEvent(QMouseEvent *e) override {
		if (e->button() != Qt::LeftButton) {
			return;
		}
		if (const auto icon = hitIcon(e->pos())) {
			_iconPicked.fire_copy(_icons[icon - 1].value);
		} else if (const auto color = hitColor(e->pos()); color >= 0) {
			_colorPicked.fire_copy(_colors[color].value);
		}
	}

	void leaveEvent(QEvent *e) override {
		if (_hovered) {
			_hovered = 0;
			update();
		}
	}

private:
	struct Cell {
		QRect rect;
		QString value;
	};

	void layoutCells(int width) {
		_pad = st::boxRowPadding.left();
		const auto previewSize = st::boxRowPadding.left() * 2;
		_preview = QRect(_pad, _pad / 2, previewSize, previewSize);
		auto y = _preview.bottom() + _pad;

		const auto cell = previewSize * 9 / 10;
		const auto columns = std::max(1, (width - 2 * _pad) / cell);
		_icons.clear();
		auto index = 0;
		for (const auto icon : kPresetIcons) {
			const auto column = index % columns;
			const auto row = index / columns;
			_icons.push_back({
				QRect(_pad + column * cell, y + row * cell, cell, cell),
				QString::fromUtf8(icon),
			});
			++index;
		}
		y += ((index + columns - 1) / columns) * cell + _pad / 2;

		const auto swatch = cell * 4 / 5;
		const auto swatches = std::max(1, (width - 2 * _pad) / swatch);
		_colors.clear();
		_colors.push_back({ QRect(_pad, y, swatch, swatch), QString() });
		index = 1;
		for (const auto color : kPresetColors) {
			const auto column = index % swatches;
			const auto row = index / swatches;
			_colors.push_back({
				QRect(_pad + column * swatch, y + row * swatch, swatch, swatch),
				QString::fromLatin1(color),
			});
			++index;
		}
		y += ((index + swatches - 1) / swatches) * swatch + _pad / 2;
		_height = y;
	}

	[[nodiscard]] int hitIcon(QPoint point) const {
		for (auto i = 0, count = int(_icons.size()); i != count; ++i) {
			if (_icons[i].rect.contains(point)) {
				return i + 1;
			}
		}
		return 0;
	}
	[[nodiscard]] int hitColor(QPoint point) const {
		for (auto i = 0, count = int(_colors.size()); i != count; ++i) {
			if (_colors[i].rect.contains(point)) {
				return i;
			}
		}
		return -1;
	}

	QString _icon;
	QString _color;
	QString _title;
	int _pad = 0;
	int _height = 0;
	int _hovered = 0;
	QRect _preview;
	std::vector<Cell> _icons;
	std::vector<Cell> _colors;
	rpl::event_stream<QString> _iconPicked;
	rpl::event_stream<QString> _colorPicked;

};

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

void ShowLocalFolderChatsBox(
		not_null<Window::SessionController*> controller,
		FilterId id) {
	ShowChatsBox(controller, id);
}

void DeleteLocalFolder(
		not_null<Window::SessionController*> controller,
		FilterId id,
		Fn<void()> done) {
	const auto session = &controller->session();
	const auto folder = session->data().chatsFilters().local().find(id);
	if (!folder) {
		return;
	}
	controller->show(Ui::MakeConfirmBox({
		.text = tr::lng_zsg_folders_delete_sure(
			tr::now,
			lt_name,
			folder->title),
		.confirmed = [=](Fn<void()> close) {
			session->data().chatsFilters().local().remove(id);
			close();
			if (done) {
				done();
			}
		},
		.confirmText = tr::lng_box_delete(),
		.confirmStyle = &st::attentionBoxButton,
	}));
}

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

	const auto look = box->addRow(
		object_ptr<LookPicker>(
			box,
			existing ? existing->iconEmoji : QString(),
			existing ? existing->color : QString(),
			existing ? existing->title : QString()),
		style::margins());
	const auto icon = box->addRow(
		object_ptr<Ui::InputField>(
			box,
			st::windowFilterNameInput,
			Ui::InputField::Mode::SingleLine,
			tr::lng_zsg_folders_icon(),
			existing ? existing->iconEmoji : QString()),
		st::windowFilterNameInputPadding);
	icon->setMaxLength(kMaxIconLength);
	const auto color = box->addRow(
		object_ptr<Ui::InputField>(
			box,
			st::windowFilterNameInput,
			Ui::InputField::Mode::SingleLine,
			tr::lng_zsg_folders_color(),
			existing ? existing->color : QString()),
		st::windowFilterNameInputPadding);
	color->setMaxLength(9);

	const auto syncing = name->lifetime().make_state<bool>(false);
	name->changes() | rpl::on_next([=] {
		look->setTitle(name->getLastText().trimmed());
	}, name->lifetime());
	icon->changes() | rpl::on_next([=] {
		if (!*syncing) {
			look->setIcon(icon->getLastText().trimmed());
		}
	}, icon->lifetime());
	color->changes() | rpl::on_next([=] {
		if (*syncing) {
			return;
		}
		const auto text = color->getLastText().trimmed();
		const auto parsed = QColor(text);
		if (text.isEmpty()) {
			look->setColor(QString());
		} else if (parsed.isValid()) {
			look->setColor(parsed.name(QColor::HexRgb));
		}
	}, color->lifetime());
	look->iconPicked() | rpl::on_next([=](const QString &value) {
		*syncing = true;
		icon->setText(value);
		*syncing = false;
		look->setIcon(value);
	}, look->lifetime());
	look->colorPicked() | rpl::on_next([=](const QString &value) {
		*syncing = true;
		color->setText(value);
		*syncing = false;
		look->setColor(value);
	}, look->lifetime());

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
		const auto colorText = color->getLastText().trimmed();
		if (!colorText.isEmpty() && !QColor(colorText).isValid()) {
			color->showError();
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
		local.setIcon(target, icon->getLastText().trimmed());
		local.setColor(target, colorText);
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
		DeleteLocalFolder(controller, id, [=] { box->closeBox(); });
	});
}

/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "media/player/media_player_dropdown.h"

#include "base/invoke_queued.h"
#include "base/timer.h"
#include "lang/lang_keys.h"
#include "media/player/media_player_button.h"
#include "ui/cached_round_corners.h"
#include "ui/widgets/menu/menu.h"
#include "ui/widgets/menu/menu_action.h"
#include "ui/widgets/continuous_sliders.h"
#include "ui/widgets/dropdown_menu.h"
#include "ui/widgets/shadow.h"
#include "ui/painter.h"
#include "ui/ui_utility.h"
#include "styles/style_media_player.h"
#include "styles/style_widgets.h"

namespace Media::Player {
namespace {

constexpr auto kSpeedDebounceTimeout = crl::time(1000);
constexpr auto kStepperRepeatDelay = crl::time(400);
constexpr auto kStepperRepeatInterval = crl::time(80);

[[nodiscard]] float64 SpeedToSliderValue(float64 speed) {
	return (speed - kSpeedMin) / (kSpeedMax - kSpeedMin);
}

[[nodiscard]] float64 SliderValueToSpeed(float64 value) {
	const auto speed = value * (kSpeedMax - kSpeedMin) + kSpeedMin;
	return RoundSpeed(speed);
}

constexpr auto kSpeedStickedValues
	= std::array<std::pair<float64, float64>, 7>{{
		{ 0.8, 0.05 },
		{ 1.0, 0.05 },
		{ 1.2, 0.05 },
		{ 1.5, 0.05 },
		{ 1.7, 0.05 },
		{ 2.0, 0.05 },
		{ 2.2, 0.05 },
	}};

class SpeedSliderItem final : public Ui::Menu::ItemBase {
public:
	SpeedSliderItem(
		not_null<Ui::Menu::Menu*> parent,
		const style::MediaSpeedMenu &st,
		rpl::producer<float64> value);

	not_null<QAction*> action() const override;
	bool isEnabled() const override;

	[[nodiscard]] float64 current() const;
	[[nodiscard]] rpl::producer<float64> changing() const;
	[[nodiscard]] rpl::producer<float64> changed() const;
	[[nodiscard]] rpl::producer<float64> debouncedChanges() const;

protected:
	int contentHeight() const override;

private:
	void setExternalValue(float64 speed);
	void setSliderValue(float64 speed);

	const base::unique_qptr<Ui::MediaSlider> _slider;
	const not_null<QAction*> _dummyAction;
	const style::MediaSpeedMenu &_st;
	Ui::Text::String _text;
	int _height = 0;

	rpl::event_stream<float64> _changing;
	rpl::event_stream<float64> _changed;
	rpl::event_stream<float64> _debounced;
	base::Timer _debounceTimer;
	rpl::variable<float64> _last = 0.;

};

SpeedSliderItem::SpeedSliderItem(
	not_null<Ui::Menu::Menu*> parent,
	const style::MediaSpeedMenu &st,
	rpl::producer<float64> value)
: Ui::Menu::ItemBase(parent, st.dropdown.menu)
, _slider(base::make_unique_q<Ui::MediaSlider>(this, st.slider))
, _dummyAction(new QAction(parent))
, _st(st)
, _height(st.sliderPadding.top()
	+ st.dropdown.menu.itemStyle.font->height
	+ st.sliderPadding.bottom())
, _debounceTimer([=] { _debounced.fire(current()); }) {
	fitToMenuWidth();
	enableMouseSelecting();
	enableMouseSelecting(_slider.get());

	setPointerCursor(false);
	setMinWidth(st.sliderPadding.left()
		+ st.sliderWidth
		+ st.sliderPadding.right());
	_slider->setAlwaysDisplayMarker(true);

	sizeValue(
	) | rpl::on_next([=](const QSize &size) {
		const auto geometry = QRect(QPoint(), size);
		const auto padding = _st.sliderPadding;
		const auto inner = geometry - padding;
		_slider->setGeometry(
			padding.left(),
			inner.y(),
			(geometry.width() - padding.left() - padding.right()),
			inner.height());
	}, lifetime());

	paintRequest(
	) | rpl::on_next([=](const QRect &clip) {
		auto p = Painter(this);

		p.fillRect(clip, _st.dropdown.menu.itemBg);

		const auto left = (_st.sliderPadding.left() - _text.maxWidth()) / 2;
		const auto top = _st.dropdown.menu.itemPadding.top();
		p.setPen(_st.dropdown.menu.itemFg);
		_text.drawLeftElided(p, left, top, _text.maxWidth(), width());
	}, lifetime());

	_slider->setChangeProgressCallback([=](float64 value) {
		const auto speed = SliderValueToSpeed(value);
		if (!EqualSpeeds(current(), speed)) {
			_last = speed;
			_changing.fire_copy(speed);
			_debounceTimer.callOnce(kSpeedDebounceTimeout);
		}
	});

	_slider->setChangeFinishedCallback([=](float64 value) {
		const auto speed = SliderValueToSpeed(value);
		_last = speed;
		_changed.fire_copy(speed);
		_debounced.fire_copy(speed);
		_debounceTimer.cancel();
	});

	std::move(
		value
	) | rpl::on_next([=](float64 external) {
		setExternalValue(external);
	}, lifetime());

	_last.value(
	) | rpl::on_next([=](float64 value) {
		const auto text = QString::number(RoundSpeed(value)) + 'x';
		if (_text.toString() != text) {
			_text.setText(_st.sliderStyle, text);
			update();
		}
	}, lifetime());

	_slider->setAdjustCallback([=](float64 value) {
		const auto speed = SliderValueToSpeed(value);
		for (const auto &snap : kSpeedStickedValues) {
			if (speed > (snap.first - snap.second)
				&& speed < (snap.first + snap.second)) {
				return SpeedToSliderValue(snap.first);
			}
		}
		return value;
	});
}

class StepperItem final : public Ui::Menu::ItemBase {
public:
	StepperItem(
		not_null<Ui::Menu::Menu*> parent,
		const style::MediaSpeedMenu &st,
		MenuStepper &&descriptor);

	not_null<QAction*> action() const override;
	bool isEnabled() const override;

protected:
	int contentHeight() const override;
	void wheelEvent(QWheelEvent *e) override;

private:
	[[nodiscard]] not_null<Ui::AbstractButton*> makeButton(int direction);
	void startRepeat(int direction);
	void stopRepeat();
	void stepBy(int direction);
	void setValue(float64 value, bool notify);
	[[nodiscard]] float64 normalized(float64 value) const;

	const style::MediaSpeedMenu &_st;
	const not_null<QAction*> _dummyAction;
	MenuStepper _descriptor;
	Ui::Text::String _label;
	QString _valueText;
	float64 _value = 0.;
	int _height = 0;
	int _buttonSize = 0;
	int _valueWidth = 0;
	Ui::AbstractButton *_minus = nullptr;
	Ui::AbstractButton *_reset = nullptr;
	Ui::AbstractButton *_plus = nullptr;
	int _repeatDirection = 0;
	base::Timer _repeatDelayTimer;
	base::Timer _repeatTimer;

};

StepperItem::StepperItem(
	not_null<Ui::Menu::Menu*> parent,
	const style::MediaSpeedMenu &st,
	MenuStepper &&descriptor)
: Ui::Menu::ItemBase(parent, st.dropdown.menu)
, _st(st)
, _dummyAction(new QAction(parent))
, _descriptor(std::move(descriptor))
, _height(st.sliderPadding.top()
	+ st.dropdown.menu.itemStyle.font->height
	+ st.sliderPadding.bottom())
, _repeatDelayTimer([=] { _repeatTimer.callEach(kStepperRepeatInterval); })
, _repeatTimer([=] { stepBy(_repeatDirection); }) {
	fitToMenuWidth();
	enableMouseSelecting();
	setPointerCursor(false);

	_label.setText(_st.dropdown.menu.itemStyle, _descriptor.label);
	_buttonSize = _height - _st.sliderPadding.top();
	const auto &font = _st.sliderStyle.font;
	for (const auto value : {
			_descriptor.min,
			_descriptor.max,
			_descriptor.reset }) {
		_valueWidth = std::max(
			_valueWidth,
			font->width(_descriptor.format(value)));
	}
	_valueWidth += font->spacew * 4;

	_minus = makeButton(-1);
	_reset = Ui::CreateChild<Ui::AbstractButton>(this);
	_plus = makeButton(1);
	_reset->resize(_valueWidth, _buttonSize);
	_reset->setClickedCallback([=] {
		setValue(_descriptor.reset, true);
	});
	_reset->paintRequest(
	) | rpl::on_next([=] {
		auto p = QPainter(_reset);
		if (_reset->isOver()) {
			auto hq = PainterHighQualityEnabler(p);
			p.setPen(Qt::NoPen);
			p.setBrush(_st.dropdown.menu.itemBgOver);
			const auto radius = _buttonSize / 4.;
			p.drawRoundedRect(_reset->rect(), radius, radius);
		}
		p.setFont(font);
		p.setPen(_st.dropdown.menu.itemFg);
		p.drawText(_reset->rect(), _valueText, style::al_center);
	}, _reset->lifetime());
	enableMouseSelecting(_reset);

	const auto &padding = _st.dropdown.menu.itemPadding;
	setMinWidth(padding.left()
		+ _label.maxWidth()
		+ font->spacew * 4
		+ _buttonSize * 2
		+ _valueWidth
		+ _st.sliderPadding.right());

	sizeValue(
	) | rpl::on_next([=](QSize size) {
		const auto top = (size.height() - _buttonSize) / 2;
		auto right = size.width() - _st.sliderPadding.right();
		right -= _buttonSize;
		_plus->move(right, top);
		right -= _valueWidth;
		_reset->move(right, top);
		right -= _buttonSize;
		_minus->move(right, top);
	}, lifetime());

	paintRequest(
	) | rpl::on_next([=](const QRect &clip) {
		auto p = Painter(this);
		p.fillRect(clip, _st.dropdown.menu.itemBg);
		p.setPen(_st.dropdown.menu.itemFg);
		_label.drawLeftElided(
			p,
			_st.dropdown.menu.itemPadding.left(),
			(height() - _label.minHeight()) / 2,
			_minus->x() - _st.dropdown.menu.itemPadding.left(),
			width());
	}, lifetime());

	std::move(
		_descriptor.value
	) | rpl::on_next([=](float64 value) {
		setValue(value, false);
	}, lifetime());
}

not_null<Ui::AbstractButton*> StepperItem::makeButton(int direction) {
	const auto button = Ui::CreateChild<Ui::AbstractButton>(this);
	button->resize(_buttonSize, _buttonSize);
	button->paintRequest(
	) | rpl::on_next([=] {
		auto p = QPainter(button);
		auto hq = PainterHighQualityEnabler(p);
		const auto enabled = (direction < 0)
			? (_value > _descriptor.min + _descriptor.step / 2.)
			: (_value < _descriptor.max - _descriptor.step / 2.);
		if (enabled && button->isOver()) {
			p.setPen(Qt::NoPen);
			p.setBrush(_st.dropdown.menu.itemBgOver);
			p.drawEllipse(button->rect());
		}
		auto pen = QPen(enabled
			? _st.dropdown.menu.itemFg->c
			: _st.dropdown.menu.itemFgDisabled->c);
		pen.setWidthF(st::lineWidth * 1.5);
		pen.setCapStyle(Qt::RoundCap);
		p.setPen(pen);
		const auto center = QRectF(button->rect()).center();
		const auto half = _buttonSize / 5.;
		p.drawLine(
			center - QPointF(half, 0.),
			center + QPointF(half, 0.));
		if (direction > 0) {
			p.drawLine(
				center - QPointF(0., half),
				center + QPointF(0., half));
		}
	}, button->lifetime());
	button->events(
	) | rpl::on_next([=](not_null<QEvent*> e) {
		const auto type = e->type();
		if (type == QEvent::MouseButtonPress
			&& static_cast<QMouseEvent*>(e.get())->button() == Qt::LeftButton) {
			startRepeat(direction);
		} else if (type == QEvent::MouseButtonRelease
			|| type == QEvent::Hide) {
			stopRepeat();
		}
	}, button->lifetime());
	enableMouseSelecting(button);
	return button;
}

void StepperItem::startRepeat(int direction) {
	_repeatDirection = direction;
	stepBy(direction);
	_repeatTimer.cancel();
	_repeatDelayTimer.callOnce(kStepperRepeatDelay);
}

void StepperItem::stopRepeat() {
	_repeatDelayTimer.cancel();
	_repeatTimer.cancel();
}

void StepperItem::stepBy(int direction) {
	if (direction) {
		setValue(_value + direction * _descriptor.step, true);
	}
}

float64 StepperItem::normalized(float64 value) const {
	const auto step = _descriptor.step;
	return std::clamp(
		base::SafeRound(value / step) * step,
		_descriptor.min,
		_descriptor.max);
}

void StepperItem::setValue(float64 value, bool notify) {
	value = normalized(value);
	const auto changed = (base::SafeRound(value / _descriptor.step)
		!= base::SafeRound(_value / _descriptor.step));
	_value = value;
	const auto text = _descriptor.format(value);
	if (_valueText != text) {
		_valueText = text;
		_reset->update();
	}
	_minus->update();
	_plus->update();
	if (notify && changed) {
		_descriptor.change(value);
	}
}

void StepperItem::wheelEvent(QWheelEvent *e) {
	const auto delta = e->angleDelta().y();
	if (delta) {
		stepBy(delta > 0 ? 1 : -1);
	}
	e->accept();
}

not_null<QAction*> StepperItem::action() const {
	return _dummyAction;
}

bool StepperItem::isEnabled() const {
	return false;
}

int StepperItem::contentHeight() const {
	return _height;
}

void FillSpeedMenu(
		not_null<Ui::Menu::Menu*> menu,
		const style::MediaSpeedMenu &st,
		rpl::producer<float64> value,
		Fn<void(float64)> callback,
		bool onlySlider) {
	auto slider = base::make_unique_q<SpeedSliderItem>(
		menu,
		st,
		rpl::duplicate(value));

	slider->debouncedChanges(
	) | rpl::on_next(callback, slider->lifetime());

	struct State {
		rpl::variable<float64> realtime;
	};
	const auto state = slider->lifetime().make_state<State>();
	state->realtime = rpl::single(
		slider->current()
	) | rpl::then(rpl::merge(
		slider->changing(),
		slider->changed()
	));

	menu->addAction(std::move(slider));

	menu->addAction(base::make_unique_q<StepperItem>(menu, st, MenuStepper{
		.label = tr::lng_zasto_media_speed(tr::now),
		.min = kSpeedMin,
		.max = kSpeedMax,
		.step = kSpeedStep,
		.reset = 1.,
		.format = [](float64 value) {
			return QString::number(RoundSpeed(value)) + 'x';
		},
		.value = state->realtime.value(),
		.change = callback,
	}));

	if (onlySlider) {
		return;
	}

	menu->addSeparator(&st.dropdown.menu.separator);

	struct SpeedPoint {
		float64 speed = 0.;
		tr::phrase<> text;
		const style::icon &icon;
		const style::icon &iconActive;
	};
	const auto points = std::vector<SpeedPoint>{
		{
			0.5,
			tr::lng_voice_speed_slow,
			st.slow,
			st.slowActive },
		{
			1.0,
			tr::lng_voice_speed_normal,
			st.normal,
			st.normalActive },
		{
			1.2,
			tr::lng_voice_speed_medium,
			st.medium,
			st.mediumActive },
		{
			1.5,
			tr::lng_voice_speed_fast,
			st.fast,
			st.fastActive },
		{
			1.7,
			tr::lng_voice_speed_very_fast,
			st.veryFast,
			st.veryFastActive },
		{
			2.0,
			tr::lng_voice_speed_super_fast,
			st.superFast,
			st.superFastActive },
	};
	for (const auto &point : points) {
		const auto speed = point.speed;
		const auto text = point.text(tr::now);
		const auto icon = &point.icon;
		const auto iconActive = &point.iconActive;
		auto action = base::make_unique_q<Ui::Menu::Action>(
			menu,
			st.dropdown.menu,
			Ui::Menu::CreateAction(menu, text, [=] { callback(speed); }),
			&point.icon,
			&point.icon);
		const auto raw = action.get();
		const auto check = Ui::CreateChild<Ui::RpWidget>(raw);
		check->resize(st.activeCheck.size());
		check->paintRequest(
		) | rpl::on_next([check, icon = &st.activeCheck] {
			auto p = QPainter(check);
			icon->paint(p, 0, 0, check->width());
		}, check->lifetime());
		raw->sizeValue(
		) | rpl::on_next([=, skip = st.activeCheckSkip](QSize size) {
			check->moveToRight(
				skip,
				(size.height() - check->height()) / 2,
				size.width());
		}, check->lifetime());
		check->setAttribute(Qt::WA_TransparentForMouseEvents);
		state->realtime.value(
		) | rpl::on_next([=](float64 now) {
			const auto chosen = EqualSpeeds(speed, now);
			const auto overriden = chosen ? iconActive : icon;
			raw->setIcon(overriden, overriden);
			raw->action()->setEnabled(!chosen);
			check->setVisible(chosen);
		}, raw->lifetime());
		menu->addAction(std::move(action));
	}
}

void SpeedSliderItem::setExternalValue(float64 speed) {
	if (!_slider->isChanging()) {
		setSliderValue(speed);
	}
}

void SpeedSliderItem::setSliderValue(float64 speed) {
	const auto value = SpeedToSliderValue(speed);
	_slider->setValue(value);
	_last = speed;
	_changed.fire_copy(speed);
}

not_null<QAction*> SpeedSliderItem::action() const {
	return _dummyAction;
}

bool SpeedSliderItem::isEnabled() const {
	return false;
}

int SpeedSliderItem::contentHeight() const {
	return _height;
}

float64 SpeedSliderItem::current() const {
	return _last.current();
}

rpl::producer<float64> SpeedSliderItem::changing() const {
	return _changing.events();
}

rpl::producer<float64> SpeedSliderItem::changed() const {
	return _changed.events();
}

rpl::producer<float64> SpeedSliderItem::debouncedChanges() const {
	return _debounced.events();
}

} // namespace

void AddMenuStepper(
		not_null<Ui::Menu::Menu*> menu,
		const style::MediaSpeedMenu &st,
		MenuStepper &&descriptor) {
	menu->addAction(base::make_unique_q<StepperItem>(
		menu,
		st,
		std::move(descriptor)));
}

Dropdown::Dropdown(QWidget *parent)
: RpWidget(parent)
, _hideTimer([=] { startHide(); })
, _showTimer([=] { startShow(); }) {
	hide();

	macWindowDeactivateEvents(
	) | rpl::filter([=] {
		return !isHidden();
	}) | rpl::on_next([=] {
		leaveEvent(nullptr);
	}, lifetime());

	hide();
	auto margin = getMargin();
	resize(margin.left() + st::mediaPlayerVolumeSize.width() + margin.right(), margin.top() + st::mediaPlayerVolumeSize.height() + margin.bottom());
}

QMargins Dropdown::getMargin() const {
	const auto top1 = st::mediaPlayerHeight
		+ st::lineWidth
		- st::mediaPlayerPlayTop
		- st::mediaPlayerVolumeToggle.height;
	const auto top2 = st::mediaPlayerPlayback.fullWidth;
	const auto top = std::max(top1, top2);
	return QMargins(st::mediaPlayerVolumeMargin, top, st::mediaPlayerVolumeMargin, st::mediaPlayerVolumeMargin);
}

bool Dropdown::overlaps(const QRect &globalRect) {
	if (isHidden() || _a_appearance.animating()) return false;

	return rect().marginsRemoved(getMargin()).contains(QRect(mapFromGlobal(globalRect.topLeft()), globalRect.size()));
}

void Dropdown::hideFast() {
	_showTimer.cancel();
	_hideTimer.cancel();
	if (!isHidden()) {
		_hiding = false;
		_a_appearance.stop();
		hidingFinished();
	}
}

void Dropdown::paintEvent(QPaintEvent *e) {
	auto p = QPainter(this);

	if (!_cache.isNull()) {
		bool animating = _a_appearance.animating();
		if (animating) {
			p.setOpacity(_a_appearance.value(_hiding ? 0. : 1.));
		} else if (_hiding || isHidden()) {
			hidingFinished();
			return;
		}
		p.drawPixmap(0, 0, _cache);
		if (!animating) {
			showChildren();
			_cache = QPixmap();
		}
		return;
	}

	// draw shadow
	auto shadowedRect = rect().marginsRemoved(getMargin());
	auto shadowedSides = RectPart::Left | RectPart::Right | RectPart::Bottom;
	Ui::Shadow::paint(p, shadowedRect, width(), st::roundShadowRadius8px, shadowedSides);
	const auto &corners = Ui::CachedCornerPixmaps(Ui::MenuCorners);
	const auto fill = Ui::CornersPixmaps{
		.p = { QPixmap(), QPixmap(), corners.p[2], corners.p[3] },
	};
	Ui::FillRoundRect(
		p,
		shadowedRect.x(),
		0,
		shadowedRect.width(),
		shadowedRect.y() + shadowedRect.height(),
		st::menuBg,
		fill);
}

void Dropdown::enterEventHook(QEnterEvent *e) {
	_hideTimer.cancel();
	if (_a_appearance.animating()) {
		startShow();
	} else {
		_showTimer.callOnce(0);
	}
	return RpWidget::enterEventHook(e);
}

void Dropdown::leaveEventHook(QEvent *e) {
	_showTimer.cancel();
	if (_a_appearance.animating()) {
		startHide();
	} else {
		_hideTimer.callOnce(300);
	}
	return RpWidget::leaveEventHook(e);
}

void Dropdown::otherEnter() {
	_hideTimer.cancel();
	if (_a_appearance.animating()) {
		startShow();
	} else {
		_showTimer.callOnce(0);
	}
}

void Dropdown::otherLeave() {
	_showTimer.cancel();
	if (_a_appearance.animating()) {
		startHide();
	} else {
		_hideTimer.callOnce(0);
	}
}

void Dropdown::startShow() {
	if (isHidden()) {
		show();
	} else if (!_hiding) {
		return;
	}
	_hiding = false;
	startAnimation();
}

void Dropdown::startHide() {
	if (_hiding) {
		return;
	}

	_hiding = true;
	startAnimation();
}

void Dropdown::startAnimation() {
	if (_cache.isNull()) {
		showChildren();
		_cache = Ui::GrabWidget(this);
	}
	hideChildren();
	_a_appearance.start(
		[=] { appearanceCallback(); },
		_hiding ? 1. : 0.,
		_hiding ? 0. : 1.,
		st::defaultInnerDropdown.duration);
}

void Dropdown::appearanceCallback() {
	if (!_a_appearance.animating() && _hiding) {
		_hiding = false;
		hidingFinished();
	} else {
		update();
	}
}

void Dropdown::hidingFinished() {
	hide();
	_cache = QPixmap();
}

bool Dropdown::eventFilter(QObject *obj, QEvent *e) {
	if (e->type() == QEvent::Enter) {
		otherEnter();
	} else if (e->type() == QEvent::Leave) {
		otherLeave();
	}
	return false;
}

WithDropdownController::WithDropdownController(
	not_null<Ui::AbstractButton*> button,
	not_null<QWidget*> menuParent,
	const style::DropdownMenu &menuSt,
	Qt::Alignment menuAlign,
	QPoint menuPosition,
	Fn<void(bool)> menuOverCallback)
: _button(button)
, _menuParent(menuParent)
, _menuSt(menuSt)
, _menuAlign(menuAlign)
, _menuPosition(menuPosition)
, _menuOverCallback(std::move(menuOverCallback)) {
	button->events(
	) | rpl::filter([=](not_null<QEvent*> e) {
		return (e->type() == QEvent::Enter)
			|| (e->type() == QEvent::Leave);
	}) | rpl::on_next([=](not_null<QEvent*> e) {
		_overButton = (e->type() == QEvent::Enter);
		if (_overButton) {
			InvokeQueued(button, [=] {
				if (_overButton) {
					showMenu();
				}
			});
		}
	}, button->lifetime());
}

not_null<Ui::AbstractButton*> WithDropdownController::button() const {
	return _button;
}

Ui::DropdownMenu *WithDropdownController::menu() const {
	return _menu.get();
}

void WithDropdownController::updateDropdownGeometry() {
	if (!_menu) {
		return;
	}
	const auto bwidth = _button->width();
	const auto bheight = _button->height();
	const auto mwidth = _menu->width();
	const auto mheight = _menu->height();
	const auto padding = _menuSt.wrap.padding;
	const auto x = _menuPosition.x();
	const auto y = _menuPosition.y();
	const auto position = _menu->parentWidget()->mapFromGlobal(
		_button->mapToGlobal(QPoint())
	) + [&] {
		switch (_menuAlign) {
		case style::al_topleft: return QPoint(
			-padding.left() - x,
			bheight - padding.top() + y);
		case style::al_topright: return QPoint(
			bwidth - mwidth + padding.right() + x,
			bheight - padding.top() + y);
		case style::al_bottomright: return QPoint(
			bwidth - mwidth + padding.right() + x,
			-mheight + padding.bottom() - y);
		case style::al_bottomleft: return QPoint(
			-padding.left() - x,
			-mheight + padding.bottom() - y);
		}
		Unexpected("Menu align value.");
	}();
	_menu->move(position);
}

rpl::producer<bool> WithDropdownController::menuToggledValue() const {
	return _menuToggled.value();
}

void WithDropdownController::hideTemporarily() {
	if (_menu && !_menu->isHidden()) {
		_temporarilyHidden = true;
		_menu->hide();
	}
}

void WithDropdownController::showBack() {
	if (_temporarilyHidden) {
		_temporarilyHidden = false;
		if (_menu && _menu->isHidden()) {
			_menu->show();
		}
	}
}

void WithDropdownController::setOtherDropdownCheck(
		Fn<bool(QPoint globalPosition)> check) {
	_otherDropdownCheck = std::move(check);
}

void WithDropdownController::showMenu() {
	if (_menu) {
		return;
	}
	_menu.emplace(_menuParent, _menuSt);
	const auto raw = _menu.get();
	_menu->events(
	) | rpl::on_next([this](not_null<QEvent*> e) {
		const auto type = e->type();
		if (type == QEvent::Enter) {
			_menuOverCallback(true);
		} else if (type == QEvent::Leave) {
			_menuOverCallback(false);
		} else if (type == QEvent::MouseMove) {
			const auto mouse = static_cast<QMouseEvent*>(e.get());
			handleMenuMove(mouse->globalPos());
		}
	}, _menu->lifetime());
	_menu->setHiddenCallback([=]{
		if (_menu.get() == raw) {
			_menuToggled = false;
		}
		Ui::PostponeCall(raw, [this] {
			_menu = nullptr;
			_menuToggled = false;
		});
	});
	_menu->setShowStartCallback([=] {
		_menuToggled = true;
	});
	_menu->setHideStartCallback([=] {
		_menuToggled = false;
	});
	_button->installEventFilter(raw);
	fillMenu(raw);
	updateDropdownGeometry();
	const auto origin = [&] {
		using Origin = Ui::PanelAnimation::Origin;
		switch (_menuAlign) {
		case style::al_topleft: return Origin::TopLeft;
		case style::al_topright: return Origin::TopRight;
		case style::al_bottomright: return Origin::BottomRight;
		case style::al_bottomleft: return Origin::BottomLeft;
		}
		Unexpected("Menu align value.");
	}();
	_menu->showAnimated(origin);
	_menuToggled = true;
}

void WithDropdownController::handleMenuMove(QPoint globalPosition) {
	if (!_menu || !_otherDropdownCheck) {
		return;
	}
	const auto local = _button->mapFromGlobal(globalPosition);
	if (_button->rect().contains(local)
		|| !_otherDropdownCheck(globalPosition)) {
		return;
	}
	_menu->hideFast();
}

OrderController::OrderController(
	not_null<Ui::IconButton*> button,
	not_null<QWidget*> menuParent,
	Fn<void(bool)> menuOverCallback,
	rpl::producer<OrderMode> value,
	Fn<void(OrderMode)> change)
: WithDropdownController(
	button,
	menuParent,
	st::mediaPlayerMenu,
	style::al_topright,
	st::mediaPlayerMenuPosition,
	std::move(menuOverCallback))
, _button(button)
, _appOrder(std::move(value))
, _change(std::move(change)) {
	button->setClickedCallback([=] {
		showMenu();
	});

	_appOrder.value(
	) | rpl::on_next([=] {
		updateIcon();
	}, button->lifetime());
}

void OrderController::fillMenu(not_null<Ui::DropdownMenu*> menu) {
	const auto addOrderAction = [&](OrderMode mode) {
		struct Fields {
			QString label;
			const style::icon &icon;
			const style::icon &activeIcon;
		};
		const auto active = (_appOrder.current() == mode);
		const auto callback = [change = _change, mode, active] {
			change(active ? OrderMode::Default : mode);
		};
		const auto fields = [&]() -> Fields {
			switch (mode) {
			case OrderMode::Reverse: return {
				.label = tr::lng_audio_player_reverse(tr::now),
				.icon = st::mediaPlayerOrderIconReverse,
				.activeIcon = st::mediaPlayerOrderIconReverseActive,
			};
			case OrderMode::Shuffle: return {
				.label = tr::lng_audio_player_shuffle(tr::now),
				.icon = st::mediaPlayerOrderIconShuffle,
				.activeIcon = st::mediaPlayerOrderIconShuffleActive,
			};
			}
			Unexpected("Order mode in addOrderAction.");
		}();
		menu->addAction(base::make_unique_q<Ui::Menu::Action>(
			menu->menu(),
			(active
				? st::mediaPlayerOrderMenuActive
				: st::mediaPlayerOrderMenu),
			Ui::Menu::CreateAction(menu, fields.label, callback),
			&(active ? fields.activeIcon : fields.icon),
			&(active ? fields.activeIcon : fields.icon)));
	};
	addOrderAction(OrderMode::Reverse);
	addOrderAction(OrderMode::Shuffle);
}

void OrderController::updateIcon() {
	switch (_appOrder.current()) {
	case OrderMode::Default:
		_button->setIconOverride(
			&st::mediaPlayerReverseDisabledIcon,
			&st::mediaPlayerReverseDisabledIconOver);
		_button->setRippleColorOverride(
			&st::mediaPlayerRepeatDisabledRippleBg);
		break;
	case OrderMode::Reverse:
		_button->setIconOverride(&st::mediaPlayerReverseIcon);
		_button->setRippleColorOverride(nullptr);
		break;
	case OrderMode::Shuffle:
		_button->setIconOverride(&st::mediaPlayerShuffleIcon);
		_button->setRippleColorOverride(nullptr);
		break;
	}
}

SpeedController::SpeedController(
	not_null<Ui::AbstractButton*> button,
	const style::MediaSpeedButton &st,
	not_null<QWidget*> menuParent,
	Fn<void(bool)> menuOverCallback,
	Fn<float64(bool lastNonDefault)> value,
	Fn<void(float64)> change,
	std::vector<VideoQuality> qualities,
	Fn<VideoQuality()> quality,
	Fn<void(VideoQuality)> changeQuality)
: WithDropdownController(
	button,
	menuParent,
	st.menu.dropdown,
	st.menuAlign,
	st.menuPosition,
	std::move(menuOverCallback))
, _st(st)
, _lookup(std::move(value))
, _change(std::move(change))
, _qualities(std::move(qualities))
, _lookupQuality(std::move(quality))
, _changeQuality(std::move(changeQuality)) {
	Expects(_qualities.empty() || (_lookupQuality && _changeQuality));

	button->setClickedCallback([=] {
		if (_lookup && !_lookupQuality && !_changeQuality) {
			toggleDefault();
			save();
			if (const auto current = menu()) {
				current->otherEnter();
			}
		} else {
			showMenu();
		}
	});
	if (const auto lookup = _lookup) {
		setSpeed(lookup(false));
		_speed = lookup(true);
	}
}

rpl::producer<> SpeedController::saved() const {
	return _saved.events();
}

rpl::producer<float64> SpeedController::realtimeValue() const {
	return _speedChanged.events_starting_with(speed());
}

void SpeedController::reloadFromLookup() {
	if (const auto lookup = _lookup) {
		setSpeed(lookup(false));
		_speed = lookup(true);
	}
}

void SpeedController::setQualities(std::vector<VideoQuality> qualities) {
	_qualities = std::move(qualities);
}

void SpeedController::setExtraMenuFiller(Fn<void(
		not_null<Ui::Menu::Menu*>,
		const style::MediaSpeedMenu &)> filler) {
	_extraMenuFiller = std::move(filler);
}

float64 SpeedController::speed() const {
	return _isDefault ? 1. : _speed;
}

bool SpeedController::isDefault() const {
	return _isDefault;
}

float64 SpeedController::lastNonDefaultSpeed() const {
	return _speed;
}

void SpeedController::toggleDefault() {
	_isDefault = !_isDefault;
	_speedChanged.fire(speed());
}

void SpeedController::setSpeed(float64 newSpeed) {
	if (!(_isDefault = EqualSpeeds(newSpeed, 1.))) {
		_speed = newSpeed;
	}
	_speedChanged.fire(speed());
}

void SpeedController::save() {
	if (const auto change = _change) {
		change(speed());
	}
	_saved.fire({});
}

void SpeedController::setQuality(VideoQuality quality) {
	_quality = quality;
	_changeQuality(quality);
}

void SpeedController::fillMenu(not_null<Ui::DropdownMenu*> menu) {
	if (_lookup) {
		FillSpeedMenu(
			menu->menu(),
			_st.menu,
			_speedChanged.events_starting_with(speed()),
			[=](float64 speed) { setSpeed(speed); save(); },
			!_qualities.empty());
	}
	if (const auto filler = _extraMenuFiller) {
		const auto raw = menu->menu();
		if (_lookup) {
			raw->addSeparator(&_st.menu.dropdown.menu.separator);
		}
		filler(raw, _st.menu);
	}
	if (_qualities.empty()) {
		return;
	}
	_quality = _lookupQuality();
	const auto raw = menu->menu();
	const auto &st = _st.menu;
	if (_lookup) {
		raw->addSeparator(&st.dropdown.menu.separator);
	}

	const auto add = [&](VideoQuality quality) {
		const auto automatic = tr::lng_mediaview_quality_auto(tr::now);
		const auto text = (!quality.height && !quality.original)
			? automatic
			: quality.original
			? tr::lng_mediaview_quality_original(
				tr::now,
				lt_quality,
				QString::number(quality.height))
			: u"%1p"_q.arg(quality.height);
		auto action = base::make_unique_q<Ui::Menu::Action>(
			raw,
			st.qualityMenu,
			Ui::Menu::CreateAction(
				raw,
				text,
				[=] { _changeQuality(quality); }),
			nullptr,
			nullptr);
		const auto rawAction = action.get();
		const auto check = Ui::CreateChild<Ui::RpWidget>(rawAction);
		check->resize(st.activeCheck.size());
		check->paintRequest(
		) | rpl::on_next([check, icon = &st.activeCheck] {
			auto p = QPainter(check);
			icon->paint(p, 0, 0, check->width());
		}, check->lifetime());
		rawAction->sizeValue(
		) | rpl::on_next([=, skip = st.activeCheckSkip](QSize size) {
			check->moveToRight(
				skip,
				(size.height() - check->height()) / 2,
				size.width());
		}, check->lifetime());
		check->setAttribute(Qt::WA_TransparentForMouseEvents);
		_quality.value(
		) | rpl::on_next([=](VideoQuality now) {
			const auto chosen = now.manual
				? (now == quality)
				: (!quality.height && !quality.original);
			rawAction->action()->setEnabled(!chosen);
			if (!quality.height && !quality.original) {
				const auto suffix = now.manual
					? QString()
					: u"\t%1p"_q.arg(now.height);
				rawAction->action()->setText(automatic + suffix);
			}
			check->setVisible(chosen);
		}, rawAction->lifetime());
		menu->addAction(std::move(action));
	};

	add(VideoQuality());
	for (const auto &quality : _qualities) {
		add(quality);
	}
}

} // namespace Media::Player

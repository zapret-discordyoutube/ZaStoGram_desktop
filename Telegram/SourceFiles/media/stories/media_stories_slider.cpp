/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "media/stories/media_stories_slider.h"

#include "media/stories/media_stories_controller.h"
#include "media/view/media_view_playback_progress.h"
#include "media/audio/media_audio.h"
#include "ui/painter.h"
#include "ui/rp_widget.h"
#include "styles/style_widgets.h"
#include "styles/style_media_view.h"

#include <QtGui/QMouseEvent>

namespace Media::Stories {
namespace {

constexpr auto kOpacityInactive = 0.4;
constexpr auto kOpacityActive = 1.;

} // namespace

Slider::Slider(not_null<Controller*> controller)
: _controller(controller)
, _progress(std::make_unique<View::PlaybackProgress>()) {
}

Slider::~Slider() {
}

void Slider::show(SliderData data) {
	resetProgress();
	data.total = std::max(data.total, 1);
	data.index = std::clamp(data.index, 0, data.total - 1);

	if (_data == data) {
		return;
	}
	_data = data;

	const auto parent = _controller->wrap();
	auto widget = std::make_unique<Ui::RpWidget>(parent);
	const auto raw = widget.get();

	_rects.resize(_data.total);

	raw->widthValue() | rpl::filter([=](int width) {
		return (width >= st::storiesSliderWidth);
	}) | rpl::on_next([=](int width) {
		layout(width);
	}, raw->lifetime());

	raw->paintRequest(
	) | rpl::filter([=] {
		return !_data.videoStream
			&& (raw->width() >= st::storiesSliderWidth);
	}) | rpl::on_next([=](QRect clip) {
		paint(QRectF(clip));
	}, raw->lifetime());

	raw->events(
	) | rpl::on_next([=](not_null<QEvent*> event) {
		if (_data.videoStream) {
			return;
		}
		const auto type = event->type();
		if (type == QEvent::MouseButtonPress) {
			const auto mouse = static_cast<QMouseEvent*>(event.get());
			if (mouse->button() == Qt::LeftButton) {
				_seeking = true;
				handleSeekProgress(mouse->pos());
			}
		} else if (type == QEvent::MouseMove) {
			if (_seeking) {
				const auto mouse = static_cast<QMouseEvent*>(event.get());
				handleSeekProgress(mouse->pos());
			}
		} else if (type == QEvent::MouseButtonRelease) {
			const auto mouse = static_cast<QMouseEvent*>(event.get());
			if (_seeking && mouse->button() == Qt::LeftButton) {
				handleSeekFinished(mouse->pos());
			}
		}
	}, raw->lifetime());

	raw->show();
	_widget = std::move(widget);

	_progress->setValueChangedCallback([=](float64, float64) {
		_widget->update(_activeBoundingRect);
	});

	_controller->layoutValue(
	) | rpl::on_next([=](const Layout &layout) {
		raw->setGeometry(layout.slider - st::storiesSliderMargin);
	}, raw->lifetime());
}

void Slider::raise() {
	if (_widget) {
		_widget->raise();
	}
}

void Slider::updatePlayback(const Player::TrackState &state) {
	_progress->updateState(state);
}

void Slider::resetProgress() {
	_progress->updateState({});
}

void Slider::layout(int width) {
	const auto single = st::storiesSliderWidth;
	const auto skip = st::storiesSliderSkip;
	// width == single * max + skip * (max - 1);
	// max == (width + skip) / (single + skip);
	const auto max = (width + skip) / (single + skip);
	Assert(max > 0);
	const auto count = std::clamp(_data.total, 1, max);
	const auto one = (width - (count - 1) * skip) / float64(count);
	auto left = 0.;
	for (auto i = 0; i != count; ++i) {
		_rects[i] = QRectF(left, 0, one, single);
		if (i == _data.index) {
			const auto from = int(std::floor(left));
			const auto size = int(std::ceil(left + one)) - from;
			_activeBoundingRect = QRect(from, 0, size, single);
		}
		left += one + skip;
	}
	for (auto i = count; i != _rects.size(); ++i) {
		_rects[i] = QRectF();
	}
}

std::optional<float64> Slider::progressAt(QPoint position) const {
	if (_activeBoundingRect.isEmpty()) {
		return std::nullopt;
	}
	const auto width = _activeBoundingRect.width();
	if (width <= 0) {
		return std::nullopt;
	}
	return std::clamp(
		(position.x() - _activeBoundingRect.x()) / float64(width),
		0.,
		1.);
}

void Slider::handleSeekProgress(QPoint position) {
	if (const auto progress = progressAt(position)) {
		_progress->setValue(*progress, false);
		_controller->sliderSeekProgress(*progress);
	}
}

void Slider::handleSeekFinished(QPoint position) {
	const auto progress = progressAt(position);
	_seeking = false;
	if (progress) {
		_progress->setValue(*progress, false);
		_controller->sliderSeekFinished(*progress);
	}
}

void Slider::paint(QRectF clip) {
	auto p = QPainter(_widget.get());
	auto hq = PainterHighQualityEnabler(p);

	p.setBrush(st::mediaviewControlFg);
	p.setPen(Qt::NoPen);
	const auto radius = st::storiesSliderWidth / 2.;
	for (auto i = 0; i != int(_rects.size()); ++i) {
		if (_rects[i].isEmpty()) {
			break;
		} else if (!_rects[i].intersects(clip)) {
			continue;
		} else if (i == _data.index) {
			const auto progress = _progress->value();
			const auto full = _rects[i].width();
			const auto height = _rects[i].height();
			const auto min = height;
			const auto activeWidth = std::max(full * progress, min);
			const auto inactiveWidth = full - activeWidth + min;
			const auto activeLeft = _rects[i].left();
			const auto inactiveLeft = activeLeft + activeWidth - min;
			p.setOpacity(kOpacityInactive);
			p.drawRoundedRect(
				QRectF(inactiveLeft, 0, inactiveWidth, height),
				radius,
				radius);
			if (activeWidth > 0.) {
				p.setOpacity(kOpacityActive);
				p.drawRoundedRect(
					QRectF(activeLeft, 0, activeWidth, height),
					radius,
					radius);
			}
		} else {
			p.setOpacity((i < _data.index)
				? kOpacityActive
				: kOpacityInactive);
			p.drawRoundedRect(_rects[i], radius, radius);
		}
	}
}

} // namespace Media::Stories

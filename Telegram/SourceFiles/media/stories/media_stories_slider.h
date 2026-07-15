/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include <optional>

namespace Ui {
class RpWidget;
} // namespace Ui

namespace Media::View {
class PlaybackProgress;
} // namespace Media::View

namespace Media::Player {
struct TrackState;
} // namespace Media::Player

namespace Media::Stories {

class Controller;

struct SliderData {
	int index = 0;
	int total = 0;
	bool videoStream = false;

	friend inline auto operator<=>(SliderData, SliderData) = default;
	friend inline bool operator==(SliderData, SliderData) = default;
};

class Slider final {
public:
	explicit Slider(not_null<Controller*> controller);
	~Slider();

	void show(SliderData data);
	void raise();

	void updatePlayback(const Player::TrackState &state);

private:
	class Widget;

	void resetProgress();

	void layout(int width);
	[[nodiscard]] std::optional<float64> progressAt(QPoint position) const;
	[[nodiscard]] bool seekAvailable() const;
	void handleSeekStart(QPoint position);
	void handleSeekProgress(QPoint position);
	void handleSeekFinished(QPoint position);
	void paint(QRectF clip);

	const not_null<Controller*> _controller;
	const std::unique_ptr<Media::View::PlaybackProgress> _progress;

	std::unique_ptr<Ui::RpWidget> _widget;
	std::vector<QRectF> _rects;
	QRect _activeBoundingRect;

	SliderData _data;
	bool _seeking = false;


};

} // namespace Media::Stories

/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information see the local LEGAL file.
*/
#pragma once

#include "base/event_filter.h"
#include "rpl/lifetime.h"

#include <QtWidgets/QWidget>

namespace Ui {

// ZaStoGram: a transparent window over the client area of the main window
// that hosts the GPU surface of the message deletion effect (Thanos).
//
// Why it exists: a QRhiWidget added to a window that is already shown makes Qt
// switch that window to GPU composition by destroying and recreating its native
// handle (QWidgetPrivate::recreate). For the main window this is harmful twice:
// Platform::MainWindow takes the WM_DESTROY for a close and quits the app, and
// it caches the handle (psHwnd, frame, shadows, taskbar state), so a window that
// survived would be half dead. Switching the whole chat window to GPU
// composition also makes every frame wait for vsync (animations fall to
// ~30 fps on 60 Hz), see lib_ui 6d6e1f0.
//
// The overlay is created hidden and gets its GPU child before its own native
// window exists, so Qt creates it already configured and recreates nothing.
// It is owned by the main window (Qt::Tool with a parent), so Windows keeps it
// right above the main window and hides it together with it. It never takes
// focus or input.
class ThanosOverlay final : public QWidget {
public:
	explicit ThanosOverlay(not_null<QWidget*> parent);

	// Matches the client area of the parent and shows the overlay.
	void present();
	void dismiss();

private:
	void syncGeometry();

	const not_null<QWidget*> _parent;
	rpl::lifetime _lifetime;

};

} // namespace Ui

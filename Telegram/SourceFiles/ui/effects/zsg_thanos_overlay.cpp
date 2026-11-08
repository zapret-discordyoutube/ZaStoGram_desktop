/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information see the local LEGAL file.
*/
#include "ui/effects/zsg_thanos_overlay.h"

#include "core/zsg_diag.h"

#include <QtGui/QWindow>

#ifdef Q_OS_WIN
#include <windows.h>
#endif // Q_OS_WIN

namespace Ui {

ThanosOverlay::ThanosOverlay(not_null<QWidget*> parent)
: QWidget(
	nullptr, // No Qt parent, see the header.
	Qt::Tool
		| Qt::FramelessWindowHint
		| Qt::NoDropShadowWindowHint
		| Qt::WindowDoesNotAcceptFocus
		| Qt::WindowTransparentForInput)
, _parent(parent) {
	setAttribute(Qt::WA_TranslucentBackground);
	setAttribute(Qt::WA_NoSystemBackground);
	setAttribute(Qt::WA_ShowWithoutActivating);
	setAttribute(Qt::WA_TransparentForMouseEvents);
	setAttribute(Qt::WA_QuitOnClose, false);
	setFocusPolicy(Qt::NoFocus);

	// The parent moves and resizes without telling us otherwise.
	base::install_event_filter(_parent, [=](not_null<QEvent*> e) {
		if ((e->type() == QEvent::Move || e->type() == QEvent::Resize)
			&& isVisible()) {
			syncGeometry();
		}
		return base::EventFilterResult::Continue;
	}, _lifetime);
}

void ThanosOverlay::syncGeometry() {
	setGeometry(QRect(_parent->mapToGlobal(QPoint()), _parent->size()));
}

void ThanosOverlay::present() {
	syncGeometry();
	if (!isVisible()) {
#ifdef Q_OS_WIN
		// The native window is created here, with the GPU child already
		// in place; the owner is set before the first show.
		if (_parent->windowHandle()) {
			SetWindowLongPtr(
				reinterpret_cast<HWND>(winId()),
				GWLP_HWNDPARENT,
				reinterpret_cast<LONG_PTR>(_parent->winId()));
		}
#endif // Q_OS_WIN
		show();
		const auto handle = windowHandle();
		Core::ZsgDiag::Trace(
			"thanos: overlay shown",
			handle ? int(handle->surfaceType()) : -1,
			(handle && handle->format().hasAlpha()) ? 1 : 0);
	}
	raise();
}

void ThanosOverlay::dismiss() {
	hide();
}

} // namespace Ui

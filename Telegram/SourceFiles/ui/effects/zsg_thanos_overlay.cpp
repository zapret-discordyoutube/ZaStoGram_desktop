/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information see the local LEGAL file.
*/
#include "ui/effects/zsg_thanos_overlay.h"

#include "core/zsg_diag.h"

#include <QtGui/QWindow>

namespace Ui {

ThanosOverlay::ThanosOverlay(not_null<QWidget*> parent)
: QWidget(
	parent,
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

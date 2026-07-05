/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "window/window_connecting_widget.h"

#include "ui/widgets/buttons.h"
#include "ui/effects/radial_animation.h"
#include "ui/painter.h"
#include "ui/ui_utility.h"
#include "mtproto/mtp_instance.h"
#include "mtproto/facade.h"
#include "main/main_account.h"
#include "core/application.h"
#include "core/core_settings.h"
#include "core/update_checker.h"
#include "boxes/connection_box.h"
#include "boxes/abstract_box.h"
#include "lang/lang_keys.h"
#include "styles/style_window.h"

#include <QtGui/QWindow>

namespace Window {
namespace {

constexpr auto kIgnoreStartConnectingFor = crl::time(3000);
constexpr auto kConnectingStateDelay = crl::time(1000);
constexpr auto kRefreshTimeout = crl::time(200);
constexpr auto kMinimalWaitingStateDuration = crl::time(4000);

[[nodiscard]] QString ProxyConnectionStatusKindText(
		MTP::ProxyConnectionStatusKind kind) {
	switch (kind) {
	case MTP::ProxyConnectionStatusKind::None:
		return QString();
	case MTP::ProxyConnectionStatusKind::Resolving:
		return tr::lng_proxy_status_resolving(tr::now);
	case MTP::ProxyConnectionStatusKind::Connecting:
		return tr::lng_proxy_status_connecting(tr::now);
	case MTP::ProxyConnectionStatusKind::Handshake:
		return tr::lng_proxy_status_handshake(tr::now);
	case MTP::ProxyConnectionStatusKind::CheckingTelegram:
		return tr::lng_proxy_status_checking(tr::now);
	case MTP::ProxyConnectionStatusKind::Connected:
		return tr::lng_proxy_status_connected(tr::now);
	case MTP::ProxyConnectionStatusKind::HostNotFound:
		return tr::lng_proxy_status_host_not_found(tr::now);
	case MTP::ProxyConnectionStatusKind::ConnectionRefused:
		return tr::lng_proxy_status_refused(tr::now);
	case MTP::ProxyConnectionStatusKind::Timeout:
		return tr::lng_proxy_status_timeout(tr::now);
	case MTP::ProxyConnectionStatusKind::Authentication:
		return tr::lng_proxy_status_auth_failed(tr::now);
	case MTP::ProxyConnectionStatusKind::ProxyProtocol:
		return tr::lng_proxy_status_protocol(tr::now);
	case MTP::ProxyConnectionStatusKind::RemoteClosed:
		return tr::lng_proxy_status_closed(tr::now);
	case MTP::ProxyConnectionStatusKind::Network:
		return tr::lng_proxy_status_network(tr::now);
	case MTP::ProxyConnectionStatusKind::BadResponse:
		return tr::lng_proxy_status_bad_response(tr::now);
	case MTP::ProxyConnectionStatusKind::Failed:
		return tr::lng_proxy_status_failed(tr::now);
	case MTP::ProxyConnectionStatusKind::MtproxyDnsFailed:
		return tr::lng_proxy_status_mtproxy_dns_failed(tr::now);
	case MTP::ProxyConnectionStatusKind::MtproxyTcpConnectTimeout:
		return tr::lng_proxy_status_mtproxy_tcp_timeout(tr::now);
	case MTP::ProxyConnectionStatusKind::MtproxyTcpConnectedNoClientHelloWrite:
		return tr::lng_proxy_status_mtproxy_tcp_no_client_hello(tr::now);
	case MTP::ProxyConnectionStatusKind::MtproxyNoServerHello:
		return tr::lng_proxy_status_mtproxy_no_server_hello(tr::now);
	case MTP::ProxyConnectionStatusKind::MtproxyTlsAlert:
		return tr::lng_proxy_status_mtproxy_tls_alert(tr::now);
	case MTP::ProxyConnectionStatusKind::MtproxyServerHelloHmacMismatch:
		return tr::lng_proxy_status_mtproxy_hmac_mismatch(tr::now);
	case MTP::ProxyConnectionStatusKind::MtproxyServerHelloOkNoAppData:
		return tr::lng_proxy_status_mtproxy_no_appdata(tr::now);
	case MTP::ProxyConnectionStatusKind::MtproxyAppDataRemoteClosed:
		return tr::lng_proxy_status_mtproxy_appdata_closed(tr::now);
	case MTP::ProxyConnectionStatusKind::MtproxyProxyProtocolBadResponse:
		return tr::lng_proxy_status_mtproxy_bad_response(tr::now);
	}
	return QString();
}

[[nodiscard]] QString ConnectionNoticeText(MTP::ConnectionNotice notice) {
	switch (notice) {
	case MTP::ConnectionNotice::None:
		return QString();

	case MTP::ConnectionNotice::WssDirectFallback:
		return tr::lng_connection_wss_direct_fallback(tr::now);
	}
	return QString();
}

class Progress : public Ui::RpWidget {
public:
	Progress(QWidget *parent);

	rpl::producer<> animationStepRequests() const;

protected:
	void paintEvent(QPaintEvent *e) override;

private:
	void animationStep();

	Ui::InfiniteRadialAnimation _animation;
	rpl::event_stream<> _animationStepRequests;

};

Progress::Progress(QWidget *parent)
: RpWidget(parent)
, _animation([=] { animationStep(); }, st::connectingRadial) {
	setAttribute(Qt::WA_OpaquePaintEvent);
	setAttribute(Qt::WA_TransparentForMouseEvents);
	resize(st::connectingRadial.size);
	_animation.start(st::connectingRadial.sineDuration);
}

void Progress::paintEvent(QPaintEvent *e) {
	auto p = QPainter(this);

	p.fillRect(e->rect(), st::windowBg);
	const auto &st = st::connectingRadial;
	const auto shift = st.thickness - (st.thickness / 2);
	_animation.draw(
		p,
		{ shift, shift },
		QSize(st.size.width() - 2 * shift, st.size.height() - 2 * shift),
		width());
}

void Progress::animationStep() {
	if (!anim::Disabled()) {
		_animationStepRequests.fire({});
		update();
	}
}

rpl::producer<> Progress::animationStepRequests() const {
	return _animationStepRequests.events();
}

} // namespace

class ConnectionState::Widget : public Ui::AbstractButton {
public:
	Widget(
		QWidget *parent,
		not_null<Main::Account*> account,
		const Layout &layout);

	QAccessible::Role accessibilityRole() override {
		return QAccessible::Role::StatusBar;
	}

	void refreshRetryLink(bool hasRetry);
	void setLayout(const Layout &layout);
	void setProgressVisibility(bool visible);

	rpl::producer<> refreshStateRequests() const;

protected:
	void resizeEvent(QResizeEvent *e) override;
	void paintEvent(QPaintEvent *e) override;

	void onStateChanged(State was, StateChangeSource source) override;

private:
	class ProxyIcon;
	using State = ConnectionState::State;
	using Layout = ConnectionState::Layout;

	void updateRetryGeometry();
	QRect innerRect() const;
	QRect contentRect() const;
	QRect textRect() const;

	const not_null<Main::Account*> _account;
	Layout _currentLayout;
	base::unique_qptr<Ui::LinkButton> _retry;
	QPointer<Progress> _progress;
	QPointer<ProxyIcon> _proxyIcon;
	rpl::event_stream<> _refreshStateRequests;

};

class ConnectionState::Widget::ProxyIcon final : public Ui::RpWidget {
public:
	ProxyIcon(QWidget *parent);

	void setStatus(
		bool enabled,
		MTP::ProxyConnectionStatusTone tone);
	void setOpacity(float64 opacity);

protected:
	void paintEvent(QPaintEvent *e) override;

private:
	void refreshCacheImages();
	[[nodiscard]] const QPixmap &cache() const;

	float64 _opacity = 1.;
	QPixmap _cacheOff;
	QPixmap _cacheProgress;
	QPixmap _cacheSuccess;
	QPixmap _cacheWarning;
	QPixmap _cacheError;
	QPixmap _cacheErrorDns;
	QPixmap _cacheErrorTimeout;
	QPixmap _cacheErrorNetwork;
	QPixmap _cacheErrorProtocol;
	QPixmap _cacheErrorAuth;
	QPixmap _cacheErrorHandshake;
	QPixmap _cacheErrorData;
	bool _enabled = true;
	MTP::ProxyConnectionStatusTone _tone
		= MTP::ProxyConnectionStatusTone::Progress;

};

ConnectionState::Widget::ProxyIcon::ProxyIcon(QWidget *parent) : RpWidget(parent) {
	resize(
		std::max(
			st::connectingRadial.size.width(),
			st::connectingProxyProgress.width()),
		std::max(
			st::connectingRadial.size.height(),
			st::connectingProxyProgress.height()));

	style::PaletteChanged(
	) | rpl::on_next([=] {
		refreshCacheImages();
	}, lifetime());

	refreshCacheImages();
}

void ConnectionState::Widget::ProxyIcon::refreshCacheImages() {
	const auto prepareCache = [&](const style::icon &icon) {
		auto image = QImage(
			size() * style::DevicePixelRatio(),
			QImage::Format_ARGB32_Premultiplied);
		image.setDevicePixelRatio(style::DevicePixelRatio());
		image.fill(st::windowBg->c);
		{
			auto p = QPainter(&image);
			icon.paint(
				p,
				(width() - icon.width()) / 2,
				(height() - icon.height()) / 2,
				width());
		}
		return Ui::PixmapFromImage(std::move(image));
	};
	_cacheOff = prepareCache(st::connectingProxyOff);
	_cacheProgress = prepareCache(st::connectingProxyProgress);
	_cacheSuccess = prepareCache(st::connectingProxySuccess);
	_cacheWarning = prepareCache(st::connectingProxyWarning);
	_cacheError = prepareCache(st::connectingProxyError);
	_cacheErrorDns = prepareCache(st::connectingProxyErrorDns);
	_cacheErrorTimeout = prepareCache(st::connectingProxyErrorTimeout);
	_cacheErrorNetwork = prepareCache(st::connectingProxyErrorNetwork);
	_cacheErrorProtocol = prepareCache(st::connectingProxyErrorProtocol);
	_cacheErrorAuth = prepareCache(st::connectingProxyErrorAuth);
	_cacheErrorHandshake = prepareCache(st::connectingProxyErrorHandshake);
	_cacheErrorData = prepareCache(st::connectingProxyErrorData);
}

void ConnectionState::Widget::ProxyIcon::setStatus(
		bool enabled,
		MTP::ProxyConnectionStatusTone tone) {
	if (_enabled != enabled || _tone != tone) {
		_enabled = enabled;
		_tone = tone;
		update();
	}
}

void ConnectionState::Widget::ProxyIcon::setOpacity(float64 opacity) {
	_opacity = opacity;
	if (_opacity == 0.) {
		hide();
	} else if (isHidden()) {
		show();
	}
	update();
}

void ConnectionState::Widget::ProxyIcon::paintEvent(QPaintEvent *e) {
	auto p = QPainter(this);
	p.setOpacity(_opacity);
	p.drawPixmap(0, 0, cache());
}

const QPixmap &ConnectionState::Widget::ProxyIcon::cache() const {
	if (!_enabled) {
		return _cacheOff;
	}
	switch (_tone) {
	case MTP::ProxyConnectionStatusTone::None:
	case MTP::ProxyConnectionStatusTone::Progress:
		return _cacheProgress;
	case MTP::ProxyConnectionStatusTone::Success:
		return _cacheSuccess;
	case MTP::ProxyConnectionStatusTone::Warning:
		return _cacheWarning;
	case MTP::ProxyConnectionStatusTone::Error:
		return _cacheError;
	case MTP::ProxyConnectionStatusTone::ErrorDns:
		return _cacheErrorDns;
	case MTP::ProxyConnectionStatusTone::ErrorTimeout:
		return _cacheErrorTimeout;
	case MTP::ProxyConnectionStatusTone::ErrorNetwork:
		return _cacheErrorNetwork;
	case MTP::ProxyConnectionStatusTone::ErrorProtocol:
		return _cacheErrorProtocol;
	case MTP::ProxyConnectionStatusTone::ErrorAuth:
		return _cacheErrorAuth;
	case MTP::ProxyConnectionStatusTone::ErrorHandshake:
		return _cacheErrorHandshake;
	case MTP::ProxyConnectionStatusTone::ErrorData:
		return _cacheErrorData;
	}
	return _cacheProgress;
}

bool ConnectionState::State::operator==(const State &other) const {
	return (type == other.type)
		&& (useProxy == other.useProxy)
		&& (exposed == other.exposed)
		&& (underCursor == other.underCursor)
		&& (updateReady == other.updateReady)
		&& (waitTillRetry == other.waitTillRetry)
		&& (proxyStatus == other.proxyStatus)
		&& (connectionNotice == other.connectionNotice);
}

ConnectionState::ConnectionState(
	not_null<Ui::RpWidget*> parent,
	not_null<Main::Account*> account,
	rpl::producer<bool> shown)
: _account(account)
, _parent(parent)
, _refreshTimer([=] { refreshState(); })
, _currentLayout(computeLayout(_state)) {
	rpl::combine(
		std::move(shown),
		visibility()
	) | rpl::on_next([=](bool shown, float64 visible) {
		if (!shown || visible == 0.) {
			_widget = nullptr;
		} else if (!_widget) {
			createWidget();
		}
	}, _lifetime);

	if (!Core::UpdaterDisabled()) {
		Core::UpdateChecker checker;
		rpl::merge(
			rpl::single(rpl::empty),
			checker.ready()
		) | rpl::on_next([=] {
			refreshState();
		}, _lifetime);
	}

	rpl::combine(
		Core::App().settings().proxy().connectionTypeValue(),
		_account->mtp().proxyConnectionStatusValue(),
		_account->mtp().connectionNoticeValue(),
		rpl::single(QRect()) | rpl::then(_parent->paintRequest())
	) | rpl::on_next([=] {
		refreshState();
	}, _lifetime);
}

void ConnectionState::createWidget() {
	_widget = base::make_unique_q<Widget>(_parent, _account, _currentLayout);
	_widget->setVisible(!_forceHidden);

	updateWidth();

	rpl::combine(
		visibility(),
		_parent->heightValue(),
		_bottomSkip.value()
	) | rpl::on_next([=](float64 visible, int height, int skip) {
		_widget->moveToLeft(0, anim::interpolate(
			height - st::connectingMargin.top(),
			height - _widget->height() - skip,
			visible));
	}, _widget->lifetime());

	_widget->refreshStateRequests(
	) | rpl::on_next([=] {
		refreshState();
	}, _widget->lifetime());
}

void ConnectionState::raise() {
	if (_widget) {
		_widget->raise();
	}
}

void ConnectionState::finishAnimating() {
	if (_contentWidth.animating()) {
		_contentWidth.stop();
		updateWidth();
	}
	if (_visibility.animating()) {
		_visibility.stop();
		updateVisibility();
	}
}

void ConnectionState::setForceHidden(bool hidden) {
	_forceHidden = hidden;
	if (_widget) {
		_widget->setVisible(!hidden);
	}
}

void ConnectionState::setBottomSkip(int skip) {
	_bottomSkip = skip;
}

void ConnectionState::refreshState() {
	using Checker = Core::UpdateChecker;
	const auto state = [&]() -> State {
		const auto exposed = _parent->window()->windowHandle()
			&& _parent->window()->windowHandle()->isExposed();
		const auto under = _widget && _widget->isOver();
		const auto ready = !Core::UpdaterDisabled()
			&& (Checker().state() == Checker::State::Ready);
		const auto state = _account->mtp().dcstate();
		const auto proxy = Core::App().settings().proxy().isEnabled();
		const auto proxyStatus = _account->mtp().proxyConnectionStatus();
		const auto connectionNotice = _account->mtp().connectionNotice();
		if (state == MTP::ConnectingState
			|| state == MTP::DisconnectedState
			|| (state < 0 && state > -600)) {
			return {
				State::Type::Connecting,
				proxy,
				exposed,
				under,
				ready,
				0,
				proxyStatus,
				connectionNotice };
		} else if (state < 0
			&& state >= -kMinimalWaitingStateDuration
			&& _state.type != State::Type::Waiting) {
			return {
				State::Type::Connecting,
				proxy,
				exposed,
				under,
				ready,
				0,
				proxyStatus,
				connectionNotice };
		} else if (state < 0) {
			const auto wait = ((-state) / 1000) + 1;
			return {
				State::Type::Waiting,
				proxy,
				exposed,
				under,
				ready,
				wait,
				proxyStatus,
				connectionNotice };
		}
		return {
			State::Type::Connected,
			proxy,
			exposed,
			under,
			ready,
			0,
			proxyStatus,
			connectionNotice };
	}();
	if (state.exposed && state.waitTillRetry > 0) {
		_refreshTimer.callOnce(kRefreshTimeout);
	}
	if (state == _state) {
		return;
	} else if (state.type == State::Type::Connecting
		&& _state.type == State::Type::Connected) {
		const auto now = crl::now();
		if (!_connectingStartedAt) {
			_connectingStartedAt = now;
			_refreshTimer.callOnce(kConnectingStateDelay);
			return;
		}
		const auto applyConnectingAt = std::max(
			_connectingStartedAt + kConnectingStateDelay,
			kIgnoreStartConnectingFor);
		if (now < applyConnectingAt) {
			_refreshTimer.callOnce(applyConnectingAt - now);
			return;
		}
	}
	applyState(state);
}

void ConnectionState::applyState(const State &state) {
	const auto newLayout = computeLayout(state);
	const auto guard = gsl::finally([&] { updateWidth(); });

	_state = state;
	if (_currentLayout.visible != newLayout.visible) {
		changeVisibilityWithLayout(newLayout);
		return;
	}
	if (_currentLayout.contentWidth != newLayout.contentWidth) {
		if (!_currentLayout.contentWidth
			|| !newLayout.contentWidth
			|| _contentWidth.animating()) {
			_contentWidth.start(
				[=] { updateWidth(); },
				_currentLayout.contentWidth,
				newLayout.contentWidth,
				st::connectingDuration);
		}
	}
	const auto saved = _currentLayout;
	setLayout(newLayout);
	if (_currentLayout.text.isEmpty()
		&& !saved.text.isEmpty()
		&& _contentWidth.animating()) {
		_currentLayout.text = saved.text;
		_currentLayout.textWidth = saved.textWidth;
	}
}

void ConnectionState::changeVisibilityWithLayout(const Layout &layout) {
	Expects(_currentLayout.visible != layout.visible);

	const auto changeLayout = !_currentLayout.visible;
	_visibility.start(
		[=] { updateVisibility(); },
		layout.visible ? 0. : 1.,
		layout.visible ? 1. : 0.,
		st::connectingDuration);
	if (_contentWidth.animating()) {
		_contentWidth.start(
			[=] { updateWidth(); },
			_currentLayout.contentWidth,
			(changeLayout ? layout : _currentLayout).contentWidth,
			st::connectingDuration);
	}
	if (changeLayout) {
		setLayout(layout);
	} else {
		_currentLayout.visible = layout.visible;
	}
}

void ConnectionState::setLayout(const Layout &layout) {
	_currentLayout = layout;
	if (_widget) {
		_widget->setLayout(layout);
	}
	refreshProgressVisibility();
}

void ConnectionState::refreshProgressVisibility() {
	if (_widget) {
		_widget->setProgressVisibility(_contentWidth.animating()
			|| _currentLayout.progressShown);
	}
}

void ConnectionState::updateVisibility() {
	const auto value = currentVisibility();
	if (value == 0. && _contentWidth.animating()) {
		_contentWidth.stop();
		updateWidth();
	}
	_visibilityValues.fire_copy(value);
}

float64 ConnectionState::currentVisibility() const {
	return _visibility.value(_currentLayout.visible ? 1. : 0.);
}

rpl::producer<float64> ConnectionState::visibility() const {
	return _visibilityValues.events_starting_with(currentVisibility());
}

auto ConnectionState::computeLayout(const State &state) const -> Layout {
	auto result = Layout();
	result.proxyEnabled = state.useProxy;
	if (state.useProxy) {
		const auto status = state.proxyStatus;
		result.proxySeverity = MTP::ProxyConnectionStatusSeverityFor(status);
		result.proxyTone = MTP::ProxyConnectionStatusToneFor(status);
	}
	result.progressShown = (state.type != State::Type::Connected);
	result.visible = state.exposed
		&& !state.updateReady;
	const auto notice = ConnectionNoticeText(state.connectionNotice);
	switch (state.type) {
	case State::Type::Connecting:
		if (state.useProxy) {
			const auto status = state.proxyStatus;
			result.text = ProxyConnectionStatusKindText(
				MTP::ProxyConnectionStatusKindFor(status));
			if (result.text.isEmpty()) {
				result.text = tr::lng_connection_proxy_connecting(tr::now);
			}
		} else if (!notice.isEmpty()) {
			result.text = notice;
		} else {
			result.text = state.underCursor
				? tr::lng_connecting(tr::now)
				: QString();
		}
		break;

	case State::Type::Waiting:
		Assert(state.waitTillRetry > 0);
		if (state.useProxy) {
			const auto status = state.proxyStatus;
			const auto statusText = ProxyConnectionStatusKindText(
				MTP::ProxyConnectionStatusKindFor(status));
			result.text = statusText.isEmpty()
				? tr::lng_proxy_status_retry(
					tr::now,
					lt_count,
					state.waitTillRetry)
				: tr::lng_proxy_status_retry_with_error(
					tr::now,
					lt_count,
					state.waitTillRetry,
					lt_error,
					statusText);
		} else if (!notice.isEmpty()) {
			result.text = notice;
		} else {
			result.text = tr::lng_reconnecting(
				tr::now,
				lt_count,
				state.waitTillRetry);
		}
		break;
	}
	result.textWidth = st::normalFont->width(result.text);
	result.contentWidth = (result.textWidth > 0)
		? (st::connectingTextPadding.left()
			+ result.textWidth
			+ st::connectingTextPadding.right())
		: 0;
	if (state.type == State::Type::Waiting) {
		result.contentWidth += st::connectingRetryLink.padding.left()
			+ st::connectingRetryLink.font->width(
				tr::lng_reconnecting_try_now(tr::now))
			+ st::connectingRetryLink.padding.right();
	}
	result.hasRetry = (state.type == State::Type::Waiting);
	return result;
}

void ConnectionState::updateWidth() {
	const auto current = _contentWidth.value(_currentLayout.contentWidth);
	const auto height = st::connectingLeft.height();
	const auto desired = QRect(0, 0, current, height).marginsAdded(
		style::margins(
			st::connectingLeft.width(),
			0,
			st::connectingRight.width(),
			0)
	).marginsAdded(
		st::connectingMargin
	);
	if (_widget) {
		_widget->resize(desired.size());
		_widget->update();
	}
	refreshProgressVisibility();
}

ConnectionState::Widget::Widget(
	QWidget *parent,
	not_null<Main::Account*> account,
	const Layout &layout)
: AbstractButton(parent)
, _account(account)
, _currentLayout(layout) {
	_proxyIcon = Ui::CreateChild<ProxyIcon>(this);
	_progress = Ui::CreateChild<Progress>(this);

	addClickHandler([=] {
		Ui::show(ProxiesBoxController::CreateOwningBox(account));
	});

	_progress->animationStepRequests(
	) | rpl::on_next([=] {
		_refreshStateRequests.fire({});
	}, _progress->lifetime());

	setLayout(_currentLayout);
	setProgressVisibility(_currentLayout.progressShown);
}

void ConnectionState::Widget::onStateChanged(
		AbstractButton::State was,
		StateChangeSource source) {
	Ui::PostponeCall(crl::guard(this, [=] {
		_refreshStateRequests.fire({});
	}));
}

rpl::producer<> ConnectionState::Widget::refreshStateRequests() const {
	return _refreshStateRequests.events();
}

void ConnectionState::Widget::paintEvent(QPaintEvent *e) {
	Painter p(this);
	PainterHighQualityEnabler hq(p);

	p.setPen(Qt::NoPen);
	p.setBrush(st::windowBg);
	const auto inner = innerRect();
	const auto content = contentRect();
	const auto text = textRect();
	const auto left = inner.topLeft();
	const auto right = content.topLeft() + QPoint(content.width(), 0);
	st::connectingLeftShadow.paint(p, left, width());
	st::connectingLeft.paint(p, left, width());
	st::connectingRightShadow.paint(p, right, width());
	st::connectingRight.paint(p, right, width());
	st::connectingBodyShadow.fill(p, content);
	st::connectingBody.fill(p, content);

	const auto available = text.width();
	if (available > 0 && !_currentLayout.text.isEmpty()) {
		p.setFont(st::normalFont);
		p.setPen(st::windowSubTextFg);
		if (available >= _currentLayout.textWidth) {
			p.drawTextLeft(
				text.x(),
				text.y(),
				width(),
				_currentLayout.text,
				_currentLayout.textWidth);
		} else {
			p.drawTextLeft(
				text.x(),
				text.y(),
				width(),
				st::normalFont->elided(_currentLayout.text, available));
		}
	}
}

QRect ConnectionState::Widget::innerRect() const {
	return rect().marginsRemoved(
		st::connectingMargin
	);
}

QRect ConnectionState::Widget::contentRect() const {
	return innerRect().marginsRemoved(style::margins(
		st::connectingLeft.width(),
		0,
		st::connectingRight.width(),
		0));
}

QRect ConnectionState::Widget::textRect() const {
	return contentRect().marginsRemoved(
		st::connectingTextPadding
	);
}

void ConnectionState::Widget::resizeEvent(QResizeEvent *e) {
	{
		const auto xShift = (height() - _progress->width()) / 2;
		const auto yShift = (height() - _progress->height()) / 2;
		_progress->moveToLeft(xShift, yShift);
	}
	{
		const auto xShift = (height() - _proxyIcon->width()) / 2;
		const auto yShift = (height() - _proxyIcon->height()) / 2;
		_proxyIcon->moveToLeft(xShift, yShift);
	}
	updateRetryGeometry();
}

void ConnectionState::Widget::updateRetryGeometry() {
	if (!_retry) {
		return;
	}
	const auto text = textRect();
	const auto available = text.width() - _currentLayout.textWidth;
	if (available <= 0) {
		_retry->hide();
	} else {
		_retry->show();
		_retry->resize(
			std::min(available, _retry->naturalWidth()),
			innerRect().height());
		_retry->moveToLeft(
			text.x() + text.width() - _retry->width(),
			st::connectingMargin.top());
	}
}

void ConnectionState::Widget::setLayout(const Layout &layout) {
	_currentLayout = layout;
	_proxyIcon->setStatus(
		_currentLayout.proxyEnabled,
		_currentLayout.proxyTone);
	refreshRetryLink(_currentLayout.hasRetry);
	setAccessibleName(_currentLayout.text);
}

void ConnectionState::Widget::setProgressVisibility(bool visible) {
	const auto progressVisible = visible && !_currentLayout.proxyEnabled;
	if (_progress->isHidden() == progressVisible) {
		_progress->setVisible(progressVisible);
	}
	_proxyIcon->setVisible(_currentLayout.proxyEnabled);
}

void ConnectionState::Widget::refreshRetryLink(bool hasRetry) {
	if (hasRetry && !_retry) {
		_retry = base::make_unique_q<Ui::LinkButton>(
			this,
			tr::lng_reconnecting_try_now(tr::now),
			st::connectingRetryLink);
		_retry->addClickHandler([=] {
			_account->mtp().restart();
		});
		updateRetryGeometry();
	} else if (!hasRetry) {
		_retry = nullptr;
	}
}

} // namespace Window

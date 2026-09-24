/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "core/proxy_wss_fallback.h"

#include "core/application.h"
#include "core/core_settings.h"
#include "logs.h"
#include "main/main_account.h"
#include "main/main_domain.h"
#include "mtproto/instance/mtp_instance.h"
#include "mtproto/runtime/proxy_data.h"
#include "mtproto/session/session_state.h"

namespace Core {
namespace {

constexpr auto kTickInterval = crl::time(1000);
constexpr auto kFallbackDelay = crl::time(15000);
constexpr auto kProbeIntervalMin = crl::time(30000);
constexpr auto kProbeIntervalMax = crl::time(300000);
constexpr auto kFlapWindow = crl::time(300000);

} // namespace

ProxyWssFallback::ProxyWssFallback()
: _tickTimer([=] { tick(); })
, _probeTimer([=] { probe(); })
, _probeInterval(kProbeIntervalMin) {
	_tickTimer.callEach(kTickInterval);
}

bool ProxyWssFallback::engaged() const {
	return _engaged;
}

void ProxyWssFallback::reset() {
	_probeTimer.cancel();
	MTP::ResetProxyCheckers(_checker, _checkerv6);
	_probing = false;
	_engaged = false;
	_connectingSince = 0;
	_restoredAt = 0;
	_probeInterval = kProbeIntervalMin;
}

bool ProxyWssFallback::allowed() const {
	const auto &proxy = App().settings().proxy();
	const auto transport = App().settings().proxyStealthOptions().transport;
	return proxy.isEnabled()
		&& proxy.selected()
		&& (transport == MTP::ProxyTransport::Wss)
		&& App().domain().started();
}

bool ProxyWssFallback::connecting() const {
	return App().activeAccount().mtp().dcstate() != MTP::ConnectedState;
}

void ProxyWssFallback::tick() {
	if (!allowed()) {
		_connectingSince = 0;
		if (_engaged) {
			reset();
			apply();
		}
		return;
	} else if (_engaged) {
		return;
	} else if (!connecting()) {
		_connectingSince = 0;
		return;
	}
	const auto now = crl::now();
	if (!_connectingSince) {
		_connectingSince = now;
	} else if (now - _connectingSince >= kFallbackDelay) {
		engage();
	}
}

void ProxyWssFallback::engage() {
	const auto now = crl::now();
	_probeInterval = (_restoredAt && now - _restoredAt < kFlapWindow)
		? std::min(_probeInterval * 2, kProbeIntervalMax)
		: kProbeIntervalMin;
	_connectingSince = 0;
	_engaged = true;
	LOG(("Proxy WSS Fallback: proxy does not connect, using WSS, "
		"probe every %1 ms.").arg(_probeInterval));
	apply();
	_probeTimer.callOnce(_probeInterval);
}

void ProxyWssFallback::probe() {
	if (!_engaged || _probing || !allowed()) {
		return;
	}
	_probing = true;
	const auto status = std::make_shared<MTP::ProxyCheckStatus>(
		MTP::ProxyCheckStatus::Idle);
	auto &settings = App().settings();
	MTP::StartProxyCheck(
		&App().activeAccount().mtp().runtimeEnvironment(),
		settings.proxy().selected(),
		settings.proxy().tryIPv6(),
		settings.proxyStealthOptions(),
		_checker,
		_checkerv6,
		[=](MTP::details::AbstractConnection *raw, int ping) {
			MTP::DropProxyChecker(_checker, _checkerv6, raw);
			probeFinished(true);
		},
		[=](MTP::details::AbstractConnection *raw) {
			MTP::DropProxyChecker(_checker, _checkerv6, raw);
			if (!MTP::HasProxyCheckers(_checker, _checkerv6)) {
				probeFinished(false);
			}
		},
		[=](MTP::ProxyCheckStatus value) {
			*status = value;
		});
	if (_probing
		&& !MTP::HasProxyCheckers(_checker, _checkerv6)
		&& *status != MTP::ProxyCheckStatus::WaitingForConnectionSlot) {
		probeFinished(false);
	}
}

void ProxyWssFallback::probeFinished(bool available) {
	if (!_probing) {
		return;
	}
	MTP::ResetProxyCheckers(_checker, _checkerv6);
	_probing = false;
	if (!_engaged) {
		return;
	} else if (!available) {
		_probeTimer.callOnce(_probeInterval);
		return;
	}
	LOG(("Proxy WSS Fallback: proxy is available again."));
	_engaged = false;
	_restoredAt = crl::now();
	apply();
}

void ProxyWssFallback::apply() {
	App().restartProxyConnections();
}

} // namespace Core

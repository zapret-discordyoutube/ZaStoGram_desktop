/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/runtime/connection_status.h"

#include "mtproto/runtime/runtime_environment.h"

namespace MTP {

ConnectionStatus::ConnectionStatus(not_null<RuntimeEnvironment*> runtime)
: _runtime(runtime) {
}

ProxyConnectionStatus ConnectionStatus::proxyStatus() const {
	return _proxyStatus.current();
}

auto ConnectionStatus::proxyStatusValue() const
-> rpl::producer<ProxyConnectionStatus> {
	return _proxyStatus.value();
}

void ConnectionStatus::setProxyStatus(ProxyConnectionStatus status) {
	if (status.phase != ProxyConnectionPhase::None) {
		if (!_runtime->proxy().enabled || !_runtime->proxy().enabled()) {
			return;
		}
		const auto selected = _runtime->proxy().selected
			? _runtime->proxy().selected()
			: ProxyData();
		const auto matches = [&] {
			if (status.proxy == selected) {
				return true;
			} else if (!selected.tryCustomResolve()) {
				return false;
			} else if (status.proxy.type != selected.type
				|| status.proxy.port != selected.port
				|| status.proxy.user != selected.user
				|| status.proxy.password != selected.password) {
				return false;
			}
			return ranges::find(selected.resolvedIPs, status.proxy.host)
				!= end(selected.resolvedIPs);
		}();
		if (!matches) {
			return;
		}
	}
	if (status == _proxyStatus.current()) {
		return;
	}
	_proxyStatus = status;
}

void ConnectionStatus::resetProxyStatus() {
	setProxyStatus({});
}

ConnectionNotice ConnectionStatus::notice() const {
	return _notice.current();
}

auto ConnectionStatus::noticeValue() const
-> rpl::producer<ConnectionNotice> {
	return _notice.value();
}

void ConnectionStatus::setNotice(
		ShiftedDcId shiftedDcId,
		ConnectionNotice notice) {
	if (notice == ConnectionNotice::None) {
		_notices.remove(shiftedDcId);
	} else {
		_notices[shiftedDcId] = notice;
	}
	const auto current = _notices.empty()
		? ConnectionNotice::None
		: begin(_notices)->second;
	if (current == _notice.current()) {
		return;
	}
	_notice = current;
}

void ConnectionStatus::resetNotices() {
	_notices.clear();
	setNotice(0, ConnectionNotice::None);
}

crl::time ConnectionStatus::pingTime() const {
	return _pingTime.current();
}

rpl::producer<crl::time> ConnectionStatus::pingTimeValue() const {
	return _pingTime.value();
}

void ConnectionStatus::setSessionPingTime(
		DcId mainDcId,
		ShiftedDcId shiftedDcId,
		crl::time time) {
	if (shiftedDcId == mainDcId) {
		_pingTime = time;
	}
}

void ConnectionStatus::resetPingTime() {
	_pingTime = 0;
}

} // namespace MTP

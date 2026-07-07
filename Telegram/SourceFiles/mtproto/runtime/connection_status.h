/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "mtproto/dc_id.h"
#include "mtproto/proxy/status.h"

namespace MTP {

struct RuntimeEnvironment;

class ConnectionStatus final {
public:
	explicit ConnectionStatus(not_null<RuntimeEnvironment*> runtime);

	[[nodiscard]] ProxyConnectionStatus proxyStatus() const;
	[[nodiscard]] auto proxyStatusValue() const
		-> rpl::producer<ProxyConnectionStatus>;
	void setProxyStatus(ProxyConnectionStatus status);
	void resetProxyStatus();

	[[nodiscard]] ConnectionNotice notice() const;
	[[nodiscard]] auto noticeValue() const
		-> rpl::producer<ConnectionNotice>;
	void setNotice(ShiftedDcId shiftedDcId, ConnectionNotice notice);
	void resetNotices();

	[[nodiscard]] crl::time pingTime() const;
	[[nodiscard]] rpl::producer<crl::time> pingTimeValue() const;
	void setSessionPingTime(
		DcId mainDcId,
		ShiftedDcId shiftedDcId,
		crl::time time);
	void resetPingTime();

private:
	const not_null<RuntimeEnvironment*> _runtime;

	rpl::variable<ProxyConnectionStatus> _proxyStatus;
	base::flat_map<ShiftedDcId, ConnectionNotice> _notices;
	rpl::variable<ConnectionNotice> _notice = ConnectionNotice::None;
	rpl::variable<crl::time> _pingTime = 0;

};

} // namespace MTP

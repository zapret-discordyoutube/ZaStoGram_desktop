/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "base/timer.h"
#include "mtproto/proxy/check.h"

namespace Core {

class ProxyWssFallback final {
public:
	ProxyWssFallback();

	[[nodiscard]] bool engaged() const;
	void reset();

private:
	[[nodiscard]] bool allowed() const;
	[[nodiscard]] bool connecting() const;
	void tick();
	void engage();
	void probe();
	void probeFinished(bool available);
	void apply();

	base::Timer _tickTimer;
	base::Timer _probeTimer;
	MTP::ProxyCheckConnection _checker;
	MTP::ProxyCheckConnection _checkerv6;
	crl::time _connectingSince = 0;
	crl::time _restoredAt = 0;
	crl::time _probeInterval = 0;
	bool _engaged = false;
	bool _probing = false;

};

} // namespace Core

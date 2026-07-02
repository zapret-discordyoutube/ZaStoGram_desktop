/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "mtproto/proxy/data.h"

namespace MTP {

enum class ProxyConnectionPhase {
	None,
	Resolving,
	Connecting,
	Handshake,
	CheckingTelegram,
	Connected,
	Failed,
};

enum class ProxyConnectionError {
	None,
	HostNotFound,
	ConnectionRefused,
	Timeout,
	Authentication,
	ProxyProtocol,
	RemoteClosed,
	Network,
	BadResponse,
	Unknown,
};

struct ProxyConnectionStatus {
	ProxyConnectionPhase phase = ProxyConnectionPhase::None;
	ProxyConnectionError error = ProxyConnectionError::None;
	ProxyData proxy;

	bool operator==(const ProxyConnectionStatus &other) const {
		return (phase == other.phase)
			&& (error == other.error)
			&& (proxy == other.proxy);
	}

};

}

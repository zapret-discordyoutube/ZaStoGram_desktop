/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "base/basic_types.h"
#include "mtproto/runtime/proxy_data.h"

#include <crl/crl_time.h>

namespace MTP::details::MtProxy {

enum class RouteAddressFamily {
	Unknown,
	Host,
	IPv4,
	IPv6,
};

enum class FailureReason {
	None,
	DnsFailed,
	TcpConnectTimeout,
	TcpConnectedNoClientHelloWrite,
	ClientHelloSentNoServerHello,
	TlsAlertAfterClientHello,
	ServerHelloHmacMismatch,
	ServerHelloOkNoAppData,
	ServerHelloOkNoMtprotoData,
	AppDataRemoteClosed,
	ConnectedNoMtprotoData,
	MtpReceiveTimeoutAfterData,
	Network,
	ProxyProtocolBadResponse,
};

struct CanonicalProxyEndpoint {
	ProxyData::Type type = ProxyData::Type::None;
	QString originalHost;
	int port = 0;
	QString secretHash;
	QString domainFromSecret;
	ProxyData::Type proxyKind = ProxyData::Type::None;

	bool operator==(const CanonicalProxyEndpoint &other) const {
		return (type == other.type)
			&& (originalHost == other.originalHost)
			&& (port == other.port)
			&& (secretHash == other.secretHash)
			&& (domainFromSecret == other.domainFromSecret)
			&& (proxyKind == other.proxyKind);
	}
};

struct RouteEndpoint {
	QString address;
	int port = 0;
	RouteAddressFamily addressFamily = RouteAddressFamily::Unknown;
	ProxyTransport transport = ProxyTransport::Tcp;
	QString resolvedFromHost;

	bool operator==(const RouteEndpoint &other) const {
		return (address == other.address)
			&& (port == other.port)
			&& (addressFamily == other.addressFamily)
			&& (transport == other.transport)
			&& (resolvedFromHost == other.resolvedFromHost);
	}
};

struct EndpointId {
	CanonicalProxyEndpoint canonical;
	RouteEndpoint route;

	bool operator==(const EndpointId &other) const {
		return (canonical == other.canonical)
			&& (route == other.route);
	}
};

enum class EndpointLaneCommandType {
	Suspend,
	Resume,
};

enum class EndpointLaneCommandResult {
	Applied,
	NotApplicable,
	Retry,
	NoDemand,
};

struct EndpointLaneCommand {
	EndpointLaneCommandType type = EndpointLaneCommandType::Suspend;
	uint64 token = 0;
	uint64 attemptId = 0;
	crl::time deadlineAt = 0;
	bool demandRequired = false;
	Fn<bool()> authorize;
	Fn<void()> demand;
	Fn<void(EndpointLaneCommandResult)> done;
};

} // namespace MTP::details::MtProxy

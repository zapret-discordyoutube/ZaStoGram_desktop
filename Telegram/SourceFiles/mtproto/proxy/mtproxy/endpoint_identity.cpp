/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/proxy/mtproxy/endpoint_identity.h"

#include "mtproto/transport/connection_abstract.h"

#include <QtCore/QByteArray>
#include <QtCore/QCryptographicHash>
#include <QtNetwork/QAbstractSocket>
#include <QtNetwork/QHostAddress>

namespace MTP::details::MtProxy {
namespace {

[[nodiscard]] QByteArray BytesToQByteArray(bytes::const_span data) {
	auto result = QByteArray();
	result.reserve(int(data.size()));
	for (const auto byte : data) {
		result.append(char(gsl::to_integer<unsigned char>(byte)));
	}
	return result;
}

[[nodiscard]] QString HashBytes(bytes::const_span data) {
	const auto hash = QCryptographicHash::hash(
		BytesToQByteArray(data),
		QCryptographicHash::Sha256);
	return QString::fromLatin1(hash.toHex());
}

[[nodiscard]] QString HashText(const QString &text) {
	const auto hash = QCryptographicHash::hash(
		text.toUtf8(),
		QCryptographicHash::Sha256);
	return QString::fromLatin1(hash.toHex());
}

[[nodiscard]] QString DomainFromSecret(bytes::const_span secret) {
	if (secret.size() <= 17) {
		return QString();
	}
	return QString::fromUtf8(BytesToQByteArray(secret.subspan(17)));
}

[[nodiscard]] QString ProxyIdentityHost(const ProxyData &proxy) {
	return proxy.originalHost.isEmpty()
		? proxy.host
		: proxy.originalHost;
}

[[nodiscard]] RouteAddressFamily AddressFamilyFor(const QString &address) {
	if (address.isEmpty()) {
		return RouteAddressFamily::Unknown;
	}
	const auto parsed = QHostAddress(address);
	switch (parsed.protocol()) {
	case QAbstractSocket::IPv4Protocol:
		return RouteAddressFamily::IPv4;
	case QAbstractSocket::IPv6Protocol:
		return RouteAddressFamily::IPv6;
	default:
		return RouteAddressFamily::Host;
	}
}

} // namespace

EndpointId EndpointIdFromProxy(
		const ProxyData &proxy,
		const ProxyStealthOptions &stealth,
		const QString &address,
		int port) {
	auto result = EndpointId();
	result.canonical.type = proxy.type;
	result.canonical.originalHost = ProxyIdentityHost(proxy);
	result.canonical.port = int(proxy.port);
	result.canonical.proxyKind = proxy.type;
	result.route = RouteEndpointFromAddress(
		address.isEmpty() ? result.canonical.originalHost : address,
		port ? port : int(proxy.port),
		stealth.transport,
		address.isEmpty() ? QString() : result.canonical.originalHost);
	if (proxy.type == ProxyData::Type::Mtproto) {
		const auto secret = proxy.secretFromMtprotoPassword();
		if (!secret.empty()) {
			result.canonical.secretHash = HashBytes(secret);
			result.canonical.domainFromSecret = DomainFromSecret(secret);
			return result;
		}
	}
	result.canonical.secretHash = HashText(proxy.password);
	return result;
}

EndpointId EndpointIdFromAddress(
		const QString &address,
		int port,
		bytes::const_span secret,
		ProxyTransport transport) {
	auto result = EndpointId();
	result.canonical.type = ProxyData::Type::Mtproto;
	result.canonical.originalHost = address;
	result.canonical.port = port;
	result.canonical.secretHash = HashBytes(secret);
	result.canonical.domainFromSecret = DomainFromSecret(secret);
	result.canonical.proxyKind = ProxyData::Type::Mtproto;
	result.route = RouteEndpointFromAddress(address, port, transport);
	return result;
}

RouteEndpoint RouteEndpointFromAddress(
		const QString &address,
		int port,
		ProxyTransport transport,
		const QString &resolvedFromHost) {
	return {
		.address = address,
		.port = port,
		.addressFamily = AddressFamilyFor(address),
		.transport = transport,
		.resolvedFromHost = resolvedFromHost,
	};
}

bool EndpointEmpty(const CanonicalProxyEndpoint &endpoint) {
	return endpoint.originalHost.isEmpty() || endpoint.port <= 0;
}

bool EndpointEmpty(const EndpointId &endpoint) {
	return EndpointEmpty(endpoint.canonical);
}

QString EndpointKey(const CanonicalProxyEndpoint &endpoint) {
	if (EndpointEmpty(endpoint)) {
		return QString();
	}
	return endpoint.originalHost
		+ u":%1:"_q.arg(endpoint.port)
		+ QString::number(int(endpoint.type))
		+ ':'
		+ QString::number(int(endpoint.proxyKind))
		+ ':'
		+ endpoint.secretHash
		+ ':'
		+ endpoint.domainFromSecret;
}

QString EndpointKey(const EndpointId &endpoint) {
	return EndpointKey(endpoint.canonical);
}

QString CapabilityProxyKey(const CanonicalProxyEndpoint &endpoint) {
	if (EndpointEmpty(endpoint)) {
		return QString();
	}
	return endpoint.originalHost
		+ ':'
		+ QString::number(endpoint.port)
		+ ':'
		+ QString::number(int(endpoint.type))
		+ ':'
		+ endpoint.secretHash
		+ ':'
		+ endpoint.domainFromSecret;
}

QString RouteKey(const RouteEndpoint &route) {
	if (route.address.isEmpty() || route.port <= 0) {
		return QString();
	}
	return route.address
		+ u":%1:"_q.arg(route.port)
		+ QString::number(int(route.addressFamily))
		+ ':'
		+ QString::number(int(route.transport))
		+ ':'
		+ route.resolvedFromHost;
}

QString RouteKey(const EndpointId &endpoint) {
	return RouteKey(endpoint.route);
}

QString ToLegacyDiagnostic(FailureReason reason) {
	switch (reason) {
	case FailureReason::DnsFailed:
		return u"dns_failed"_q;
	case FailureReason::TcpConnectTimeout:
		return u"tcp_connect_timeout"_q;
	case FailureReason::TcpConnectedNoClientHelloWrite:
		return u"tcp_connected_no_client_hello_write"_q;
	case FailureReason::ClientHelloSentNoServerHello:
		return u"client_hello_sent_no_server_hello"_q;
	case FailureReason::TlsAlertAfterClientHello:
		return u"tls_alert_after_client_hello"_q;
	case FailureReason::ServerHelloHmacMismatch:
		return u"server_hello_hmac_mismatch"_q;
	case FailureReason::ServerHelloOkNoAppData:
		return u"server_hello_ok_no_appdata"_q;
	case FailureReason::ServerHelloOkNoMtprotoData:
		return u"server_hello_ok_no_mtproto_data"_q;
	case FailureReason::AppDataRemoteClosed:
		return u"appdata_remote_closed"_q;
	case FailureReason::ConnectedNoMtprotoData:
		return u"connected_no_mtproto_data"_q;
	case FailureReason::MtpReceiveTimeoutAfterData:
		return u"mtp_receive_timeout_after_data"_q;
	case FailureReason::Network:
		return u"network_error"_q;
	case FailureReason::ProxyProtocolBadResponse:
		return u"proxy_protocol_bad_response"_q;
	case FailureReason::None:
		return QString();
	}
	return QString();
}

FailureReason FailureReasonFromErrorCode(int errorCode) {
	if (errorCode == AbstractConnection::kErrorCodeOther) {
		return FailureReason::None;
	}
	switch (errorCode) {
	case QAbstractSocket::HostNotFoundError:
	case QAbstractSocket::ProxyNotFoundError:
		return FailureReason::DnsFailed;
	case QAbstractSocket::SocketTimeoutError:
	case QAbstractSocket::ProxyConnectionTimeoutError:
		return FailureReason::TcpConnectTimeout;
	case QAbstractSocket::RemoteHostClosedError:
	case QAbstractSocket::ProxyConnectionClosedError:
		return FailureReason::AppDataRemoteClosed;
	case QAbstractSocket::NetworkError:
		return FailureReason::Network;
	}
	return FailureReason::None;
}

ProxyConnectionError ToProxyConnectionError(FailureReason reason) {
	switch (reason) {
	case FailureReason::DnsFailed:
		return ProxyConnectionError::HostNotFound;
	case FailureReason::TcpConnectTimeout:
	case FailureReason::TcpConnectedNoClientHelloWrite:
	case FailureReason::ServerHelloOkNoMtprotoData:
	case FailureReason::ConnectedNoMtprotoData:
	case FailureReason::MtpReceiveTimeoutAfterData:
		return ProxyConnectionError::Timeout;
	case FailureReason::AppDataRemoteClosed:
		return ProxyConnectionError::RemoteClosed;
	case FailureReason::Network:
		return ProxyConnectionError::Network;
	case FailureReason::ProxyProtocolBadResponse:
	case FailureReason::ClientHelloSentNoServerHello:
	case FailureReason::TlsAlertAfterClientHello:
	case FailureReason::ServerHelloHmacMismatch:
	case FailureReason::ServerHelloOkNoAppData:
		return ProxyConnectionError::BadResponse;
	case FailureReason::None:
		return ProxyConnectionError::None;
	}
	return ProxyConnectionError::Unknown;
}

ProxyMtproxyTerminalReason ToProxyMtproxyTerminalReason(
		FailureReason reason) {
	switch (reason) {
	case FailureReason::DnsFailed:
		return ProxyMtproxyTerminalReason::DnsFailed;
	case FailureReason::TcpConnectTimeout:
		return ProxyMtproxyTerminalReason::TcpConnectTimeout;
	case FailureReason::TcpConnectedNoClientHelloWrite:
		return ProxyMtproxyTerminalReason::TcpConnectedNoClientHelloWrite;
	case FailureReason::ClientHelloSentNoServerHello:
		return ProxyMtproxyTerminalReason::ClientHelloSentNoServerHello;
	case FailureReason::TlsAlertAfterClientHello:
		return ProxyMtproxyTerminalReason::TlsAlertAfterClientHello;
	case FailureReason::ServerHelloHmacMismatch:
		return ProxyMtproxyTerminalReason::ServerHelloHmacMismatch;
	case FailureReason::ServerHelloOkNoAppData:
		return ProxyMtproxyTerminalReason::ServerHelloOkNoAppData;
	case FailureReason::ServerHelloOkNoMtprotoData:
		return ProxyMtproxyTerminalReason::ServerHelloOkNoMtprotoData;
	case FailureReason::AppDataRemoteClosed:
		return ProxyMtproxyTerminalReason::AppDataRemoteClosed;
	case FailureReason::ConnectedNoMtprotoData:
		return ProxyMtproxyTerminalReason::ConnectedNoMtprotoData;
	case FailureReason::MtpReceiveTimeoutAfterData:
		return ProxyMtproxyTerminalReason::MtpReceiveTimeoutAfterData;
	case FailureReason::ProxyProtocolBadResponse:
		return ProxyMtproxyTerminalReason::ProxyProtocolBadResponse;
	case FailureReason::None:
	case FailureReason::Network:
		return ProxyMtproxyTerminalReason::None;
	}
	return ProxyMtproxyTerminalReason::None;
}

FailureReason FromProxyMtproxyTerminalReason(
		ProxyMtproxyTerminalReason reason) {
	switch (reason) {
	case ProxyMtproxyTerminalReason::None:
		return FailureReason::None;
	case ProxyMtproxyTerminalReason::DnsFailed:
		return FailureReason::DnsFailed;
	case ProxyMtproxyTerminalReason::TcpConnectTimeout:
		return FailureReason::TcpConnectTimeout;
	case ProxyMtproxyTerminalReason::TcpConnectedNoClientHelloWrite:
		return FailureReason::TcpConnectedNoClientHelloWrite;
	case ProxyMtproxyTerminalReason::ClientHelloSentNoServerHello:
		return FailureReason::ClientHelloSentNoServerHello;
	case ProxyMtproxyTerminalReason::TlsAlertAfterClientHello:
		return FailureReason::TlsAlertAfterClientHello;
	case ProxyMtproxyTerminalReason::ServerHelloHmacMismatch:
		return FailureReason::ServerHelloHmacMismatch;
	case ProxyMtproxyTerminalReason::ServerHelloOkNoAppData:
		return FailureReason::ServerHelloOkNoAppData;
	case ProxyMtproxyTerminalReason::ServerHelloOkNoMtprotoData:
		return FailureReason::ServerHelloOkNoMtprotoData;
	case ProxyMtproxyTerminalReason::AppDataRemoteClosed:
		return FailureReason::AppDataRemoteClosed;
	case ProxyMtproxyTerminalReason::ConnectedNoMtprotoData:
		return FailureReason::ConnectedNoMtprotoData;
	case ProxyMtproxyTerminalReason::MtpReceiveTimeoutAfterData:
		return FailureReason::MtpReceiveTimeoutAfterData;
	case ProxyMtproxyTerminalReason::ProxyProtocolBadResponse:
		return FailureReason::ProxyProtocolBadResponse;
	}
	return FailureReason::Network;
}

} // namespace MTP::details::MtProxy

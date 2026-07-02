/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/details/mtproto_abstract_socket.h"

#include "mtproto/details/mtproto_tcp_socket.h"
#include "mtproto/details/mtproto_tls_socket.h"
#include "mtproto/details/mtproto_wss_socket.h"
#include "mtproto/proxy/diagnostics.h"
#include "logs.h"

#include <QtNetwork/QAbstractSocket>

namespace MTP::details {

std::unique_ptr<AbstractSocket> AbstractSocket::Create(
		not_null<QThread*> thread,
		const bytes::vector &secret,
		const QNetworkProxy &proxy,
		bool protocolForFiles,
		const ProxyStealthOptions &stealth,
		int16 protocolDcId) {
	if (stealth.transport == ProxyTransport::Wss) {
		auto route = WssCustomRoute(stealth);
		if (!route) {
			route = WssOfficialRoute(protocolDcId, protocolForFiles);
		}
		if (route) {
			return std::make_unique<WssSocket>(
				thread,
				proxy,
				protocolForFiles,
				std::move(*route));
		}
	}
	if (secret.size() >= 21 && secret[0] == bytes::type(0xEE)) {
		return std::make_unique<TlsSocket>(
			thread,
			secret,
			proxy,
			protocolForFiles,
			stealth);
	} else {
		return std::make_unique<TcpSocket>(thread, proxy, protocolForFiles);
	}
}

ProxyConnectionError SocketProxyConnectionError(int errorCode) {
	if (errorCode == AbstractConnection::kErrorCodeOther) {
		return ProxyConnectionError::BadResponse;
	}
	switch (errorCode) {
	case QAbstractSocket::HostNotFoundError:
	case QAbstractSocket::ProxyNotFoundError:
		return ProxyConnectionError::HostNotFound;

	case QAbstractSocket::ConnectionRefusedError:
	case QAbstractSocket::ProxyConnectionRefusedError:
		return ProxyConnectionError::ConnectionRefused;

	case QAbstractSocket::SocketTimeoutError:
	case QAbstractSocket::ProxyConnectionTimeoutError:
		return ProxyConnectionError::Timeout;

	case QAbstractSocket::ProxyAuthenticationRequiredError:
		return ProxyConnectionError::Authentication;

	case QAbstractSocket::ProxyProtocolError:
		return ProxyConnectionError::ProxyProtocol;

	case QAbstractSocket::RemoteHostClosedError:
	case QAbstractSocket::ProxyConnectionClosedError:
		return ProxyConnectionError::RemoteClosed;

	case QAbstractSocket::NetworkError:
		return ProxyConnectionError::Network;
	}
	return ProxyConnectionError::Unknown;
}

void AbstractSocket::logError(int errorCode, const QString &errorText) {
	const auto log = [&](const QString &message) {
		const auto full = QString("Socket %1 Error: ").arg(_debugId) + message;
		if (_debugId.contains(u"mtproxy "_q)) {
			WriteProxyDiagnosticsLine({
				.source = ProxyDiagnosticsSource::MTProxy,
				.phase = ProxyDiagnosticsPhase::Failed,
				.severity = ProxyDiagnosticsSeverity::Error,
				.error = SocketProxyConnectionError(errorCode),
				.socketId = _debugId,
				.message = full,
			});
		} else {
			DEBUG_LOG((full));
		}
	};
	switch (errorCode) {
	case QAbstractSocket::ConnectionRefusedError:
		log(u"Socket connection refused - %1."_q.arg(errorText));
		break;

	case QAbstractSocket::RemoteHostClosedError:
		log(u"Remote host closed socket connection - %1."_q.arg(errorText));
		break;

	case QAbstractSocket::HostNotFoundError:
		log(u"Host not found - %1."_q.arg(errorText));
		break;

	case QAbstractSocket::SocketTimeoutError:
		log(u"Socket timeout - %1."_q.arg(errorText));
		break;

	case QAbstractSocket::NetworkError: {
		log(u"Network - %1."_q.arg(errorText));
	} break;

	case QAbstractSocket::ProxyAuthenticationRequiredError:
	case QAbstractSocket::ProxyConnectionRefusedError:
	case QAbstractSocket::ProxyConnectionClosedError:
	case QAbstractSocket::ProxyConnectionTimeoutError:
	case QAbstractSocket::ProxyNotFoundError:
	case QAbstractSocket::ProxyProtocolError:
		log(u"Proxy (%1) - %2."_q.arg(errorCode).arg(errorText));
		break;

	default:
		log(u"Other (%1) - %2."_q.arg(errorCode).arg(errorText));
		break;
	}
}

} // namespace MTP::details

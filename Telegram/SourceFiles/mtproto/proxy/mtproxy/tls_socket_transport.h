/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "base/basic_types.h"

#include <QtCore/QByteArray>
#include <QtCore/QThread>
#include <QtCore/QVariant>
#include <QtNetwork/QAbstractSocket>
#include <QtNetwork/QNetworkProxy>

#include <memory>

namespace MTP::details {

struct TlsSocketTransportCallbacks final {
	Fn<void()> connected;
	Fn<void()> disconnected;
	Fn<void()> readyRead;
	Fn<void(QAbstractSocket::SocketError)> error;
};

class TlsSocketTransport {
public:
	virtual ~TlsSocketTransport() = default;

	virtual void setCallbacks(TlsSocketTransportCallbacks callbacks) = 0;
	virtual void moveToThread(not_null<QThread*> thread) = 0;
	virtual void setProxy(const QNetworkProxy &proxy) = 0;
	virtual void setSocketOption(
		QAbstractSocket::SocketOption option,
		const QVariant &value) = 0;
	virtual void connectToHost(const QString &address, int port) = 0;
	[[nodiscard]] virtual QAbstractSocket::SocketState state() const = 0;
	[[nodiscard]] virtual qint64 bytesAvailable() const = 0;
	[[nodiscard]] virtual QByteArray readAll() = 0;
	virtual qint64 write(const char *data, qint64 size) = 0;
	virtual void flush() = 0;
	[[nodiscard]] virtual QString errorString() const = 0;
};

[[nodiscard]] std::unique_ptr<TlsSocketTransport> CreateTlsSocketTransport();

} // namespace MTP::details

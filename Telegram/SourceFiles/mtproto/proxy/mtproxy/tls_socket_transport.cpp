/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/proxy/mtproxy/tls_socket_transport.h"

#include <QtNetwork/QTcpSocket>

namespace MTP::details {
namespace {

class QTcpSocketTransport final : public TlsSocketTransport {
public:
	void setCallbacks(TlsSocketTransportCallbacks callbacks) override {
		_callbacks = std::move(callbacks);
		using Error = QAbstractSocket::SocketError;
		QObject::connect(&_socket, &QTcpSocket::connected, &_socket, [this] {
			if (_callbacks.connected) {
				_callbacks.connected();
			}
		});
		QObject::connect(&_socket, &QTcpSocket::disconnected, &_socket, [this] {
			if (_callbacks.disconnected) {
				_callbacks.disconnected();
			}
		});
		QObject::connect(&_socket, &QTcpSocket::readyRead, &_socket, [this] {
			if (_callbacks.readyRead) {
				_callbacks.readyRead();
			}
		});
		QObject::connect(
			&_socket,
			&QAbstractSocket::errorOccurred,
			&_socket,
			[this](Error error) {
				if (_callbacks.error) {
					_callbacks.error(error);
				}
			});
	}

	void moveToThread(not_null<QThread*> thread) override {
		_socket.moveToThread(thread);
	}

	void setProxy(const QNetworkProxy &proxy) override {
		_socket.setProxy(proxy);
	}

	void setSocketOption(
			QAbstractSocket::SocketOption option,
			const QVariant &value) override {
		_socket.setSocketOption(option, value);
	}

	void connectToHost(const QString &address, int port) override {
		_socket.connectToHost(address, port);
	}

	QAbstractSocket::SocketState state() const override {
		return _socket.state();
	}

	qint64 bytesAvailable() const override {
		return _socket.bytesAvailable();
	}

	QByteArray readAll() override {
		return _socket.readAll();
	}

	qint64 write(const char *data, qint64 size) override {
		return _socket.write(data, size);
	}

	void flush() override {
		_socket.flush();
	}

	QString errorString() const override {
		return _socket.errorString();
	}

private:
	QTcpSocket _socket;
	TlsSocketTransportCallbacks _callbacks;
};

} // namespace

std::unique_ptr<TlsSocketTransport> CreateTlsSocketTransport() {
	return std::make_unique<QTcpSocketTransport>();
}

} // namespace MTP::details

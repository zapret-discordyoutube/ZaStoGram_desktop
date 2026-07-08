/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/proxy/mtproxy/tls_socket_transport.h"
#include "mtproto/runtime/runtime_environment.h"

#include <QtCore/QByteArray>

#include <algorithm>
#include <cstdio>
#include <utility>
#include <vector>

namespace {

[[nodiscard]] int Fail(const char *message) {
	std::fprintf(stderr, "%s\n", message);
	return 1;
}

class ScriptedAsync final {
public:
	[[nodiscard]] MTP::RuntimeAsyncGateway gateway() {
		return {
			.now = [this] {
				return _now;
			},
			.randomIndex = [](int) {
				return 0;
			},
			.singleShot = [this](
					crl::time delay,
					QObject*,
					Fn<void()> callback) {
				auto timer = makeTimer(std::move(callback));
				timer.callOnce(delay);
			},
			.makeTimer = [this](
					not_null<QThread*>,
					Fn<void()> callback) {
				return makeTimer(std::move(callback));
			},
		};
	}

	void advance(crl::time by) {
		_now += by;
		for (auto &entry : _timers) {
			if (entry.active && entry.deadline <= _now) {
				entry.active = false;
				entry.callback();
			}
		}
	}

private:
	struct TimerEntry {
		crl::time deadline = 0;
		bool active = false;
		Fn<void()> callback;
	};

	[[nodiscard]] MTP::RuntimeTimer makeTimer(Fn<void()> callback) {
		const auto index = _timers.size();
		_timers.push_back({ .callback = std::move(callback) });
		return MTP::RuntimeTimer(
			[this, index](crl::time delay) {
				_timers[index].deadline = _now + delay;
				_timers[index].active = true;
			},
			[this, index](crl::time delay) {
				_timers[index].deadline = _now + delay;
				_timers[index].active = true;
			},
			[this, index] {
				_timers[index].active = false;
			},
			[this, index] {
				return _timers[index].active;
			});
	}

	crl::time _now = 0;
	std::vector<TimerEntry> _timers;
};

class FakeTlsSocketTransport final : public MTP::details::TlsSocketTransport {
public:
	void setCallbacks(
			MTP::details::TlsSocketTransportCallbacks callbacks) override {
		_callbacks = std::move(callbacks);
	}

	void moveToThread(not_null<QThread*>) override {
	}

	void setProxy(const QNetworkProxy&) override {
	}

	void setSocketOption(
			QAbstractSocket::SocketOption,
			const QVariant&) override {
	}

	void connectToHost(const QString &address, int port) override {
		connectedTo = address + ':' + QString::number(port);
	}

	QAbstractSocket::SocketState state() const override {
		return socketState;
	}

	qint64 bytesAvailable() const override {
		return incoming.size();
	}

	QByteArray readAll() override {
		return std::exchange(incoming, QByteArray());
	}

	qint64 write(const char *data, qint64 size) override {
		outgoing.append(data, size);
		return size;
	}

	void flush() override {
		flushed = true;
	}

	QString errorString() const override {
		return errorText;
	}

	void emitConnected() {
		socketState = QAbstractSocket::ConnectedState;
		_callbacks.connected();
	}

	void emitReadyRead(QByteArray bytes) {
		incoming += bytes;
		_callbacks.readyRead();
	}

	void emitError(QAbstractSocket::SocketError error) {
		socketState = QAbstractSocket::UnconnectedState;
		_callbacks.error(error);
	}

	QString connectedTo;
	QByteArray incoming;
	QByteArray outgoing;
	QString errorText = u"scripted socket error"_q;
	QAbstractSocket::SocketState socketState
		= QAbstractSocket::UnconnectedState;
	bool flushed = false;

private:
	MTP::details::TlsSocketTransportCallbacks _callbacks;
};

[[nodiscard]] bool ScenarioSuccessToFirstAppData() {
	auto transport = FakeTlsSocketTransport();
	auto callbacks = MTP::details::TlsSocketTransportCallbacks();
	auto connected = false;
	auto ready = false;
	callbacks.connected = [&] { connected = true; };
	callbacks.readyRead = [&] { ready = true; };
	transport.setCallbacks(std::move(callbacks));
	transport.connectToHost(QString::fromLatin1("203.0.113.10"), 443);
	transport.emitConnected();
	transport.emitReadyRead(QByteArray("appdata", 7));
	return connected
		&& ready
		&& transport.connectedTo == QString::fromLatin1("203.0.113.10:443")
		&& transport.bytesAvailable() == 7;
}

[[nodiscard]] bool ScenarioTimeoutBeforeServerHello() {
	auto async = ScriptedAsync();
	auto fired = false;
	const auto thread = not_null{ QThread::currentThread() };
	auto timer = async.gateway().makeTimer(
		thread,
		[&] { fired = true; });
	timer.callOnce(10);
	async.advance(9);
	if (fired) {
		return false;
	}
	async.advance(1);
	return fired;
}

[[nodiscard]] bool ScenarioTlsAlertAfterClientHello() {
	auto transport = FakeTlsSocketTransport();
	auto failed = false;
	auto callbacks = MTP::details::TlsSocketTransportCallbacks();
	callbacks.error = [&](QAbstractSocket::SocketError) {
		failed = true;
	};
	transport.setCallbacks(std::move(callbacks));
	transport.emitError(QAbstractSocket::RemoteHostClosedError);
	return failed;
}

[[nodiscard]] bool ScenarioNoAppData() {
	auto transport = FakeTlsSocketTransport();
	transport.write("\x16\x03\x03", 3);
	return transport.outgoing == QByteArray("\x16\x03\x03", 3);
}

[[nodiscard]] bool ScenarioReconnectCancelDropsStaleCallbacks() {
	auto async = ScriptedAsync();
	auto fired = false;
	const auto thread = not_null{ QThread::currentThread() };
	auto timer = async.gateway().makeTimer(
		thread,
		[&] { fired = true; });
	timer.callOnce(10);
	timer.cancel();
	async.advance(10);
	return !fired;
}

} // namespace

int main(int, char *[]) {
	if (!ScenarioSuccessToFirstAppData()) {
		return Fail("success to first app-data scenario failed");
	} else if (!ScenarioTimeoutBeforeServerHello()) {
		return Fail("timeout before ServerHello scenario failed");
	} else if (!ScenarioTlsAlertAfterClientHello()) {
		return Fail("TLS alert after ClientHello scenario failed");
	} else if (!ScenarioNoAppData()) {
		return Fail("no app-data scenario failed");
	} else if (!ScenarioReconnectCancelDropsStaleCallbacks()) {
		return Fail("reconnect/cancel scenario failed");
	}
	return 0;
}

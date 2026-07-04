/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/proxy/check.h"

#include "mtproto/facade.h"
#include "mtproto/mtproto_dc_options.h"
#include "mtproto/proxy/diagnostics.h"
#include "mtproto/proxy/transport_policy.h"

#include <QtCore/QTimer>

#include <utility>

namespace MTP {

using Connection = details::AbstractConnection;

ProxyCheckConnection::ProxyCheckConnection()
: _data(std::make_shared<Data>()) {
}

ProxyCheckConnection::ProxyCheckConnection(
		ProxyCheckConnection &&other) noexcept
: _data(std::move(other._data)) {
}

ProxyCheckConnection &ProxyCheckConnection::operator=(
		ProxyCheckConnection &&other) noexcept {
	if (this != &other) {
		reset();
		_data = std::move(other._data);
	}
	return *this;
}

ProxyCheckConnection::~ProxyCheckConnection() {
	reset();
}

Connection *ProxyCheckConnection::get() const {
	return _data ? _data->connection.get() : nullptr;
}

ProxyCheckConnection::operator bool() const {
	return get() != nullptr;
}

Connection *ProxyCheckConnection::operator->() const {
	return get();
}

std::shared_ptr<ProxyCheckConnection::Data> ProxyCheckConnection::state() const {
	return _data;
}

void ProxyCheckConnection::reset() {
	if (_data) {
		_data->handshakeGate.release();
		_data->finished = true;
		_data->connection = nullptr;
	}
}

void ResetProxyCheckers(
		ProxyCheckConnection &v4,
		ProxyCheckConnection &v6) {
	v4.reset();
	v6.reset();
}

void DropProxyChecker(
		ProxyCheckConnection &v4,
		ProxyCheckConnection &v6,
		not_null<Connection*> raw) {
	if (v4.get() == raw) {
		v4.reset();
	} else if (v6.get() == raw) {
		v6.reset();
	}
}

bool HasProxyCheckers(
		const ProxyCheckConnection &v4,
		const ProxyCheckConnection &v6) {
	return v4 || v6;
}

void StartProxyCheck(
		not_null<Instance*> mtproto,
		const ProxyData &proxy,
		bool tryIPv6,
		const ProxyStealthOptions &stealth,
		ProxyCheckConnection &v4,
		ProxyCheckConnection &v6,
		Fn<void(Connection *raw, int ping)> done,
		Fn<void(Connection *raw)> fail) {
	using Variants = DcOptions::Variants;

	ResetProxyCheckers(v4, v6);
	const auto connType = (proxy.type == ProxyData::Type::Http)
		? Variants::Http
		: Variants::Tcp;
	const auto dcId = mtproto->mainDcId();
	const auto checkStealth = MTP::EffectiveProxyStealthOptions(
		proxy,
		ProxyData::Settings::Enabled,
		stealth);
	ReportProxyEvent(mtproto, {
		.phase = ProxyDiagnosticsPhase::ProxyCheckStarted,
		.proxy = proxy,
		.dc = QString::number(dcId),
		.message = u"proxy check started"_q,
	});
	const auto setup = [&](
			ProxyCheckConnection &checker,
			const bytes::vector &secret) {
		const auto state = checker.state();
		auto handshakeGate = details::ReserveHandshakeGateForProxy(proxy);
		state->connection = Connection::Create(
			mtproto,
			connType,
			QThread::currentThread(),
			secret,
			proxy,
			checkStealth);
		state->finished = false;
		state->handshakeGate = std::move(handshakeGate);
		const auto raw = state->connection.get();
		const auto finishWithFail = [=](ProxyConnectionError error) {
			if (state->connection.get() != raw || state->finished) {
				return;
			}
			state->finished = true;
			state->handshakeGate.release();
			ReportProxyEvent(mtproto, {
				.phase = ProxyDiagnosticsPhase::ProxyCheckFinished,
				.error = error,
				.severity = ProxyDiagnosticsSeverity::Error,
				.proxy = proxy,
				.dc = QString::number(dcId),
				.connectionId = raw->debugId(),
				.message = u"proxy check failed"_q,
			});
			if (fail) {
				fail(raw);
			}
		};
		raw->connect(raw, &Connection::connected, [=] {
			if (state->connection.get() != raw || state->finished) {
				return;
			}
			state->finished = true;
			state->handshakeGate.release();
			ReportProxyEvent(mtproto, {
				.phase = ProxyDiagnosticsPhase::ProxyCheckFinished,
				.proxy = proxy,
				.dc = QString::number(dcId),
				.connectionId = raw->debugId(),
				.message = u"proxy check succeeded"_q,
			});
			if (done) {
				done(raw, raw->pingTime());
			}
		});
		raw->connect(raw, &Connection::disconnected, [=] {
			finishWithFail(ProxyConnectionError::RemoteClosed);
		});
		raw->connect(raw, &Connection::error, [=] {
			finishWithFail(ProxyConnectionError::Unknown);
		});
		const auto timeout = state->handshakeGate.delay()
			+ raw->fullConnectTimeout();
		QTimer::singleShot(int(timeout), raw, [=] {
			if (state->connection.get() != raw || state->finished) {
				return;
			}
			raw->timedOut();
			finishWithFail(ProxyConnectionError::Timeout);
		});
	};
	const auto start = [&](
			ProxyCheckConnection &checker,
			QString address,
			int port,
			bytes::vector secret) {
		const auto state = checker.state();
		const auto raw = state->connection.get();
		const auto gateDelay = state->handshakeGate.delay();
		const auto start = [=, secret = std::move(secret)] {
			if (state->connection.get() != raw) {
				return;
			}
			raw->connectToServer(
				address,
				port,
				secret,
				dcId,
				false);
		};
		if (gateDelay > 0) {
			QTimer::singleShot(int(gateDelay), raw, start);
		} else {
			start();
		}
	};
	if (proxy.type == ProxyData::Type::Mtproto) {
		const auto secret = proxy.secretFromMtprotoPassword();
		setup(v4, secret);
		start(
			v4,
			proxy.host,
			proxy.port,
			secret);
		return;
	}
	const auto options = mtproto->dcOptions().lookup(
		dcId,
		DcType::Regular,
		true);
	const auto tryConnect = [&](
			ProxyCheckConnection &checker,
			Variants::Address address) {
		const auto &list = options.data[address][connType];
		if (list.empty() || ((address == Variants::IPv6) && !tryIPv6)) {
			checker.reset();
			return;
		}
		const auto &endpoint = list.front();
		setup(checker, endpoint.secret);
		start(
			checker,
			QString::fromStdString(endpoint.ip),
			endpoint.port,
			endpoint.secret);
	};
	tryConnect(v4, Variants::IPv4);
	tryConnect(v6, Variants::IPv6);
}

} // namespace MTP

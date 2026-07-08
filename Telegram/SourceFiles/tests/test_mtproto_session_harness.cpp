/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "base/basic_types.h"
#include "mtproto/proxy/mtproxy/endpoint_health.h"

#include <QtCore/QString>

#include <cstdio>
#include <utility>
#include <vector>

namespace {

[[nodiscard]] int Fail(const char *message) {
	std::fprintf(stderr, "%s\n", message);
	return 1;
}

class ScriptedSessionScheduler final {
public:
	using Callback = Fn<void()>;

	[[nodiscard]] int callOnce(crl::time delay, Callback callback) {
		const auto id = int(_timers.size() + 1);
		_timers.push_back({
			.id = id,
			.deadline = _now + delay,
			.callback = std::move(callback),
			.active = true,
		});
		return id;
	}

	void cancel(int id) {
		for (auto &timer : _timers) {
			if (timer.id == id) {
				timer.active = false;
			}
		}
	}

	void advance(crl::time delay) {
		_now += delay;
		for (auto &timer : _timers) {
			if (timer.active && timer.deadline <= _now) {
				timer.active = false;
				timer.callback();
			}
		}
	}

private:
	struct Timer {
		int id = 0;
		crl::time deadline = 0;
		Callback callback;
		bool active = false;
	};

	crl::time _now = 0;
	std::vector<Timer> _timers;
};

class FakeSessionConnection final {
public:
	void connectToServer(
			const QString &ip,
			int port,
			bool protocolForFiles) {
		connectedTo = ip + ':' + QString::number(port);
		use = protocolForFiles
			? MTP::MtProxy::EndpointUse::Media
			: MTP::MtProxy::EndpointUse::Main;
		started = true;
	}

	void emitConnected() {
		connected = true;
		++connectedCallbacks;
	}

	void emitError(int errorCode) {
		lastError = errorCode;
		++errorCallbacks;
	}

	void emitReceivedData() {
		receivedData = true;
		++receivedCallbacks;
	}

	QString connectedTo;
	MTP::MtProxy::EndpointUse use = MTP::MtProxy::EndpointUse::Main;
	int fullConnectTimeout = 0;
	int connectedCallbacks = 0;
	int errorCallbacks = 0;
	int receivedCallbacks = 0;
	int lastError = 0;
	bool started = false;
	bool connected = false;
	bool receivedData = false;
};

class ScriptedSessionProxyPort final {
public:
	struct PendingStart {
		uint64 ticketId = 0;
		MTP::MtProxy::EndpointUse use = MTP::MtProxy::EndpointUse::Main;
		bool canceled = false;
	};

	[[nodiscard]] uint64 requestConnection(MTP::MtProxy::EndpointUse use) {
		const auto id = ++lastTicketId;
		pending.push_back({ .ticketId = id, .use = use });
		return id;
	}

	bool cancel(uint64 ticketId) {
		for (auto &start : pending) {
			if (start.ticketId == ticketId) {
				start.canceled = true;
				++canceledTickets;
				return true;
			}
		}
		return false;
	}

	bool start(uint64 ticketId, FakeSessionConnection &connection) {
		for (auto &entry : pending) {
			if (entry.ticketId == ticketId && !entry.canceled) {
				connection.connectToServer(u"203.0.113.10"_q, 443, (
					entry.use == MTP::MtProxy::EndpointUse::Media));
				++startedTickets;
				return true;
			}
		}
		return false;
	}

	void reportConnected(MTP::MtProxy::EndpointUse use) {
		lastSuccessUse = use;
		++successReports;
	}

	void reportReceiveTimeout(bool receivedBefore) {
		lastTimeoutHadData = receivedBefore;
		++receiveTimeoutReports;
	}

	uint64 lastTicketId = 0;
	int startedTickets = 0;
	int canceledTickets = 0;
	int successReports = 0;
	int receiveTimeoutReports = 0;
	bool lastTimeoutHadData = false;
	MTP::MtProxy::EndpointUse lastSuccessUse = MTP::MtProxy::EndpointUse::Main;
	std::vector<PendingStart> pending;
};

class FakeSessionAuthKeyCreator final {
public:
	void start() {
		started = true;
	}

	void succeed() {
		started = false;
		succeeded = true;
	}

	void fail() {
		started = false;
		failed = true;
	}

	void stop() {
		stopped = true;
		started = false;
	}

	bool started = false;
	bool succeeded = false;
	bool failed = false;
	bool stopped = false;
};

[[nodiscard]] bool ScenarioConnectionSuccess() {
	auto port = ScriptedSessionProxyPort();
	auto connection = FakeSessionConnection();
	const auto ticket = port.requestConnection(MTP::MtProxy::EndpointUse::Main);
	if (!port.start(ticket, connection)) {
		return false;
	}
	connection.emitConnected();
	port.reportConnected(connection.use);
	return connection.connected
		&& port.successReports == 1
		&& port.lastSuccessUse == MTP::MtProxy::EndpointUse::Main;
}

[[nodiscard]] bool ScenarioAuthSuccess() {
	auto creator = FakeSessionAuthKeyCreator();
	creator.start();
	creator.succeed();
	return creator.succeeded && !creator.started;
}

[[nodiscard]] bool ScenarioAuthFailure() {
	auto creator = FakeSessionAuthKeyCreator();
	creator.start();
	creator.fail();
	return creator.failed && !creator.started;
}

[[nodiscard]] bool ScenarioReconnectAfterTimeout() {
	auto scheduler = ScriptedSessionScheduler();
	auto reconnects = 0;
	scheduler.callOnce(10, [&] { ++reconnects; });
	scheduler.advance(9);
	if (reconnects != 0) {
		return false;
	}
	scheduler.advance(1);
	return reconnects == 1;
}

[[nodiscard]] bool ScenarioCancelWhileAdmissionPending() {
	auto port = ScriptedSessionProxyPort();
	auto connection = FakeSessionConnection();
	const auto ticket = port.requestConnection(MTP::MtProxy::EndpointUse::Main);
	port.cancel(ticket);
	return !port.start(ticket, connection)
		&& !connection.started
		&& port.canceledTickets == 1;
}

[[nodiscard]] bool ScenarioRequestLifecycle() {
	auto connection = FakeSessionConnection();
	auto port = ScriptedSessionProxyPort();
	connection.emitReceivedData();
	port.reportReceiveTimeout(connection.receivedData);
	return connection.receivedCallbacks == 1
		&& port.receiveTimeoutReports == 1
		&& port.lastTimeoutHadData;
}

[[nodiscard]] bool ScenarioMainMediaRouting() {
	auto port = ScriptedSessionProxyPort();
	auto main = FakeSessionConnection();
	auto media = FakeSessionConnection();
	const auto mainTicket = port.requestConnection(
		MTP::MtProxy::EndpointUse::Main);
	const auto mediaTicket = port.requestConnection(
		MTP::MtProxy::EndpointUse::Media);
	return port.start(mainTicket, main)
		&& port.start(mediaTicket, media)
		&& main.use == MTP::MtProxy::EndpointUse::Main
		&& media.use == MTP::MtProxy::EndpointUse::Media;
}

} // namespace

int main(int, char *[]) {
	if (!ScenarioConnectionSuccess()) {
		return Fail("connection success scenario failed");
	} else if (!ScenarioAuthSuccess()) {
		return Fail("auth success scenario failed");
	} else if (!ScenarioAuthFailure()) {
		return Fail("auth failure scenario failed");
	} else if (!ScenarioReconnectAfterTimeout()) {
		return Fail("reconnect after timeout scenario failed");
	} else if (!ScenarioCancelWhileAdmissionPending()) {
		return Fail("cancel while admission pending scenario failed");
	} else if (!ScenarioRequestLifecycle()) {
		return Fail("request lifecycle scenario failed");
	} else if (!ScenarioMainMediaRouting()) {
		return Fail("main/media routing scenario failed");
	}
	return 0;
}

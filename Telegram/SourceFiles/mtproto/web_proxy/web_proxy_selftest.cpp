/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/web_proxy/web_proxy_selftest.h"

#include "base/invoke_queued.h"
#include "logs.h"
#include "mtproto/web_proxy/web_proxy_transport.h"
#include "mtproto/web_proxy/web_proxy_webview.h"

#include <QtCore/QCoreApplication>
#include <QtCore/QFile>
#include <QtCore/QTimer>
#include <crl/crl_time.h>
#include <rpl/lifetime.h>

#include <algorithm>
#include <vector>

namespace MTP::WebProxy {
namespace {

constexpr auto kPingInterval = crl::time(100);
constexpr auto kPumpInterval = 5;
constexpr auto kIdlePhase = crl::time(3000);
constexpr auto kPhaseTimeout = crl::time(180 * 1000);
constexpr auto kClientBacklog = int64(1024 * 1024);
constexpr auto kChunk = 64 * 1024;
constexpr auto kPingSize = 16;

struct Config {
	QString host;
	QString secret;
	int64 up = 32 * 1024 * 1024;
	int64 down = 32 * 1024 * 1024;
	int upStreams = 1;
	int downStreams = 1;
	QString ctl;
	QStringList nets;
};

[[nodiscard]] std::optional<Config> ParseConfig() {
	const auto value = qEnvironmentVariable("TDESKTOP_WEB_PROXY_SELFTEST");
	const auto parts = value.split(':');
	if (parts.size() < 2) {
		return std::nullopt;
	}
	auto result = Config{ .host = parts[0], .secret = parts[1] };
	for (auto i = 2; i < parts.size(); ++i) {
		const auto pair = parts[i].split('=');
		if (pair.size() != 2) {
			continue;
		} else if (pair[0] == u"ctl"_q) {
			result.ctl = pair[1];
			continue;
		} else if (pair[0] == u"net"_q) {
			result.nets = pair[1].split('|', Qt::SkipEmptyParts);
			continue;
		}
		const auto number = pair[1].toLongLong();
		if (number <= 0) {
			continue;
		} else if (pair[0] == u"up"_q) {
			result.up = number * 1024 * 1024;
		} else if (pair[0] == u"down"_q) {
			result.down = number * 1024 * 1024;
		} else if (pair[0] == u"ul"_q) {
			result.upStreams = int(std::min(number, 16LL));
		} else if (pair[0] == u"dl"_q) {
			result.downStreams = int(std::min(number, 16LL));
		}
	}
	return result;
}

[[nodiscard]] QByteArray Filler(int size) {
	auto result = QByteArray(size, Qt::Uninitialized);
	for (auto i = 0; i != size; ++i) {
		result[i] = char((i * 131) ^ (i >> 7));
	}
	return result;
}

class SelfTest final : public QObject {
public:
	SelfTest(not_null<Transport*> transport, Config config);

	void start();

private:
	enum class Phase {
		Idle,
		Upload,
		Download,
		Mixed,
		Done,
	};
	struct Stream {
		uint32 id = 0;
		std::shared_ptr<StreamProbe> probe;
		char kind = 0;
		int64 total = 0;
		int64 handed = 0;
		int64 received = 0;
		bool connected = false;
		bool done = false;
		crl::time finishedAt = 0;
		QByteArray buffer;
	};
	struct Snapshot {
		crl::time at = 0;
		int64 upWrites = 0;
		int64 upBytes = 0;
		int64 upAckMs = 0;
		int64 downMessages = 0;
		int64 downBytes = 0;
	};

	Stream &open(char kind, int64 total);
	void opened(uint32 id);
	void received(uint32 id, QByteArray data);
	void send(Stream &stream, QByteArray data);
	void tick();
	void pump(Stream &stream);
	void ping();
	void beginRound();
	void beginPhase(Phase phase);
	void finishPhase();
	[[nodiscard]] bool phaseDone();
	[[nodiscard]] Stream *find(uint32 id);
	[[nodiscard]] static Snapshot Take();
	[[nodiscard]] static QString PhaseName(Phase phase);

	const not_null<Transport*> _transport;
	const Config _config;
	const QByteArray _filler;
	std::vector<Stream> _streams;
	uint32 _pingId = 0;
	int64 _pingSequence = 0;
	std::vector<crl::time> _pings;
	Phase _phase = Phase::Idle;
	int _round = 0;
	Snapshot _phaseStart;
	crl::time _lastPing = 0;
	QTimer *_timer = nullptr;

};

SelfTest::SelfTest(not_null<Transport*> transport, Config config)
: _transport(transport)
, _config(std::move(config))
, _filler(Filler(kChunk)) {
}

void SelfTest::start() {
	LOG(("Web Proxy SelfTest: start, up %1 MB x%2, down %3 MB x%4."
		).arg(_config.up / (1024 * 1024)
		).arg(_config.upStreams
		).arg(_config.down / (1024 * 1024)
		).arg(_config.downStreams));
	_pingId = open('E', 0).id;
	_timer = new QTimer(this);
	_timer->setInterval(kPumpInterval);
	QObject::connect(_timer, &QTimer::timeout, this, [=] { tick(); });
	_timer->start();
	beginRound();
}

void SelfTest::beginRound() {
	if (_round < _config.nets.size() && !_config.ctl.isEmpty()) {
		auto file = QFile(_config.ctl);
		if (file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
			file.write(_config.nets[_round].toUtf8().replace('/', ' '));
		}
		LOG(("Web Proxy SelfTest: round %1 net %2."
			).arg(_round + 1
			).arg(_config.nets[_round]));
	}
	beginPhase(Phase::Idle);
}

auto SelfTest::open(char kind, int64 total) -> Stream & {
	_streams.push_back({
		.id = Transport::NextStreamId(),
		.probe = std::make_shared<StreamProbe>(),
		.kind = kind,
		.total = total,
	});
	auto &stream = _streams.back();
	const auto id = stream.id;
	_transport->registerStream(id, {
		.context = this,
		.connected = [=] { opened(id); },
		.data = [=](QByteArray data) { received(id, std::move(data)); },
		.disconnected = [=] {
			LOG(("Web Proxy SelfTest: stream %1 closed by relay.").arg(id));
		},
		.failed = [=] {
			LOG(("Web Proxy SelfTest: stream %1 failed.").arg(id));
		},
		.streamClass = (kind == 'S')
			? StreamClass::Upload
			: (kind == 'D')
			? StreamClass::Download
			: StreamClass::Interactive,
		.probe = stream.probe,
	});
	return stream;
}

SelfTest::Stream *SelfTest::find(uint32 id) {
	const auto i = ranges::find(_streams, id, &Stream::id);
	return (i != end(_streams)) ? &*i : nullptr;
}

void SelfTest::send(Stream &stream, QByteArray data) {
	stream.handed += data.size();
	_transport->sendData(stream.id, std::move(data));
}

void SelfTest::opened(uint32 id) {
	const auto stream = find(id);
	if (!stream) {
		return;
	}
	stream->connected = true;
	auto tag = QByteArray(1, stream->kind);
	if (stream->kind == 'D') {
		const auto size = uint32(stream->total);
		tag.append(char(size >> 24));
		tag.append(char(size >> 16));
		tag.append(char(size >> 8));
		tag.append(char(size));
	}
	send(*stream, tag);
}

void SelfTest::received(uint32 id, QByteArray data) {
	const auto stream = find(id);
	if (!stream) {
		return;
	}
	stream->received += data.size();
	_transport->grantWindow(id, uint32(data.size()));
	if (stream->kind != 'E') {
		return;
	}
	stream->buffer.append(data);
	const auto now = crl::now();
	while (stream->buffer.size() >= kPingSize) {
		auto sent = int64();
		memcpy(&sent, stream->buffer.constData(), sizeof(sent));
		stream->buffer.remove(0, kPingSize);
		_pings.push_back(now - sent);
	}
}

void SelfTest::pump(Stream &stream) {
	if (!stream.connected || stream.kind != 'S') {
		return;
	}
	while (stream.handed < stream.total + 1) {
		const auto inClient = stream.handed - stream.probe->sentBytes.load();
		if (inClient >= kClientBacklog) {
			break;
		}
		const auto left = stream.total + 1 - stream.handed;
		send(stream, (left >= kChunk) ? _filler : _filler.left(int(left)));
	}
}

void SelfTest::ping() {
	const auto stream = find(_pingId);
	if (!stream || !stream->connected) {
		return;
	}
	const auto now = crl::now();
	if (now - _lastPing < kPingInterval) {
		return;
	}
	_lastPing = now;
	auto data = QByteArray(kPingSize, char(0));
	memcpy(data.data(), &now, sizeof(now));
	++_pingSequence;
	memcpy(data.data() + 8, &_pingSequence, sizeof(_pingSequence));
	send(*stream, data);
}

void SelfTest::tick() {
	if (_phase == Phase::Done) {
		return;
	}
	ping();
	for (auto &stream : _streams) {
		pump(stream);
	}
	const auto now = crl::now();
	if (phaseDone() || (now - _phaseStart.at > kPhaseTimeout)) {
		finishPhase();
	}
}

bool SelfTest::phaseDone() {
	if (_phase == Phase::Idle) {
		return (crl::now() - _phaseStart.at >= kIdlePhase);
	}
	auto any = false;
	auto all = true;
	for (auto &stream : _streams) {
		if (stream.kind == 'E' || stream.done) {
			continue;
		}
		any = true;
		const auto finished = (stream.kind == 'S')
			? (stream.probe->sentBytes.load()
				- stream.probe->unackedBytes.load() >= stream.total + 1)
			: (stream.received >= stream.total);
		if (!finished) {
			all = false;
		} else if (!stream.finishedAt) {
			stream.finishedAt = crl::now();
		}
	}
	return any && all;
}

SelfTest::Snapshot SelfTest::Take() {
	const auto &bridge = Bridge();
	return {
		.at = crl::now(),
		.upWrites = bridge.upWrites.load(),
		.upBytes = bridge.upBytes.load(),
		.upAckMs = bridge.upAckMsTotal.load(),
		.downMessages = bridge.downMessages.load(),
		.downBytes = bridge.downBytes.load(),
	};
}

QString SelfTest::PhaseName(Phase phase) {
	switch (phase) {
	case Phase::Idle: return u"idle"_q;
	case Phase::Upload: return u"upload"_q;
	case Phase::Download: return u"download"_q;
	case Phase::Mixed: return u"mixed"_q;
	case Phase::Done: return u"done"_q;
	}
	return QString();
}

void SelfTest::beginPhase(Phase phase) {
	_phase = phase;
	_phaseStart = Take();
	_pings.clear();
	const auto up = (phase == Phase::Upload || phase == Phase::Mixed);
	const auto down = (phase == Phase::Download || phase == Phase::Mixed);
	if (up) {
		for (auto i = 0; i != _config.upStreams; ++i) {
			open('S', _config.up / _config.upStreams);
		}
	}
	if (down) {
		for (auto i = 0; i != _config.downStreams; ++i) {
			open('D', _config.down / _config.downStreams);
		}
	}
}

void SelfTest::finishPhase() {
	const auto end = Take();
	const auto seconds = std::max(end.at - _phaseStart.at, crl::time(1))
		/ 1000.;
	auto up = int64();
	auto down = int64();
	auto upEnd = _phaseStart.at;
	auto downEnd = _phaseStart.at;
	for (auto &stream : _streams) {
		if (stream.kind == 'E' || stream.done) {
			continue;
		}
		const auto finished = stream.finishedAt
			? stream.finishedAt
			: end.at;
		if (stream.kind == 'S') {
			up += stream.probe->sentBytes.load()
				- stream.probe->unackedBytes.load();
			upEnd = std::max(upEnd, finished);
		} else {
			down += stream.received;
			downEnd = std::max(downEnd, finished);
		}
		stream.done = true;
		_transport->closeStream(stream.id);
	}
	auto pings = _pings;
	ranges::sort(pings);
	const auto percentile = [&](int percent) {
		return pings.empty()
			? crl::time(-1)
			: pings[std::min(
				int(pings.size()) - 1,
				int(pings.size()) * percent / 100)];
	};
	const auto writes = end.upWrites - _phaseStart.upWrites;
	const auto messages = end.downMessages - _phaseStart.downMessages;
	const auto mb = [&](int64 bytes) {
		return QString::number(bytes / seconds / (1024. * 1024.), 'f', 2);
	};
	const auto rate = [&](int64 bytes, crl::time till) {
		const auto spent = std::max(till - _phaseStart.at, crl::time(1));
		return QString::number(
			bytes * 1000. / spent / (1024. * 1024.),
			'f',
			2);
	};
	LOG(("Web Proxy SelfTest: phase=%1 seconds=%2 up_MBps=%3 down_MBps=%4 "
		"ping_n=%5 ping_p50=%6 ping_p95=%7 ping_max=%8 "
		"bridge_up_writes=%9 bridge_up_avg_bytes=%10 bridge_up_ack_avg_ms=%11 "
		"bridge_up_MBps=%12 bridge_down_msgs=%13 bridge_down_avg_bytes=%14 "
		"bridge_down_MBps=%15"
		).arg(PhaseName(_phase)
		).arg(seconds, 0, 'f', 2
		).arg(rate(up, upEnd)
		).arg(rate(down, downEnd)
		).arg(pings.size()
		).arg(percentile(50)
		).arg(percentile(95)
		).arg(pings.empty() ? -1 : pings.back()
		).arg(writes
		).arg(writes ? ((end.upBytes - _phaseStart.upBytes) / writes) : 0
		).arg(writes ? ((end.upAckMs - _phaseStart.upAckMs) / double(writes)) : 0., 0, 'f', 2
		).arg(mb(end.upBytes - _phaseStart.upBytes)
		).arg(messages
		).arg(messages ? ((end.downBytes - _phaseStart.downBytes) / messages) : 0
		).arg(mb(end.downBytes - _phaseStart.downBytes)));
	switch (_phase) {
	case Phase::Idle: beginPhase(Phase::Upload); break;
	case Phase::Upload: beginPhase(Phase::Download); break;
	case Phase::Download: beginPhase(Phase::Mixed); break;
	case Phase::Mixed:
		if (++_round < _config.nets.size()) {
			beginRound();
			break;
		}
		_phase = Phase::Done;
		_timer->stop();
		_transport->closeStream(_pingId);
		LOG(("Web Proxy SelfTest: done."));
		break;
	case Phase::Done: break;
	}
}

[[nodiscard]] rpl::lifetime &SelfTestLifetime() {
	static auto result = rpl::lifetime();
	return result;
}

} // namespace

std::optional<ProxyData> SelfTestProxy() {
	const auto config = ParseConfig();
	if (!config) {
		return std::nullopt;
	}
	auto result = ProxyData();
	result.type = ProxyData::Type::Web;
	result.host = config->host;
	result.port = 443;
	result.password = config->secret;
	return result.valid() ? std::make_optional(result) : std::nullopt;
}

void StartSelfTest() {
	const auto config = ParseConfig();
	if (!config) {
		return;
	}
	const auto proxy = SelfTestProxy();
	if (!proxy) {
		LOG(("Web Proxy SelfTest: bad TDESKTOP_WEB_PROXY_SELFTEST value."));
		return;
	}
	const auto launch = [config = *config] {
		const auto transport = Transport::Instance();
		if (!transport) {
			return;
		}
		const auto test = new SelfTest(transport, config);
		test->moveToThread(transport->thread());
		InvokeQueued(test, [=] { test->start(); });
	};
	if (Transport::CurrentState(*proxy) == Transport::State::Connected) {
		launch();
		return;
	}
	Transport::StateChanges(
	) | rpl::filter([=](const Transport::StateChange &change) {
		return (change.proxy == *proxy)
			&& (change.state == Transport::State::Connected);
	}) | rpl::take(1) | rpl::on_next([=] {
		launch();
	}, SelfTestLifetime());
}

} // namespace MTP::WebProxy

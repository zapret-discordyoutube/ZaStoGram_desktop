/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/web_proxy/web_proxy_transport.h"

#include "base/bytes.h"
#include "base/flat_map.h"
#include "base/flat_set.h"
#include "base/invoke_queued.h"
#include "core/file_utilities.h"
#include "logs.h"
#include "mtproto/proxy/diagnostics.h"
#include "mtproto/web_proxy/web_proxy_frame.h"
#include "mtproto/web_proxy/web_proxy_webview.h"

#include <QtCore/QCoreApplication>
#include <QtCore/QCryptographicHash>
#include <QtCore/QDateTime>
#include <QtCore/QJsonArray>
#include <QtCore/QJsonDocument>
#include <QtCore/QJsonObject>
#include <QtCore/QMap>
#include <QtCore/QPointer>
#include <QtCore/QThread>
#include <QtCore/QTimer>
#include <QtCore/QUrl>
#include <QtNetwork/QHostAddress>
#include <QtNetwork/QTcpServer>
#include <QtNetwork/QTcpSocket>
#include <crl/crl_time.h>
#include <rpl/event_stream.h>

#include <algorithm>
#include <atomic>
#include <deque>
#include <limits>

namespace MTP::WebProxy {
namespace {

constexpr auto kMaxHttpHeaderSize = 16 * 1024;
constexpr auto kMaxLocalWebSocketPayload = 2 * 1024 * 1024;
constexpr auto kMaxPendingStreamBytes = 8 * 1024 * 1024;
constexpr auto kMaxPendingStreamItems = 1024;
constexpr auto kMaxPendingTransportBytes = 64 * 1024 * 1024;
constexpr auto kMaxPendingTransportItems = 8192;
constexpr auto kMaxLocalSocketPendingBytes = 4 * 1024 * 1024;
constexpr auto kLocalSocketControlReserve = 64 * 1024;
constexpr auto kMaxPendingControlBytes = 64 * 1024;
constexpr auto kMaxPendingControlFrames = 1024;
constexpr auto kMaxFlushFramesPerTurn = 256;
constexpr auto kDataFrameSize = 64 * 1024;
constexpr auto kMaxLocalClients = 32;
constexpr auto kMaxClosedStreamIds = 4096;
constexpr auto kMaxWebviewPendingItems = 512;
constexpr auto kWebviewItemsControlReserve = 64;
constexpr auto kWindowFlushBytes = 256 * 1024;
constexpr auto kWindowFlushDelay = crl::time(20);
constexpr auto kCapabilityLifetime = crl::time(5 * 60 * 1000);
constexpr auto kLocalClientHandshakeTimeout = crl::time(10 * 1000);
constexpr auto kWelcomeTimeout = crl::time(30 * 1000);
constexpr auto kWriteProgressTimeout = crl::time(30 * 1000);
constexpr auto kWebviewRetryMinTimeout = crl::time(2 * 1000);
constexpr auto kWebviewRetryMaxTimeout = crl::time(30 * 1000);
constexpr auto kWebviewCloseGrace = crl::time(200);
constexpr auto kMaxWebviewFailures = 3;
constexpr auto kHealthCheckInterval = crl::time(2 * 1000);

// Frames written within one turn of the carrier thread go to the WebView
// bridge as one batch, flushed early at this size.
constexpr auto kBridgeBatchBytes = 1024 * 1024;

// How often the adaptive windows are fed with what the carrier delivered:
// once per base round trip, within these bounds.
constexpr auto kFlowUpdateMinInterval = crl::time(50);
constexpr auto kFlowUpdateMaxInterval = crl::time(200);

// A direction counts as busy for the other one this long after it was
// last limited by its window (see FlowSample::extraDelay).
constexpr auto kBusyMemory = crl::time(1000);

// Every kProbeInterval of busy carrier both windows drop to their floors
// for a round trip (at least kProbeMinDuration), so that frames sent then
// measure the path without the queues (see AdaptiveWindow).
constexpr auto kProbeInterval = crl::time(20 * 1000);
constexpr auto kProbeMinDuration = crl::time(200);

// Upload bytes the relay has not credited yet, sized by AdaptiveWindow.
// It starts at one relay stream window, what one upstream upload session
// may have in flight, so a burst is never slower than without shaping;
// on a slow uplink that first window is queued in front of chats once
// (a few seconds at 400 KB/s, against 40 s with upstream's sessions) and
// the window then settles at the target delay. The floor lets that queue
// drop below the target on such an uplink (upload frames shrink with it,
// see UplinkLimits::minUploadFrame), the ceiling is four such windows.
constexpr auto kUploadWindowInitial = int64(4 * 1024 * 1024);
constexpr auto kUploadWindowMin = int64(16 * 1024);
constexpr auto kUploadWindowMax = int64(16 * 1024 * 1024);

// Credit shared by download streams, same idea for the relay's downlink.
// It starts at what one stream gets from the protocol anyway, so a fresh
// carrier is never slower than without shaping, and it may grow to four
// such windows.
constexpr auto kDownloadBudgetInitial = int64(4 * 1024 * 1024);
constexpr auto kDownloadBudgetMin = int64(256 * 1024);
constexpr auto kDownloadBudgetMax = int64(16 * 1024 * 1024);
constexpr auto kDownloadStreamMin = int64(64 * 1024);
constexpr auto kHealthSummaryInterval = crl::time(10 * 1000);
constexpr auto kWebSocketGuid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

struct Globals {
	std::unique_ptr<QThread> thread;
	QPointer<Transport> transport;
	std::atomic<Transport*> available = nullptr;
	std::atomic<bool> webActive = false;
	std::unique_ptr<WebviewCarrier> webview;
	std::vector<std::unique_ptr<WebviewCarrier>> closingWebviews;
	ProxyData active;
	Transport::State state = Transport::State::Idle;
	QString browser;
	rpl::event_stream<Transport::StateChange> changes;
	uint64 webviewGeneration = 0;
	crl::time webviewRetryDelay = kWebviewRetryMinTimeout;
	int webviewFailures = 0;
	bool webviewRetryScheduled = false;
	bool webviewDisabled = false;
	bool webviewSupported = false;
};

[[nodiscard]] Globals &Global() {
	static const auto result = new Globals();
	return *result;
}

[[nodiscard]] QString JsonString(const QString &value) {
	const auto json = QJsonDocument(QJsonArray{ value }).toJson(
		QJsonDocument::Compact);
	return QString::fromUtf8(json.mid(1, json.size() - 2));
}

[[nodiscard]] QString RandomUrlToken(int bytesCount) {
	auto random = bytes::vector(bytesCount);
	bytes::set_random(bytes::make_span(random));
	return QString::fromLatin1(QByteArray(
		reinterpret_cast<const char*>(random.data()),
		random.size()
	).toBase64(
		QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals));
}

[[nodiscard]] QByteArray WebSocketFrame(uchar opcode, const QByteArray &payload) {
	auto result = QByteArray();
	result.reserve(payload.size() + 10);
	result.append(char(0x80 | opcode));
	const auto size = uint64(payload.size());
	if (size < 126) {
		result.append(char(size));
	} else if (size <= 0xFFFF) {
		result.append(char(126));
		result.append(char(size >> 8));
		result.append(char(size));
	} else {
		result.append(char(127));
		for (auto shift = 56; shift >= 0; shift -= 8) {
			result.append(char(size >> shift));
		}
	}
	result.append(payload);
	return result;
}

[[nodiscard]] int WebSocketHeaderSize(int payloadSize) {
	return (payloadSize < 126) ? 2 : (payloadSize <= 0xFFFF) ? 4 : 10;
}

[[nodiscard]] bool HeaderHasToken(
		const QByteArray &header,
		const QByteArray &token) {
	for (const auto &part : header.toLower().split(',')) {
		if (part.trimmed() == token) {
			return true;
		}
	}
	return false;
}

[[nodiscard]] QByteArray WindowPayload(uint32 amount) {
	auto result = QByteArray(4, Qt::Uninitialized);
	auto data = reinterpret_cast<uchar*>(result.data());
	data[0] = uchar(amount >> 24);
	data[1] = uchar(amount >> 16);
	data[2] = uchar(amount >> 8);
	data[3] = uchar(amount);
	return result;
}

[[nodiscard]] uint32 ReadWindow(const QByteArray &payload) {
	Expects(payload.size() == 4);

	const auto data = reinterpret_cast<const uchar*>(payload.constData());
	return (uint32(data[0]) << 24)
		| (uint32(data[1]) << 16)
		| (uint32(data[2]) << 8)
		| uint32(data[3]);
}

void PublishState(
		const ProxyData &proxy,
		Transport::State state,
		const QString &browser) {
	InvokeQueued(QCoreApplication::instance(), [=] {
		auto &global = Global();
		if (global.active != proxy) {
			return;
		}
		global.state = state;
		global.browser = browser;
		global.changes.fire({ proxy, state, browser });
	});
}

void RetireWebview(std::unique_ptr<WebviewCarrier> webview) {
	if (!webview) {
		return;
	}
	auto &global = Global();
	const auto raw = webview.get();
	raw->close();
	global.closingWebviews.push_back(std::move(webview));
	QTimer::singleShot(
		int(kWebviewCloseGrace),
		QCoreApplication::instance(),
		[=] {
			auto &list = Global().closingWebviews;
			const auto i = ranges::find(
				list,
				raw,
				&std::unique_ptr<WebviewCarrier>::get);
			if (i != end(list)) {
				list.erase(i);
			}
		});
}

} // namespace

class Transport::Private {
public:
	explicit Private(not_null<Transport*> owner);

	void configure(const ProxyData &proxy);
	void deactivate();
	void stop();
	[[nodiscard]] QString mintBrowserUrl();

	void registerStream(uint32 streamId, StreamHandlers handlers);
	void closeStream(uint32 streamId);
	void sendData(uint32 streamId, QByteArray data);
	void grantWindow(uint32 streamId, uint32 amount);
	void failStream(uint32 streamId);
	void webviewStarting(uint64 generation);
	void webviewReady(uint64 generation);
	void webviewPayload(uint64 generation, const QByteArray &payload);
	void webviewWritten(uint64 generation, int bytes, int items);
	void webviewFailed(uint64 generation);
	void webviewUnavailable();

private:
	struct Client {
		QByteArray input;
		QByteArray fragmented;
		uchar fragmentedOpcode = 0;
		bool webSocket = false;
		bool authenticated = false;
	};
	struct Stream {
		struct Pending {
			QByteArray data;
			int offset = 0;
		};

		explicit Stream(StreamHandlers handlers)
		: context(std::move(handlers.context))
		, connected(std::move(handlers.connected))
		, data(std::move(handlers.data))
		, disconnected(std::move(handlers.disconnected))
		, failed(std::move(handlers.failed))
		, probe(std::move(handlers.probe))
		, streamClass(handlers.streamClass) {
		}

		std::deque<Pending> pending;
		QPointer<QObject> context;
		Fn<void()> connected;
		Fn<void(QByteArray)> data;
		Fn<void()> disconnected;
		Fn<void()> failed;
		std::shared_ptr<StreamProbe> probe;
		StreamClass streamClass = StreamClass::Interactive;
		uint64 sendWindow = kInitialStreamWindow;
		uint32 receiveWindow = kInitialStreamWindow;
		uint32 pendingWindow = 0;

		// Read by the socket but not returned to the relay yet: download
		// streams get only a share of the protocol window, see
		// DownlinkCreditTarget().
		uint32 withheldWindow = 0;

		// Written to the carrier and not yet credited back by the relay.
		int64 unacked = 0;

		// (total written after the frame, when) for credit round trips.
		std::deque<std::pair<int64, crl::time>> sentLog;
		int64 sentTotal = 0;
		int64 creditedTotal = 0;

		// Interactive streams: when the first unanswered write went out.
		crl::time awaitingSince = 0;

		int pendingBytes = 0;
		bool opened = false;
	};
	struct Traffic {
		int64 up = 0;
		int64 down = 0;
		int64 withheldPeak = 0;
		int uploadBlocked = 0;
		int probes = 0;
		int flooded = 0;
		std::optional<crl::time> rttMin;
		std::optional<crl::time> interactiveMin;
		std::optional<crl::time> interactiveMax;
	};
	struct FlowInterval {
		crl::time startedAt = 0;
		int64 upCredited = 0;
		int64 downReceived = 0;
		bool upLimited = false;
		bool downLimited = false;
		std::optional<crl::time> rtt;
		std::optional<crl::time> interactive;
	};

	[[nodiscard]] bool ensureServer();
	void stopListening();
	void acceptClients();
	void clientReadyRead(not_null<QTcpSocket*> socket);
	void clientDisconnected(not_null<QTcpSocket*> socket);
	void processHttp(not_null<QTcpSocket*> socket, Client &client);
	void processWebSocket(not_null<QTcpSocket*> socket);
	void processWebSocketMessage(
		not_null<QTcpSocket*> socket,
		Client &client,
		uchar opcode,
		QByteArray payload);
	void processBrowserControl(
		not_null<QTcpSocket*> socket,
		Client &client,
		const QByteArray &payload);
	void processRelayPayload(const QByteArray &payload);
	bool processRelayFrame(const Frame &frame);

	void authenticateBrowser(
		not_null<QTcpSocket*> socket,
		const QString &token,
		const QString &browser);
	void writeWebSocket(
		not_null<QTcpSocket*> socket,
		uchar opcode,
		const QByteArray &payload);
	void closeWebSocket(
		not_null<QTcpSocket*> socket,
		uint16 code);
	void writeHttp(
		not_null<QTcpSocket*> socket,
		QByteArray status,
		QByteArray contentType,
		QByteArray body,
		QByteArray extraHeaders = QByteArray());
	[[nodiscard]] QByteArray page(const QString &nonce) const;
	[[nodiscard]] QByteArray pageHeaders(const QString &nonce) const;
	[[nodiscard]] QByteArray bridgeControl() const;

	void sendFrame(
		FrameType type,
		uint32 streamId,
		const QByteArray &payload = QByteArray());
	void queueControlFrame(QByteArray frame);
	void flushControlFrames();
	void scheduleWindowFlush();
	void flushWindows();
	void ensureWriteProgressCheck();
	void browserBytesWritten();
	void writeCarrierFrame(QByteArray frame);
	[[nodiscard]] bool carrierAvailable() const;
	[[nodiscard]] int carrierPendingBytes() const;
	[[nodiscard]] int carrierPendingItems() const;
	[[nodiscard]] bool carrierAccepts(int frameSize, bool control) const;
	[[nodiscard]] int carrierFrameSize(int payloadSize) const;
	void markStreamReady(uint32 streamId);
	void forgetStream(uint32 streamId, Stream &stream);
	void flushStreams();
	void flushStream(uint32 streamId, int maxBytes);
	void publishStream(const Stream &stream);
	void publishConnected();
	void addUnacked(Stream &stream, int64 bytes);
	void noteRtt(crl::time rtt);
	void noteInteractive(crl::time delay);
	void updateFlow(crl::time now);
	void flushWebviewBatch();
	void creditUnacked(uint32 streamId, Stream &stream, int64 bytes);
	[[nodiscard]] bool releaseDownlinkCredit(Stream &stream);
	void rebalanceDownlinkCredit();
	void scheduleHealthCheck();
	void checkHealth();
	void recoverStalledCarrier(crl::time silence);
	void logCarrier(ProxyDiagnosticsSeverity severity, const QString &text);
	void logSummary(crl::time now);
	[[nodiscard]] QString flowSummary(const Traffic &traffic);
	void releasePending(Stream &stream);
	void rememberClosedStream(uint32 streamId);
	void notifyConnected(const Stream &stream);
	void notifyData(const Stream &stream, QByteArray data);
	void notifyDisconnected(const Stream &stream);
	void notifyFailed(const Stream &stream);
	void welcome();
	void loseBrowser(bool failed);
	void closeAllStreams(bool failed);
	void protocolError();
	void setState(State state, const QString &browser = QString());

	const not_null<Transport*> _owner;
	std::unique_ptr<QTcpServer> _server;
	base::flat_map<QTcpSocket*, Client> _clients;
	base::flat_map<uint32, Stream> _streams;
	UplinkScheduler _scheduler;
	DownlinkLimits _downlinkLimits;
	AdaptiveWindow _upWindow;
	AdaptiveWindow _downWindow;
	FlowInterval _flow;
	crl::time _probeUntil = 0;
	crl::time _nextProbeAt = 0;
	crl::time _upLimitedAt = 0;
	crl::time _downLimitedAt = 0;
	void applyWindows(crl::time now);
	QByteArray _webviewBatch;
	bool _webviewBatchScheduled = false;
	const LivenessLimits _livenessLimits;
	int _downloadStreams = 0;
	int64 _totalUnacked = 0;
	Traffic _traffic;
	crl::time _lastSummaryAt = 0;
	int64 _lastBridgeWrites = 0;
	int64 _lastBridgeBytes = 0;
	int64 _lastBridgeAckMs = 0;
	int64 _lastBridgeDownMessages = 0;
	bool _healthCheckScheduled = false;
	base::flat_set<uint32> _closedStreams;
	std::deque<uint32> _closedStreamOrder;
	std::deque<QByteArray> _controlFrames;
	int _controlBytes = 0;
	QPointer<QTcpSocket> _browserSocket;
	ProxyData _proxy;
	QString _pendingToken;
	crl::time _pendingTokenExpiresAt = 0;
	QString _browser;
	State _state = State::Idle;
	uint64 _webviewCandidateGeneration = 0;
	uint64 _webviewGeneration = 0;
	int _webviewPendingBytes = 0;
	int _webviewPendingItems = 0;
	quint16 _serverPort = 0;
	bool _welcomed = false;
	bool _browserWriteFailed = false;
	bool _writeProgressCheckScheduled = false;
	bool _windowFlushScheduled = false;
	crl::time _lastWriteProgress = 0;

};

Transport::Private::Private(not_null<Transport*> owner)
: _owner(owner)
, _scheduler(UplinkLimits{
	.frameSize = kDataFrameSize,
	.uploadInFlight = kUploadWindowInitial,
})
, _downlinkLimits{
	.streamWindow = kInitialStreamWindow,
	.downloadBudget = kDownloadBudgetInitial,
	.downloadMin = kDownloadStreamMin,
}
, _upWindow({
	.initial = kUploadWindowInitial,
	.min = kUploadWindowMin,
	.max = kUploadWindowMax,
	.blindMax = kUploadWindowInitial,
})
, _downWindow({
	.initial = kDownloadBudgetInitial,
	.min = kDownloadBudgetMin,
	.max = kDownloadBudgetMax,
	.blindMax = kDownloadBudgetInitial,
}) {
}

void Transport::Private::configure(const ProxyData &proxy) {
	Expects(QThread::currentThread() == _owner->thread());
	Expects(proxy.type == ProxyData::Type::Web);

	if (_proxy == proxy) {
		return;
	}
	deactivate();
	_proxy = proxy;
	setState(State::Connecting);
}

void Transport::Private::deactivate() {
	Expects(QThread::currentThread() == _owner->thread());

	closeAllStreams(false);
	const auto sockets = _clients | ranges::views::keys | ranges::to_vector;
	_clients.clear();
	_browserSocket = nullptr;
	for (const auto socket : sockets) {
		socket->disconnectFromHost();
		socket->deleteLater();
	}
	_closedStreams.clear();
	_closedStreamOrder.clear();
	_scheduler.clear();
	_controlFrames.clear();
	_controlBytes = 0;
	_pendingToken.clear();
	_pendingTokenExpiresAt = 0;
	_browser.clear();
	_webviewCandidateGeneration = 0;
	_webviewGeneration = 0;
	_webviewPendingBytes = 0;
	_webviewBatch = QByteArray();
	_webviewPendingItems = 0;
	_welcomed = false;
	_browserWriteFailed = false;
	_writeProgressCheckScheduled = false;
	_lastWriteProgress = 0;
	if (_server) {
		_server->close();
		_server = nullptr;
	}
	_serverPort = 0;
	_proxy = ProxyData();
	_state = State::Idle;
	_traffic = Traffic();
	_lastSummaryAt = 0;
	_flow = FlowInterval();
	_probeUntil = 0;
	_nextProbeAt = 0;
	_upLimitedAt = 0;
	_downLimitedAt = 0;
	_upWindow.reset();
	_downWindow.reset();
	_scheduler.setUploadInFlight(_upWindow.window());
	_downlinkLimits.downloadBudget = _downWindow.window();
	publishConnected();
}

void Transport::Private::stop() {
	deactivate();
}

QString Transport::Private::mintBrowserUrl() {
	Expects(QThread::currentThread() == _owner->thread());

	if (!_proxy || !ensureServer()) {
		return QString();
	}
	_pendingToken = RandomUrlToken(32);
	_pendingTokenExpiresAt = crl::now() + kCapabilityLifetime;
	const auto expiresAt = _pendingTokenExpiresAt;
	QTimer::singleShot(int(kCapabilityLifetime), _owner, [=] {
		if (_pendingTokenExpiresAt == expiresAt) {
			_pendingToken.clear();
			_pendingTokenExpiresAt = 0;
			stopListening();
		}
	});
	return u"http://127.0.0.1:%1/#%2"_q
		.arg(_serverPort)
		.arg(_pendingToken);
}

bool Transport::Private::ensureServer() {
	if (_server && _server->isListening()) {
		return true;
	} else if (!_server) {
		_server = std::make_unique<QTcpServer>();
		QObject::connect(
			_server.get(),
			&QTcpServer::newConnection,
			_owner,
			[=] { acceptClients(); });
	}
	if (!_server->listen(QHostAddress::LocalHost, 0)) {
		return false;
	}
	_serverPort = _server->serverPort();
	return true;
}

void Transport::Private::stopListening() {
	if (_server && _server->isListening()) {
		_server->close();
	}
}

void Transport::Private::acceptClients() {
	while (_server && _server->hasPendingConnections()) {
		const auto socket = _server->nextPendingConnection();
		if (!socket->peerAddress().isLoopback()
			|| _clients.size() >= kMaxLocalClients) {
			socket->disconnectFromHost();
			socket->deleteLater();
			continue;
		}
		_clients.emplace(socket, Client());
		QObject::connect(
			socket,
			&QTcpSocket::readyRead,
			_owner,
			[=] { clientReadyRead(socket); });
		QObject::connect(
			socket,
			&QTcpSocket::disconnected,
			_owner,
			[=] { clientDisconnected(socket); });
		QObject::connect(
			socket,
			&QTcpSocket::bytesWritten,
			_owner,
			[=] {
				if (_browserSocket == socket) {
					browserBytesWritten();
				}
			});
		const auto guard = QPointer<QTcpSocket>(socket);
		QTimer::singleShot(int(kLocalClientHandshakeTimeout), _owner, [=] {
			if (!guard) {
				return;
			}
			const auto i = _clients.find(guard.data());
			if (i != end(_clients) && !i->second.authenticated) {
				guard->abort();
			}
		});
	}
}

void Transport::Private::clientReadyRead(not_null<QTcpSocket*> socket) {
	while (socket->bytesAvailable() > 0) {
		const auto i = _clients.find(socket);
		if (i == end(_clients)) {
			return;
		}
		auto &client = i->second;
		const auto limit = client.webSocket
			? kDataFrameSize
			: (kMaxHttpHeaderSize + 1);
		const auto chunk = socket->read(limit);
		if (chunk.isEmpty()) {
			return;
		}
		client.input.append(chunk);
		if (client.webSocket) {
			processWebSocket(socket);
		} else {
			processHttp(socket, client);
		}
		if (socket->state() != QAbstractSocket::ConnectedState) {
			return;
		}
	}
}

void Transport::Private::clientDisconnected(not_null<QTcpSocket*> socket) {
	const auto browser = (_browserSocket == socket.get());
	_clients.erase(socket.get());
	socket->deleteLater();
	if (browser) {
		_browserSocket = nullptr;
		_browserWriteFailed = false;
		_controlFrames.clear();
		_controlBytes = 0;
		_writeProgressCheckScheduled = false;
		_lastWriteProgress = 0;
		loseBrowser(_state == State::Failed);
	}
}

void Transport::Private::processHttp(
		not_null<QTcpSocket*> socket,
		Client &client) {
	if (client.input.size() > kMaxHttpHeaderSize) {
		writeHttp(socket, "431 Request Header Fields Too Large", "text/plain", {});
		return;
	}
	const auto end = client.input.indexOf("\r\n\r\n");
	if (end < 0) {
		return;
	}
	const auto headerData = client.input.left(end);
	client.input.remove(0, end + 4);
	const auto lines = headerData.split('\n');
	if (lines.empty()) {
		writeHttp(socket, "400 Bad Request", "text/plain", {});
		return;
	}
	const auto request = lines.front().trimmed().split(' ');
	if (request.size() != 3
		|| request[0] != "GET"
		|| request[2] != "HTTP/1.1") {
		writeHttp(socket, "400 Bad Request", "text/plain", {});
		return;
	}
	auto headers = QMap<QByteArray, QByteArray>();
	for (auto i = 1; i != lines.size(); ++i) {
		const auto line = lines[i].trimmed();
		const auto colon = line.indexOf(':');
		if (colon <= 0) {
			writeHttp(socket, "400 Bad Request", "text/plain", {});
			return;
		}
		const auto name = line.left(colon).trimmed().toLower();
		if (name.isEmpty() || headers.contains(name)) {
			writeHttp(socket, "400 Bad Request", "text/plain", {});
			return;
		}
		headers.insert(name, line.mid(colon + 1).trimmed());
	}
	if (headers.contains("content-length")
		|| headers.contains("transfer-encoding")) {
		writeHttp(socket, "400 Bad Request", "text/plain", {});
		return;
	}
	const auto expectedHost = QByteArray("127.0.0.1:")
		+ QByteArray::number(_serverPort);
	if (headers.value("host") != expectedHost) {
		writeHttp(socket, "403 Forbidden", "text/plain", {});
		return;
	}
	const auto path = request[1];
	if (path == "/") {
		const auto nonce = RandomUrlToken(18);
		writeHttp(
			socket,
			"200 OK",
			"text/html; charset=utf-8",
			page(nonce),
			pageHeaders(nonce));
		return;
	}
	if (path != "/transport"
		|| headers.value("upgrade").toLower() != "websocket"
		|| !HeaderHasToken(headers.value("connection"), "upgrade")
		|| headers.value("sec-websocket-version") != "13") {
		writeHttp(socket, "404 Not Found", "text/plain", {});
		return;
	}
	const auto expectedOrigin = QByteArray("http://") + expectedHost;
	const auto key = headers.value("sec-websocket-key");
	if (headers.value("origin") != expectedOrigin
		|| QByteArray::fromBase64(
			key,
			QByteArray::AbortOnBase64DecodingErrors).size() != 16) {
		writeHttp(socket, "403 Forbidden", "text/plain", {});
		return;
	}
	const auto accept = QCryptographicHash::hash(
		key + kWebSocketGuid,
		QCryptographicHash::Sha1
	).toBase64();
	const auto response = QByteArray("HTTP/1.1 101 Switching Protocols\r\n")
		+ "Upgrade: websocket\r\n"
		+ "Connection: Upgrade\r\n"
		+ "Sec-WebSocket-Accept: " + accept + "\r\n\r\n";
	socket->write(response);
	client.webSocket = true;
	if (!client.input.isEmpty()) {
		processWebSocket(socket);
	}
}

void Transport::Private::processWebSocket(not_null<QTcpSocket*> socket) {
	// QAbstractSocket::disconnectFromHost() emits disconnected()
	// synchronously when the write buffer is empty, so processing one
	// message may run clientDisconnected() and erase any entry from
	// _clients, invalidating references into the flat_map storage.
	// The client entry must therefore be found again on every iteration.
	while (true) {
		const auto i = _clients.find(socket);
		if (i == end(_clients) || i->second.input.size() < 2) {
			return;
		}
		auto &client = i->second;
		const auto data = reinterpret_cast<const uchar*>(client.input.constData());
		const auto fin = (data[0] & 0x80) != 0;
		const auto opcode = uchar(data[0] & 0x0F);
		const auto masked = (data[1] & 0x80) != 0;
		auto size = uint64(data[1] & 0x7F);
		auto header = 2;
		if ((data[0] & 0x70) != 0 || !masked) {
			closeWebSocket(socket, 1002);
			return;
		}
		if (size == 126) {
			if (client.input.size() < 4) {
				return;
			}
			size = (uint64(data[2]) << 8) | uint64(data[3]);
			if (size < 126) {
				closeWebSocket(socket, 1002);
				return;
			}
			header = 4;
		} else if (size == 127) {
			if (client.input.size() < 10) {
				return;
			}
			if (data[2] & 0x80) {
				closeWebSocket(socket, 1002);
				return;
			}
			size = 0;
			for (auto i = 2; i != 10; ++i) {
				size = (size << 8) | uint64(data[i]);
			}
			if (size <= 0xFFFF) {
				closeWebSocket(socket, 1002);
				return;
			}
			header = 10;
		}
		const auto control = (opcode & 0x08) != 0;
		if (size > kMaxLocalWebSocketPayload
			|| (control && (!fin || size > 125))) {
			closeWebSocket(socket, 1009);
			return;
		}
		const auto full = uint64(header) + 4 + size;
		if (uint64(client.input.size()) < full) {
			return;
		}
		const auto mask = data + header;
		auto payload = client.input.mid(header + 4, int(size));
		for (auto i = 0; i != payload.size(); ++i) {
			payload[i] = char(uchar(payload[i]) ^ mask[i % 4]);
		}
		client.input.remove(0, int(full));
		if (opcode == 0x08) {
			if (payload.size() == 1) {
				closeWebSocket(socket, 1002);
				return;
			}
			writeWebSocket(socket, 0x08, payload.left(125));
			socket->disconnectFromHost();
			return;
		} else if (opcode == 0x09) {
			if (client.authenticated) {
				writeWebSocket(socket, 0x0A, payload);
			}
			continue;
		} else if (opcode == 0x0A) {
			continue;
		} else if (opcode == 0x00) {
			if (!client.fragmentedOpcode) {
				closeWebSocket(socket, 1002);
				return;
			}
			client.fragmented.append(payload);
			if (client.fragmented.size() > kMaxLocalWebSocketPayload) {
				closeWebSocket(socket, 1009);
				return;
			}
			if (fin) {
				const auto fragmentedOpcode = base::take(client.fragmentedOpcode);
				processWebSocketMessage(
					socket,
					client,
					fragmentedOpcode,
					base::take(client.fragmented));
			}
		} else if (opcode == 0x01 || opcode == 0x02) {
			if (client.fragmentedOpcode) {
				closeWebSocket(socket, 1002);
				return;
			}
			if (fin) {
				processWebSocketMessage(
					socket,
					client,
					opcode,
					std::move(payload));
			} else {
				client.fragmentedOpcode = opcode;
				client.fragmented = std::move(payload);
			}
		} else {
			closeWebSocket(socket, 1002);
			return;
		}
	}
}

void Transport::Private::processWebSocketMessage(
		not_null<QTcpSocket*> socket,
		Client &client,
		uchar opcode,
		QByteArray payload) {
	if (opcode == 0x01) {
		processBrowserControl(socket, client, payload);
	} else if (!client.authenticated || _browserSocket != socket.get()) {
		closeWebSocket(socket, 1008);
	} else {
		processRelayPayload(payload);
	}
}

void Transport::Private::processBrowserControl(
		not_null<QTcpSocket*> socket,
		Client &client,
		const QByteArray &payload) {
	QJsonParseError error;
	const auto document = QJsonDocument::fromJson(payload, &error);
	if (error.error != QJsonParseError::NoError || !document.isObject()) {
		closeWebSocket(socket, 1008);
		return;
	}
	const auto object = document.object();
	const auto type = object.value(u"t"_q).toString();
	if (!client.authenticated) {
		if (type != u"auth"_q) {
			closeWebSocket(socket, 1008);
			return;
		}
		authenticateBrowser(
			socket,
			object.value(u"token"_q).toString(),
			object.value(u"browser"_q).toString().left(160));
		return;
	}
	if (_browserSocket != socket.get()) {
		return;
	}
	if (type != u"status"_q) {
		closeWebSocket(socket, 1008);
		return;
	}
	const auto state = object.value(u"state"_q).toString();
	if (state == u"failed"_q) {
		loseBrowser(true);
		closeWebSocket(socket, 1000);
	} else if (state == u"connecting"_q
		|| state == u"reconnecting"_q) {
		setState(State::Connecting, _browser);
	} else if (state == u"connected"_q) {
		setState(_welcomed ? State::Connected : State::Connecting, _browser);
	} else {
		closeWebSocket(socket, 1008);
	}
}

void Transport::Private::authenticateBrowser(
		not_null<QTcpSocket*> socket,
		const QString &token,
		const QString &browser) {
	if (_pendingTokenExpiresAt <= crl::now()) {
		_pendingToken.clear();
		_pendingTokenExpiresAt = 0;
	}
	if (_pendingToken.isEmpty() || token != _pendingToken) {
		closeWebSocket(socket, 1008);
		return;
	}
	if (_webviewGeneration) {
		closeWebSocket(socket, 1000);
		return;
	}
	_pendingToken.clear();
	_pendingTokenExpiresAt = 0;
	if (_browserSocket && _browserSocket != socket.get()) {
		closeAllStreams(false);
		closeWebSocket(_browserSocket.data(), 1000);
	}
	const auto i = _clients.find(socket);
	if (i == end(_clients)) {
		return;
	}
	i->second.authenticated = true;
	_browserSocket = socket.get();
	_browserWriteFailed = false;
	_controlFrames.clear();
	_controlBytes = 0;
	_writeProgressCheckScheduled = false;
	_lastWriteProgress = crl::now();
	_browser = browser;
	_closedStreams.clear();
	_closedStreamOrder.clear();
	_welcomed = false;
	stopListening();
	setState(State::Connecting, _browser);
	writeWebSocket(socket, 0x01, bridgeControl());
	sendFrame(FrameType::Hello, 0, QByteArray(1, char(1)));
	const auto authenticated = QPointer<QTcpSocket>(socket.get());
	QTimer::singleShot(int(kWelcomeTimeout), _owner, [=] {
		if (authenticated
			&& _browserSocket == authenticated
			&& !_welcomed) {
			protocolError();
		}
	});
}

void Transport::Private::webviewStarting(uint64 generation) {
	if (!_proxy || !generation) {
		return;
	}
	_webviewCandidateGeneration = generation;
	if (!carrierAvailable() && _state != State::WaitingForBrowser) {
		setState(State::Connecting);
	}
}

void Transport::Private::webviewReady(uint64 generation) {
	if (_webviewCandidateGeneration != generation || _webviewGeneration) {
		return;
	}
	_webviewCandidateGeneration = 0;
	const auto replaceConnectedBrowser = _browserSocket && _welcomed;
	if (replaceConnectedBrowser) {
		closeAllStreams(false);
	}
	const auto browser = _browserSocket;
	_browserSocket = nullptr;
	_browserWriteFailed = false;
	_controlFrames.clear();
	_controlBytes = 0;
	_writeProgressCheckScheduled = false;
	_lastWriteProgress = crl::now();
	_welcomed = false;
	if (browser) {
		if (const auto i = _clients.find(browser.data()); i != end(_clients)) {
			i->second.authenticated = false;
		}
		closeWebSocket(browser.data(), 1000);
	}
	_webviewGeneration = generation;
	_webviewPendingBytes = 0;
	_webviewBatch = QByteArray();
	_webviewPendingItems = 0;
	_browser = u"WebView"_q;
	_pendingToken.clear();
	_pendingTokenExpiresAt = 0;
	stopListening();
	welcome();
}

void Transport::Private::webviewPayload(
		uint64 generation,
		const QByteArray &payload) {
	if (_webviewGeneration == generation) {
		processRelayPayload(payload);
	}
}

void Transport::Private::webviewWritten(
		uint64 generation,
		int bytes,
		int items) {
	if (_webviewGeneration != generation) {
		return;
	} else if (bytes <= 0
		|| bytes > _webviewPendingBytes
		|| items <= 0
		|| items > _webviewPendingItems) {
		protocolError();
		return;
	}
	_webviewPendingBytes -= bytes;
	_webviewPendingItems -= items;
	_lastWriteProgress = crl::now();
	flushControlFrames();
	flushStreams();
}

void Transport::Private::webviewFailed(uint64 generation) {
	const auto candidate = (_webviewCandidateGeneration == generation);
	const auto active = (_webviewGeneration == generation);
	if (!candidate && !active) {
		return;
	}
	if (candidate) {
		_webviewCandidateGeneration = 0;
	}
	if (active) {
		logCarrier(
			ProxyDiagnosticsSeverity::Warning,
			u"webview carrier lost (streams: %1)"_q.arg(_streams.size()));
		_webviewGeneration = 0;
		_webviewPendingBytes = 0;
		_webviewPendingItems = 0;
		_webviewBatch = QByteArray();
		_welcomed = false;
		closeAllStreams(false);
		_controlFrames.clear();
		_controlBytes = 0;
		_browserWriteFailed = false;
		_writeProgressCheckScheduled = false;
		_lastWriteProgress = 0;
		_closedStreams.clear();
		_closedStreamOrder.clear();
	}
	if (!_browserSocket && _state != State::WaitingForBrowser) {
		setState(State::Connecting);
	}
	publishConnected();
}

void Transport::Private::webviewUnavailable() {
	if (!_proxy || _browserSocket || _webviewGeneration) {
		return;
	}
	setState(State::WaitingForBrowser);
}

void Transport::Private::processRelayPayload(const QByteArray &payload) {
	auto input = payload;
	auto frames = std::vector<Frame>();
	if (!ParseFrames(input, frames) || !input.isEmpty() || frames.empty()) {
		protocolError();
		return;
	}
	_owner->_healthLastDownlinkAt = crl::now();
	for (const auto &frame : frames) {
		if (!processRelayFrame(frame)) {
			protocolError();
			return;
		}
	}
}

bool Transport::Private::processRelayFrame(const Frame &frame) {
	if (!_welcomed
		&& (frame.type != FrameType::Welcome || frame.streamId != 0)) {
		return false;
	}
	if (frame.streamId == 0) {
		switch (frame.type) {
		case FrameType::Welcome:
			if (_welcomed || !frame.payload.isEmpty()) {
				return false;
			}
			welcome();
			return true;
		case FrameType::Ping:
			if (frame.payload.size() > 64) {
				return false;
			}
			sendFrame(FrameType::Pong, 0, frame.payload);
			return true;
		case FrameType::Bye:
			if (_webviewGeneration) {
				const auto generation = _webviewGeneration;
				webviewFailed(generation);
				_owner->FinishWebview(generation);
			} else {
				loseBrowser(true);
			}
			if (_browserSocket) {
				closeWebSocket(_browserSocket.data(), 1000);
			}
			return true;
		default:
			return false;
		}
	}
	const auto i = _streams.find(frame.streamId);
	if (i == end(_streams)) {
		if (!_closedStreams.contains(frame.streamId)) {
			return false;
		}
		switch (frame.type) {
		case FrameType::Data:
			return !frame.payload.isEmpty();
		case FrameType::Window:
			return (frame.payload.size() == 4)
				&& (ReadWindow(frame.payload) != 0);
		case FrameType::Close:
			return frame.payload.isEmpty();
		default:
			return false;
		}
	} else if (!i->second.opened) {
		return false;
	}
	auto &stream = i->second;
	switch (frame.type) {
	case FrameType::Data:
		if (frame.payload.isEmpty()
			|| uint32(frame.payload.size()) > stream.receiveWindow) {
			return false;
		}
		stream.receiveWindow -= frame.payload.size();
		_traffic.down += frame.payload.size();
		_flow.downReceived += frame.payload.size();
		{
			const auto now = crl::now();
			if (stream.probe) {
				stream.probe->lastReceivedAt = now;
			}
			if (stream.awaitingSince) {
				noteInteractive(now - base::take(stream.awaitingSince));
			}
			notifyData(stream, frame.payload);
			updateFlow(now);
		}
		return true;
	case FrameType::Window: {
		if (frame.payload.size() != 4) {
			return false;
		}
		const auto amount = ReadWindow(frame.payload);
		if (!amount) {
			return false;
		}
		stream.sendWindow = std::min<uint64>(
			stream.sendWindow + amount,
			uint64(std::numeric_limits<uint32>::max()));
		creditUnacked(frame.streamId, stream, amount);
		markStreamReady(frame.streamId);
		flushStreams();
		return true;
	} break;
	case FrameType::Close: {
		if (!frame.payload.isEmpty()) {
			return false;
		}
		rememberClosedStream(frame.streamId);
		auto removed = std::move(i->second);
		_streams.erase(i);
		forgetStream(frame.streamId, removed);
		releasePending(removed);
		notifyDisconnected(removed);
		return true;
	} break;
	default:
		return false;
	}
}

void Transport::Private::registerStream(
		uint32 streamId,
		StreamHandlers handlers) {
	auto stream = Stream(std::move(handlers));
	if (!_proxy
		|| _streams.contains(streamId)
		|| _closedStreams.contains(streamId)) {
		notifyFailed(stream);
		return;
	}
	if (stream.probe) {
		stream.probe->open = true;
	}
	_scheduler.add(streamId, stream.streamClass);
	if (stream.streamClass == StreamClass::Download) {
		++_downloadStreams;
	}
	_streams.emplace(streamId, std::move(stream));
	if (_welcomed) {
		auto &stream = _streams.find(streamId)->second;
		stream.opened = true;
		sendFrame(FrameType::Open, streamId);
		notifyConnected(stream);
	}
	scheduleHealthCheck();
}

void Transport::Private::closeStream(uint32 streamId) {
	const auto i = _streams.find(streamId);
	if (i == end(_streams)) {
		return;
	}
	if (i->second.opened) {
		sendFrame(FrameType::Close, streamId);
		rememberClosedStream(streamId);
	}
	auto removed = std::move(i->second);
	_streams.erase(i);
	forgetStream(streamId, removed);
	releasePending(removed);
}

void Transport::Private::sendData(uint32 streamId, QByteArray data) {
	const auto i = _streams.find(streamId);
	if (i == end(_streams) || data.isEmpty()) {
		_owner->releasePending(data.size(), data.isEmpty() ? 0 : 1);
		return;
	}
	auto &stream = i->second;
	const auto coalesce = !stream.pending.empty()
		&& stream.pending.back().offset == 0
		&& stream.pending.back().data.size() + data.size() <= kDataFrameSize;
	if (stream.pendingBytes + data.size() > kMaxPendingStreamBytes
		|| (!coalesce && stream.pending.size() >= kMaxPendingStreamItems)) {
		_owner->releasePending(data.size(), 1);
		if (stream.opened) {
			sendFrame(FrameType::Close, streamId);
			rememberClosedStream(streamId);
		}
		LOG(("Web Proxy Error: stream %1 (%2) overflowed its queue, "
			"%3 bytes pending."
			).arg(streamId
			).arg(QString::fromLatin1(StreamClassName(stream.streamClass))
			).arg(stream.pendingBytes));
		auto removed = std::move(stream);
		_streams.erase(i);
		forgetStream(streamId, removed);
		releasePending(removed);
		notifyFailed(removed);
		return;
	}
	stream.pendingBytes += data.size();
	if (coalesce) {
		stream.pending.back().data.append(data);
		_owner->releasePending(0, 1);
	} else {
		stream.pending.push_back({ std::move(data), 0 });
	}
	publishStream(stream);
	markStreamReady(streamId);
	flushStreams();
}

void Transport::Private::grantWindow(uint32 streamId, uint32 amount) {
	const auto i = _streams.find(streamId);
	if (i == end(_streams) || !i->second.opened || !amount) {
		return;
	}
	auto &stream = i->second;
	if (amount > kInitialStreamWindow
		- stream.receiveWindow
		- stream.withheldWindow) {
		protocolError();
		return;
	}
	stream.withheldWindow += amount;
	if (!releaseDownlinkCredit(stream)) {
		return;
	} else if (stream.pendingWindow >= kWindowFlushBytes) {
		const auto pending = base::take(stream.pendingWindow);
		sendFrame(FrameType::Window, streamId, WindowPayload(pending));
	} else {
		scheduleWindowFlush();
	}
}

bool Transport::Private::releaseDownlinkCredit(Stream &stream) {
	const auto target = DownlinkCreditTarget(
		_downlinkLimits,
		stream.streamClass,
		_downloadStreams);
	const auto release = uint32(DownlinkCreditRelease(
		stream.receiveWindow,
		stream.withheldWindow,
		target));
	if (stream.streamClass == StreamClass::Download
		&& release < stream.withheldWindow) {
		// The reader wanted more credit back than the budget allows.
		_flow.downLimited = true;
	}
	if (!release) {
		_traffic.withheldPeak = std::max(
			_traffic.withheldPeak,
			int64(stream.withheldWindow));
		return false;
	}
	stream.withheldWindow -= release;
	stream.receiveWindow += release;
	stream.pendingWindow += release;
	return true;
}

void Transport::Private::rebalanceDownlinkCredit() {
	auto released = false;
	for (auto &[streamId, stream] : _streams) {
		if (stream.opened
			&& stream.withheldWindow
			&& releaseDownlinkCredit(stream)) {
			released = true;
		}
	}
	if (released) {
		scheduleWindowFlush();
	}
}

void Transport::Private::scheduleWindowFlush() {
	if (_windowFlushScheduled) {
		return;
	}
	_windowFlushScheduled = true;
	QTimer::singleShot(int(kWindowFlushDelay), _owner, [=] {
		_windowFlushScheduled = false;
		flushWindows();
	});
}

void Transport::Private::flushWindows() {
	for (auto &[streamId, stream] : _streams) {
		if (stream.opened && stream.pendingWindow) {
			const auto pending = base::take(stream.pendingWindow);
			sendFrame(FrameType::Window, streamId, WindowPayload(pending));
		}
	}
}

void Transport::Private::sendFrame(
		FrameType type,
		uint32 streamId,
		const QByteArray &payload) {
	if (!carrierAvailable()) {
		return;
	}
	queueControlFrame(SerializeFrame(type, streamId, payload));
}

void Transport::Private::queueControlFrame(QByteArray frame) {
	if (!carrierAvailable() || _browserWriteFailed) {
		return;
	}
	if (_controlFrames.empty() && carrierAccepts(frame.size(), true)) {
		writeCarrierFrame(std::move(frame));
		ensureWriteProgressCheck();
		return;
	}
	if (frame.size() > kMaxPendingControlBytes
		|| _controlFrames.size() >= kMaxPendingControlFrames
		|| _controlBytes > kMaxPendingControlBytes - frame.size()) {
		_browserWriteFailed = true;
		InvokeQueued(_owner, [=] {
			if (carrierAvailable()) {
				protocolError();
			}
		});
		return;
	}
	_controlBytes += frame.size();
	_controlFrames.push_back(std::move(frame));
	ensureWriteProgressCheck();
}

void Transport::Private::flushControlFrames() {
	while (carrierAvailable() && !_controlFrames.empty()) {
		auto &frame = _controlFrames.front();
		if (!carrierAccepts(frame.size(), true)) {
			break;
		}
		const auto size = frame.size();
		writeCarrierFrame(std::move(frame));
		_controlBytes -= size;
		_controlFrames.pop_front();
	}
	if (carrierAvailable()
		&& (!_controlFrames.empty() || carrierPendingBytes() > 0)) {
		ensureWriteProgressCheck();
	}
}

void Transport::Private::ensureWriteProgressCheck() {
	if (_writeProgressCheckScheduled || !carrierAvailable()) {
		return;
	}
	_writeProgressCheckScheduled = true;
	const auto socket = QPointer<QTcpSocket>(_browserSocket);
	const auto generation = _webviewGeneration;
	QTimer::singleShot(int(kWriteProgressTimeout), _owner, [=] {
		_writeProgressCheckScheduled = false;
		if ((generation && _webviewGeneration != generation)
			|| (!generation && (!socket || _browserSocket != socket))) {
			return;
		}
		if (carrierPendingBytes() == 0 && _controlFrames.empty()) {
			return;
		}
		if (crl::now() - _lastWriteProgress >= kWriteProgressTimeout) {
			protocolError();
		} else {
			ensureWriteProgressCheck();
		}
	});
}

void Transport::Private::browserBytesWritten() {
	_lastWriteProgress = crl::now();
	flushControlFrames();
	flushStreams();
}

void Transport::Private::writeCarrierFrame(QByteArray frame) {
	if (_webviewGeneration) {
		// Everything written in this turn goes to the bridge as one batch:
		// a page call costs a round trip through the WebView, a frame
		// does not have to.
		_webviewPendingBytes += frame.size();
		_webviewBatch.append(frame);
		if (_webviewBatch.size() >= kBridgeBatchBytes) {
			flushWebviewBatch();
		} else if (!_webviewBatchScheduled) {
			_webviewBatchScheduled = true;
			InvokeQueued(_owner, [=] {
				_webviewBatchScheduled = false;
				flushWebviewBatch();
			});
		}
	} else if (_browserSocket) {
		_browserSocket->write(WebSocketFrame(0x02, frame));
	}
}

void Transport::Private::flushWebviewBatch() {
	if (_webviewBatch.isEmpty() || !_webviewGeneration) {
		_webviewBatch = QByteArray();
		return;
	}
	++_webviewPendingItems;
	_owner->sendWebviewFrame(_webviewGeneration, base::take(_webviewBatch));
}

bool Transport::Private::carrierAvailable() const {
	return _webviewGeneration || _browserSocket;
}

int Transport::Private::carrierPendingBytes() const {
	return _webviewGeneration
		? _webviewPendingBytes
		: _browserSocket
		? int(_browserSocket->bytesToWrite())
		: 0;
}

int Transport::Private::carrierPendingItems() const {
	return _webviewGeneration ? _webviewPendingItems : 0;
}

bool Transport::Private::carrierAccepts(int frameSize, bool control) const {
	const auto bytesLimit = control
		? kMaxLocalSocketPendingBytes
		: (kMaxLocalSocketPendingBytes - kLocalSocketControlReserve);
	const auto itemsLimit = control
		? kMaxWebviewPendingItems
		: (kMaxWebviewPendingItems - kWebviewItemsControlReserve);
	return (carrierPendingBytes() <= bytesLimit - carrierFrameSize(frameSize))
		&& (carrierPendingItems() < itemsLimit);
}

int Transport::Private::carrierFrameSize(int payloadSize) const {
	return payloadSize + (_webviewGeneration
		? 0
		: WebSocketHeaderSize(payloadSize));
}

void Transport::Private::markStreamReady(uint32 streamId) {
	const auto i = _streams.find(streamId);
	if (i == end(_streams)
		|| !i->second.opened
		|| !i->second.sendWindow
		|| i->second.pending.empty()) {
		return;
	}
	_scheduler.markReady(streamId);
}

void Transport::Private::forgetStream(uint32 streamId, Stream &stream) {
	_scheduler.remove(streamId);
	if (stream.unacked) {
		_totalUnacked -= stream.unacked;
		stream.unacked = 0;
		_owner->_healthUnacked = _totalUnacked;
	}
	if (stream.probe) {
		stream.probe->open = false;
	}
	if (stream.streamClass == StreamClass::Download) {
		--_downloadStreams;
		rebalanceDownlinkCredit();
	}
}

void Transport::Private::publishStream(const Stream &stream) {
	if (const auto probe = stream.probe.get()) {
		probe->queuedBytes = stream.pendingBytes;
		probe->unackedBytes = stream.unacked;
	}
}

void Transport::Private::publishConnected() {
	_owner->_healthConnected = _welcomed && carrierAvailable();
}

void Transport::Private::addUnacked(Stream &stream, int64 bytes) {
	if (bytes <= 0) {
		return;
	} else if (!_totalUnacked) {
		_owner->_healthOutstandingSince = crl::now();
	}
	stream.unacked += bytes;
	_totalUnacked += bytes;
	_owner->_healthUnacked = _totalUnacked;
}

void Transport::Private::creditUnacked(
		uint32 streamId,
		Stream &stream,
		int64 bytes) {
	const auto now = crl::now();
	const auto credited = std::min(stream.unacked, bytes);
	stream.unacked -= credited;
	_totalUnacked -= credited;
	_owner->_healthUnacked = _totalUnacked;
	_owner->_healthLastCreditAt = now;
	_scheduler.acknowledged(streamId, bytes);
	if (stream.probe && !stream.unacked) {
		stream.probe->deliveredAt = now;
	}
	publishStream(stream);

	// Every frame fully credited now went through the whole uplink: the
	// bridge, the carrier, the relay's queue and into the backend socket.
	stream.creditedTotal += credited;
	while (!stream.sentLog.empty()
		&& stream.sentLog.front().first <= stream.creditedTotal) {
		noteRtt(now - stream.sentLog.front().second);
		stream.sentLog.pop_front();
	}
	_flow.upCredited += credited;
	updateFlow(now);
}

void Transport::Private::noteRtt(crl::time rtt) {
	_flow.rtt = std::min(_flow.rtt.value_or(rtt), rtt);
	_traffic.rttMin = std::min(_traffic.rttMin.value_or(rtt), rtt);
}

void Transport::Private::noteInteractive(crl::time delay) {
	_flow.interactive = std::min(_flow.interactive.value_or(delay), delay);
	_traffic.interactiveMin = std::min(
		_traffic.interactiveMin.value_or(delay),
		delay);
	_traffic.interactiveMax = std::max(
		_traffic.interactiveMax.value_or(delay),
		delay);
}

void Transport::Private::updateFlow(crl::time now) {
	if (!_flow.startedAt) {
		_flow.startedAt = now;
		return;
	}
	const auto interval = now - _flow.startedAt;
	const auto every = std::clamp(
		_upWindow.baseDelay().value_or(kFlowUpdateMaxInterval),
		kFlowUpdateMinInterval,
		kFlowUpdateMaxInterval);
	if (interval < every) {
		return;
	}
	if (_flow.upLimited) {
		_upLimitedAt = now;
	}
	if (_flow.downLimited) {
		_downLimitedAt = now;
	}
	const auto busy = [&](crl::time at) {
		return at && (now - at < kBusyMemory);
	};
	const auto share = _upWindow.limits().targetDelay;
	// A frame is credited when the relay has written it to the backend,
	// and the credit comes back in the relay's downlink FIFO: its round
	// trip holds both queues a chat request waits in. Both windows follow
	// it, so together they keep that wait near the target. Interactive
	// request-to-reply times would say the same, but they cannot be told
	// apart when requests are pipelined, so they are only reported.
	const auto probing = (_probeUntil && _flow.startedAt < _probeUntil);

	// New download streams start with the protocol's whole window each, and
	// until they use it up the relay's downlink FIFO holds more than any
	// budget: that delay is charged to nobody we control. Credits for the
	// uplink come back behind it, so the upload window is held, not cut.
	auto relayHeld = int64();
	for (const auto &[streamId, stream] : _streams) {
		if (stream.streamClass == StreamClass::Download) {
			relayHeld += int64(stream.receiveWindow) - stream.pendingWindow;
		}
	}
	const auto flooded = (relayHeld > _downlinkLimits.downloadBudget);
	if (flooded) {
		++_traffic.flooded;
		_upWindow.hold({
			.now = now,
			.interval = interval,
			.bytes = _flow.upCredited,
			.windowLimited = _flow.upLimited,
			.delay = _flow.rtt,
		});
	} else {
		_upWindow.update({
			.now = now,
			.interval = interval,
			.bytes = _flow.upCredited,
			.windowLimited = _flow.upLimited,
			.delay = _flow.rtt,
			.probing = probing,
			.extraDelay = busy(_downLimitedAt) ? share : 0,
		});
	}
	_downWindow.update({
		.now = now,
		.interval = interval,
		.bytes = _flow.downReceived,
		.windowLimited = _flow.downLimited,
		.delay = _flow.rtt,
		.probing = probing,
		.extraDelay = busy(_upLimitedAt) ? share : 0,
	});
	const auto limited = _flow.upLimited || _flow.downLimited;
	_flow = FlowInterval{ .startedAt = now };
	if (_probeUntil && now >= _probeUntil) {
		_probeUntil = 0;
	}
	if (!_nextProbeAt) {
		_nextProbeAt = now + kProbeInterval;
	} else if (limited && now >= _nextProbeAt) {
		const auto base = _upWindow.baseDelay().value_or(0);
		_probeUntil = now + std::max(kProbeMinDuration, base);
		_nextProbeAt = now + kProbeInterval;
		++_traffic.probes;
	}
	applyWindows(now);
}

void Transport::Private::applyWindows(crl::time now) {
	const auto probing = (_probeUntil && now < _probeUntil);
	_scheduler.setUploadInFlight(probing
		? _upWindow.limits().min
		: _upWindow.window());
	const auto budget = probing
		? _downWindow.limits().min
		: _downWindow.window();
	if (budget != _downlinkLimits.downloadBudget) {
		const auto grew = (budget > _downlinkLimits.downloadBudget);
		_downlinkLimits.downloadBudget = budget;
		if (grew) {
			rebalanceDownlinkCredit();
		}
	}
}

void Transport::Private::flushStreams() {
	if (!carrierAvailable() || _browserWriteFailed) {
		return;
	}
	flushControlFrames();
	if (!_controlFrames.empty()) {
		return;
	}
	auto processed = 0;
	while (processed != kMaxFlushFramesPerTurn
		&& carrierAccepts(kFrameHeaderSize + 1, false)) {
		const auto grant = _scheduler.next();
		if (!grant) {
			break;
		}
		flushStream(grant->streamId, grant->maxBytes);
		markStreamReady(grant->streamId);
		++processed;
	}
	if (_scheduler.uploadBlocked()) {
		++_traffic.uploadBlocked;
		_flow.upLimited = true;
	}
	if (carrierPendingBytes() > 0) {
		ensureWriteProgressCheck();
	}
}

void Transport::Private::flushStream(uint32 streamId, int maxBytes) {
	const auto i = _streams.find(streamId);
	if (i == end(_streams) || !i->second.opened || !carrierAvailable()) {
		return;
	}
	auto &stream = i->second;
	if (stream.sendWindow
		&& !stream.pending.empty()
		&& !_browserWriteFailed) {
		const auto localAllowance = kMaxLocalSocketPendingBytes
			- kLocalSocketControlReserve
			- carrierPendingBytes();
		if (localAllowance <= kFrameHeaderSize + 10
			|| !carrierAccepts(kFrameHeaderSize + 1, false)) {
			return;
		}
		auto &front = stream.pending.front();
		const auto remaining = front.data.size() - front.offset;
		const auto take = int(std::min<uint64>({
			stream.sendWindow,
			uint64(remaining),
			uint64(kDataFrameSize),
			uint64(std::max(maxBytes, 1)),
			uint64(localAllowance - kFrameHeaderSize - 10),
		}));
		auto frame = SerializeFrame(
			FrameType::Data,
			streamId,
			front.data.mid(front.offset, take));
		writeCarrierFrame(std::move(frame));
		front.offset += take;
		stream.pendingBytes -= take;
		stream.sendWindow -= take;
		const auto itemDone = (front.offset == front.data.size());
		_owner->releasePending(take, itemDone ? 1 : 0);
		if (itemDone) {
			stream.pending.pop_front();
		}
		_scheduler.sent(streamId, take);
		addUnacked(stream, take);
		if (stream.probe) {
			stream.probe->sentBytes += take;
		}
		{
			const auto now = crl::now();
			stream.sentTotal += take;
			stream.sentLog.emplace_back(stream.sentTotal, now);
			if (stream.streamClass == StreamClass::Interactive
				&& !stream.awaitingSince) {
				stream.awaitingSince = now;
			}
		}
		_traffic.up += take;
		publishStream(stream);
		ensureWriteProgressCheck();
	}
}

void Transport::Private::failStream(uint32 streamId) {
	const auto i = _streams.find(streamId);
	if (i == end(_streams)) {
		return;
	}
	if (i->second.opened) {
		sendFrame(FrameType::Close, streamId);
		rememberClosedStream(streamId);
	}
	auto removed = std::move(i->second);
	_streams.erase(i);
	forgetStream(streamId, removed);
	releasePending(removed);
	notifyFailed(removed);
}

void Transport::Private::releasePending(Stream &stream) {
	_owner->releasePending(stream.pendingBytes, int(stream.pending.size()));
	stream.pending.clear();
	stream.pendingBytes = 0;
}

void Transport::Private::rememberClosedStream(uint32 streamId) {
	if (_closedStreams.contains(streamId)) {
		return;
	}
	_closedStreams.emplace(streamId);
	_closedStreamOrder.push_back(streamId);
	if (_closedStreamOrder.size() > kMaxClosedStreamIds) {
		_closedStreams.erase(_closedStreamOrder.front());
		_closedStreamOrder.pop_front();
	}
}

void Transport::Private::notifyConnected(const Stream &stream) {
	if (const auto context = stream.context.data()) {
		const auto callback = stream.connected;
		InvokeQueued(context, [=] { callback(); });
	}
}

void Transport::Private::notifyData(const Stream &stream, QByteArray data) {
	if (const auto context = stream.context.data()) {
		const auto callback = stream.data;
		InvokeQueued(context, [=, data = std::move(data)]() mutable {
			callback(std::move(data));
		});
	}
}

void Transport::Private::notifyDisconnected(const Stream &stream) {
	if (const auto context = stream.context.data()) {
		const auto callback = stream.disconnected;
		InvokeQueued(context, [=] { callback(); });
	}
}

void Transport::Private::notifyFailed(const Stream &stream) {
	if (const auto context = stream.context.data()) {
		const auto callback = stream.failed;
		InvokeQueued(context, [=] { callback(); });
	}
}

void Transport::Private::welcome() {
	if (_welcomed || !carrierAvailable()) {
		protocolError();
		return;
	}
	_welcomed = true;
	setState(State::Connected, _browser);
	logCarrier(
		ProxyDiagnosticsSeverity::Info,
		u"connected through %1 (streams: %2)"_q
			.arg(_webviewGeneration ? u"webview"_q : u"browser"_q)
			.arg(_streams.size()));
	_owner->_healthLastDownlinkAt = crl::now();
	for (auto &[streamId, stream] : _streams) {
		stream.opened = true;
		sendFrame(FrameType::Open, streamId);
		notifyConnected(stream);
		markStreamReady(streamId);
	}
	flushStreams();
	scheduleHealthCheck();
}

void Transport::Private::loseBrowser(bool failed) {
	logCarrier(
		failed
			? ProxyDiagnosticsSeverity::Warning
			: ProxyDiagnosticsSeverity::Info,
		u"browser carrier lost (failed: %1, streams: %2)"_q
			.arg(failed ? u"yes"_q : u"no"_q)
			.arg(_streams.size()));
	_welcomed = false;
	closeAllStreams(failed);
	_controlFrames.clear();
	_controlBytes = 0;
	_closedStreams.clear();
	_closedStreamOrder.clear();
	setState(
		_webviewCandidateGeneration
			? State::Connecting
			: failed
			? State::Failed
			: State::WaitingForBrowser,
		_browser);
}

void Transport::Private::closeAllStreams(bool failed) {
	auto streams = std::move(_streams);
	_streams.clear();
	_scheduler.clear();
	_downloadStreams = 0;
	_totalUnacked = 0;
	_owner->_healthUnacked = 0;
	for (auto &entry : streams) {
		auto &stream = entry.second;
		if (stream.probe) {
			stream.probe->open = false;
		}
		releasePending(stream);
		if (failed) {
			notifyFailed(stream);
		} else {
			notifyDisconnected(stream);
		}
	}
}

void Transport::Private::protocolError() {
	logCarrier(
		ProxyDiagnosticsSeverity::Warning,
		u"carrier protocol error (streams: %1)"_q.arg(_streams.size()));
	if (_webviewGeneration) {
		const auto generation = _webviewGeneration;
		closeAllStreams(true);
		webviewFailed(generation);
		_owner->FinishWebview(generation);
		return;
	}
	closeAllStreams(true);
	_controlFrames.clear();
	_controlBytes = 0;
	_closedStreams.clear();
	_closedStreamOrder.clear();
	_welcomed = false;
	setState(State::Failed, _browser);
	if (_browserSocket) {
		closeWebSocket(_browserSocket.data(), 1002);
	}
}

void Transport::Private::setState(State state, const QString &browser) {
	publishConnected();
	if (_state == state && _browser == browser) {
		return;
	}
	_state = state;
	_browser = browser;
	PublishState(_proxy, state, browser);
}

void Transport::Private::scheduleHealthCheck() {
	if (_healthCheckScheduled || !_proxy) {
		return;
	}
	_healthCheckScheduled = true;
	QTimer::singleShot(int(kHealthCheckInterval), _owner, [=] {
		_healthCheckScheduled = false;
		checkHealth();
	});
}

void Transport::Private::checkHealth() {
	if (!_proxy) {
		return;
	}
	const auto now = crl::now();
	const auto health = _owner->carrierHealth();
	if (CarrierStalled(now, health, _livenessLimits)) {
		recoverStalledCarrier(now - std::max({
			health.outstandingSince,
			health.lastCreditAt,
			health.lastDownlinkAt,
		}));
	} else if (now - _lastSummaryAt >= kHealthSummaryInterval) {
		logSummary(now);
	}
	if (!_streams.empty() || _totalUnacked > 0) {
		scheduleHealthCheck();
	}
}

void Transport::Private::recoverStalledCarrier(crl::time silence) {
	logCarrier(
		ProxyDiagnosticsSeverity::Warning,
		u"stalled: no relay progress for %1ms with %2 bytes outstanding, "
		"recovering the carrier once for %3 streams"_q
			.arg(silence)
			.arg(_totalUnacked)
			.arg(_streams.size()));
	if (_webviewGeneration) {
		// A fresh bridge page opens a fresh relay session.
		protocolError();
		return;
	}
	// An external browser cannot be reopened from here, so keep its page
	// and reset the streams on it in one go instead.
	const auto ids = _streams | ranges::views::keys | ranges::to_vector;
	for (const auto streamId : ids) {
		failStream(streamId);
	}
}

void Transport::Private::logCarrier(
		ProxyDiagnosticsSeverity severity,
		const QString &text) {
	if (!_proxy) {
		return;
	}
	auto event = ProxyDiagnosticsEvent{
		.source = ProxyDiagnosticsSource::Network,
		.phase = ProxyDiagnosticsPhase::WebCarrier,
		.severity = severity,
		.proxy = _proxy,
		.transport = u"WEB"_q,
		.message = text,
	};
	event.timestamp = QDateTime::currentDateTime();
	Logs::writeMtproxy(FormatProxyDiagnosticsEvent(event));
}

void Transport::Private::logSummary(crl::time now) {
	const auto interval = _lastSummaryAt
		? (now - _lastSummaryAt)
		: kHealthSummaryInterval;
	_lastSummaryAt = now;
	const auto traffic = base::take(_traffic);
	const auto stats = _scheduler.stats();
	auto queued = int64();
	auto withheld = int64();
	for (const auto &[streamId, stream] : _streams) {
		queued += stream.pendingBytes;
		withheld += stream.withheldWindow;
	}
	const auto idle = !traffic.up
		&& !traffic.down
		&& !queued
		&& !_totalUnacked;
	if (idle) {
		return;
	}
	const auto health = _owner->carrierHealth();
	const auto since = [&](int64 at) {
		return at ? QString::number(now - at) : u"never"_q;
	};
	const auto perClass = [](const std::array<int, kStreamClassCount> &v) {
		return u"%1/%2/%3"_q.arg(v[0]).arg(v[1]).arg(v[2]);
	};
	logCarrier(
		ProxyDiagnosticsSeverity::Info,
		(u"health: streams(i/d/u)=%1 ready=%2 queued=%3 unacked=%4 "
			"upload_inflight=%5/%6 upload_blocked=%7 withheld=%8 "
			"withheld_peak=%9 "_q
			.arg(perClass(stats.streams))
			.arg(perClass(stats.ready))
			.arg(queued)
			.arg(_totalUnacked)
			.arg(stats.uploadInFlight)
			.arg(_scheduler.limits().uploadInFlight)
			.arg(traffic.uploadBlocked)
			.arg(withheld)
			.arg(traffic.withheldPeak))
		+ (u"up=%1 down=%2 interval_ms=%3 last_down_ms=%4 "
			"last_credit_ms=%5 carrier_pending=%6 "_q
			.arg(traffic.up)
			.arg(traffic.down)
			.arg(interval)
			.arg(since(health.lastDownlinkAt))
			.arg(since(health.lastCreditAt))
			.arg(carrierPendingBytes()))
		+ flowSummary(traffic));
}

QString Transport::Private::flowSummary(const Traffic &traffic) {
	const auto optional = [](const std::optional<crl::time> &value) {
		return value ? QString::number(*value) : u"-"_q;
	};
	const auto &bridge = Bridge();
	const auto writes = bridge.upWrites.load() - _lastBridgeWrites;
	const auto bytes = bridge.upBytes.load() - _lastBridgeBytes;
	const auto ackMs = bridge.upAckMsTotal.load() - _lastBridgeAckMs;
	const auto messages = bridge.downMessages.load() - _lastBridgeDownMessages;
	_lastBridgeWrites += writes;
	_lastBridgeBytes += bytes;
	_lastBridgeAckMs += ackMs;
	_lastBridgeDownMessages += messages;
	return (u"up_window=%1 up_rate=%2 up_base_ms=%3 up_delay_ms=%4 "
		"up_shrinks=%5 down_budget=%6 down_rate=%7 down_base_ms=%8 "
		"down_delay_ms=%9 "_q
		.arg(_upWindow.window())
		.arg(_upWindow.rate())
		.arg(optional(_upWindow.baseDelay()))
		.arg(optional(_upWindow.lastDelay()))
		.arg(_upWindow.shrinks())
		.arg(_downWindow.window())
		.arg(_downWindow.rate())
		.arg(optional(_downWindow.baseDelay()))
		.arg(optional(_downWindow.lastDelay())))
		+ (u"probes=%1 flooded=%2 rtt_min=%3 interactive_ms=%4..%5 "
			"bridge_writes=%6 bridge_avg_bytes=%7 bridge_ack_avg_ms=%8 "
			"bridge_down_msgs=%9"_q
			.arg(traffic.probes)
			.arg(traffic.flooded)
			.arg(optional(traffic.rttMin))
			.arg(optional(traffic.interactiveMin))
			.arg(optional(traffic.interactiveMax))
			.arg(writes)
			.arg(writes ? (bytes / writes) : 0)
			.arg(writes ? (ackMs / writes) : 0)
			.arg(messages));
}

void Transport::Private::writeWebSocket(
		not_null<QTcpSocket*> socket,
		uchar opcode,
		const QByteArray &payload) {
	const auto frame = WebSocketFrame(opcode, payload);
	if (socket.get() == _browserSocket
		&& (_browserWriteFailed
			|| frame.size() > kMaxLocalSocketPendingBytes
			|| socket->bytesToWrite()
				> kMaxLocalSocketPendingBytes - frame.size())) {
		if (!_browserWriteFailed) {
			_browserWriteFailed = true;
			InvokeQueued(_owner, [=] {
				if (_browserSocket == socket.get()) {
					protocolError();
				}
			});
		}
		return;
	}
	socket->write(frame);
}

void Transport::Private::closeWebSocket(
		not_null<QTcpSocket*> socket,
		uint16 code) {
	auto payload = QByteArray(2, Qt::Uninitialized);
	payload[0] = char(code >> 8);
	payload[1] = char(code);
	writeWebSocket(socket, 0x08, payload);
	socket->disconnectFromHost();
}

void Transport::Private::writeHttp(
		not_null<QTcpSocket*> socket,
		QByteArray status,
		QByteArray contentType,
		QByteArray body,
		QByteArray extraHeaders) {
	const auto response = QByteArray("HTTP/1.1 ") + status + "\r\n"
		+ "Content-Type: " + contentType + "\r\n"
		+ "Content-Length: " + QByteArray::number(body.size()) + "\r\n"
		+ "Cache-Control: no-store\r\n"
		+ "X-Content-Type-Options: nosniff\r\n"
		+ "Referrer-Policy: no-referrer\r\n"
		+ extraHeaders
		+ "Connection: close\r\n\r\n"
		+ body;
	socket->write(response);
	socket->disconnectFromHost();
}

QByteArray Transport::Private::bridgeControl() const {
	return QJsonDocument(QJsonObject{
		{ u"t"_q, u"bridge"_q },
		{ u"url"_q, WebProxyBridgeUrl(_proxy) },
	}).toJson(QJsonDocument::Compact);
}

QByteArray Transport::Private::page(const QString &nonce) const {
	const auto origin = QUrl(u"https://"_q + _proxy.host);
	const auto encoded = origin.toString(QUrl::FullyEncoded);
	const auto target = JsonString(encoded);
	const auto base = JsonString(encoded + WebProxyBridgePath(_proxy));
	const auto html = uR"HTML(<!doctype html>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Telegram Web Proxy</title>
<style>
body{font:16px system-ui,sans-serif;margin:0;min-height:100vh;display:grid;place-items:center;background:#f4f6f8;color:#17212b}
main{width:min(34rem,calc(100% - 4rem));padding:2rem;text-align:center}h1{font-size:1.5rem}#state{color:#5288c1}.traffic{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:.75rem;margin:1.5rem 0;text-align:left}.traffic div{padding:1rem;border:1px solid #dce3e9;border-radius:.75rem;background:#fff}.traffic dt{font-size:.8rem;color:#6c7883}.traffic dd{margin:.35rem 0 0;font-size:1.1rem;font-weight:600}.traffic small{display:block;margin-top:.25rem;color:#5288c1;font-size:.8rem;font-weight:400}.note{font-size:.8rem;color:#6c7883}iframe{display:none}
</style>
<main><h1>Telegram Web Proxy</h1><p id="state">Connecting to Telegram Desktop…</p><dl class="traffic"><div><dt>Sent through HTTPS</dt><dd><span id="up-total">0 B</span><small id="up-rate">0 B/s</small></dd></div><div><dt>Received through HTTPS</dt><dd><span id="down-total">0 B</span><small id="down-rate">0 B/s</small></dd></div></dl><p>Keep this tab open while using Telegram.</p><p class="note">Counts obfuscated carrier payload after successful requests; HTTPS overhead is not included.</p></main>
<script nonce="%2">
(()=>{
const relayOrigin=%1,relayBase=%3,state=document.getElementById('state');
const upTotal=document.getElementById('up-total'),downTotal=document.getElementById('down-total'),upRate=document.getElementById('up-rate'),downRate=document.getElementById('down-rate');
const traffic={up:0,down:0,lastUp:0,lastDown:0,lastAt:performance.now()};
const formatBytes=value=>{const units=['B','KiB','MiB','GiB','TiB'];let unit=0;while(value>=1024&&unit<units.length-1){value/=1024;unit++}return value.toFixed(unit&&value<100?1:0)+' '+units[unit]};
const refreshTraffic=()=>{const now=performance.now(),seconds=Math.max((now-traffic.lastAt)/1000,.001);upTotal.textContent=formatBytes(traffic.up);downTotal.textContent=formatBytes(traffic.down);upRate.textContent=formatBytes((traffic.up-traffic.lastUp)/seconds)+'/s';downRate.textContent=formatBytes((traffic.down-traffic.lastDown)/seconds)+'/s';traffic.lastUp=traffic.up;traffic.lastDown=traffic.down;traffic.lastAt=now};
setInterval(refreshTraffic,1000);
const token=location.hash.slice(1);history.replaceState(null,'',location.pathname);
const browser=(navigator.userAgentData&&navigator.userAgentData.brands)
 ?navigator.userAgentData.brands.map(x=>x.brand+' '+x.version).join(', ')
 :navigator.userAgent.slice(0,150);
const channel=new MessageChannel(),port=channel.port1,pending=[],localQueueLimit=33554432;let initialized=false,localClosed=false,iframe=null;
port.start();
const local=new WebSocket('ws://127.0.0.1:'+location.port+'/transport');
local.binaryType='arraybuffer';
let rtcGuard=null,rtcRetryTimer=0,rtcFailures=0;)HTML"
uR"HTML(
const disposeRtc=guard=>{if(guard.first)guard.first.onicecandidate=null;if(guard.second){guard.second.onicecandidate=null;guard.second.ondatachannel=null}if(guard.receiver)guard.receiver.close();if(guard.channel)guard.channel.close();if(guard.first)guard.first.close();if(guard.second)guard.second.close()};
const stopRtc=()=>{if(rtcRetryTimer){clearTimeout(rtcRetryTimer);rtcRetryTimer=0}const guard=rtcGuard;rtcGuard=null;if(guard)disposeRtc(guard)};
const scheduleRtc=()=>{if(local.readyState!==WebSocket.OPEN||rtcGuard||rtcRetryTimer||rtcFailures>=5)return;const delay=Math.min(1000*(2**Math.max(0,rtcFailures-1)),30000);rtcRetryTimer=setTimeout(()=>{rtcRetryTimer=0;startRtc()},delay)};
const restartRtc=guard=>{if(rtcGuard!==guard)return;rtcGuard=null;disposeRtc(guard);rtcFailures++;scheduleRtc()};
const startRtc=async()=>{if(local.readyState!==WebSocket.OPEN||rtcGuard||rtcRetryTimer||rtcFailures>=5)return;if(typeof RTCPeerConnection!=='function'){rtcFailures=5;return}
 const guard={first:null,second:null,channel:null,receiver:null};rtcGuard=guard;
 try{
  guard.first=new RTCPeerConnection({iceServers:[]});guard.second=new RTCPeerConnection({iceServers:[]});guard.channel=guard.first.createDataChannel('tab-lifecycle');
  const toFirst=[],toSecond=[];
  const loopbackCandidate=candidate=>{const value=candidate.toJSON(),parts=value.candidate.split(/\s+/);if(parts.length<6)return null;parts[4]='127.0.0.1';value.candidate=parts.join(' ');return value};
  const relayCandidate=(peer,queue,candidate)=>{candidate=candidate&&loopbackCandidate(candidate);if(!candidate)return;if(peer.remoteDescription)peer.addIceCandidate(candidate).catch(()=>{});else queue.push(candidate)};
  guard.first.onicecandidate=event=>relayCandidate(guard.second,toSecond,event.candidate);
  guard.second.onicecandidate=event=>relayCandidate(guard.first,toFirst,event.candidate);
  guard.second.ondatachannel=event=>{guard.receiver=event.channel};
  const opened=new Promise((resolve,reject)=>{const check=()=>{if(guard.first.connectionState==='failed'||guard.first.connectionState==='closed'||guard.second.connectionState==='failed'||guard.second.connectionState==='closed')reject()};guard.channel.addEventListener('open',resolve,{once:true});guard.channel.addEventListener('close',reject,{once:true});guard.first.addEventListener('connectionstatechange',check);guard.second.addEventListener('connectionstatechange',check)});
  const offer=await guard.first.createOffer();await guard.first.setLocalDescription(offer);
  await guard.second.setRemoteDescription(offer);
  await Promise.all(toSecond.splice(0).map(candidate=>guard.second.addIceCandidate(candidate)));
  const answer=await guard.second.createAnswer();await guard.second.setLocalDescription(answer);
  await guard.first.setRemoteDescription(answer);
  await Promise.all(toFirst.splice(0).map(candidate=>guard.first.addIceCandidate(candidate)));)HTML"
uR"HTML(
  let timeout=0;try{await Promise.race([opened,new Promise((resolve,reject)=>{timeout=setTimeout(reject,10000)})])}finally{clearTimeout(timeout)}
  if(rtcGuard!==guard||local.readyState!==WebSocket.OPEN){restartRtc(guard);return}
  rtcFailures=0;
  const check=()=>{if(guard.channel.readyState==='closed'||guard.first.connectionState==='failed'||guard.first.connectionState==='closed'||guard.second.connectionState==='failed'||guard.second.connectionState==='closed')restartRtc(guard)};
  guard.channel.addEventListener('close',check,{once:true});guard.first.addEventListener('connectionstatechange',check);guard.second.addEventListener('connectionstatechange',check);
 }catch(error){restartRtc(guard)}};
local.onopen=()=>{local.send(JSON.stringify({t:'auth',token,browser}));startRtc()};
local.onclose=()=>{stopRtc();localClosed=true;state.textContent='Telegram Desktop disconnected. Reopen the browser from Proxy Settings.';if(initialized)port.postMessage({t:'close'})};
local.onerror=()=>{state.textContent='Could not connect to Telegram Desktop.'};
const openBridge=url=>{if(iframe||localClosed)return;iframe=document.createElement('iframe');iframe.sandbox='allow-scripts allow-same-origin';iframe.referrerPolicy='no-referrer';
 iframe.onload=()=>{if(localClosed)return;if(initialized){state.textContent='The proxy page reloaded. Reopen the browser from Proxy Settings.';local.close();return}iframe.contentWindow.postMessage({t:'tproxy-init',v:1},relayOrigin,[channel.port2]);initialized=true;while(pending.length){const data=pending.shift();port.postMessage(data,[data])}};
 iframe.src=url;document.body.appendChild(iframe)};
local.onmessage=e=>{if(e.data instanceof ArrayBuffer){if(initialized)port.postMessage(e.data,[e.data]);else pending.push(e.data);return}
 if(typeof e.data!=='string')return;let control=null;try{control=JSON.parse(e.data)}catch(error){return}
 if(!control||typeof control!=='object'||control.t!=='bridge'||typeof control.url!=='string'||!control.url.startsWith(relayBase+'?bridge='))return;openBridge(control.url)};
port.onmessage=e=>{if(e.data instanceof ArrayBuffer){if(local.readyState===WebSocket.OPEN){if(local.bufferedAmount>localQueueLimit-e.data.byteLength){state.textContent='Telegram Desktop is not consuming proxy data.';local.close();return}try{local.send(e.data)}catch(error){local.close()}}return}
 if(e.data&&e.data.t==='status'){const s=e.data.state;state.textContent=s==='connected'?'Connected. Keep this tab open.':s==='failed'?'The proxy site is unavailable.':'Connecting to the proxy site…';if(local.readyState===WebSocket.OPEN)local.send(JSON.stringify(e.data));return}
 if(e.data&&e.data.t==='traffic'){const up=e.data.up,down=e.data.down;if(Number.isSafeInteger(up)&&up>=0&&Number.isSafeInteger(down)&&down>=0){traffic.up+=up;traffic.down+=down}return}
 if(e.data&&e.data.t==='close'){state.textContent='The proxy site closed the connection.';local.close()}}
addEventListener('pagehide',stopRtc,{once:true});
addEventListener('pageshow',startRtc);
})();
</script>)HTML"_q.arg(target, nonce, base).toUtf8();
	return html;
}

QByteArray Transport::Private::pageHeaders(const QString &nonce) const {
	const auto origin = QUrl(u"https://"_q + _proxy.host);
	const auto connectSource = u"ws://127.0.0.1:%1"_q.arg(_serverPort);
	return u"Content-Security-Policy: default-src 'none'; "
		"script-src 'nonce-%3'; style-src 'unsafe-inline'; "
		"base-uri 'none'; form-action 'none'; frame-ancestors 'none'; "
		"frame-src %1; connect-src %2\r\n"_q
		.arg(origin.toString(QUrl::FullyEncoded), connectSource, nonce)
		.toUtf8();
}

Transport::Transport()
: _private(std::make_unique<Private>(this)) {
}

Transport::~Transport() = default;

void Transport::StartWebview(const ProxyData &proxy) {
	Expects(QThread::currentThread() == QCoreApplication::instance()->thread());

	auto &global = Global();
	if (!global.transport || global.active != proxy || global.webview) {
		return;
	}
	const auto generation = ++global.webviewGeneration;
	const auto transport = global.transport;
	transport->webviewStarting(generation);
	if (global.webviewDisabled || !global.webviewSupported) {
		transport->webviewFailed(generation);
		return;
	}
	global.webview = std::make_unique<WebviewCarrier>(
		proxy,
		generation,
		WebviewCarrier::Callbacks{
			.ready = [=](uint64 readyGeneration) {
				auto &global = Global();
				if (global.webviewGeneration == readyGeneration) {
					global.webviewFailures = 0;
					global.webviewRetryDelay = kWebviewRetryMinTimeout;
				}
				if (transport) {
					transport->webviewReady(readyGeneration);
				}
			},
			.payload = [=](uint64 payloadGeneration, QByteArray payload) {
				if (transport) {
					transport->webviewPayload(
						payloadGeneration,
						std::move(payload));
				}
			},
			.written = [=](
					uint64 writtenGeneration,
					int bytes,
					int items) {
				if (transport) {
					transport->webviewWritten(
						writtenGeneration,
						bytes,
						items);
				}
			},
			.failed = [=](uint64 failedGeneration) {
				if (transport) {
					transport->webviewFailed(failedGeneration);
				}
			},
		});
	if (!global.webview->valid()) {
		global.webview = nullptr;
		global.webviewFailures = kMaxWebviewFailures;
		global.webviewRetryDelay = kWebviewRetryMaxTimeout;
		transport->webviewFailed(generation);
	}
}

void Transport::FinishWebview(uint64 generation) {
	InvokeQueued(QCoreApplication::instance(), [=] {
		auto &global = Global();
		if (global.webviewGeneration != generation) {
			return;
		}
		RetireWebview(base::take(global.webview));
		if (!global.active || global.webviewRetryScheduled) {
			return;
		}
		const auto transport = global.transport;
		if (global.webviewFailures < kMaxWebviewFailures) {
			++global.webviewFailures;
		}
		const auto retry = !global.webviewDisabled && global.webviewSupported;
		if (!retry || global.webviewFailures >= kMaxWebviewFailures) {
			if (transport) {
				transport->webviewUnavailable();
			}
		}
		if (!retry) {
			return;
		}
		global.webviewRetryScheduled = true;
		const auto proxy = global.active;
		const auto delay = global.webviewRetryDelay;
		global.webviewRetryDelay = std::min(
			delay * 2,
			kWebviewRetryMaxTimeout);
		QTimer::singleShot(
			int(delay),
			QCoreApplication::instance(),
			[=] {
				auto &global = Global();
				if (global.active != proxy) {
					return;
				}
				global.webviewRetryScheduled = false;
				StartWebview(proxy);
			});
	});
}

void Transport::Activate(const ProxyData &proxy) {
	Expects(QThread::currentThread() == QCoreApplication::instance()->thread());
	Expects(proxy.type == ProxyData::Type::Web);
	Expects(proxy.valid());

	auto &global = Global();
	const auto changed = (global.active != proxy);
	if (!global.transport) {
		global.thread = std::make_unique<QThread>();
		global.transport = new Transport();
		global.available = global.transport.data();
		global.transport->moveToThread(global.thread.get());
		QObject::connect(
			global.thread.get(),
			&QThread::finished,
			global.transport,
			&QObject::deleteLater);
		global.thread->start();
	}
	global.active = proxy;
	global.webActive = true;
	if (changed) {
		RetireWebview(base::take(global.webview));
		++global.webviewGeneration;
		global.webviewRetryScheduled = false;
		global.webviewFailures = 0;
		global.webviewRetryDelay = kWebviewRetryMinTimeout;
		global.webviewSupported = WebviewCarrier::Supported();
		global.state = State::Connecting;
		global.browser.clear();
		const auto transport = global.transport.data();
		QMetaObject::invokeMethod(transport, [=] {
			transport->_private->configure(proxy);
		}, Qt::BlockingQueuedConnection);
		global.changes.fire({ proxy, State::Connecting, QString() });
		StartWebview(proxy);
	}
}

void Transport::Deactivate() {
	Expects(QThread::currentThread() == QCoreApplication::instance()->thread());

	auto &global = Global();
	RetireWebview(base::take(global.webview));
	++global.webviewGeneration;
	global.webviewRetryScheduled = false;
	if (global.transport && global.active) {
		const auto transport = global.transport.data();
		QMetaObject::invokeMethod(transport, [=] {
			transport->_private->deactivate();
		}, Qt::BlockingQueuedConnection);
	}
	const auto old = base::take(global.active);
	global.webActive = false;
	global.state = State::Idle;
	global.browser.clear();
	if (old.type == ProxyData::Type::Web) {
		global.changes.fire({ old, State::Idle, QString() });
	}
}

void Transport::Shutdown() {
	Expects(QThread::currentThread() == QCoreApplication::instance()->thread());

	auto &global = Global();
	if (!global.transport) {
		return;
	}
	Deactivate();
	const auto transport = global.transport.data();
	QMetaObject::invokeMethod(transport, [=] {
		transport->_private->stop();
	}, Qt::BlockingQueuedConnection);
	global.thread->quit();
	global.thread->wait();
	global.available = nullptr;
	global.webview = nullptr;
	global.closingWebviews.clear();
	global.transport = nullptr;
	global.thread = nullptr;
}

Transport *Transport::Instance() {
	return Global().available.load();
}

Transport::State Transport::CurrentState(const ProxyData &proxy) {
	const auto &global = Global();
	return (global.active == proxy) ? global.state : State::Idle;
}

rpl::producer<Transport::StateChange> Transport::StateChanges() {
	return Global().changes.events();
}

bool Transport::ToggleWebviewDisabled() {
	Expects(QThread::currentThread() == QCoreApplication::instance()->thread());

	auto &global = Global();
	global.webviewDisabled = !global.webviewDisabled;
	if (global.webviewDisabled) {
		const auto generation = global.webviewGeneration;
		RetireWebview(base::take(global.webview));
		++global.webviewGeneration;
		global.webviewRetryScheduled = false;
		if (global.transport && global.active && generation) {
			global.transport->webviewFailed(generation);
			global.transport->webviewUnavailable();
		}
	} else if (global.transport && global.active) {
		global.webviewFailures = 0;
		global.webviewRetryDelay = kWebviewRetryMinTimeout;
		global.webviewRetryScheduled = false;
		StartWebview(global.active);
	}
	return global.webviewDisabled;
}

void Transport::OpenBrowser(const ProxyData &proxy) {
	Expects(QThread::currentThread() == QCoreApplication::instance()->thread());

	auto &global = Global();
	if (!global.transport || global.active != proxy) {
		return;
	}
	auto url = QString();
	const auto transport = global.transport.data();
	QMetaObject::invokeMethod(transport, [&] {
		url = transport->_private->mintBrowserUrl();
	}, Qt::BlockingQueuedConnection);
	if (!url.isEmpty()) {
		File::OpenUrl(url);
	}
}

uint32 Transport::NextStreamId() {
	static auto next = std::atomic<uint64>(0);
	return uint32((next.fetch_add(1) % 0x00FFFFFF) + 1);
}

bool Transport::Active() {
	return Global().webActive.load();
}

CarrierHealth Transport::carrierHealth() const {
	return {
		.connected = _healthConnected.load(),
		.lastDownlinkAt = _healthLastDownlinkAt.load(),
		.lastCreditAt = _healthLastCreditAt.load(),
		.unackedBytes = _healthUnacked.load(),
		.outstandingSince = _healthOutstandingSince.load(),
	};
}

void Transport::registerStream(uint32 streamId, StreamHandlers handlers) {
	InvokeQueued(this, [=, handlers = std::move(handlers)]() mutable {
		_private->registerStream(streamId, std::move(handlers));
	});
}

void Transport::closeStream(uint32 streamId) {
	if (QThread::currentThread() == thread()) {
		_private->closeStream(streamId);
	} else if (thread()->isRunning()) {
		QMetaObject::invokeMethod(this, [=] {
			_private->closeStream(streamId);
		}, Qt::BlockingQueuedConnection);
	}
}

void Transport::sendData(uint32 streamId, QByteArray data) {
	if (data.isEmpty()) {
		return;
	}
	if (!reservePending(data.size())) {
		if (QThread::currentThread() == thread()) {
			_private->failStream(streamId);
		} else if (thread()->isRunning()) {
			QMetaObject::invokeMethod(this, [=] {
				_private->failStream(streamId);
			}, Qt::BlockingQueuedConnection);
		}
		return;
	}
	InvokeQueued(this, [=, data = std::move(data)]() mutable {
		_private->sendData(streamId, std::move(data));
	});
}

void Transport::grantWindow(uint32 streamId, uint32 amount) {
	InvokeQueued(this, [=] { _private->grantWindow(streamId, amount); });
}

void Transport::webviewStarting(uint64 generation) {
	InvokeQueued(this, [=] { _private->webviewStarting(generation); });
}

void Transport::webviewReady(uint64 generation) {
	InvokeQueued(this, [=] { _private->webviewReady(generation); });
}

void Transport::webviewPayload(uint64 generation, QByteArray payload) {
	if (payload.isEmpty() || !reservePending(payload.size())) {
		webviewFailed(generation);
		return;
	}
	InvokeQueued(this, [=, payload = std::move(payload)]() mutable {
		const auto size = payload.size();
		_private->webviewPayload(generation, payload);
		releasePending(size, 1);
	});
}

void Transport::webviewWritten(uint64 generation, int bytes, int items) {
	InvokeQueued(this, [=] {
		_private->webviewWritten(generation, bytes, items);
	});
}

void Transport::webviewFailed(uint64 generation) {
	FinishWebview(generation);
	InvokeQueued(this, [=] { _private->webviewFailed(generation); });
}

void Transport::webviewUnavailable() {
	InvokeQueued(this, [=] { _private->webviewUnavailable(); });
}

void Transport::sendWebviewFrame(uint64 generation, QByteArray frame) {
	const auto guard = QPointer<Transport>(this);
	InvokeQueued(QCoreApplication::instance(), [=, frame = std::move(frame)]() mutable {
		auto &global = Global();
		if (global.webviewGeneration == generation && global.webview) {
			global.webview->send(std::move(frame));
		} else if (guard) {
			guard->webviewFailed(generation);
		}
	});
}

bool Transport::reservePending(int bytes) {
	Expects(bytes > 0);

	auto items = _pendingItems.load();
	do {
		if (items >= kMaxPendingTransportItems) {
			return false;
		}
	} while (!_pendingItems.compare_exchange_weak(items, items + 1));
	auto pending = _pendingBytes.load();
	do {
		if (pending > kMaxPendingTransportBytes - bytes) {
			_pendingItems.fetch_sub(1);
			return false;
		}
	} while (!_pendingBytes.compare_exchange_weak(pending, pending + bytes));
	return true;
}

void Transport::releasePending(int bytes, int items) {
	Expects(bytes >= 0);
	Expects(items >= 0);

	if (bytes) {
		const auto before = _pendingBytes.fetch_sub(bytes);
		Assert(before >= bytes);
	}
	if (items) {
		const auto before = _pendingItems.fetch_sub(items);
		Assert(before >= items);
	}
}

} // namespace MTP::WebProxy

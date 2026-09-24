/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "base/basic_types.h"
#include "mtproto/proxy/data.h"

#include <QtCore/QByteArray>
#include <QtCore/QObject>
#include <crl/crl_time.h>

#include <atomic>
#include <deque>
#include <memory>
#include <string>

class QTimer;

namespace Webview {
class Window;
} // namespace Webview

namespace MTP::WebProxy {

// What crossed the native <-> page boundary, for diagnostics and the
// self-test. Written on the main thread, read anywhere.
struct BridgeCounters {
	std::atomic<int64> upWrites = 0;
	std::atomic<int64> upBytes = 0;
	std::atomic<int64> upAckMsTotal = 0;
	std::atomic<int64> upAckMsMax = 0;
	std::atomic<int64> upQueuedMax = 0;
	std::atomic<int64> downMessages = 0;
	std::atomic<int64> downBytes = 0;
};
[[nodiscard]] BridgeCounters &Bridge();

class WebviewCarrier final : public QObject {
public:
	struct Callbacks {
		Fn<void(uint64)> ready;
		Fn<void(uint64, QByteArray)> payload;
		// Bytes and items (send() calls) the page has taken over.
		Fn<void(uint64, int, int)> written;
		Fn<void(uint64)> failed;
	};

	WebviewCarrier(
		const ProxyData &proxy,
		uint64 generation,
		Callbacks callbacks);
	~WebviewCarrier();

	[[nodiscard]] static bool Supported();
	[[nodiscard]] bool valid() const;

	// One or more whole frames. Consecutive sends are coalesced into one
	// page call and several page calls are kept in flight, so the bridge
	// costs one round trip per batch, not per frame.
	void send(QByteArray frames);

	// Asks the bridge page to close its relay session and stops reacting
	// to the page. The object should be kept alive shortly afterwards so
	// that the asynchronous close script gets a chance to run.
	void close();

private:
	struct Pending {
		QByteArray frame;
		bool notifyWritten = false;
	};
	struct InFlight {
		uint64 sequence = 0;
		int bytes = 0;
		int items = 0;
		bool notifyWritten = false;
		crl::time since = 0;
	};

	void handleMessage(std::string message, std::string sourceUrl);
	void handleControl(const QByteArray &control);
	void handleBinary(QByteArray frame);
	[[nodiscard]] bool validNavigation(const QString &url) const;
	[[nodiscard]] bool validSource(const std::string &sourceUrl) const;
	void extendHandshake();
	void probeRestrictions();
	void enqueue(Pending pending);
	void drain();
	void heartbeat();
	void fail(const char *reason);

	const ProxyData _proxy;
	const uint64 _generation = 0;
	const QString _nonce;
	const QString _url;
	Callbacks _callbacks;
	std::unique_ptr<Webview::Window> _window;
	std::unique_ptr<QTimer> _handshakeTimer;
	std::unique_ptr<QTimer> _healthTimer;
	std::unique_ptr<QTimer> _probeTimer;
	std::unique_ptr<QTimer> _writeTimer;
	std::deque<Pending> _pending;
	std::deque<InFlight> _inFlight;
	int _inFlightBytes = 0;
	uint64 _writeSequence = 0;
	crl::time _handshakeStarted = 0;
	int _pendingBytes = 0;
	bool _bridgeInitialized = false;
	bool _adopted = false;
	bool _failed = false;
	bool _closing = false;
#ifndef NDEBUG
	bool _probed = false;
#endif // !NDEBUG
};

} // namespace MTP::WebProxy

/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "mtproto/proxy/data.h"
#include "mtproto/web_proxy/web_proxy_flow.h"

#include <QtCore/QObject>
#include <QtCore/QPointer>
#include <rpl/producer.h>

#include <atomic>
#include <memory>

namespace MTP::WebProxy {

// What the carrier knows about one stream, readable from the socket's
// thread while the carrier thread updates it.
struct StreamProbe {
	std::atomic<int64> queuedBytes = 0;
	std::atomic<int64> unackedBytes = 0;
	std::atomic<int64> sentBytes = 0;
	std::atomic<int64> lastReceivedAt = 0;
	std::atomic<int64> deliveredAt = 0;
	std::atomic<bool> open = false;

	[[nodiscard]] StreamHealth snapshot() const {
		return {
			.open = open.load(),
			.queuedBytes = queuedBytes.load(),
			.unackedBytes = unackedBytes.load(),
			.lastReceivedAt = lastReceivedAt.load(),
			.deliveredAt = deliveredAt.load(),
		};
	}
};

class Transport final : public QObject {
	Q_OBJECT

public:
	enum class State {
		Idle,
		WaitingForBrowser,
		Connecting,
		Connected,
		Failed,
	};
	struct StateChange {
		ProxyData proxy;
		State state = State::Idle;
		QString browser;
	};
	struct StreamHandlers {
		QPointer<QObject> context;
		Fn<void()> connected;
		Fn<void(QByteArray)> data;
		Fn<void()> disconnected;
		Fn<void()> failed;
		StreamClass streamClass = StreamClass::Interactive;
		std::shared_ptr<StreamProbe> probe;
	};

	static void Activate(const ProxyData &proxy);
	static void Deactivate();
	static void Shutdown();
	[[nodiscard]] static Transport *Instance();
	[[nodiscard]] static State CurrentState(const ProxyData &proxy);
	[[nodiscard]] static rpl::producer<StateChange> StateChanges();
	[[nodiscard]] static bool ToggleWebviewDisabled();
	static void OpenBrowser(const ProxyData &proxy);
	[[nodiscard]] static uint32 NextStreamId();

	// A WEB proxy is the active proxy, so every session shares one carrier
	// and file transfers should not fan out.
	[[nodiscard]] static bool Active();

	// Any thread.
	[[nodiscard]] CarrierHealth carrierHealth() const;

	void registerStream(uint32 streamId, StreamHandlers handlers);
	void closeStream(uint32 streamId);
	void sendData(uint32 streamId, QByteArray data);
	void grantWindow(uint32 streamId, uint32 amount);

	~Transport();

private:
	Transport();
	static void StartWebview(const ProxyData &proxy);
	static void FinishWebview(uint64 generation);
	void webviewStarting(uint64 generation);
	void webviewReady(uint64 generation);
	void webviewPayload(uint64 generation, QByteArray payload);
	void webviewWritten(uint64 generation, int bytes, int items);
	void webviewFailed(uint64 generation);
	void webviewUnavailable();
	void sendWebviewFrame(uint64 generation, QByteArray frame);
	[[nodiscard]] bool reservePending(int bytes);
	void releasePending(int bytes, int items);

	class Private;
	const std::unique_ptr<Private> _private;
	std::atomic<int64> _pendingBytes = 0;
	std::atomic<int> _pendingItems = 0;
	std::atomic<bool> _healthConnected = false;
	std::atomic<int64> _healthLastDownlinkAt = 0;
	std::atomic<int64> _healthLastCreditAt = 0;
	std::atomic<int64> _healthUnacked = 0;
	std::atomic<int64> _healthOutstandingSince = 0;

};

} // namespace MTP::WebProxy

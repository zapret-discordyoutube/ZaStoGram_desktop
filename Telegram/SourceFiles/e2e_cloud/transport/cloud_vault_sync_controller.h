/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "e2e_cloud/transport/cloud_vault_transport.h"
#include "e2e_cloud/vault/cloud_vault_selection.h"

#include <QtCore/QByteArray>

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <set>
#include <vector>

namespace E2ECloud {

enum class CloudVaultSyncStatus {
	Selected,
	Present,
	Missing,
	Unreadable,
	CapacityExceeded,
	IdentityConflict,
	ForkDetected,
	RollbackDetected,
	ChainGap,
	RetryableTransportError,
	PermanentTransportError,
	InvalidPagination,
	Cancelled,
};

struct CloudVaultSyncCompletion {
	CloudVaultSyncStatus status = CloudVaultSyncStatus::Cancelled;
	std::optional<UnlockedCloudVault> vault;
	std::uint64_t pages = 0;
	std::uint64_t candidates = 0;
};

class CloudVaultSyncController final {
public:
	using CompletionCallback = std::function<void(CloudVaultSyncCompletion)>;

	CloudVaultSyncController(
		std::uint64_t telegramUserIdBinding,
		CloudVaultRemote &remote,
		const CloudVaultSelector &selector,
		CompletionCallback completionCallback);
	~CloudVaultSyncController();

	[[nodiscard]] bool start(
		QByteArray password,
		std::optional<CloudVaultAnchor> localAnchor = std::nullopt);
	[[nodiscard]] bool startDiscovery();
	void cancel();

	[[nodiscard]] bool running() const;

private:
	struct CallbackGuard;

	[[nodiscard]] bool startRequests(
		std::optional<CloudVaultAnchor> localAnchor);
	void pumpRequests();
	void pageReceived(
		CloudVaultRemote::Result result,
		CarrierDownloadPage page);
	void discoveryReceived(
		CloudVaultRemote::Result result,
		bool present);
	void finish(CloudVaultSyncCompletion completion);

	std::uint64_t _telegramUserIdBinding = 0;
	CloudVaultRemote &_remote;
	const CloudVaultSelector &_selector;
	CompletionCallback _completionCallback;
	QByteArray _password;
	std::optional<CloudVaultAnchor> _localAnchor;
	std::vector<QByteArray> _candidates;
	std::set<QByteArray> _seenCursors;
	QByteArray _cursor;
	std::uint64_t _candidateBytes = 0;
	std::uint64_t _pages = 0;
	std::uint64_t _storedCursorBytes = 0;
	std::shared_ptr<CallbackGuard> _callbackGuard;
	bool _running = false;
	bool _requestActive = false;
	bool _pumping = false;
	bool _requestQueued = false;
};

} // namespace E2ECloud

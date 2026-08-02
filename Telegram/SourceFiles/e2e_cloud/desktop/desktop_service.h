/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "base/weak_ptr.h"
#include "e2e_cloud/group/group_state.h"
#include "e2e_cloud/storage/file_atomic_blob_store.h"
#include "e2e_cloud/storage/persistent_content_store.h"
#include "e2e_cloud/transport/cloud_vault_sync_controller.h"
#include "e2e_cloud/transport/file_chunk_download_controller.h"
#include "e2e_cloud/transport/observed_content_sync_controller.h"
#include "e2e_cloud/transport/outbox_upload_controller.h"
#include "e2e_cloud/transport/public_bootstrap_discovery_controller.h"
#include "e2e_cloud/transport/public_bootstrap_sync_controller.h"
#include "e2e_cloud/transport/telegram_session_carrier_backend.h"
#include "e2e_cloud/vault/argon2id_password_kdf.h"
#include "e2e_cloud/vault/persistent_cloud_vault_anchor.h"

#include <rpl/producer.h>
#include <rpl/variable.h>

#include <QtCore/QByteArray>
#include <QtCore/QString>

#include <cstddef>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <vector>

namespace Main {
class Session;
} // namespace Main

class PeerData;
class HistoryItem;

namespace E2ECloud {

enum class DesktopVaultState {
	Uninitialized,
	Discovering,
	Locked,
	Loading,
	Missing,
	Creating,
	Ready,
	WrongPasswordOrDamaged,
	RetryableTransportError,
	PermanentTransportError,
	DiscoveryRetryableError,
	DiscoveryPermanentError,
	SecurityBlocked,
};

enum class DesktopGroupCreationState {
	Idle,
	Preparing,
	UpdatingVault,
	PublishingBootstrap,
	AwaitingAdmission,
	AwaitingFreshness,
	Ready,
	RetryableTransportError,
	PermanentTransportError,
	LocalFailure,
};

enum class DesktopContentState {
	Idle,
	Synchronizing,
	Ready,
	AwaitingFreshness,
	RetryableTransportError,
	PermanentTransportError,
	LocalFailure,
	SecurityBlocked,
};

enum class ProtectedFileSaveResult {
	Saved,
	Busy,
	InvalidRequest,
	RetryableTransportError,
	PermanentTransportError,
	MissingChunks,
	SecurityBlocked,
	LocalFailure,
};

struct DesktopProtectedGroupSummary {
	ConversationId conversationId;
	std::uint64_t telegramPeerIdBinding = 0;
	QString title;
	std::uint64_t generation = 0;
	std::size_t contentCount = 0;
	bool active = false;
	bool removed = false;
	bool sendingAllowed = false;
	bool fileTransferPending = false;
};

struct DesktopProtectedMember {
	AccountId accountId;
	std::uint64_t telegramUserIdBinding = 0;
	GroupRole role = GroupRole::Member;
	HistoryAccess historyAccess;
	std::size_t clientCount = 0;
	QString accountSafetyCode;
	QString pairwiseSafetyCode;
	bool local = false;
};

struct DesktopProtectedSecurity {
	std::uint64_t generation = 0;
	QString groupSafetyCode;
	std::size_t memberCount = 0;
	std::size_t witnessCount = 0;
	HistoryAccess defaultHistoryAccess;
	bool canSetRoles = false;
	bool canRemoveMembers = false;
	bool canGrantHistory = false;
	bool canGrantFullHistory = false;
	bool canChangeDefaultHistory = false;
	std::vector<DesktopProtectedMember> members;
};

class DesktopService final : public base::has_weak_ptr {
public:
	explicit DesktopService(not_null<Main::Session*> session);
	~DesktopService();

	[[nodiscard]] DesktopVaultState vaultState() const;
	[[nodiscard]] rpl::producer<DesktopVaultState> vaultStateValue() const;
	[[nodiscard]] const UnlockedCloudVault *vault() const;

	void ensureVaultDiscovery();
	[[nodiscard]] bool unlock(QByteArray password);
	[[nodiscard]] bool createVault(QByteArray password);
	[[nodiscard]] bool retryCreateVault();
	[[nodiscard]] DesktopGroupCreationState groupCreationState() const;
	[[nodiscard]] rpl::producer<DesktopGroupCreationState>
		groupCreationStateValue() const;
	[[nodiscard]] bool createProtectedGroup(
		not_null<PeerData*> peer,
		HistoryAccess defaultHistoryAccess);
	[[nodiscard]] bool retryProtectedGroupCreation();
	[[nodiscard]] std::vector<DesktopProtectedGroupSummary>
		protectedGroups() const;
	[[nodiscard]] std::optional<ConversationId>
		protectedConversationForPeer(
			std::uint64_t telegramPeerIdBinding) const;
	[[nodiscard]] bool isProtectedPeerForPresentation(
		std::uint64_t telegramPeerIdBinding) const;
	[[nodiscard]] std::vector<ProtectedContentRecord> protectedContent(
		ConversationId conversationId,
		std::size_t offset,
		std::size_t limit,
		std::optional<ObjectKind> kind = std::nullopt) const;
	[[nodiscard]] std::size_t protectedContentCount(
		ConversationId conversationId,
		std::optional<ObjectKind> kind = std::nullopt) const;
	[[nodiscard]] std::optional<DesktopProtectedSecurity> protectedSecurity(
		ConversationId conversationId) const;
	[[nodiscard]] bool sendProtectedText(
		ConversationId conversationId,
		QString text);
	[[nodiscard]] bool sendProtectedFile(
		ConversationId conversationId,
		QString path);
	[[nodiscard]] bool cancelProtectedFileTransfer(
		ConversationId conversationId);
	[[nodiscard]] bool saveProtectedFile(
		ConversationId conversationId,
		ObjectId eventObjectId,
		QString path,
		std::function<void(ProtectedFileSaveResult)> callback);
	[[nodiscard]] bool setProtectedDefaultHistory(
		ConversationId conversationId,
		HistoryAccess historyAccess);
	[[nodiscard]] bool setProtectedMemberHistory(
		ConversationId conversationId,
		AccountId accountId,
		HistoryAccess historyAccess);
	[[nodiscard]] bool setProtectedMemberRole(
		ConversationId conversationId,
		AccountId accountId,
		GroupRole role);
	[[nodiscard]] bool removeProtectedMember(
		ConversationId conversationId,
		AccountId accountId);
	[[nodiscard]] DesktopContentState contentState(
		ConversationId conversationId) const;
	[[nodiscard]] rpl::producer<DesktopContentState>
		contentStateValue() const;
	[[nodiscard]] rpl::producer<std::uint64_t>
		contentRevisionValue() const;
	[[nodiscard]] rpl::producer<std::uint64_t>
		fileTransferRevisionValue() const;
	[[nodiscard]] rpl::producer<std::uint64_t>
		securityRevisionValue() const;
	void synchronizeProtectedContent(ConversationId conversationId);
	void lock();

private:
	struct PendingGroupCreation;
	struct PendingGroupJoin;
	struct PendingGroupDiscovery;
	enum class LocalGroupRecoveryResult;

	[[nodiscard]] bool vaultReady() const;
	[[nodiscard]] bool hasProtectedRuntimeState() const;
	void scheduleSecurityLock();
	void applyVaultDiscoveryResult(CloudVaultSyncCompletion result);
	void applySyncResult(CloudVaultSyncCompletion result);
	void applyGroupVaultSyncResult(CloudVaultSyncCompletion result);
	void uploadPendingCreation();
	void beginGroupVaultPreflight();
	void uploadPendingConversationIndex();
	void publishNextBootstrapObject();
	void resumePendingGroupCreation();
	void beginIndexedGroupJoin(const CloudVaultConversation &conversation);
	void applyPublicBootstrapSyncResult(
		PublicBootstrapSyncCompletion result);
	[[nodiscard]] bool prepareGroupJoin(
		CloudVaultConversation conversation,
		VerifiedPublicGroupBootstrap verified,
		bool discovered);
	void queueGroupDiscovery(std::uint64_t telegramPeerIdBinding);
	void startNextGroupDiscovery();
	void applyGroupDiscovery(PublicBootstrapSyncCompletion result);
	void beginGroupObservation(ConversationId conversationId);
	void resumeDeferredGroupObservations();
	void applyGroupObservation(
		ConversationId conversationId,
		PublicBootstrapSyncCompletion result);
	[[nodiscard]] bool queueFreshnessChallenge(
		PendingGroupCreation &group);
	[[nodiscard]] bool resumeQueuedFreshnessChallenge(
		PendingGroupCreation &group,
		const EncodedEnvelope &encoded);
	[[nodiscard]] bool processObservedFreshness(
		ConversationId conversationId,
		const std::vector<TelegramTransport::UntrustedObject> &objects);
	[[nodiscard]] bool processObservedSafetyGossip(
		ConversationId conversationId,
		const std::vector<TelegramTransport::UntrustedObject> &objects);
	[[nodiscard]] bool synchronizeObservedGroupChanges(
		ConversationId conversationId,
		const std::vector<TelegramTransport::UntrustedObject> &objects);
	void publishQueuedGroupOutbox(ConversationId conversationId);
	[[nodiscard]] bool initializeActivePipeline(
		PendingGroupCreation &group);
	void pumpActiveOutbox(ConversationId conversationId);
	[[nodiscard]] bool prepareActiveUploadAcknowledgement(
		ConversationId conversationId,
		ObjectId objectId);
	[[nodiscard]] bool prepareFileManifestAcknowledgement(
		PendingGroupCreation &group,
		ObjectId objectId);
	[[nodiscard]] bool commitPreparedFileTransfer(
		ConversationId conversationId);
	[[nodiscard]] bool finishFileTransferCancellation(
		PendingGroupCreation &group);
	void completeActiveUpload(
		ConversationId conversationId,
		UploadCompletion completion);
	[[nodiscard]] bool pumpFileTransfer(ConversationId conversationId);
	void completeFileChunkUpload(
		ConversationId conversationId,
		std::uint32_t chunkIndex,
		TelegramTransport::UploadResult result);
	[[nodiscard]] bool beginFileChunkDownload(
		ConversationId conversationId,
		bool legacyCarrier);
	[[nodiscard]] FileChunkDownloadPageStatus processFileChunkDownloadPage(
		ConversationId conversationId,
		std::vector<TelegramTransport::UntrustedObject> objects);
	void applyFileChunkDownload(
		ConversationId conversationId,
		FileChunkDownloadCompletion completion);
	[[nodiscard]] bool writePendingProtectedFile(
		ConversationId conversationId);
	void continuePendingProtectedFileWrite(
		ConversationId conversationId,
		ObjectId eventObjectId,
		std::uint64_t operationEpoch);
	void finishFileChunkDownload(
		ConversationId conversationId,
		ProtectedFileSaveResult result);
	[[nodiscard]] bool queuePendingFileManifest(
		ConversationId conversationId);
	[[nodiscard]] bool finalizeFileTransfer(
		ConversationId conversationId);
	void beginContentObservation(ConversationId conversationId);
	[[nodiscard]] ObservedContentPageResult previewObservedFileManifests(
		ConversationId conversationId,
		const std::vector<TelegramTransport::UntrustedObject> &objects,
		std::size_t objectLimit);
	[[nodiscard]] ObservedContentPageResult processObservedContentPage(
		ConversationId conversationId,
		std::vector<TelegramTransport::UntrustedObject> objects);
	void applyContentObservation(
		ConversationId conversationId,
		ObservedContentSyncCompletion completion);
	void setContentState(
		ConversationId conversationId,
		DesktopContentState state);
	void notifyContentRevision();
	void notifyFileTransferRevision();
	void notifySecurityRevision();
	void rememberProtectedPeerForPresentation(
		std::uint64_t telegramPeerIdBinding);
	[[nodiscard]] bool completeObservedJoin(
		ConversationId conversationId,
		const PublicBootstrapSyncCompletion &result);
	bool acceptObservedHistoryGrant(
		ConversationId conversationId,
		const std::vector<TelegramTransport::UntrustedObject> &objects);
	[[nodiscard]] bool resumeObservedJoinHistory(
		ConversationId conversationId);
	[[nodiscard]] bool admitObservedClient(
		ConversationId conversationId,
		const std::vector<TelegramTransport::UntrustedObject> &objects);
	[[nodiscard]] bool applyAdministrativeTransition(
		ConversationId conversationId,
		GroupTransition transition);
	void handleNewTelegramItem(not_null<HistoryItem*> item);
	[[nodiscard]] LocalGroupRecoveryResult restoreLocalGroup(
		ConversationId conversationId,
		const CloudVaultConversation *indexedConversation);
	[[nodiscard]] bool commitVaultAnchor(
		const UnlockedCloudVault &vault);
	[[nodiscard]] bool commitVaultAnchor(
		const PreparedCloudVaultUpdate &update,
		const AccountPrivateIdentity &identity);

	const not_null<Main::Session*> _session;
	const std::uint64_t _telegramUserIdBinding = 0;
	const std::uint64_t _telegramSelfPeerId = 0;
	Argon2idPasswordKdf _passwordKdf;
	OpenSslSha256Provider _sha256;
	CloudVaultCodecV1 _vaultCodec;
	CloudVaultSelector _vaultSelector;
	FileAtomicBlobStore _vaultAnchorBlob;
	PersistentCloudVaultAnchor _vaultAnchor;
	std::unique_ptr<TelegramSessionCarrierBackend> _backend;
	std::unique_ptr<TelegramCloudVaultTransport> _remote;
	std::unique_ptr<CloudVaultSyncController> _sync;
	QByteArray _pendingUnlockPassword;
	QByteArray _unlockedPassword;
	std::optional<CreatedCloudVault> _pendingCreation;
	std::optional<UnlockedCloudVault> _vault;
	std::unique_ptr<PendingGroupCreation> _pendingGroupCreation;
	std::unique_ptr<PendingGroupJoin> _pendingGroupJoin;
	std::unique_ptr<PendingGroupDiscovery> _pendingGroupDiscovery;
	std::set<std::uint64_t> _groupDiscoveryQueue;
	std::map<ConversationId, std::unique_ptr<PendingGroupCreation>> _groups;
	std::set<std::uint64_t> _presentationProtectedPeers;
	bool _presentationProtectedPeersValid = true;
	rpl::variable<DesktopVaultState> _vaultState
		= DesktopVaultState::Uninitialized;
	rpl::variable<DesktopGroupCreationState> _groupCreationState
		= DesktopGroupCreationState::Idle;
	rpl::variable<DesktopContentState> _contentState
		= DesktopContentState::Idle;
	std::map<ConversationId, DesktopContentState> _contentStates;
	rpl::variable<std::uint64_t> _contentRevision = 0;
	rpl::variable<std::uint64_t> _fileTransferRevision = 0;
	rpl::variable<std::uint64_t> _securityRevision = 0;
	std::uint64_t _operationEpoch = 1;
	bool _securityLockScheduled = false;
	rpl::lifetime _lifetime;
};

} // namespace E2ECloud

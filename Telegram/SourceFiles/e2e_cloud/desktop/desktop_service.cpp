/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "e2e_cloud/desktop/desktop_service.h"

#include "base/unixtime.h"
#include "core/application.h"
#include "data/data_session.h"
#include "data/data_peer.h"
#include "data/data_document.h"
#include "data/data_document_media.h"
#include "e2e_cloud/archive/archive_epoch_crypto.h"
#include "e2e_cloud/archive/archived_content_outbox.h"
#include "e2e_cloud/archive/history_grant_service.h"
#include "e2e_cloud/archive/persistent_archive_state.h"
#include "e2e_cloud/content/protected_message_body.h"
#include "e2e_cloud/files/file_chunk_file_store.h"
#include "e2e_cloud/files/file_chunk_envelope.h"
#include "e2e_cloud/files/persistent_file_transfer.h"
#include "e2e_cloud/files/private_file_manifest.h"
#include "e2e_cloud/group/persistent_group_ledger.h"
#include "e2e_cloud/identity/safety_gossip.h"
#include "e2e_cloud/mls/key_package_lifecycle.h"
#include "e2e_cloud/mls/mls_outbox_reconciler.h"
#include "e2e_cloud/mls/observed_key_package.h"
#include "e2e_cloud/mls/openmls_application_engine.h"
#include "e2e_cloud/mls/openmls_group_change_engine.h"
#include "e2e_cloud/mls/openmls_inbound_group_change.h"
#include "e2e_cloud/protocol/group_bootstrap.h"
#include "e2e_cloud/protocol/group_bootstrap_transaction.h"
#include "e2e_cloud/protocol/group_change_transaction.h"
#include "e2e_cloud/protocol/freshness_protocol.h"
#include "e2e_cloud/protocol/observed_group_change_sync.h"
#include "e2e_cloud/protocol/observed_content_processor.h"
#include "e2e_cloud/protocol/public_join_catchup.h"
#include "e2e_cloud/storage/aes_gcm_local_record_protector.h"
#include "e2e_cloud/storage/file_atomic_blob_store.h"
#include "e2e_cloud/storage/local_record_key_derivation.h"
#include "e2e_cloud/storage/persistent_conversation_metadata.h"
#include "e2e_cloud/storage/persistent_content_sync_state.h"
#include "e2e_cloud/storage/persistent_freshness_trust.h"
#include "e2e_cloud/storage/persistent_inbound_journal.h"
#include "e2e_cloud/storage/persistent_key_package_pool.h"
#include "e2e_cloud/storage/persistent_mls_state.h"
#include "e2e_cloud/storage/persistent_outbox.h"
#include "e2e_cloud/transport/telegram_carrier_transport.h"
#include "e2e_cloud/transport/observed_content_sync_controller.h"
#include "e2e_cloud/transport/outbox_upload_controller.h"
#include "main/main_session.h"
#include "history/history.h"
#include "history/history_item.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <QtCore/QDir>
#include <QtCore/QFile>
#include <QtCore/QFileInfo>
#include <QtCore/QMimeDatabase>
#include <QtCore/QSaveFile>
#include <QtCore/QScopeGuard>

#include <algorithm>
#include <array>
#include <cctype>
#include <limits>
#include <set>
#include <utility>

namespace E2ECloud {
namespace {

inline constexpr auto kControlSyncOverlap = std::size_t(32);

[[nodiscard]] Argon2idConfig DesktopArgon2idConfig() {
	return {
		.parameterVersion = 1,
		.memoryKibibytes = 64 * 1024,
		.iterations = 3,
		.parallelism = 1,
	};
}

template <typename Id>
[[nodiscard]] std::optional<Id> RandomId() {
	auto result = Id();
	return (RAND_bytes(result.bytes.data(), result.bytes.size()) == 1
		&& bool(result))
		? std::optional<Id>(result)
		: std::nullopt;
}

[[nodiscard]] QString ConversationDirectory(
		std::uint64_t telegramUserIdBinding,
		ConversationId conversationId) {
	const auto encoded = QByteArray(
		reinterpret_cast<const char*>(conversationId.bytes.data()),
		int(conversationId.bytes.size())).toHex();
	return cWorkingDir()
		+ u"tdata/e2e_cloud/"_q
		+ QString::number(telegramUserIdBinding)
		+ u"/"_q
		+ QString::fromLatin1(encoded)
		+ u"/"_q;
}

[[nodiscard]] bool IsProtectedGroupPeerBinding(
		not_null<Main::Session*> session,
		std::uint64_t telegramPeerIdBinding) {
	if (!telegramPeerIdBinding) {
		return false;
	}
	const auto peerId = PeerId(telegramPeerIdBinding);
	if (!peerIsChat(peerId) && !peerIsChannel(peerId)) {
		return false;
	}
	const auto peer = session->data().peerLoaded(peerId);
	return !peer || peer->isChat() || peer->isMegagroup();
}

[[nodiscard]] QString AccountDirectory(
		std::uint64_t telegramUserIdBinding) {
	return cWorkingDir()
		+ u"tdata/e2e_cloud/"_q
		+ QString::number(telegramUserIdBinding)
		+ u"/"_q;
}

[[nodiscard]] QString CloudVaultAnchorPath(
		std::uint64_t telegramUserIdBinding) {
	return AccountDirectory(telegramUserIdBinding) + u"vault.anchor"_q;
}

[[nodiscard]] std::optional<ConversationId> DecodeConversationDirectory(
		const QString &name) {
	const auto encoded = name.toLatin1();
	if (encoded.size() != 64
		|| !std::all_of(
			encoded.begin(),
			encoded.end(),
			[](char value) {
				return std::isxdigit(static_cast<unsigned char>(value));
			})) {
		return std::nullopt;
	}
	const auto bytes = QByteArray::fromHex(encoded);
	if (bytes.size() != 32) {
		return std::nullopt;
	}
	auto result = ConversationId();
	std::copy_n(
		reinterpret_cast<const std::uint8_t*>(bytes.constData()),
		result.bytes.size(),
		result.bytes.begin());
	return result ? std::optional<ConversationId>(result) : std::nullopt;
}

void Cleanse(QByteArray &bytes) {
	if (!bytes.isEmpty()) {
		OPENSSL_cleanse(bytes.data(), bytes.size());
	}
	bytes.clear();
}

[[nodiscard]] ObjectId FreshnessResponseObjectId(
		ObjectId challengeObjectId,
		ClientId witnessClientId,
		const Sha256Provider &sha256) {
	auto input = QByteArray("TDE2E/freshness-response-object/v1");
	input.append(
		reinterpret_cast<const char*>(challengeObjectId.bytes.data()),
		challengeObjectId.bytes.size());
	input.append(
		reinterpret_cast<const char*>(witnessClientId.bytes.data()),
		witnessClientId.bytes.size());
	const auto digest = sha256.digest(input);
	auto result = ObjectId();
	std::copy(digest.bytes.begin(), digest.bytes.end(), result.bytes.begin());
	return result;
}

inline constexpr auto kDesktopFileChunkSize = std::uint32_t(1024 * 1024);

struct HashedFile {
	std::uint64_t size = 0;
	Digest hash;
};

[[nodiscard]] std::optional<HashedFile> HashFile(const QString &path) {
	auto file = QFile(path);
	if (!file.open(QIODevice::ReadOnly) || file.size() < 0) {
		return std::nullopt;
	}
	const auto originalSize = file.size();
	const auto context = EVP_MD_CTX_new();
	if (!context || EVP_DigestInit_ex(context, EVP_sha256(), nullptr) != 1) {
		EVP_MD_CTX_free(context);
		return std::nullopt;
	}
	auto processed = qint64();
	auto ok = true;
	while (processed != originalSize) {
		auto bytes = file.read(std::min<qint64>(
			kDesktopFileChunkSize,
			originalSize - processed));
		const auto size = bytes.size();
		const auto updated = !bytes.isEmpty()
			&& EVP_DigestUpdate(
				context,
				bytes.constData(),
				bytes.size()) == 1;
		Cleanse(bytes);
		if (!updated) {
			ok = false;
			break;
		}
		processed += size;
	}
	auto result = HashedFile{
		.size = std::uint64_t(originalSize),
		.hash = {},
	};
	auto hashSize = 0U;
	ok = ok
		&& file.size() == originalSize
		&& EVP_DigestFinal_ex(
			context,
			result.hash.bytes.data(),
			&hashSize) == 1
		&& hashSize == result.hash.bytes.size();
	EVP_MD_CTX_free(context);
	return (ok && result.hash)
		? std::optional<HashedFile>(result)
		: std::nullopt;
}

} // namespace

struct DesktopService::PendingGroupCreation {
	enum class Phase {
		Creating,
		AwaitingAdmission,
		Active,
		Removed,
	};

	PendingGroupCreation(
			QString directory,
			LocalRecordKey &&localRecordKey,
			not_null<Main::Session*> session,
			std::uint64_t telegramPeerIdBinding,
			ConversationId conversationId,
			const Sha256Provider &sha256)
	: conversationId(conversationId)
	, telegramPeerIdBinding(telegramPeerIdBinding)
	, directory(std::move(directory))
	, protector(std::move(localRecordKey))
	, metadataBlob(this->directory + u"conversation.meta"_q)
	, journalBlob(this->directory + u"bootstrap.wal"_q)
	, mlsBlob(this->directory + u"mls.state"_q)
	, archiveBlob(this->directory + u"archive.state"_q)
	, groupBlob(this->directory + u"group.state"_q)
	, outboxBlob(this->directory + u"outbox.state"_q)
	, changeJournalBlob(this->directory + u"group-change.wal"_q)
	, keyPackagePoolBlob(this->directory + u"key-packages.state"_q)
	, freshnessTrustBlob(this->directory + u"freshness-trust.state"_q)
	, inboundJournalBlob(this->directory + u"content-inbound.state"_q)
	, controlInboundJournalBlob(
		this->directory + u"control-inbound.state"_q)
	, contentIndexBlob(this->directory + u"content-index.state"_q)
	, controlSyncBlob(this->directory + u"control-sync.state"_q)
	, contentSyncBlob(this->directory + u"content-sync.state"_q)
	, fileTransferBlob(this->directory + u"file-transfer.state"_q)
	, metadata(metadataBlob, protector)
	, journal(journalBlob, protector)
	, mlsState(mlsBlob, protector)
	, archiveState(archiveBlob, protector)
	, groupLedger(groupBlob, protector, sha256)
	, outbox(outboxBlob, protector)
	, changeJournal(changeJournalBlob, protector)
	, keyPackages(
		keyPackagePoolBlob,
		protector,
		envelopeCodec,
		sha256)
	, freshnessTrust(freshnessTrustBlob, protector)
	, inboundJournal(inboundJournalBlob, protector)
	, controlInboundJournal(
		controlInboundJournalBlob,
		protector,
		InboundJournalDomain::Control)
	, contentStore(
		conversationId,
		this->directory + u"content-records"_q,
		contentIndexBlob,
		protector,
		sha256)
	, controlSyncState(
		controlSyncBlob,
		protector,
		ObservedSyncStream::Control)
	, contentSyncState(contentSyncBlob, protector)
	, fileTransfer(fileTransferBlob, protector)
	, chunkStore(this->directory + u"file-chunks"_q, protector)
	, backend(
		session,
		session->data().history(PeerId(telegramPeerIdBinding)),
		telegramPeerIdBinding)
	, transport(conversationId, telegramPeerIdBinding, backend)
	, controlBackend(
		session,
		session->data().history(PeerId(telegramPeerIdBinding)),
		telegramPeerIdBinding,
		ProtectedControlCarrierFilename(),
		ProtectedCarrierMimeType(),
		ProtectedCarrierMaximumObjectSize())
	, controlTransport(
		conversationId,
		telegramPeerIdBinding,
		controlBackend)
	, contentBackend(
		session,
		session->data().history(PeerId(telegramPeerIdBinding)),
		telegramPeerIdBinding,
		ProtectedContentCarrierFilename(),
		ProtectedCarrierMimeType(),
		ProtectedCarrierMaximumObjectSize())
	, contentTransport(
		conversationId,
		telegramPeerIdBinding,
		contentBackend) {
	}

	ConversationId conversationId;
	std::uint64_t telegramPeerIdBinding = 0;
	QString directory;
	AesGcmLocalRecordProtector protector;
	FileAtomicBlobStore metadataBlob;
	FileAtomicBlobStore journalBlob;
	FileAtomicBlobStore mlsBlob;
	FileAtomicBlobStore archiveBlob;
	FileAtomicBlobStore groupBlob;
	FileAtomicBlobStore outboxBlob;
	FileAtomicBlobStore changeJournalBlob;
	FileAtomicBlobStore keyPackagePoolBlob;
	FileAtomicBlobStore freshnessTrustBlob;
	FileAtomicBlobStore inboundJournalBlob;
	FileAtomicBlobStore controlInboundJournalBlob;
	FileAtomicBlobStore contentIndexBlob;
	FileAtomicBlobStore controlSyncBlob;
	FileAtomicBlobStore contentSyncBlob;
	FileAtomicBlobStore fileTransferBlob;
	EnvelopeCodecV1 envelopeCodec;
	PersistentConversationMetadata metadata;
	PersistentGroupBootstrapJournal journal;
	PersistentMlsStateStore mlsState;
	PersistentArchiveState archiveState;
	PersistentGroupLedger groupLedger;
	PersistentOutboxStore outbox;
	PersistentGroupChangeJournal changeJournal;
	PersistentKeyPackagePool keyPackages;
	PersistentFreshnessTrust freshnessTrust;
	PersistentInboundJournal inboundJournal;
	PersistentInboundJournal controlInboundJournal;
	PersistentContentStore contentStore;
	PersistentContentSyncState controlSyncState;
	PersistentContentSyncState contentSyncState;
	PersistentFileTransfer fileTransfer;
	FileChunkFileStore chunkStore;
	std::unique_ptr<FreshnessGate> freshnessGate;
	std::unique_ptr<OpenMlsApplicationEngine> applicationEngine;
	std::unique_ptr<OutboxCoordinator> outboxCoordinator;
	std::unique_ptr<OutboxUploadController> uploadController;
	TelegramSessionCarrierBackend backend;
	TelegramCarrierTransport transport;
	TelegramSessionCarrierBackend controlBackend;
	TelegramCarrierTransport controlTransport;
	TelegramSessionCarrierBackend contentBackend;
	TelegramCarrierTransport contentTransport;
	CloudVaultConversation conversation;
	std::optional<PreparedCloudVaultUpdate> vaultUpdate;
	std::unique_ptr<PublicBootstrapSyncController> observation;
	std::unique_ptr<ObservedContentSyncController> contentObservation;
	std::set<AccountId> safetyWitnesses;
	std::uint64_t safetyWitnessGeneration = 0;
	bool ownSafetyGossipObserved = false;
	bool observationDirty = false;
	bool contentObservationDirty = false;
	bool vaultPreflightRequired = true;
	bool uploadInProgress = false;
	Phase phase = Phase::Creating;
};

struct DesktopService::PendingGroupJoin {
	PendingGroupJoin(
			not_null<Main::Session*> session,
			CloudVaultConversation conversation)
	: conversation(conversation)
	, backend(
		session,
		session->data().history(PeerId(
			conversation.telegramPeerIdBinding)),
		conversation.telegramPeerIdBinding)
	, transport(
		conversation.conversationId,
		conversation.telegramPeerIdBinding,
		backend)
	, controlBackend(
		session,
		session->data().history(PeerId(
			conversation.telegramPeerIdBinding)),
		conversation.telegramPeerIdBinding,
		ProtectedControlCarrierFilename(),
		ProtectedCarrierMimeType(),
		ProtectedCarrierMaximumObjectSize())
	, controlTransport(
		conversation.conversationId,
		conversation.telegramPeerIdBinding,
		controlBackend) {
	}

	CloudVaultConversation conversation;
	EnvelopeCodecV1 envelopeCodec;
	TelegramSessionCarrierBackend backend;
	TelegramCarrierTransport transport;
	TelegramSessionCarrierBackend controlBackend;
	TelegramCarrierTransport controlTransport;
	std::unique_ptr<PublicBootstrapSyncController> sync;
};

struct DesktopService::PendingGroupDiscovery {
	PendingGroupDiscovery(
			not_null<Main::Session*> session,
			std::uint64_t telegramPeerIdBinding)
	: telegramPeerIdBinding(telegramPeerIdBinding)
	, backend(
		session,
		session->data().history(PeerId(telegramPeerIdBinding)),
		telegramPeerIdBinding,
		ProtectedControlCarrierFilename(),
		ProtectedCarrierMimeType(),
		ProtectedCarrierMaximumObjectSize()) {
	}

	std::uint64_t telegramPeerIdBinding = 0;
	EnvelopeCodecV1 envelopeCodec;
	TelegramSessionCarrierBackend backend;
	std::unique_ptr<PublicBootstrapDiscoveryController> sync;
};

enum class DesktopService::LocalGroupRecoveryResult {
	Missing,
	Complete,
	Restored,
	Invalid,
};

DesktopService::DesktopService(not_null<Main::Session*> session)
: _session(session)
, _telegramUserIdBinding(session->userId().bare)
, _telegramSelfPeerId(session->userPeerId().value)
, _vaultCodec(_passwordKdf, _sha256)
, _vaultSelector(_vaultCodec, _sha256)
, _vaultAnchorBlob(CloudVaultAnchorPath(_telegramUserIdBinding))
, _vaultAnchor(_vaultAnchorBlob, _telegramUserIdBinding)
, _backend(std::make_unique<TelegramSessionCarrierBackend>(
	_session,
	_session->data().history(_session->userPeerId()),
	_telegramSelfPeerId,
	CloudVaultCarrierFilename(),
	CloudVaultCarrierMimeType(),
	CloudVaultMaximumCarrierSize()))
, _remote(std::make_unique<TelegramCloudVaultTransport>(
	_telegramSelfPeerId,
	*_backend)) {
	const auto anchorLoad = _vaultAnchor.load();
	if (anchorLoad == CloudVaultAnchorLoadResult::StorageError
		|| anchorLoad == CloudVaultAnchorLoadResult::InvalidSnapshot) {
		_vaultState = DesktopVaultState::SecurityBlocked;
	}
	_session->data().newItemAdded(
	) | rpl::on_next([weak = base::weak_ptr(this)](
			not_null<HistoryItem*> item) {
		if (weak) {
			weak->handleNewTelegramItem(item);
		}
	}, _lifetime);
	Core::App().passcodeLockValue(
	) | rpl::on_next([weak = base::weak_ptr(this)](bool locked) {
		if (locked && weak) {
			weak->lock();
		}
	}, _lifetime);
}

DesktopService::~DesktopService() {
	Cleanse(_pendingUnlockPassword);
	Cleanse(_unlockedPassword);
}

DesktopVaultState DesktopService::vaultState() const {
	return _vaultState.current();
}

rpl::producer<DesktopVaultState> DesktopService::vaultStateValue() const {
	return _vaultState.value();
}

const UnlockedCloudVault *DesktopService::vault() const {
	return _vault ? &*_vault : nullptr;
}

void DesktopService::ensureVaultDiscovery() {
	const auto state = _vaultState.current();
	if (_sync
		|| !_vaultAnchor.loaded()
		|| (state != DesktopVaultState::Uninitialized
			&& state != DesktopVaultState::DiscoveryRetryableError)) {
		return;
	}
	_vaultState = DesktopVaultState::Discovering;
	_sync = std::make_unique<CloudVaultSyncController>(
		_telegramUserIdBinding,
		*_remote,
		_vaultSelector,
		[weak = base::weak_ptr(this)](CloudVaultSyncCompletion result) {
			if (weak) {
				weak->applyVaultDiscoveryResult(std::move(result));
			}
		});
	if (!_sync->startDiscovery()) {
		_sync.reset();
		_vaultState = DesktopVaultState::DiscoveryRetryableError;
	}
}

bool DesktopService::unlock(QByteArray password) {
	const auto state = _vaultState.current();
	if (_sync
		|| _pendingCreation
		|| !_vaultAnchor.loaded()
		|| (state != DesktopVaultState::Locked
			&& state != DesktopVaultState::WrongPasswordOrDamaged
			&& state != DesktopVaultState::RetryableTransportError)
		|| password.isEmpty()) {
		return false;
	}
	Cleanse(_pendingUnlockPassword);
	_pendingUnlockPassword = password;
	_vault.reset();
	_vaultState = DesktopVaultState::Loading;
	_sync = std::make_unique<CloudVaultSyncController>(
		_telegramUserIdBinding,
		*_remote,
		_vaultSelector,
		[weak = base::weak_ptr(this)](CloudVaultSyncCompletion result) {
			if (weak) {
				weak->applySyncResult(std::move(result));
			}
		});
	if (!_sync->start(std::move(password), _vaultAnchor.anchor())) {
		_sync.reset();
		Cleanse(_pendingUnlockPassword);
		_vaultState = DesktopVaultState::Locked;
		return false;
	}
	return true;
}

bool DesktopService::createVault(QByteArray password) {
	if (_sync
		|| _pendingCreation
		|| _vault
		|| _vaultAnchor.anchor()
		|| _vaultState.current() != DesktopVaultState::Missing
		|| password.isEmpty()) {
		return false;
	}
	Cleanse(_pendingUnlockPassword);
	_pendingUnlockPassword = password;
	auto identity = GenerateAccountPrivateIdentity();
	_pendingCreation = identity
		? _vaultCodec.create(
			_telegramUserIdBinding,
			std::move(*identity),
			std::move(password),
			DesktopArgon2idConfig())
		: std::nullopt;
	if (!_pendingCreation) {
		Cleanse(_pendingUnlockPassword);
		_vaultState = DesktopVaultState::WrongPasswordOrDamaged;
		return false;
	}
	uploadPendingCreation();
	return true;
}

bool DesktopService::retryCreateVault() {
	if (!_pendingCreation
		|| _vaultState.current()
			!= DesktopVaultState::RetryableTransportError) {
		return false;
	}
	uploadPendingCreation();
	return true;
}

DesktopGroupCreationState DesktopService::groupCreationState() const {
	return _groupCreationState.current();
}

rpl::producer<DesktopGroupCreationState>
DesktopService::groupCreationStateValue() const {
	return _groupCreationState.value();
}

bool DesktopService::createProtectedGroup(
		not_null<PeerData*> peer,
		HistoryAccess defaultHistoryAccess) {
	if (!_vault
		|| _vaultState.current() != DesktopVaultState::Ready
		|| _pendingGroupCreation
		|| (!peer->isChat() && !peer->isMegagroup())
		|| std::any_of(
			begin(_vault->conversations),
			end(_vault->conversations),
			[&](const CloudVaultConversation &conversation) {
				return conversation.telegramPeerIdBinding == peer->id.value;
			})
		|| !IsValidHistoryAccess(defaultHistoryAccess)) {
		return false;
	}
	_groupCreationState = DesktopGroupCreationState::Preparing;
	const auto conversationId = RandomId<ConversationId>();
	const auto clientId = RandomId<ClientId>();
	const auto genesisObjectId = RandomId<ObjectId>();
	const auto credentialObjectId = RandomId<ObjectId>();
	const auto mlsPublicObjectId = RandomId<ObjectId>();
	const auto archiveActivationEventId = RandomId<ObjectId>();
	const auto ownerHistoryGrantObjectId = RandomId<ObjectId>();
	const auto archiveKey = ArchiveEpochCrypto().generateKey();
	if (!conversationId
		|| !clientId
		|| !genesisObjectId
		|| !credentialObjectId
		|| !mlsPublicObjectId
		|| !archiveActivationEventId
		|| !ownerHistoryGrantObjectId
		|| !archiveKey) {
		_groupCreationState = DesktopGroupCreationState::LocalFailure;
		return false;
	}
	auto localRecordKey = DeriveConversationLocalRecordKey(
		_vault->masterKey,
		_telegramUserIdBinding,
		*conversationId);
	if (!localRecordKey) {
		_groupCreationState = DesktopGroupCreationState::LocalFailure;
		return false;
	}
	auto operation = std::make_unique<PendingGroupCreation>(
		ConversationDirectory(_telegramUserIdBinding, *conversationId),
		std::move(*localRecordKey),
		_session,
		peer->id.value,
		*conversationId,
		_sha256);
	if (operation->metadata.load(*conversationId)
			!= ConversationMetadataLoadResult::Missing
		|| operation->journal.load(*conversationId)
			!= GroupBootstrapJournalLoadResult::Empty
		|| operation->mlsState.load(*conversationId)
			!= MlsStateLoadResult::Missing
		|| operation->archiveState.load(*conversationId)
			!= ArchiveStateLoadResult::Missing
		|| operation->groupLedger.load(*conversationId)
			!= GroupLedgerLoadResult::Missing
		|| operation->outbox.load()
			!= PersistentOutboxLoadResult::Empty
		|| operation->changeJournal.load(*conversationId)
			!= GroupChangeJournalLoadResult::Empty
		|| operation->keyPackages.load(*conversationId, peer->id.value)
			!= KeyPackagePoolLoadResult::Empty
		|| operation->freshnessTrust.load(*conversationId)
			!= FreshnessTrustLoadResult::Missing
		|| operation->inboundJournal.load()
			!= InboundJournalLoadResult::Missing
		|| operation->controlInboundJournal.load()
			!= InboundJournalLoadResult::Missing
		|| operation->contentStore.load()
			!= ContentStoreLoadResult::Missing
		|| operation->controlSyncState.load(*conversationId)
			!= ContentSyncStateLoadResult::Missing
		|| operation->contentSyncState.load(*conversationId)
			!= ContentSyncStateLoadResult::Missing
		|| operation->fileTransfer.load(*conversationId)
			!= FileTransferLoadResult::Empty) {
		_groupCreationState = DesktopGroupCreationState::LocalFailure;
		return false;
	}
	auto bootstrap = PrepareProtectedGroupBootstrap({
		.conversationId = *conversationId,
		.telegramPeerIdBinding = peer->id.value,
		.ownerTelegramUserIdBinding = _telegramUserIdBinding,
		.ownerClientId = *clientId,
		.policy = { .defaultHistoryAccess = defaultHistoryAccess },
		.genesisObjectId = *genesisObjectId,
		.ownerCredentialObjectId = *credentialObjectId,
		.initialMlsPublicObjectId = *mlsPublicObjectId,
		.archiveActivationEventId = *archiveActivationEventId,
		.ownerHistoryGrantObjectId = *ownerHistoryGrantObjectId,
		.ownerIdentity = &_vault->identity,
		.initialArchiveKey = &*archiveKey,
	},
	OpenMlsBridge(),
	MlsContextCodecV1(),
	MlsRosterCodecV1(),
	EnvelopeCodecV1(),
	_sha256);
	if (!bootstrap.prepared) {
		_groupCreationState = DesktopGroupCreationState::LocalFailure;
		return false;
	}
	const auto conversation = CloudVaultConversation{
		.conversationId = *conversationId,
		.telegramPeerIdBinding = peer->id.value,
		.checkpoint = bootstrap.prepared->checkpoint,
		.ownerAccountId = bootstrap.prepared->ownerAccountId,
	};
	if (operation->metadata.initialize({
			.conversationId = *conversationId,
			.telegramPeerIdBinding = peer->id.value,
			.accountId = bootstrap.prepared->ownerAccountId,
			.clientId = *clientId,
		}) != ConversationMetadataCommitResult::Committed
		|| operation->freshnessTrust.initialize(true)
			!= FreshnessTrustCommitResult::Committed) {
		_groupCreationState = DesktopGroupCreationState::LocalFailure;
		return false;
	}
	const auto envelopeCodec = EnvelopeCodecV1();
	auto coordinator = GroupBootstrapTransactionCoordinator(
		operation->journal,
		operation->mlsState,
		operation->archiveState,
		operation->groupLedger,
		operation->outbox,
		envelopeCodec,
		_sha256);
	auto transaction = MakeGroupBootstrapTransaction(
		std::move(*bootstrap.prepared),
		_vault->identity.credential,
		operation->outbox.revision());
	if (coordinator.apply(std::move(transaction))
			!= GroupBootstrapApplyStatus::Applied) {
		_groupCreationState = DesktopGroupCreationState::LocalFailure;
		return false;
	}
	operation->conversation = conversation;
	operation->freshnessGate = std::make_unique<FreshnessGate>(
		conversation.checkpoint,
		true);
	_pendingGroupCreation = std::move(operation);
	beginGroupVaultPreflight();
	return true;
}

bool DesktopService::retryProtectedGroupCreation() {
	if (_groupCreationState.current()
			!= DesktopGroupCreationState::RetryableTransportError
		|| _pendingGroupJoin) {
		return false;
	}
	if (!_pendingGroupCreation) {
		resumePendingGroupCreation();
		return true;
	} else if (_pendingGroupCreation->uploadInProgress) {
		return false;
	}
	if (_pendingGroupCreation->vaultPreflightRequired) {
		beginGroupVaultPreflight();
	} else if (_pendingGroupCreation->vaultUpdate) {
		uploadPendingConversationIndex();
	} else {
		publishNextBootstrapObject();
	}
	return true;
}

std::vector<DesktopProtectedGroupSummary>
DesktopService::protectedGroups() const {
	auto result = std::vector<DesktopProtectedGroupSummary>();
	result.reserve(_groups.size());
	for (const auto &[conversationId, group] : _groups) {
		const auto state = group->groupLedger.state();
		const auto removed = group->phase
			== PendingGroupCreation::Phase::Removed;
		result.push_back({
			.conversationId = conversationId,
			.telegramPeerIdBinding = group->telegramPeerIdBinding,
			.title = _session->data().peer(
				PeerId(group->telegramPeerIdBinding))->name(),
			.generation = state ? state->generation() : 0,
			.contentCount = group->contentStore.records().size(),
			.active = group->phase == PendingGroupCreation::Phase::Active,
			.removed = removed,
			.sendingAllowed = !removed
				&& group->freshnessGate
				&& group->freshnessGate->sendingAllowed(),
		});
	}
	std::sort(
		begin(result),
		end(result),
		[](const auto &a, const auto &b) {
			return a.title.compare(b.title, Qt::CaseInsensitive) < 0;
		});
	return result;
}

std::optional<ConversationId> DesktopService::protectedConversationForPeer(
		std::uint64_t telegramPeerIdBinding) const {
	if (!telegramPeerIdBinding) {
		return std::nullopt;
	}
	auto result = std::optional<ConversationId>();
	const auto consider = [&](
			ConversationId conversationId,
			std::uint64_t peerId) {
		if (peerId != telegramPeerIdBinding) {
			return true;
		} else if (result && *result != conversationId) {
			return false;
		}
		result = conversationId;
		return true;
	};
	for (const auto &[conversationId, group] : _groups) {
		if (!consider(conversationId, group->telegramPeerIdBinding)) {
			return std::nullopt;
		}
	}
	if (_vault) {
		for (const auto &conversation : _vault->conversations) {
			if (!consider(
					conversation.conversationId,
					conversation.telegramPeerIdBinding)) {
				return std::nullopt;
			}
		}
	}
	if (_pendingGroupCreation
		&& !consider(
			_pendingGroupCreation->conversation.conversationId,
			_pendingGroupCreation->telegramPeerIdBinding)) {
		return std::nullopt;
	}
	return result;
}

std::vector<ProtectedContentRecord> DesktopService::protectedContent(
		ConversationId conversationId) const {
	const auto i = _groups.find(conversationId);
	if (i == end(_groups)) {
		return {};
	}
	auto result = i->second->contentStore.records();
	std::sort(
		begin(result),
		end(result),
		[](const auto &a, const auto &b) {
			return (a.unixTime != b.unixTime)
				? a.unixTime < b.unixTime
				: a.eventObjectId < b.eventObjectId;
		});
	return result;
}

std::optional<DesktopProtectedSecurity> DesktopService::protectedSecurity(
		ConversationId conversationId) const {
	const auto i = _groups.find(conversationId);
	if (i == end(_groups) || !_vault) {
		return std::nullopt;
	}
	const auto &group = *i->second;
	const auto state = group.groupLedger.state();
	const auto localAccountId = DeriveAccountId(
		_vault->identity.credential,
		_sha256);
	if (!state || !localAccountId) {
		return std::nullopt;
	}
	const auto owner = std::find_if(
		begin(state->members()),
		end(state->members()),
		[](const GroupMember &member) {
			return member.role == GroupRole::Owner;
		});
	auto accountIds = std::vector<AccountId>();
	accountIds.reserve(state->members().size());
	for (const auto &member : state->members()) {
		accountIds.push_back(member.accountId);
	}
	const auto groupDigest = (owner != end(state->members()))
		? DeriveGroupSafetyDigest(
			conversationId,
			owner->accountId,
			accountIds,
			_sha256)
		: std::nullopt;
	if (!groupDigest) {
		return std::nullopt;
	}
	const auto localMember = state->member(*localAccountId);
	const auto administrationAllowed = localMember
		&& group.freshnessGate
		&& group.freshnessGate->administrationAllowed();
	const auto hasPermission = [&](AdminPermission permission) {
		return administrationAllowed
			&& (localMember->role == GroupRole::Owner
				|| (localMember->role == GroupRole::Administrator
					&& (localMember->adminPermissions
						& PermissionMask(permission))));
	};
	auto witnesses = (group.safetyWitnessGeneration == state->generation())
		? group.safetyWitnesses
		: std::set<AccountId>();
	if (state->member(*localAccountId)) {
		witnesses.emplace(*localAccountId);
	}
	auto result = DesktopProtectedSecurity{
		.generation = state->generation(),
		.groupSafetyCode = FormatSafetyCode(*groupDigest).value_or(QString()),
		.memberCount = state->members().size(),
		.witnessCount = 0,
		.defaultHistoryAccess = state->policy().defaultHistoryAccess,
		.canSetRoles = administrationAllowed
			&& localMember->role == GroupRole::Owner,
		.canRemoveMembers = hasPermission(AdminPermission::RemoveMembers),
		.canGrantHistory = hasPermission(AdminPermission::GrantHistory),
		.canGrantFullHistory = hasPermission(
			AdminPermission::GrantFullHistory),
		.canChangeDefaultHistory = hasPermission(
			AdminPermission::ChangeDefaultHistory),
		.members = {},
	};
	result.members.reserve(state->members().size());
	for (const auto &member : state->members()) {
		auto accountDigest = Digest();
		accountDigest.bytes = member.accountId.bytes;
		const auto pairwise = (member.accountId != *localAccountId)
			? DerivePairwiseSafetyDigest(
				*localAccountId,
				member.accountId,
				_sha256)
			: std::nullopt;
		result.members.push_back({
			.accountId = member.accountId,
			.telegramUserIdBinding = member.telegramUserIdBinding,
			.role = member.role,
			.historyAccess = member.historyAccess,
			.clientCount = member.clients.size(),
			.accountSafetyCode = FormatSafetyCode(accountDigest)
				.value_or(QString()),
			.pairwiseSafetyCode = pairwise
				? FormatSafetyCode(*pairwise).value_or(QString())
				: QString(),
			.local = member.accountId == *localAccountId,
		});
		if (witnesses.contains(member.accountId)) {
			++result.witnessCount;
		}
	}
	std::sort(
		begin(result.members),
		end(result.members),
		[](const auto &a, const auto &b) {
			return (a.role != b.role)
				? a.role == GroupRole::Owner
				: a.telegramUserIdBinding < b.telegramUserIdBinding;
		});
	return result;
}

bool DesktopService::sendProtectedText(
		ConversationId conversationId,
		QString text) {
	const auto i = _groups.find(conversationId);
	if (i == end(_groups)
		|| !_vault
		|| text.isEmpty()
		|| i->second->observation
		|| i->second->observationDirty
		|| i->second->phase != PendingGroupCreation::Phase::Active) {
		return false;
	}
	auto &group = *i->second;
	const auto metadata = group.metadata.metadata();
	const auto state = group.groupLedger.state();
	const auto epoch = group.archiveState.currentEpoch();
	const auto eventObjectId = RandomId<ObjectId>();
	const auto contentObjectId = RandomId<ObjectId>();
	auto plaintext = ProtectedMessageBodyCodecV1().encodePlaintext({
		.unixTime = std::uint64_t(base::unixtime::now()),
		.textUtf8 = text.toUtf8(),
	});
	const auto plaintextGuard = qScopeGuard([&] {
		if (plaintext) {
			Cleanse(*plaintext);
		}
	});
	if (!metadata
		|| !state
		|| !epoch
		|| !eventObjectId
		|| !contentObjectId
		|| !plaintext
		|| group.fileTransfer.pending()
		|| !initializeActivePipeline(group)) {
		setContentState(conversationId, DesktopContentState::LocalFailure);
		return false;
	}
	if (group.freshnessGate->state() == FreshnessState::Required
		&& !group.outbox.size()
		&& !queueFreshnessChallenge(group)) {
		setContentState(conversationId, DesktopContentState::LocalFailure);
		return false;
	}
	const auto queued = QueueArchivedContent({
		.conversationId = conversationId,
		.eventObjectId = *eventObjectId,
		.contentObjectId = *contentObjectId,
		.objectKind = ObjectKind::EncryptedMessageBody,
		.senderAccountId = metadata->accountId,
		.senderClientId = metadata->clientId,
		.telegramPeerIdBinding = group.telegramPeerIdBinding,
		.groupGeneration = state->generation(),
		.archiveEpochGeneration = epoch->generation,
		.archiveEpochKey = &epoch->key,
		.senderSigningPrivateKey = &_vault->identity.signingPrivateKey,
		.plaintext = *plaintext,
		.mlsContext = QByteArray("TDE2E/archived-content/v1"),
	},
	ArchiveEpochCrypto(),
	EncryptedArchivedContentCodecV1(),
	ArchivedContentDescriptorCodecV1(),
	group.envelopeCodec,
	_sha256,
	*group.outboxCoordinator);
	if (queued != ArchivedContentQueueResult::Queued) {
		setContentState(conversationId, DesktopContentState::LocalFailure);
		return false;
	}
	pumpActiveOutbox(conversationId);
	return true;
}

bool DesktopService::sendProtectedFile(
		ConversationId conversationId,
		QString path) {
	const auto i = _groups.find(conversationId);
	if (i == end(_groups)
		|| !_vault
		|| path.isEmpty()
		|| i->second->observation
		|| i->second->observationDirty
		|| i->second->phase != PendingGroupCreation::Phase::Active) {
		return false;
	}
	auto &group = *i->second;
	const auto metadata = group.metadata.metadata();
	const auto state = group.groupLedger.state();
	const auto source = HashFile(path);
	const auto material = GenerateFileEncryptionMaterial();
	const auto eventObjectId = RandomId<ObjectId>();
	const auto contentObjectId = RandomId<ObjectId>();
	if (!metadata
		|| !state
		|| !source
		|| !material
		|| !eventObjectId
		|| !contentObjectId
		|| group.outbox.size()
		|| group.uploadInProgress
		|| (group.uploadController
			&& group.uploadController->uploadInProgress())
		|| source->size
			> std::uint64_t(kDesktopFileChunkSize)
				* std::numeric_limits<std::uint32_t>::max()) {
		return false;
	}
	const auto chunkCount = source->size
		? std::uint32_t(1 + ((source->size - 1) / kDesktopFileChunkSize))
		: 0;
	const auto sourceInfo = QFileInfo(path);
	const auto absolutePath = sourceInfo.absoluteFilePath();
	const auto manifest = PrivateFileManifest{
		.context = {
			.conversationId = conversationId,
			.fileId = material->fileId,
			.plaintextSize = source->size,
			.chunkSize = kDesktopFileChunkSize,
			.chunkCount = chunkCount,
			.noncePrefix = material->noncePrefix,
		},
		.key = FileEncryptionKey(std::array<std::uint8_t, 32>(
			material->key.bytes())),
		.plaintextHash = source->hash,
		.unixTime = std::uint64_t(base::unixtime::now()),
		.filenameUtf8 = sourceInfo.fileName().toUtf8(),
		.mimeTypeUtf8 = QMimeDatabase().mimeTypeForFile(
			absolutePath,
			QMimeDatabase::MatchExtension).name().toUtf8(),
	};
	auto manifestPlaintext = PrivateFileManifestCodecV1()
		.encodePlaintext(manifest);
	const auto manifestGuard = qScopeGuard([&] {
		if (manifestPlaintext) {
			Cleanse(*manifestPlaintext);
		}
	});
	if (!manifestPlaintext
		|| (group.freshnessGate->state() == FreshnessState::Required
			&& !queueFreshnessChallenge(group))) {
		setContentState(conversationId, DesktopContentState::LocalFailure);
		return false;
	}
	auto transfer = PendingFileTransfer{
		.conversationId = conversationId,
		.eventObjectId = *eventObjectId,
		.contentObjectId = *contentObjectId,
		.groupGeneration = state->generation(),
		.nextChunkIndex = 0,
		.sourcePathUtf8 = absolutePath.toUtf8(),
		.manifestPlaintext = *manifestPlaintext,
	};
	const auto queued = group.fileTransfer.pending()
		? group.fileTransfer.replace(std::move(transfer))
		: group.fileTransfer.begin(std::move(transfer));
	if (queued != FileTransferCommitResult::Committed) {
		setContentState(conversationId, DesktopContentState::LocalFailure);
		return false;
	}
	pumpActiveOutbox(conversationId);
	return true;
}

bool DesktopService::saveProtectedFile(
		ConversationId conversationId,
		ObjectId eventObjectId,
		QString path) const {
	const auto i = _groups.find(conversationId);
	auto record = (i != end(_groups))
		? i->second->contentStore.record(eventObjectId)
		: std::nullopt;
	const auto recordGuard = qScopeGuard([&] {
		if (record) {
			Cleanse(record->plaintext);
		}
	});
	const auto manifest = (record
		&& record->objectKind == ObjectKind::EncryptedFileManifest)
		? PrivateFileManifestCodecV1().decodePlaintext(record->plaintext)
		: std::nullopt;
	if (!manifest || path.isEmpty()) {
		return false;
	}
	auto output = QSaveFile(path);
	if (!output.open(QIODevice::WriteOnly)) {
		return false;
	}
	const auto digest = EVP_MD_CTX_new();
	if (!digest || EVP_DigestInit_ex(digest, EVP_sha256(), nullptr) != 1) {
		EVP_MD_CTX_free(digest);
		output.cancelWriting();
		return false;
	}
	auto written = std::uint64_t();
	auto ok = true;
	const auto cipher = AesGcmFileChunkCipher();
	for (auto index = std::uint32_t();
			index != manifest->context.chunkCount;
			++index) {
		const auto stored = i->second->chunkStore.read(
			conversationId,
			manifest->context.fileId,
			index);
		auto plaintext = (stored.status == FileChunkReadStatus::Found)
			? cipher.decrypt(
				manifest->key,
				manifest->context,
				index,
				stored.chunk.exactCiphertext)
			: std::nullopt;
		if (!plaintext
			|| output.write(*plaintext) != plaintext->size()
			|| EVP_DigestUpdate(
				digest,
				plaintext->constData(),
				plaintext->size()) != 1) {
			if (plaintext) {
				Cleanse(*plaintext);
			}
			ok = false;
			break;
		}
		written += plaintext->size();
		Cleanse(*plaintext);
	}
	auto hash = Digest();
	auto hashSize = 0U;
	ok = ok
		&& written == manifest->context.plaintextSize
		&& EVP_DigestFinal_ex(
			digest,
			hash.bytes.data(),
			&hashSize) == 1
		&& hashSize == hash.bytes.size()
		&& hash == manifest->plaintextHash;
	EVP_MD_CTX_free(digest);
	if (!ok) {
		output.cancelWriting();
		return false;
	}
	return output.commit();
}

bool DesktopService::setProtectedDefaultHistory(
		ConversationId conversationId,
		HistoryAccess historyAccess) {
	if (!IsValidHistoryAccess(historyAccess)) {
		return false;
	}
	return applyAdministrativeTransition(conversationId, {
		.kind = GroupTransitionKind::SetDefaultHistory,
		.targetRole = GroupRole::Member,
		.historyAccess = historyAccess,
	});
}

bool DesktopService::setProtectedMemberHistory(
		ConversationId conversationId,
		AccountId accountId,
		HistoryAccess historyAccess) {
	if (!accountId || !IsValidHistoryAccess(historyAccess)) {
		return false;
	}
	return applyAdministrativeTransition(conversationId, {
		.kind = GroupTransitionKind::SetMemberHistory,
		.targetAccountId = accountId,
		.targetRole = GroupRole::Member,
		.historyAccess = historyAccess,
	});
}

bool DesktopService::setProtectedMemberRole(
		ConversationId conversationId,
		AccountId accountId,
		GroupRole role) {
	if (!accountId
		|| (role != GroupRole::Member
			&& role != GroupRole::Administrator)) {
		return false;
	}
	return applyAdministrativeTransition(conversationId, {
		.kind = GroupTransitionKind::SetRole,
		.targetAccountId = accountId,
		.targetRole = role,
		.targetAdminPermissions = (role == GroupRole::Administrator)
			? kDefaultAdminPermissions
			: 0,
		.historyAccess = {},
	});
}

bool DesktopService::removeProtectedMember(
		ConversationId conversationId,
		AccountId accountId) {
	if (!accountId) {
		return false;
	}
	return applyAdministrativeTransition(conversationId, {
		.kind = GroupTransitionKind::RemoveMember,
		.targetAccountId = accountId,
		.targetRole = GroupRole::Member,
		.historyAccess = {},
	});
}

DesktopContentState DesktopService::contentState(
		ConversationId conversationId) const {
	const auto i = _contentStates.find(conversationId);
	return (i != end(_contentStates))
		? i->second
		: DesktopContentState::Idle;
}

rpl::producer<DesktopContentState> DesktopService::contentStateValue() const {
	return _contentState.value();
}

void DesktopService::setContentState(
		ConversationId conversationId,
		DesktopContentState state) {
	_contentStates[conversationId] = state;
	_contentState = state;
}

rpl::producer<std::uint64_t> DesktopService::contentRevisionValue() const {
	return _contentRevision.value();
}

rpl::producer<std::uint64_t> DesktopService::securityRevisionValue() const {
	return _securityRevision.value();
}

void DesktopService::synchronizeProtectedContent(
		ConversationId conversationId) {
	beginGroupObservation(conversationId);
	pumpActiveOutbox(conversationId);
	beginContentObservation(conversationId);
}

void DesktopService::lock() {
	const auto securityBlocked = _vaultState.current()
		== DesktopVaultState::SecurityBlocked;
	const auto knownVault = _vault || _vaultAnchor.anchor().has_value();
	if (++_operationEpoch == 0) {
		++_operationEpoch;
	}
	_sync.reset();
	_pendingCreation.reset();
	_pendingGroupCreation.reset();
	_pendingGroupJoin.reset();
	_pendingGroupDiscovery.reset();
	_groupDiscoveryQueue.clear();
	_groups.clear();
	_vault.reset();
	Cleanse(_pendingUnlockPassword);
	Cleanse(_unlockedPassword);
	if (securityBlocked) {
		_vaultState = DesktopVaultState::SecurityBlocked;
	} else if (knownVault) {
		_vaultState = DesktopVaultState::Locked;
	} else {
		_vaultState = DesktopVaultState::Uninitialized;
	}
	_groupCreationState = DesktopGroupCreationState::Idle;
	_contentState = DesktopContentState::Idle;
	_contentStates.clear();
	_contentRevision = 0;
	_securityRevision = 0;
}

void DesktopService::applyVaultDiscoveryResult(
		CloudVaultSyncCompletion result) {
	_sync.reset();
	switch (result.status) {
	case CloudVaultSyncStatus::Present:
		_vaultState = DesktopVaultState::Locked;
		break;
	case CloudVaultSyncStatus::Missing:
		_vaultState = _vaultAnchor.anchor()
			? DesktopVaultState::SecurityBlocked
			: DesktopVaultState::Missing;
		break;
	case CloudVaultSyncStatus::RetryableTransportError:
		_vaultState = DesktopVaultState::DiscoveryRetryableError;
		break;
	case CloudVaultSyncStatus::PermanentTransportError:
		_vaultState = DesktopVaultState::DiscoveryPermanentError;
		break;
	case CloudVaultSyncStatus::CapacityExceeded:
	case CloudVaultSyncStatus::InvalidPagination:
	case CloudVaultSyncStatus::Selected:
	case CloudVaultSyncStatus::Unreadable:
	case CloudVaultSyncStatus::IdentityConflict:
	case CloudVaultSyncStatus::ForkDetected:
	case CloudVaultSyncStatus::RollbackDetected:
	case CloudVaultSyncStatus::ChainGap:
		_vaultState = DesktopVaultState::SecurityBlocked;
		break;
	case CloudVaultSyncStatus::Cancelled:
		_vaultState = DesktopVaultState::Uninitialized;
		break;
	}
}

void DesktopService::applySyncResult(CloudVaultSyncCompletion result) {
	_sync.reset();
	switch (result.status) {
	case CloudVaultSyncStatus::Selected:
		if (result.vault) {
			auto selected = std::move(*result.vault);
			if (!commitVaultAnchor(selected)) {
				_vaultState = DesktopVaultState::SecurityBlocked;
			} else {
				_vault = std::move(selected);
				Cleanse(_unlockedPassword);
				_unlockedPassword = std::move(_pendingUnlockPassword);
				_vaultState = DesktopVaultState::Ready;
				resumePendingGroupCreation();
			}
		} else {
			_vaultState = DesktopVaultState::WrongPasswordOrDamaged;
		}
		break;
	case CloudVaultSyncStatus::Present:
		_vaultState = DesktopVaultState::SecurityBlocked;
		break;
	case CloudVaultSyncStatus::Missing:
		_vaultState = DesktopVaultState::Missing;
		break;
	case CloudVaultSyncStatus::Unreadable:
		_vaultState = DesktopVaultState::WrongPasswordOrDamaged;
		break;
	case CloudVaultSyncStatus::RetryableTransportError:
		_vaultState = DesktopVaultState::RetryableTransportError;
		break;
	case CloudVaultSyncStatus::PermanentTransportError:
		_vaultState = DesktopVaultState::PermanentTransportError;
		break;
	case CloudVaultSyncStatus::CapacityExceeded:
	case CloudVaultSyncStatus::IdentityConflict:
	case CloudVaultSyncStatus::ForkDetected:
	case CloudVaultSyncStatus::RollbackDetected:
	case CloudVaultSyncStatus::ChainGap:
	case CloudVaultSyncStatus::InvalidPagination:
		_vaultState = DesktopVaultState::SecurityBlocked;
		break;
	case CloudVaultSyncStatus::Cancelled:
		_vaultState = DesktopVaultState::Locked;
		break;
	}
	if (_vaultState.current() != DesktopVaultState::Ready) {
		Cleanse(_pendingUnlockPassword);
	}
}

void DesktopService::uploadPendingCreation() {
	if (!_pendingCreation) {
		return;
	}
	_vaultState = DesktopVaultState::Creating;
	const auto operationEpoch = _operationEpoch;
	_remote->uploadExact(
		_pendingCreation->encoded,
		[weak = base::weak_ptr(this), operationEpoch](
				TelegramTransport::UploadResult result) {
			if (!weak
				|| weak->_operationEpoch != operationEpoch
				|| !weak->_pendingCreation) {
				return;
			}
			if (result == TelegramTransport::UploadResult::Accepted) {
				if (!weak->commitVaultAnchor(
						weak->_pendingCreation->unlocked)) {
					weak->_pendingCreation.reset();
					Cleanse(weak->_pendingUnlockPassword);
					weak->_vaultState = DesktopVaultState::SecurityBlocked;
					return;
				}
				weak->_vault = std::move(weak->_pendingCreation->unlocked);
				weak->_pendingCreation.reset();
				Cleanse(weak->_unlockedPassword);
				weak->_unlockedPassword = std::move(
					weak->_pendingUnlockPassword);
				weak->_vaultState = DesktopVaultState::Ready;
			} else if (result
					== TelegramTransport::UploadResult::RetryableError) {
				weak->_vaultState
					= DesktopVaultState::RetryableTransportError;
			} else {
				weak->_pendingCreation.reset();
				Cleanse(weak->_pendingUnlockPassword);
				weak->_vaultState
					= DesktopVaultState::PermanentTransportError;
			}
		});
}

void DesktopService::beginGroupVaultPreflight() {
	if (!_pendingGroupCreation
		|| !_pendingGroupCreation->vaultPreflightRequired
		|| _sync
		|| !_vault
		|| _unlockedPassword.isEmpty()) {
		_groupCreationState = DesktopGroupCreationState::LocalFailure;
		return;
	}
	if (!_vaultAnchor.anchor()) {
		_groupCreationState = DesktopGroupCreationState::LocalFailure;
		return;
	}
	_groupCreationState = DesktopGroupCreationState::UpdatingVault;
	_sync = std::make_unique<CloudVaultSyncController>(
		_telegramUserIdBinding,
		*_remote,
		_vaultSelector,
		[weak = base::weak_ptr(this)](CloudVaultSyncCompletion result) {
			if (weak) {
				weak->applyGroupVaultSyncResult(std::move(result));
			}
		});
	if (!_sync->start(_unlockedPassword, _vaultAnchor.anchor())) {
		_sync.reset();
		_groupCreationState = DesktopGroupCreationState::LocalFailure;
	}
}

void DesktopService::applyGroupVaultSyncResult(
		CloudVaultSyncCompletion result) {
	_sync.reset();
	if (!_pendingGroupCreation) {
		return;
	}
	if (result.status == CloudVaultSyncStatus::RetryableTransportError) {
		_groupCreationState = DesktopGroupCreationState::RetryableTransportError;
		return;
	} else if (result.status == CloudVaultSyncStatus::PermanentTransportError) {
		_groupCreationState = DesktopGroupCreationState::PermanentTransportError;
		return;
	} else if (result.status != CloudVaultSyncStatus::Selected
		|| !result.vault) {
		_vaultState = DesktopVaultState::SecurityBlocked;
		_groupCreationState = DesktopGroupCreationState::LocalFailure;
		return;
	}
	auto selected = std::move(*result.vault);
	if (!commitVaultAnchor(selected)) {
		_vaultState = DesktopVaultState::SecurityBlocked;
		_groupCreationState = DesktopGroupCreationState::LocalFailure;
		return;
	}
	_vault = std::move(selected);
	const auto &conversation = _pendingGroupCreation->conversation;
	auto conversations = _vault->conversations;
	const auto existing = std::find_if(
		begin(conversations),
		end(conversations),
		[&](const CloudVaultConversation &value) {
			return value.conversationId == conversation.conversationId
				|| value.telegramPeerIdBinding
					== conversation.telegramPeerIdBinding;
		});
	if (existing != end(conversations)) {
		if (existing->conversationId != conversation.conversationId
			|| existing->telegramPeerIdBinding
				!= conversation.telegramPeerIdBinding
			|| existing->ownerAccountId != conversation.ownerAccountId
			|| existing->checkpoint.conversationId
				!= conversation.conversationId
			|| (existing->checkpoint.generation
					== conversation.checkpoint.generation
				&& existing->checkpoint != conversation.checkpoint)
			|| existing->checkpoint.generation
				> conversation.checkpoint.generation) {
			_vaultState = DesktopVaultState::SecurityBlocked;
			_groupCreationState = DesktopGroupCreationState::LocalFailure;
			return;
		} else if (*existing == conversation) {
			_pendingGroupCreation->vaultPreflightRequired = false;
			publishNextBootstrapObject();
			return;
		}
		*existing = conversation;
	} else {
		conversations.push_back(conversation);
	}
	_pendingGroupCreation->vaultUpdate = _vaultCodec.prepareUpdate(
		*_vault,
		std::move(conversations));
	if (!_pendingGroupCreation->vaultUpdate) {
		_groupCreationState = DesktopGroupCreationState::LocalFailure;
		return;
	}
	_pendingGroupCreation->vaultPreflightRequired = false;
	uploadPendingConversationIndex();
}

void DesktopService::uploadPendingConversationIndex() {
	if (!_pendingGroupCreation
		|| !_pendingGroupCreation->vaultUpdate
		|| _pendingGroupCreation->uploadInProgress
		|| !_vault) {
		return;
	}
	_pendingGroupCreation->uploadInProgress = true;
	_groupCreationState = DesktopGroupCreationState::UpdatingVault;
	const auto operationEpoch = _operationEpoch;
	_remote->uploadExact(
		_pendingGroupCreation->vaultUpdate->encoded,
		[weak = base::weak_ptr(this), operationEpoch](
				TelegramTransport::UploadResult result) {
			if (!weak
				|| weak->_operationEpoch != operationEpoch
				|| !weak->_pendingGroupCreation
				|| !weak->_pendingGroupCreation->vaultUpdate
				|| !weak->_vault) {
				return;
			}
			weak->_pendingGroupCreation->uploadInProgress = false;
			if (result == TelegramTransport::UploadResult::Accepted) {
				if (!weak->commitVaultAnchor(
						*weak->_pendingGroupCreation->vaultUpdate,
						weak->_vault->identity)) {
					weak->_vaultState = DesktopVaultState::SecurityBlocked;
					weak->_groupCreationState
						= DesktopGroupCreationState::LocalFailure;
					return;
				}
				auto update = std::move(
					*weak->_pendingGroupCreation->vaultUpdate);
				weak->_pendingGroupCreation->vaultUpdate.reset();
				if (!weak->_vaultCodec.applyPublished(
						*weak->_vault,
						std::move(update))) {
					weak->_groupCreationState
						= DesktopGroupCreationState::LocalFailure;
					return;
				}
				weak->publishNextBootstrapObject();
			} else if (result
					== TelegramTransport::UploadResult::RetryableError) {
				weak->_groupCreationState
					= DesktopGroupCreationState::RetryableTransportError;
			} else {
				weak->_groupCreationState
					= DesktopGroupCreationState::PermanentTransportError;
			}
		});
}

void DesktopService::publishNextBootstrapObject() {
	if (!_pendingGroupCreation
		|| _pendingGroupCreation->uploadInProgress
		|| _pendingGroupCreation->vaultUpdate) {
		return;
	}
	if (_pendingGroupCreation->phase == PendingGroupCreation::Phase::Active
		&& _pendingGroupCreation->freshnessGate
		&& _pendingGroupCreation->freshnessGate->state()
			== FreshnessState::Required
		&& !_pendingGroupCreation->outbox.size()
		&& !queueFreshnessChallenge(*_pendingGroupCreation)) {
		_groupCreationState = DesktopGroupCreationState::LocalFailure;
		return;
	}
	auto item = _pendingGroupCreation->outbox.front(
		_pendingGroupCreation->conversationId);
	const auto itemGuard = qScopeGuard([&] {
		if (item) {
			CleanseOutboxItem(*item);
		}
	});
	if (!item) {
		const auto conversationId = _pendingGroupCreation->conversationId;
		const auto phase = _pendingGroupCreation->phase;
		if (phase == PendingGroupCreation::Phase::Creating) {
			_pendingGroupCreation->phase = PendingGroupCreation::Phase::Active;
		}
		_groups[conversationId] = std::move(_pendingGroupCreation);
		if (_groups[conversationId]->phase
				== PendingGroupCreation::Phase::Active
			&& !initializeActivePipeline(*_groups[conversationId])) {
			_groupCreationState = DesktopGroupCreationState::LocalFailure;
			setContentState(
				conversationId,
				DesktopContentState::LocalFailure);
			return;
		}
		if (phase == PendingGroupCreation::Phase::AwaitingAdmission) {
			_groupCreationState = DesktopGroupCreationState::AwaitingAdmission;
		} else if (_groups[conversationId]->freshnessGate
				&& !_groups[conversationId]
					->freshnessGate->sendingAllowed()
				&& phase != PendingGroupCreation::Phase::Removed) {
			_groupCreationState = DesktopGroupCreationState::AwaitingFreshness;
		} else {
			_groupCreationState = DesktopGroupCreationState::Ready;
		}
		beginGroupObservation(conversationId);
		beginContentObservation(conversationId);
		resumePendingGroupCreation();
		startNextGroupDiscovery();
		return;
	} else if (item->stage != OutboxItemStage::Sealed
		|| !item->sealed) {
		_groupCreationState = DesktopGroupCreationState::LocalFailure;
		return;
	}
	const auto persistedEnvelope = _pendingGroupCreation->envelopeCodec.decode(
		*item->sealed);
	if (_pendingGroupCreation->phase == PendingGroupCreation::Phase::Active
		&& persistedEnvelope
		&& persistedEnvelope->objectKind
			== ObjectKind::FreshnessChallenge
		&& !resumeQueuedFreshnessChallenge(
			*_pendingGroupCreation,
			*item->sealed)) {
		_groupCreationState = DesktopGroupCreationState::LocalFailure;
		return;
	}
	const auto objectId = item->sealed->objectId;
	_pendingGroupCreation->uploadInProgress = true;
	_groupCreationState = DesktopGroupCreationState::PublishingBootstrap;
	_pendingGroupCreation->transport.uploadExact(
		*item->sealed,
		[weak = base::weak_ptr(this), objectId](
				TelegramTransport::UploadResult result) {
			if (!weak || !weak->_pendingGroupCreation) {
				return;
			}
			weak->_pendingGroupCreation->uploadInProgress = false;
			if (result == TelegramTransport::UploadResult::Accepted) {
				if (!weak->_pendingGroupCreation->outbox.remove(objectId)) {
					weak->_groupCreationState
						= DesktopGroupCreationState::LocalFailure;
					return;
				}
				const auto reconciled = ReconcileMlsOutboxReceipts(
					weak->_pendingGroupCreation->mlsState,
					weak->_pendingGroupCreation->outbox,
					weak->_pendingGroupCreation->envelopeCodec,
					weak->_pendingGroupCreation->inboundJournal);
				if (reconciled == MlsReceiptReconcileResult::ObjectIdConflict) {
					weak->_vaultState = DesktopVaultState::SecurityBlocked;
					weak->_groupCreationState
						= DesktopGroupCreationState::LocalFailure;
					return;
				} else if (reconciled
						!= MlsReceiptReconcileResult::Reconciled
					&& reconciled
						!= MlsReceiptReconcileResult::NothingToDo) {
					weak->_groupCreationState
						= DesktopGroupCreationState::LocalFailure;
					return;
				}
				weak->publishNextBootstrapObject();
			} else if (result
					== TelegramTransport::UploadResult::RetryableError) {
				weak->_groupCreationState
					= DesktopGroupCreationState::RetryableTransportError;
			} else {
				weak->_groupCreationState
					= DesktopGroupCreationState::PermanentTransportError;
			}
		});
}

void DesktopService::resumePendingGroupCreation() {
	if (_pendingGroupCreation
		|| !_vault
		|| _vaultState.current() != DesktopVaultState::Ready) {
		return;
	}
	for (const auto &conversation : _vault->conversations) {
		if (_groups.contains(conversation.conversationId)) {
			continue;
		}
		const auto result = restoreLocalGroup(
			conversation.conversationId,
			&conversation);
		if (result == LocalGroupRecoveryResult::Restored) {
			publishNextBootstrapObject();
			return;
		} else if (result == LocalGroupRecoveryResult::Missing) {
			beginIndexedGroupJoin(conversation);
			return;
		} else if (result == LocalGroupRecoveryResult::Invalid) {
			_vaultState = DesktopVaultState::SecurityBlocked;
			_groupCreationState = DesktopGroupCreationState::LocalFailure;
			return;
		}
	}
	const auto entries = QDir(AccountDirectory(_telegramUserIdBinding))
		.entryList(
			QDir::Dirs | QDir::NoDotAndDotDot | QDir::NoSymLinks,
			QDir::Name);
	if (entries.size() > 512) {
		_vaultState = DesktopVaultState::SecurityBlocked;
		_groupCreationState = DesktopGroupCreationState::LocalFailure;
		return;
	}
	auto indexed = std::set<ConversationId>();
	for (const auto &conversation : _vault->conversations) {
		indexed.emplace(conversation.conversationId);
	}
	for (const auto &entry : entries) {
		const auto conversationId = DecodeConversationDirectory(entry);
		if (!conversationId || indexed.contains(*conversationId)) {
			continue;
		}
		const auto result = restoreLocalGroup(*conversationId, nullptr);
		if (result == LocalGroupRecoveryResult::Restored) {
			beginGroupVaultPreflight();
			return;
		} else if (result == LocalGroupRecoveryResult::Invalid) {
			_vaultState = DesktopVaultState::SecurityBlocked;
			_groupCreationState = DesktopGroupCreationState::LocalFailure;
			return;
		}
	}
	startNextGroupDiscovery();
}

void DesktopService::beginIndexedGroupJoin(
		const CloudVaultConversation &conversation) {
	if (_pendingGroupJoin
		|| _pendingGroupCreation
		|| _groups.contains(conversation.conversationId)
		|| !_vault) {
		return;
	}
	if (!IsProtectedGroupPeerBinding(
			_session,
			conversation.telegramPeerIdBinding)) {
		_vaultState = DesktopVaultState::SecurityBlocked;
		_groupCreationState = DesktopGroupCreationState::LocalFailure;
		return;
	}
	_pendingGroupJoin = std::make_unique<PendingGroupJoin>(
		_session,
		conversation);
	_groupCreationState = DesktopGroupCreationState::Preparing;
	_pendingGroupJoin->sync =
		std::make_unique<PublicBootstrapSyncController>(
			conversation.conversationId,
			conversation.telegramPeerIdBinding,
			conversation.ownerAccountId,
			_pendingGroupJoin->controlTransport,
			_pendingGroupJoin->envelopeCodec,
			_sha256,
			[weak = base::weak_ptr(this)](
					PublicBootstrapSyncCompletion result) {
				if (weak) {
					weak->applyPublicBootstrapSyncResult(std::move(result));
				}
			});
	if (!_pendingGroupJoin->sync->start()) {
		_pendingGroupJoin.reset();
		_groupCreationState = DesktopGroupCreationState::LocalFailure;
	}
}

void DesktopService::applyPublicBootstrapSyncResult(
		PublicBootstrapSyncCompletion result) {
	if (!_pendingGroupJoin || !_vault) {
		return;
	}
	_pendingGroupJoin->sync.reset();
	if (result.status == PublicBootstrapSyncStatus::RetryableTransportError
		|| result.status == PublicBootstrapSyncStatus::Missing) {
		_pendingGroupJoin.reset();
		_groupCreationState = DesktopGroupCreationState::RetryableTransportError;
		return;
	} else if (result.status
			== PublicBootstrapSyncStatus::PermanentTransportError) {
		_pendingGroupJoin.reset();
		_groupCreationState = DesktopGroupCreationState::PermanentTransportError;
		return;
	} else if (result.status != PublicBootstrapSyncStatus::Verified
		|| !result.verified) {
		_pendingGroupJoin.reset();
		_vaultState = DesktopVaultState::SecurityBlocked;
		_groupCreationState = DesktopGroupCreationState::LocalFailure;
		return;
	}
	auto conversation = _pendingGroupJoin->conversation;
	auto verified = std::move(*result.verified);
	if (verified.checkpoint != conversation.checkpoint
		|| verified.genesis.ownerAccountId != conversation.ownerAccountId) {
		_pendingGroupJoin.reset();
		_vaultState = DesktopVaultState::SecurityBlocked;
		_groupCreationState = DesktopGroupCreationState::LocalFailure;
		return;
	}
	_pendingGroupJoin.reset();
	if (!prepareGroupJoin(
		std::move(conversation),
		std::move(verified),
		false)) {
		_groupCreationState = DesktopGroupCreationState::LocalFailure;
	}
}

bool DesktopService::prepareGroupJoin(
		CloudVaultConversation conversation,
		VerifiedPublicGroupBootstrap verified,
		bool discovered) {
	if (!_vault
		|| _pendingGroupCreation
		|| _groups.contains(conversation.conversationId)
		|| verified.checkpoint != conversation.checkpoint
		|| verified.genesis.ownerAccountId != conversation.ownerAccountId) {
		return false;
	}
	const auto accountId = DeriveAccountId(
		_vault->identity.credential,
		_sha256);
	const auto clientId = RandomId<ClientId>();
	const auto publicationObjectId = RandomId<ObjectId>();
	auto localRecordKey = DeriveConversationLocalRecordKey(
		_vault->masterKey,
		_telegramUserIdBinding,
		conversation.conversationId);
	if (!accountId || !clientId || !publicationObjectId || !localRecordKey) {
		_groupCreationState = DesktopGroupCreationState::LocalFailure;
		return false;
	}
	auto operation = std::make_unique<PendingGroupCreation>(
		ConversationDirectory(
			_telegramUserIdBinding,
			conversation.conversationId),
		std::move(*localRecordKey),
		_session,
		conversation.telegramPeerIdBinding,
		conversation.conversationId,
		_sha256);
	if (operation->metadata.load(conversation.conversationId)
			!= ConversationMetadataLoadResult::Missing
		|| operation->journal.load(conversation.conversationId)
			!= GroupBootstrapJournalLoadResult::Empty
		|| operation->mlsState.load(conversation.conversationId)
			!= MlsStateLoadResult::Missing
		|| operation->archiveState.load(conversation.conversationId)
			!= ArchiveStateLoadResult::Missing
		|| operation->groupLedger.load(conversation.conversationId)
			!= GroupLedgerLoadResult::Missing
		|| operation->outbox.load() != PersistentOutboxLoadResult::Empty
		|| operation->changeJournal.load(conversation.conversationId)
			!= GroupChangeJournalLoadResult::Empty
		|| operation->keyPackages.load(
			conversation.conversationId,
			conversation.telegramPeerIdBinding)
			!= KeyPackagePoolLoadResult::Empty
		|| operation->freshnessTrust.load(conversation.conversationId)
			!= FreshnessTrustLoadResult::Missing
		|| operation->inboundJournal.load()
			!= InboundJournalLoadResult::Missing
		|| operation->controlInboundJournal.load()
			!= InboundJournalLoadResult::Missing
		|| operation->contentStore.load()
			!= ContentStoreLoadResult::Missing
		|| operation->controlSyncState.load(conversation.conversationId)
			!= ContentSyncStateLoadResult::Missing
		|| operation->contentSyncState.load(conversation.conversationId)
			!= ContentSyncStateLoadResult::Missing
		|| operation->fileTransfer.load(conversation.conversationId)
			!= FileTransferLoadResult::Empty
		|| operation->metadata.initialize({
			.conversationId = conversation.conversationId,
			.telegramPeerIdBinding = conversation.telegramPeerIdBinding,
			.accountId = *accountId,
			.clientId = *clientId,
		}) != ConversationMetadataCommitResult::Committed
		|| operation->groupLedger.initialize(
			verified.genesis,
			verified.state,
			verified.checkpoint,
			verified.ownerCredential)
			!= GroupLedgerCommitResult::Committed
		|| operation->freshnessTrust.initialize(false)
			!= FreshnessTrustCommitResult::Committed) {
		_groupCreationState = DesktopGroupCreationState::LocalFailure;
		return false;
	}
	const auto createdAt = std::uint64_t(base::unixtime::now());
	auto keyPackage = PrepareClientKeyPackage({
		.client = {
			.conversationId = conversation.conversationId,
			.accountId = *accountId,
			.clientId = *clientId,
			.telegramPeerIdBinding = conversation.telegramPeerIdBinding,
		},
		.currentGeneration = verified.state.generation(),
		.publicationObjectId = *publicationObjectId,
		.createdAt = createdAt,
		.accountCredential = &_vault->identity.credential,
		.accountSigningPrivateKey = &_vault->identity.signingPrivateKey,
	},
	OpenMlsBridge(),
	MlsContextCodecV1(),
	ClientKeyPackagePublicationCodecV1(),
	operation->envelopeCodec,
	_sha256);
	if (keyPackage.status != PrepareClientKeyPackageStatus::Prepared
		|| !keyPackage.entry
		|| operation->keyPackages.add(std::move(*keyPackage.entry))
			!= KeyPackagePoolMutationResult::Committed
		|| operation->keyPackages.enqueuePending(
			operation->outbox,
			createdAt) != KeyPackagePoolEnqueueResult::Queued) {
		_groupCreationState = DesktopGroupCreationState::LocalFailure;
		return false;
	}
	operation->conversation = conversation;
	operation->freshnessGate = std::make_unique<FreshnessGate>(
		conversation.checkpoint,
		false);
	operation->vaultPreflightRequired = discovered;
	operation->phase = PendingGroupCreation::Phase::AwaitingAdmission;
	_pendingGroupCreation = std::move(operation);
	if (discovered) {
		_groupCreationState = DesktopGroupCreationState::UpdatingVault;
		beginGroupVaultPreflight();
	} else {
		publishNextBootstrapObject();
	}
	return true;
}

bool DesktopService::queueFreshnessChallenge(
		PendingGroupCreation &group) {
	if (!_vault
		|| !group.freshnessGate
		|| group.freshnessGate->state() != FreshnessState::Required) {
		return false;
	}
	const auto metadata = group.metadata.metadata();
	const auto nonce = RandomId<ChallengeNonce>();
	const auto objectId = RandomId<ObjectId>();
	if (!metadata
		|| !nonce
		|| !objectId
		|| !group.freshnessGate->beginChallenge(*nonce)) {
		return false;
	}
	const auto challenge = group.freshnessGate->challenge();
	const auto envelope = challenge
		? PrepareFreshnessChallengeEnvelope({
			.challenge = *challenge,
			.requesterAccountId = metadata->accountId,
			.requesterClientId = metadata->clientId,
			.telegramPeerIdBinding = group.telegramPeerIdBinding,
			.objectId = *objectId,
			.requesterSigningPrivateKey =
				&_vault->identity.signingPrivateKey,
		}, group.envelopeCodec, _sha256)
		: std::nullopt;
	if (!envelope || !group.outbox.appendSealed(*envelope)) {
		group.freshnessGate->requireFreshness(
			group.groupLedger.checkpoint());
		return false;
	}
	return true;
}

bool DesktopService::resumeQueuedFreshnessChallenge(
		PendingGroupCreation &group,
		const EncodedEnvelope &encoded) {
	const auto metadata = group.metadata.metadata();
	const auto envelope = group.envelopeCodec.decode(encoded);
	const auto challenge = envelope
		? FreshnessChallengeCodecV1().decode(envelope->payload)
		: std::nullopt;
	if (!metadata
		|| !group.freshnessGate
		|| !envelope
		|| !challenge
		|| challenge->conversationId != group.conversationId
		|| challenge->knownCheckpoint
			!= group.freshnessGate->knownCheckpoint()
		|| envelope->conversationId != group.conversationId
		|| envelope->objectKind != ObjectKind::FreshnessChallenge
		|| envelope->senderAccountId != metadata->accountId
		|| envelope->senderClientId != metadata->clientId
		|| envelope->telegramPeerIdBinding
			!= group.telegramPeerIdBinding
		|| envelope->epochOrGeneration
			!= challenge->knownCheckpoint.generation
		|| envelope->payloadHash != _sha256.digest(envelope->payload)) {
		return false;
	}
	const auto state = group.freshnessGate->state();
	return (state == FreshnessState::Required)
		? group.freshnessGate->beginChallenge(challenge->nonce)
		: (state == FreshnessState::WaitingForWitness
			&& group.freshnessGate->challenge() == challenge);
}

bool DesktopService::processObservedFreshness(
		ConversationId conversationId,
		const std::vector<TelegramTransport::UntrustedObject> &objects) {
	const auto i = _groups.find(conversationId);
	if (i == end(_groups)
		|| !_vault
		|| i->second->phase != PendingGroupCreation::Phase::Active) {
		return false;
	}
	auto &group = *i->second;
	const auto metadata = group.metadata.metadata();
	if (!metadata || !group.freshnessGate) {
		return false;
	}
	auto changed = false;
	for (const auto &object : objects) {
		if (group.freshnessGate->sendingAllowed()) {
			const auto challenge = VerifyObservedFreshnessChallenge(
				object,
				conversationId,
				group.telegramPeerIdBinding,
				group.envelopeCodec,
				group.groupLedger,
				_sha256);
			if (!challenge
				|| (challenge->requesterAccountId == metadata->accountId
					&& challenge->requesterClientId
						== metadata->clientId)) {
				continue;
			}
			const auto replay = group.controlInboundJournal.lookup(
				conversationId,
				challenge->objectId,
				challenge->payloadHash);
			if (replay == InboundJournalLookup::Accepted) {
				continue;
			} else if (replay == InboundJournalLookup::ObjectIdConflict) {
				_vaultState = DesktopVaultState::SecurityBlocked;
				_groupCreationState = DesktopGroupCreationState::LocalFailure;
				setContentState(
					conversationId,
					DesktopContentState::SecurityBlocked);
				return false;
			} else if (replay == InboundJournalLookup::StorageError) {
				_groupCreationState = DesktopGroupCreationState::LocalFailure;
				setContentState(
					conversationId,
					DesktopContentState::LocalFailure);
				return false;
			}
			const auto responseObjectId = FreshnessResponseObjectId(
				challenge->objectId,
				metadata->clientId,
				_sha256);
			const auto response = PrepareFreshnessResponseEnvelope({
				.challenge = challenge->challenge,
				.witnessCheckpoint = group.groupLedger.checkpoint(),
				.witnessAccountId = metadata->accountId,
				.witnessClientId = metadata->clientId,
				.telegramPeerIdBinding = group.telegramPeerIdBinding,
				.objectId = responseObjectId,
				.witnessSigningPrivateKey =
					&_vault->identity.signingPrivateKey,
			}, group.envelopeCodec, _sha256);
			const auto alreadyPublished = response && std::any_of(
				begin(objects),
				end(objects),
				[&](const auto &candidate) {
					return candidate.bytes == response->bytes;
				});
			const auto queued = response
				? QueueFreshnessResponseOnce({
					.conversationId = conversationId,
					.challengeObjectId = challenge->objectId,
					.challengePayloadHash = challenge->payloadHash,
					.responseEnvelope = *response,
					.responseAlreadyPublished = alreadyPublished,
				}, group.outbox, group.controlInboundJournal)
				: FreshnessResponseQueueResult::InvalidArguments;
			if (queued == FreshnessResponseQueueResult::Queued) {
				changed = true;
			} else if (queued
					== FreshnessResponseQueueResult::ObjectIdConflict) {
				_vaultState = DesktopVaultState::SecurityBlocked;
				_groupCreationState = DesktopGroupCreationState::LocalFailure;
				setContentState(
					conversationId,
					DesktopContentState::SecurityBlocked);
				return false;
			} else if (queued
					== FreshnessResponseQueueResult::InvalidArguments
				|| queued
					== FreshnessResponseQueueResult::PersistenceFailed) {
				_groupCreationState = DesktopGroupCreationState::LocalFailure;
				setContentState(
					conversationId,
					DesktopContentState::LocalFailure);
				return false;
			}
		} else if (group.freshnessGate->state()
				== FreshnessState::WaitingForWitness) {
			const auto response = VerifyObservedFreshnessResponse(
				object,
				conversationId,
				group.telegramPeerIdBinding,
				group.envelopeCodec,
				group.groupLedger,
				_sha256);
			if (!response) {
				continue;
			}
			const auto verifier = AccountFreshnessResponseVerifier(
				group.groupLedger);
			const auto accepted = group.freshnessGate->acceptResponse(
				response->response,
				verifier);
			if (accepted == FreshnessResponseResult::Accepted) {
				const auto committed = group.freshnessTrust.confirm();
				if (committed != FreshnessTrustCommitResult::Committed
					&& committed
						!= FreshnessTrustCommitResult::AlreadyCommitted) {
					group.freshnessGate->requireFreshness(
						group.groupLedger.checkpoint());
					_groupCreationState
						= DesktopGroupCreationState::LocalFailure;
					return false;
				}
				_groupCreationState = DesktopGroupCreationState::Ready;
				changed = true;
			} else if (accepted == FreshnessResponseResult::ForkDetected) {
				_vaultState = DesktopVaultState::SecurityBlocked;
				_groupCreationState = DesktopGroupCreationState::LocalFailure;
				return false;
			} else if (accepted
					== FreshnessResponseResult::ResynchronizationRequired) {
				const auto target = group.freshnessGate
					->resynchronizationTarget();
				const auto knownTarget = target
					? group.groupLedger.checkpointAt(target->generation)
					: std::nullopt;
				const auto caughtUp = target
					&& knownTarget == target
					&& group.freshnessGate
						->completeResynchronization(
							*target,
							verifier)
					&& group.freshnessGate->advanceTrustedCheckpoint(
						group.groupLedger.checkpoint());
				if (caughtUp) {
					const auto committed = group.freshnessTrust.confirm();
					if (committed != FreshnessTrustCommitResult::Committed
						&& committed
							!= FreshnessTrustCommitResult::AlreadyCommitted) {
						group.freshnessGate->requireFreshness(
							group.groupLedger.checkpoint());
						_groupCreationState
							= DesktopGroupCreationState::LocalFailure;
						return false;
					}
					_groupCreationState = DesktopGroupCreationState::Ready;
				} else {
					_groupCreationState
						= DesktopGroupCreationState::AwaitingFreshness;
				}
				changed = true;
			}
		}
	}
	return changed;
}

bool DesktopService::processObservedSafetyGossip(
		ConversationId conversationId,
		const std::vector<TelegramTransport::UntrustedObject> &objects) {
	const auto i = _groups.find(conversationId);
	if (i == end(_groups)
		|| !_vault
		|| (i->second->phase != PendingGroupCreation::Phase::Active
			&& i->second->phase != PendingGroupCreation::Phase::Removed)) {
		return false;
	}
	auto &group = *i->second;
	const auto metadata = group.metadata.metadata();
	const auto state = group.groupLedger.state();
	if (!metadata || !state) {
		return false;
	}
	const auto sameGeneration = group.safetyWitnessGeneration
		== state->generation();
	auto witnesses = sameGeneration
		? group.safetyWitnesses
		: std::set<AccountId>();
	auto ownCurrentGossipObserved = sameGeneration
		&& group.ownSafetyGossipObserved;
	for (const auto &object : objects) {
		const auto observed = VerifyObservedSafetyGossip(
			object,
			conversationId,
			group.telegramPeerIdBinding,
			group.envelopeCodec,
			group.groupLedger,
			_sha256);
		if (observed.result == SafetyGossipVerifyResult::ForkDetected
			|| observed.result
				== SafetyGossipVerifyResult::IdentityConflict
			|| observed.result
				== SafetyGossipVerifyResult::FutureCheckpoint) {
			_vaultState = DesktopVaultState::SecurityBlocked;
			_groupCreationState = DesktopGroupCreationState::LocalFailure;
			setContentState(
				conversationId,
				DesktopContentState::SecurityBlocked);
			return true;
		} else if (observed.result != SafetyGossipVerifyResult::Verified
			|| !observed.verified
			|| observed.verified->gossip.checkpoint
				!= group.groupLedger.checkpoint()) {
			continue;
		}
		witnesses.emplace(observed.verified->gossip.reporterAccountId);
		if (observed.verified->gossip.reporterAccountId
				== metadata->accountId
			&& observed.verified->gossip.reporterClientId
				== metadata->clientId) {
			ownCurrentGossipObserved = true;
		}
	}
	witnesses.emplace(metadata->accountId);
	const auto witnessChanged = group.safetyWitnessGeneration
			!= state->generation()
		|| group.safetyWitnesses != witnesses;
	group.safetyWitnessGeneration = state->generation();
	group.safetyWitnesses = std::move(witnesses);
	group.ownSafetyGossipObserved = ownCurrentGossipObserved;
	if (witnessChanged) {
		const auto revision = _securityRevision.current();
		if (revision != std::numeric_limits<std::uint64_t>::max()) {
			_securityRevision = revision + 1;
		}
	}
	if (group.phase != PendingGroupCreation::Phase::Active
		|| ownCurrentGossipObserved) {
		return witnessChanged;
	}
	const auto gossipId = DeriveSafetyGossipObjectId(
		group.groupLedger.checkpoint(),
		metadata->accountId,
		metadata->clientId,
		_sha256);
	if (!gossipId || group.outbox.contains(gossipId)) {
		return witnessChanged;
	}
	const auto envelope = PrepareSafetyGossipEnvelope({
		.gossipId = gossipId,
		.reporterAccountId = metadata->accountId,
		.reporterClientId = metadata->clientId,
		.telegramPeerIdBinding = group.telegramPeerIdBinding,
		.reporterSigningPrivateKey = &_vault->identity.signingPrivateKey,
	}, group.groupLedger, group.envelopeCodec, _sha256);
	if (!envelope || !group.outbox.appendSealed(*envelope)) {
		setContentState(conversationId, DesktopContentState::LocalFailure);
		return true;
	}
	return true;
}

bool DesktopService::synchronizeObservedGroupChanges(
		ConversationId conversationId,
		const std::vector<TelegramTransport::UntrustedObject> &objects) {
	const auto i = _groups.find(conversationId);
	if (i == end(_groups)
		|| !_vault
		|| _pendingGroupCreation
		|| i->second->phase != PendingGroupCreation::Phase::Active) {
		return false;
	}
	auto &group = *i->second;
	const auto metadata = group.metadata.metadata();
	const auto accountId = DeriveAccountId(
		_vault->identity.credential,
		_sha256);
	if (!metadata
		|| !accountId
		|| metadata->accountId != *accountId
		|| !group.freshnessGate) {
		_vaultState = DesktopVaultState::SecurityBlocked;
		_groupCreationState = DesktopGroupCreationState::LocalFailure;
		return true;
	}
	const auto synchronized = SynchronizeObservedGroupChanges(
		objects,
		{
			.conversationId = conversationId,
			.accountId = *accountId,
			.clientId = metadata->clientId,
			.telegramPeerIdBinding = group.telegramPeerIdBinding,
		},
		std::uint64_t(base::unixtime::now()),
		group.envelopeCodec,
		OpenMlsBridge(),
		MlsContextCodecV1(),
		MlsRosterCodecV1(),
		GroupControlCodecV1(),
		_sha256,
		group.mlsState,
		group.archiveState,
		group.groupLedger,
		group.changeJournal);
	if (synchronized.status == ObservedGroupChangeSyncStatus::NoChange) {
		return false;
	} else if (synchronized.status
			== ObservedGroupChangeSyncStatus::WaitingForObjects) {
		return true;
	} else if (synchronized.status
			== ObservedGroupChangeSyncStatus::ForkDetected
		|| synchronized.status
			== ObservedGroupChangeSyncStatus::InvalidState) {
		_vaultState = DesktopVaultState::SecurityBlocked;
		_groupCreationState = DesktopGroupCreationState::LocalFailure;
		return true;
	} else if (synchronized.status
			== ObservedGroupChangeSyncStatus::PersistenceFailure) {
		_groupCreationState = DesktopGroupCreationState::LocalFailure;
		return true;
	}
	const auto checkpoint = group.groupLedger.checkpoint();
	if (synchronized.status
			== ObservedGroupChangeSyncStatus::LocalClientRemoved) {
		group.phase = PendingGroupCreation::Phase::Removed;
		group.freshnessGate->requireFreshness(checkpoint);
	} else if (group.freshnessGate->state() == FreshnessState::Ready) {
		if (!group.freshnessGate->advanceTrustedCheckpoint(checkpoint)) {
			_vaultState = DesktopVaultState::SecurityBlocked;
			_groupCreationState = DesktopGroupCreationState::LocalFailure;
			return true;
		}
	} else if (group.freshnessGate->state()
			== FreshnessState::ResynchronizationRequired) {
		const auto target = group.freshnessGate->resynchronizationTarget();
		const auto knownTarget = target
			? group.groupLedger.checkpointAt(target->generation)
			: std::nullopt;
		const auto verifier = AccountFreshnessResponseVerifier(
			group.groupLedger);
		if (target
			&& knownTarget == target
			&& group.freshnessGate->completeResynchronization(
				*target,
				verifier)
			&& group.freshnessGate->advanceTrustedCheckpoint(checkpoint)) {
			const auto committed = group.freshnessTrust.confirm();
			if (committed != FreshnessTrustCommitResult::Committed
				&& committed
					!= FreshnessTrustCommitResult::AlreadyCommitted) {
				group.freshnessGate->requireFreshness(checkpoint);
				_groupCreationState = DesktopGroupCreationState::LocalFailure;
				return true;
			}
		}
	}
	group.conversation.checkpoint = checkpoint;
	_pendingGroupCreation = std::move(i->second);
	_groups.erase(i);
	_pendingGroupCreation->vaultPreflightRequired = true;
	_groupCreationState = DesktopGroupCreationState::UpdatingVault;
	beginGroupVaultPreflight();
	return true;
}

void DesktopService::publishQueuedGroupOutbox(
		ConversationId conversationId) {
	const auto i = _groups.find(conversationId);
	if (i == end(_groups)
		|| _pendingGroupCreation
		|| !i->second->outbox.size()) {
		return;
	}
	if (i->second->phase == PendingGroupCreation::Phase::Active) {
		pumpActiveOutbox(conversationId);
		return;
	}
	_pendingGroupCreation = std::move(i->second);
	_groups.erase(i);
	_pendingGroupCreation->vaultPreflightRequired = false;
	publishNextBootstrapObject();
}

bool DesktopService::initializeActivePipeline(
		PendingGroupCreation &group) {
	if (group.applicationEngine
		&& group.outboxCoordinator
		&& group.uploadController) {
		return group.applicationEngine->ready();
	}
	const auto metadata = group.metadata.metadata();
	if (!metadata
		|| !group.freshnessGate
		|| group.phase != PendingGroupCreation::Phase::Active) {
		return false;
	}
	group.applicationEngine = std::make_unique<OpenMlsApplicationEngine>(
		OpenMlsClientContext{
			.conversationId = group.conversationId,
			.accountId = metadata->accountId,
			.clientId = metadata->clientId,
			.telegramPeerIdBinding = group.telegramPeerIdBinding,
		},
		OpenMlsBridge(),
		MlsContextCodecV1(),
		group.envelopeCodec,
		_sha256,
		group.mlsState);
	if (!group.applicationEngine->ready()) {
		group.applicationEngine.reset();
		return false;
	}
	group.outboxCoordinator = std::make_unique<OutboxCoordinator>(
		*group.freshnessGate,
		group.outbox,
		*group.applicationEngine);
	const auto conversationId = group.conversationId;
	group.uploadController = std::make_unique<OutboxUploadController>(
		*group.outboxCoordinator,
		group.transport,
		[weak = base::weak_ptr(this), conversationId](
				UploadCompletion completion) {
			if (weak) {
				weak->completeActiveUpload(
					conversationId,
					std::move(completion));
			}
		});
	return true;
}

void DesktopService::pumpActiveOutbox(ConversationId conversationId) {
	const auto i = _groups.find(conversationId);
	if (i == end(_groups)
		|| i->second->phase != PendingGroupCreation::Phase::Active
		|| !initializeActivePipeline(*i->second)) {
		return;
	}
	auto &group = *i->second;
	if (group.observation
		|| (group.observationDirty && !group.outbox.size())) {
		beginGroupObservation(conversationId);
		if (group.observation || group.observationDirty) {
			setContentState(
				conversationId,
				DesktopContentState::Synchronizing);
			return;
		}
	}
	if (!group.freshnessGate->sendingAllowed()) {
		if (group.freshnessGate->state() == FreshnessState::Required
			&& !group.outbox.size()
			&& !queueFreshnessChallenge(group)) {
			setContentState(
				conversationId,
				DesktopContentState::LocalFailure);
			return;
		}
		auto item = group.outbox.front(conversationId);
		const auto itemGuard = qScopeGuard([&] {
			if (item) {
				CleanseOutboxItem(*item);
			}
		});
		const auto envelope = (item && item->sealed)
			? group.envelopeCodec.decode(*item->sealed)
			: std::nullopt;
		if (!item
			|| item->stage != OutboxItemStage::Sealed
			|| !item->sealed
			|| !envelope
			|| envelope->objectKind != ObjectKind::FreshnessChallenge) {
			setContentState(
				conversationId,
				DesktopContentState::AwaitingFreshness);
			return;
		}
		if (!resumeQueuedFreshnessChallenge(group, *item->sealed)) {
			setContentState(
				conversationId,
				DesktopContentState::LocalFailure);
			return;
		}
		if (group.uploadInProgress) {
			return;
		}
		const auto objectId = item->sealed->objectId;
		group.uploadInProgress = true;
		group.transport.uploadExact(
			*item->sealed,
			[weak = base::weak_ptr(this), conversationId, objectId](
					TelegramTransport::UploadResult result) {
				if (!weak) {
					return;
				}
				const auto i = weak->_groups.find(conversationId);
				if (i == end(weak->_groups)) {
					return;
				}
				auto &group = *i->second;
				group.uploadInProgress = false;
				if (result == TelegramTransport::UploadResult::Accepted) {
					if (!group.outbox.remove(objectId)) {
						weak->setContentState(
							conversationId,
							DesktopContentState::LocalFailure);
						return;
					}
					weak->setContentState(
						conversationId,
						DesktopContentState::AwaitingFreshness);
					weak->beginGroupObservation(conversationId);
				} else if (result
						== TelegramTransport::UploadResult::RetryableError) {
					weak->setContentState(
						conversationId,
						DesktopContentState::RetryableTransportError);
				} else {
					weak->setContentState(
						conversationId,
						DesktopContentState::PermanentTransportError);
				}
			});
		return;
	}
	if (group.fileTransfer.pending()) {
		(void)pumpFileTransfer(conversationId);
		return;
	}
	const auto pumped = group.uploadController->pump();
	switch (pumped) {
	case UploadPumpResult::Empty:
		setContentState(conversationId, DesktopContentState::Ready);
		beginContentObservation(conversationId);
		break;
	case UploadPumpResult::Started:
	case UploadPumpResult::UploadInProgress:
		setContentState(conversationId, DesktopContentState::Synchronizing);
		break;
	case UploadPumpResult::AwaitingFreshness:
		setContentState(
			conversationId,
			DesktopContentState::AwaitingFreshness);
		break;
	case UploadPumpResult::InvalidItem:
	case UploadPumpResult::ProtectionFailed:
	case UploadPumpResult::PersistenceFailed:
		setContentState(conversationId, DesktopContentState::LocalFailure);
		break;
	}
}

void DesktopService::completeActiveUpload(
		ConversationId conversationId,
		UploadCompletion completion) {
	const auto i = _groups.find(conversationId);
	if (i == end(_groups)) {
		return;
	}
	auto &group = *i->second;
	if (!completion.outboxUpdated) {
		setContentState(conversationId, DesktopContentState::LocalFailure);
		return;
	} else if (completion.transportResult
			== TelegramTransport::UploadResult::RetryableError) {
		setContentState(
			conversationId,
			DesktopContentState::RetryableTransportError);
		return;
	} else if (completion.transportResult
			== TelegramTransport::UploadResult::PermanentError) {
		setContentState(
			conversationId,
			DesktopContentState::PermanentTransportError);
		return;
	}
	const auto receipt = group.mlsState.receipt(completion.objectId);
	if (receipt) {
		const auto envelope = group.envelopeCodec.decode(receipt->envelope);
		const auto reconciled = envelope
			? ReconcileObservedMlsReceipt(
				*envelope,
				group.envelopeCodec,
				group.mlsState,
				group.inboundJournal)
			: ObservedMlsReceiptReconcileResult::ObjectIdConflict;
		if (reconciled != ObservedMlsReceiptReconcileResult::Reconciled) {
			const auto state = (reconciled
					== ObservedMlsReceiptReconcileResult::ObjectIdConflict)
				? DesktopContentState::SecurityBlocked
				: DesktopContentState::LocalFailure;
			setContentState(conversationId, state);
			if (state == DesktopContentState::SecurityBlocked) {
				_vaultState = DesktopVaultState::SecurityBlocked;
			}
			return;
		}
	}
	pumpActiveOutbox(conversationId);
}

bool DesktopService::pumpFileTransfer(ConversationId conversationId) {
	const auto i = _groups.find(conversationId);
	if (i == end(_groups)
		|| !_vault
		|| i->second->phase != PendingGroupCreation::Phase::Active) {
		return false;
	}
	auto &group = *i->second;
	const auto pending = group.fileTransfer.pending();
	if (!pending) {
		return false;
	} else if (!group.freshnessGate
		|| !group.freshnessGate->sendingAllowed()) {
		setContentState(
			conversationId,
			DesktopContentState::AwaitingFreshness);
		return true;
	} else if (group.uploadInProgress
		|| (group.uploadController
			&& group.uploadController->uploadInProgress())) {
		return true;
	}
	const auto manifest = PrivateFileManifestCodecV1().decodePlaintext(
		pending->manifestPlaintext);
	if (!manifest) {
		setContentState(conversationId, DesktopContentState::LocalFailure);
		return true;
	} else if (pending->nextChunkIndex == manifest->context.chunkCount) {
		(void)finalizeFileTransfer(conversationId);
		return true;
	}
	auto source = QFile(QString::fromUtf8(pending->sourcePathUtf8));
	const auto index = pending->nextChunkIndex;
	const auto offset = std::uint64_t(manifest->context.chunkSize) * index;
	const auto expected = (index + 1 < manifest->context.chunkCount)
		? std::uint64_t(manifest->context.chunkSize)
		: manifest->context.plaintextSize - offset;
	if (!source.open(QIODevice::ReadOnly)
		|| source.size() < 0
		|| std::uint64_t(source.size()) != manifest->context.plaintextSize
		|| !source.seek(qint64(offset))) {
		setContentState(conversationId, DesktopContentState::LocalFailure);
		return true;
	}
	auto plaintext = source.read(qint64(expected));
	const auto prepared = IdempotentFileChunkProtector(
		AesGcmFileChunkCipher(),
		group.chunkStore).prepare(
			manifest->key,
			manifest->context,
			index,
			plaintext);
	Cleanse(plaintext);
	const auto metadata = group.metadata.metadata();
	const auto envelope = (metadata && prepared.exactCiphertext)
		? PrepareFileChunkEnvelope({
			.conversationId = conversationId,
			.senderAccountId = metadata->accountId,
			.senderClientId = metadata->clientId,
			.telegramPeerIdBinding = group.telegramPeerIdBinding,
			.groupGeneration = pending->groupGeneration,
			.fileId = manifest->context.fileId,
			.chunkIndex = index,
			.chunkCount = manifest->context.chunkCount,
			.senderSigningPrivateKey = &_vault->identity.signingPrivateKey,
			.exactCiphertext = *prepared.exactCiphertext,
		}, group.envelopeCodec, _sha256)
		: std::nullopt;
	if (prepared.result != FileChunkPrepareResult::Ready || !envelope) {
		setContentState(conversationId, DesktopContentState::LocalFailure);
		return true;
	}
	group.uploadInProgress = true;
	setContentState(conversationId, DesktopContentState::Synchronizing);
	group.contentTransport.uploadExact(
		envelope->encoded,
		[weak = base::weak_ptr(this), conversationId, index](
				TelegramTransport::UploadResult result) {
			if (weak) {
				weak->completeFileChunkUpload(
					conversationId,
					index,
					result);
			}
		});
	return true;
}

void DesktopService::completeFileChunkUpload(
		ConversationId conversationId,
		std::uint32_t chunkIndex,
		TelegramTransport::UploadResult result) {
	const auto i = _groups.find(conversationId);
	if (i == end(_groups)) {
		return;
	}
	auto &group = *i->second;
	group.uploadInProgress = false;
	if (result == TelegramTransport::UploadResult::RetryableError) {
		setContentState(
			conversationId,
			DesktopContentState::RetryableTransportError);
		return;
	} else if (result == TelegramTransport::UploadResult::PermanentError) {
		setContentState(
			conversationId,
			DesktopContentState::PermanentTransportError);
		return;
	}
	if (group.fileTransfer.advance(chunkIndex)
			!= FileTransferCommitResult::Committed) {
		setContentState(conversationId, DesktopContentState::LocalFailure);
		return;
	}
	pumpActiveOutbox(conversationId);
}

bool DesktopService::finalizeFileTransfer(
		ConversationId conversationId) {
	const auto i = _groups.find(conversationId);
	if (i == end(_groups) || !_vault) {
		return false;
	}
	auto &group = *i->second;
	const auto pending = group.fileTransfer.pending();
	const auto manifest = pending
		? PrivateFileManifestCodecV1().decodePlaintext(
			pending->manifestPlaintext)
		: std::nullopt;
	const auto source = pending
		? HashFile(QString::fromUtf8(pending->sourcePathUtf8))
		: std::nullopt;
	const auto metadata = group.metadata.metadata();
	const auto state = group.groupLedger.state();
	const auto epoch = group.archiveState.currentEpoch();
	if (!pending
		|| !manifest
		|| !source
		|| source->size != manifest->context.plaintextSize
		|| source->hash != manifest->plaintextHash
		|| !metadata
		|| !state
		|| !epoch
		|| !group.outboxCoordinator) {
		setContentState(conversationId, DesktopContentState::LocalFailure);
		return false;
	}
	const auto hasEvent = group.outbox.contains(pending->eventObjectId);
	const auto hasContent = group.outbox.contains(pending->contentObjectId);
	if (hasEvent != hasContent) {
		setContentState(
			conversationId,
			DesktopContentState::SecurityBlocked);
		_vaultState = DesktopVaultState::SecurityBlocked;
		return false;
	}
	if (!hasEvent) {
		const auto queued = QueueArchivedContent({
			.conversationId = conversationId,
			.eventObjectId = pending->eventObjectId,
			.contentObjectId = pending->contentObjectId,
			.objectKind = ObjectKind::EncryptedFileManifest,
			.senderAccountId = metadata->accountId,
			.senderClientId = metadata->clientId,
			.telegramPeerIdBinding = group.telegramPeerIdBinding,
			.groupGeneration = state->generation(),
			.archiveEpochGeneration = epoch->generation,
			.archiveEpochKey = &epoch->key,
			.senderSigningPrivateKey = &_vault->identity.signingPrivateKey,
			.plaintext = pending->manifestPlaintext,
			.mlsContext = QByteArray("TDE2E/archived-content/v1"),
		},
		ArchiveEpochCrypto(),
		EncryptedArchivedContentCodecV1(),
		ArchivedContentDescriptorCodecV1(),
		group.envelopeCodec,
		_sha256,
		*group.outboxCoordinator);
		if (queued != ArchivedContentQueueResult::Queued) {
			setContentState(
				conversationId,
				DesktopContentState::LocalFailure);
			return false;
		}
	}
	const auto cleared = group.fileTransfer.clear();
	if (cleared != FileTransferCommitResult::Committed
		&& cleared != FileTransferCommitResult::AlreadyCommitted) {
		setContentState(conversationId, DesktopContentState::LocalFailure);
		return false;
	}
	pumpActiveOutbox(conversationId);
	return true;
}

void DesktopService::beginGroupObservation(ConversationId conversationId) {
	const auto i = _groups.find(conversationId);
	if (i == end(_groups)
		|| (i->second->phase != PendingGroupCreation::Phase::Active
			&& i->second->phase
				!= PendingGroupCreation::Phase::AwaitingAdmission)) {
		return;
	}
	auto &group = *i->second;
	if (group.observation) {
		group.observationDirty = true;
		return;
	} else if (group.uploadInProgress
		|| (group.outbox.size()
			&& (!group.freshnessGate
				|| group.freshnessGate->sendingAllowed()))) {
		group.observationDirty = true;
		return;
	}
	group.observationDirty = false;
	group.observation = std::make_unique<PublicBootstrapSyncController>(
		conversationId,
		group.telegramPeerIdBinding,
		group.conversation.ownerAccountId,
		group.controlTransport,
		group.envelopeCodec,
		_sha256,
		[weak = base::weak_ptr(this), conversationId](
				PublicBootstrapSyncCompletion result) {
			if (weak) {
				weak->applyGroupObservation(
					conversationId,
					std::move(result));
			}
		});
	const auto boundary = group.safetyWitnessGeneration
		? group.controlSyncState.newestObservedMessageId()
		: 0;
	const auto started = boundary
		? group.observation->startFromBoundary(boundary)
		: group.observation->start();
	if (!started) {
		group.observation.reset();
		group.observationDirty = true;
	}
}

void DesktopService::beginContentObservation(
		ConversationId conversationId) {
	const auto i = _groups.find(conversationId);
	if (i == end(_groups)
		|| (i->second->phase != PendingGroupCreation::Phase::Active
			&& i->second->phase != PendingGroupCreation::Phase::Removed)) {
		return;
	}
	auto &group = *i->second;
	if (group.contentObservation) {
		group.contentObservationDirty = true;
		return;
	}
	group.contentObservationDirty = false;
	group.contentObservation =
		std::make_unique<ObservedContentSyncController>(
			conversationId,
			group.telegramPeerIdBinding,
			group.contentTransport,
			[weak = base::weak_ptr(this), conversationId](
					std::vector<TelegramTransport::UntrustedObject> objects) {
				return weak
					? weak->processObservedContentPage(
						conversationId,
						std::move(objects))
					: ObservedContentPageResult::PersistenceFailed;
			},
			[weak = base::weak_ptr(this), conversationId](
					ObservedContentSyncCompletion completion) {
				if (weak) {
					weak->applyContentObservation(
						conversationId,
						std::move(completion));
				}
			});
	setContentState(conversationId, DesktopContentState::Synchronizing);
	if (!group.contentObservation->start(
			group.contentSyncState.newestObservedMessageId())) {
		group.contentObservation.reset();
		setContentState(conversationId, DesktopContentState::LocalFailure);
	}
}

ObservedContentPageResult DesktopService::processObservedContentPage(
		ConversationId conversationId,
		std::vector<TelegramTransport::UntrustedObject> objects) {
	const auto i = _groups.find(conversationId);
	if (i == end(_groups)) {
		return ObservedContentPageResult::PersistenceFailed;
	}
	auto &group = *i->second;
	const auto metadata = group.metadata.metadata();
	if (!metadata) {
		return ObservedContentPageResult::PersistenceFailed;
	}
	const auto processed = ProcessObservedContentPage(
		objects,
		{
			.conversationId = conversationId,
			.accountId = metadata->accountId,
			.clientId = metadata->clientId,
			.telegramPeerIdBinding = group.telegramPeerIdBinding,
		},
		_telegramUserIdBinding,
		group.envelopeCodec,
		OpenMlsBridge(),
		MlsContextCodecV1(),
		_sha256,
		group.mlsState,
		group.archiveState,
		group.groupLedger,
		group.inboundJournal,
		group.contentStore,
		group.chunkStore);
	if (processed.status == ObservedContentProcessStatus::SecurityBlocked) {
		_vaultState = DesktopVaultState::SecurityBlocked;
		setContentState(
			conversationId,
			DesktopContentState::SecurityBlocked);
		return ObservedContentPageResult::SecurityBlocked;
	} else if (processed.status
			== ObservedContentProcessStatus::PersistenceFailed
		|| processed.status == ObservedContentProcessStatus::InvalidState) {
		setContentState(conversationId, DesktopContentState::LocalFailure);
		return ObservedContentPageResult::PersistenceFailed;
	}
	if (processed.stats.messagesStored
		|| processed.stats.manifestsStored) {
		const auto revision = _contentRevision.current();
		if (revision != std::numeric_limits<std::uint64_t>::max()) {
			_contentRevision = revision + 1;
		}
	}
	return ObservedContentPageResult::Persisted;
}

void DesktopService::applyContentObservation(
		ConversationId conversationId,
		ObservedContentSyncCompletion completion) {
	const auto i = _groups.find(conversationId);
	if (i == end(_groups)) {
		return;
	}
	auto &group = *i->second;
	const auto rerun = group.contentObservationDirty;
	group.contentObservationDirty = false;
	group.contentObservation.reset();
	switch (completion.status) {
	case ObservedContentSyncStatus::Complete:
		if (completion.previousBoundaryMessageId
				!= group.contentSyncState.newestObservedMessageId()
			|| (completion.nextBoundaryMessageId
				&& (!completion.newestObservedMessageId
					|| completion.nextBoundaryMessageId
						> completion.newestObservedMessageId))) {
			_vaultState = DesktopVaultState::SecurityBlocked;
			setContentState(
				conversationId,
				DesktopContentState::SecurityBlocked);
			return;
		}
		if (completion.nextBoundaryMessageId) {
			const auto committed = group.contentSyncState.advance(
				completion.nextBoundaryMessageId);
			if (committed == ContentSyncStateCommitResult::InvalidBoundary) {
				_vaultState = DesktopVaultState::SecurityBlocked;
				setContentState(
					conversationId,
					DesktopContentState::SecurityBlocked);
				return;
			} else if (committed
					== ContentSyncStateCommitResult::PersistenceFailed) {
				setContentState(
					conversationId,
					DesktopContentState::LocalFailure);
				return;
			}
		}
		setContentState(conversationId, DesktopContentState::Ready);
		if (rerun) {
			beginContentObservation(conversationId);
		}
		break;
	case ObservedContentSyncStatus::RetryableTransportError:
		setContentState(
			conversationId,
			DesktopContentState::RetryableTransportError);
		break;
	case ObservedContentSyncStatus::PermanentTransportError:
		setContentState(
			conversationId,
			DesktopContentState::PermanentTransportError);
		break;
	case ObservedContentSyncStatus::SecurityBlocked:
	case ObservedContentSyncStatus::InvalidPagination:
		_vaultState = DesktopVaultState::SecurityBlocked;
		setContentState(
			conversationId,
			DesktopContentState::SecurityBlocked);
		break;
	case ObservedContentSyncStatus::PersistenceFailed:
		setContentState(conversationId, DesktopContentState::LocalFailure);
		break;
	case ObservedContentSyncStatus::Cancelled:
		setContentState(conversationId, DesktopContentState::Idle);
		break;
	}
}

void DesktopService::applyGroupObservation(
		ConversationId conversationId,
		PublicBootstrapSyncCompletion result) {
	const auto i = _groups.find(conversationId);
	if (i == end(_groups)) {
		return;
	}
	const auto rerun = i->second->observationDirty;
	i->second->observationDirty = false;
	i->second->observation.reset();
	if (result.status == PublicBootstrapSyncStatus::ObjectConflict
		|| result.status == PublicBootstrapSyncStatus::Ambiguous
		|| result.status == PublicBootstrapSyncStatus::CapacityExceeded
		|| result.status == PublicBootstrapSyncStatus::InvalidPagination) {
		_vaultState = DesktopVaultState::SecurityBlocked;
		_groupCreationState = DesktopGroupCreationState::LocalFailure;
		return;
	} else if (result.status != PublicBootstrapSyncStatus::Verified
		&& result.status != PublicBootstrapSyncStatus::Incremental) {
		i->second->observationDirty = true;
		setContentState(
			conversationId,
			(result.status
					== PublicBootstrapSyncStatus::PermanentTransportError)
				? DesktopContentState::PermanentTransportError
				: DesktopContentState::RetryableTransportError);
		return;
	}
	const auto awaiting = i->second->phase
		== PendingGroupCreation::Phase::AwaitingAdmission;
	auto changed = false;
	if (awaiting) {
		changed = completeObservedJoin(
			conversationId,
			result.untrustedObjects);
	} else {
		const auto processingFailed = [&] {
			const auto state = contentState(conversationId);
			return _vaultState.current()
					== DesktopVaultState::SecurityBlocked
				|| _groupCreationState.current()
					== DesktopGroupCreationState::LocalFailure
				|| state == DesktopContentState::SecurityBlocked
				|| state == DesktopContentState::LocalFailure;
		};
		const auto synchronized = synchronizeObservedGroupChanges(
			conversationId,
			result.untrustedObjects);
		if (synchronized
			|| !_groups.contains(conversationId)
			|| processingFailed()) {
			return;
		}
		const auto safetyChanged = processObservedSafetyGossip(
			conversationId,
			result.untrustedObjects);
		if (processingFailed()) {
			return;
		}
		const auto freshnessChanged = processObservedFreshness(
			conversationId,
			result.untrustedObjects);
		if (processingFailed()) {
			return;
		}
		const auto grantAccepted = acceptObservedHistoryGrant(
			conversationId,
			result.untrustedObjects);
		if (processingFailed()) {
			return;
		}
		const auto admitted = admitObservedClient(
			conversationId,
			result.untrustedObjects);
		if (processingFailed() || !_groups.contains(conversationId)) {
			return;
		}
		changed = safetyChanged
			|| freshnessChanged
			|| grantAccepted
			|| admitted;
		auto &group = *_groups.find(conversationId)->second;
		if ((result.previousBoundaryMessageId
				&& result.previousBoundaryMessageId
					!= group.controlSyncState
						.newestObservedMessageId())
			|| !result.newestObservedMessageId) {
			_vaultState = DesktopVaultState::SecurityBlocked;
			_groupCreationState = DesktopGroupCreationState::LocalFailure;
			setContentState(
				conversationId,
				DesktopContentState::SecurityBlocked);
			return;
		}
		auto nextBoundaryMessageId = result.previousBoundaryMessageId;
		if (!nextBoundaryMessageId) {
			if (result.untrustedObjects.empty()) {
				_vaultState = DesktopVaultState::SecurityBlocked;
				_groupCreationState = DesktopGroupCreationState::LocalFailure;
				setContentState(
					conversationId,
					DesktopContentState::SecurityBlocked);
				return;
			}
			const auto index = std::min(
				kControlSyncOverlap,
				result.untrustedObjects.size() - 1);
			nextBoundaryMessageId = result.untrustedObjects[index]
				.observedMessageId;
		} else if (result.untrustedObjects.size() > kControlSyncOverlap) {
			nextBoundaryMessageId = result.untrustedObjects[
				kControlSyncOverlap].observedMessageId;
		}
		const auto committed = group.controlSyncState.advance(
			nextBoundaryMessageId);
		if (committed == ContentSyncStateCommitResult::InvalidBoundary) {
			_vaultState = DesktopVaultState::SecurityBlocked;
			_groupCreationState = DesktopGroupCreationState::LocalFailure;
			setContentState(
				conversationId,
				DesktopContentState::SecurityBlocked);
			return;
		} else if (committed
				== ContentSyncStateCommitResult::PersistenceFailed) {
			_groupCreationState = DesktopGroupCreationState::LocalFailure;
			setContentState(
				conversationId,
				DesktopContentState::LocalFailure);
			return;
		}
		if (rerun) {
			beginGroupObservation(conversationId);
			return;
		} else if (!admitted) {
			publishQueuedGroupOutbox(conversationId);
		}
	}
	if (!changed && rerun) {
		beginGroupObservation(conversationId);
	}
}

void DesktopService::handleNewTelegramItem(not_null<HistoryItem*> item) {
	const auto peer = item->history()->peer;
	if (!peer->isChat() && !peer->isMegagroup()) {
		return;
	}
	const auto media = item->media();
	const auto document = media ? media->document() : nullptr;
	if (!document
		|| !IsProtectedGroupCarrierMetadata(
			document->filename(),
			document->mimeString())) {
		return;
	}
	const auto peerId = item->history()->peer->id.value;
	if (document->filename() == ProtectedContentCarrierFilename()) {
		for (const auto &[conversationId, group] : _groups) {
			if (group->telegramPeerIdBinding == peerId) {
				beginContentObservation(conversationId);
			}
		}
		return;
	} else if (document->filename() != ProtectedControlCarrierFilename()
		&& document->filename() != ProtectedLegacyCarrierFilename()) {
		return;
	}
	auto conversations = std::vector<ConversationId>();
	for (const auto &[conversationId, group] : _groups) {
		if (group->telegramPeerIdBinding == peerId) {
			conversations.push_back(conversationId);
		}
	}
	for (const auto conversationId : conversations) {
		beginGroupObservation(conversationId);
	}
	if (conversations.empty()) {
		queueGroupDiscovery(peerId);
	}
}

void DesktopService::queueGroupDiscovery(
		std::uint64_t telegramPeerIdBinding) {
	const auto peer = telegramPeerIdBinding
		? _session->data().peerLoaded(PeerId(telegramPeerIdBinding))
		: nullptr;
	if (!telegramPeerIdBinding
		|| !peer
		|| (!peer->isChat() && !peer->isMegagroup())
		|| !_vault
		|| _vaultState.current() != DesktopVaultState::Ready
		|| std::any_of(
			begin(_vault->conversations),
			end(_vault->conversations),
			[&](const CloudVaultConversation &conversation) {
				return conversation.telegramPeerIdBinding
					== telegramPeerIdBinding;
			})) {
		return;
	}
	_groupDiscoveryQueue.emplace(telegramPeerIdBinding);
	startNextGroupDiscovery();
}

void DesktopService::startNextGroupDiscovery() {
	if (_pendingGroupDiscovery
		|| _pendingGroupCreation
		|| _pendingGroupJoin
		|| !_vault
		|| _vaultState.current() != DesktopVaultState::Ready) {
		return;
	}
	while (!_groupDiscoveryQueue.empty()) {
		const auto peerId = *_groupDiscoveryQueue.begin();
		_groupDiscoveryQueue.erase(_groupDiscoveryQueue.begin());
		if (std::any_of(
				begin(_vault->conversations),
				end(_vault->conversations),
				[&](const CloudVaultConversation &conversation) {
					return conversation.telegramPeerIdBinding == peerId;
				})
			|| std::any_of(
				begin(_groups),
				end(_groups),
				[&](const auto &entry) {
					return entry.second->telegramPeerIdBinding == peerId;
				})) {
			continue;
		}
		_pendingGroupDiscovery =
			std::make_unique<PendingGroupDiscovery>(_session, peerId);
		_pendingGroupDiscovery->sync =
			std::make_unique<PublicBootstrapDiscoveryController>(
				peerId,
				_pendingGroupDiscovery->backend,
				_pendingGroupDiscovery->envelopeCodec,
				_sha256,
				[weak = base::weak_ptr(this)](
						PublicBootstrapSyncCompletion result) {
					if (weak) {
						weak->applyGroupDiscovery(std::move(result));
					}
				});
		if (!_pendingGroupDiscovery->sync->start()) {
			_pendingGroupDiscovery.reset();
			continue;
		}
		return;
	}
}

void DesktopService::applyGroupDiscovery(
		PublicBootstrapSyncCompletion result) {
	if (!_pendingGroupDiscovery || !_vault) {
		return;
	}
	const auto peerId = _pendingGroupDiscovery->telegramPeerIdBinding;
	_pendingGroupDiscovery->sync.reset();
	_pendingGroupDiscovery.reset();
	if (result.status == PublicBootstrapSyncStatus::ObjectConflict
		|| result.status == PublicBootstrapSyncStatus::Ambiguous
		|| result.status == PublicBootstrapSyncStatus::CapacityExceeded
		|| result.status == PublicBootstrapSyncStatus::InvalidPagination) {
		_vaultState = DesktopVaultState::SecurityBlocked;
		_groupCreationState = DesktopGroupCreationState::LocalFailure;
		return;
	} else if (result.status != PublicBootstrapSyncStatus::Verified
		|| !result.verified) {
		startNextGroupDiscovery();
		return;
	}
	auto verified = std::move(*result.verified);
	if (verified.genesis.telegramPeerIdBinding != peerId
		|| std::any_of(
			begin(_vault->conversations),
			end(_vault->conversations),
			[&](const CloudVaultConversation &conversation) {
				return conversation.conversationId
					== verified.genesis.conversationId
					|| conversation.telegramPeerIdBinding == peerId;
			})) {
		startNextGroupDiscovery();
		return;
	}
	auto conversation = CloudVaultConversation{
		.conversationId = verified.genesis.conversationId,
		.telegramPeerIdBinding = peerId,
		.checkpoint = verified.checkpoint,
		.ownerAccountId = verified.genesis.ownerAccountId,
	};
	if (!prepareGroupJoin(
			std::move(conversation),
			std::move(verified),
			true)) {
		_groupCreationState = DesktopGroupCreationState::LocalFailure;
		startNextGroupDiscovery();
	}
}

bool DesktopService::completeObservedJoin(
		ConversationId conversationId,
		const std::vector<TelegramTransport::UntrustedObject> &objects) {
	const auto i = _groups.find(conversationId);
	if (i == end(_groups)
		|| !_vault
		|| _pendingGroupCreation
		|| i->second->phase
			!= PendingGroupCreation::Phase::AwaitingAdmission) {
		return false;
	}
	auto &group = *i->second;
	const auto metadata = group.metadata.metadata();
	const auto accountId = DeriveAccountId(
		_vault->identity.credential,
		_sha256);
	if (!metadata
		|| !accountId
		|| metadata->accountId != *accountId) {
		_vaultState = DesktopVaultState::SecurityBlocked;
		_groupCreationState = DesktopGroupCreationState::LocalFailure;
		return false;
	}
	auto catchup = CatchUpPublicJoin(
		objects,
		conversationId,
		group.telegramPeerIdBinding,
		*accountId,
		metadata->clientId,
		_vault->identity.credential,
		std::uint64_t(base::unixtime::now()),
		group.envelopeCodec,
		_sha256,
		group.groupLedger,
		group.keyPackages);
	if (catchup.status == PublicJoinCatchupStatus::Waiting) {
		return false;
	} else if (catchup.status == PublicJoinCatchupStatus::UpdatedWaiting) {
		group.conversation.checkpoint = group.groupLedger.checkpoint();
		group.freshnessGate->requireFreshness(
			group.conversation.checkpoint);
		_pendingGroupCreation = std::move(i->second);
		_groups.erase(i);
		_pendingGroupCreation->vaultPreflightRequired = true;
		_groupCreationState = DesktopGroupCreationState::UpdatingVault;
		beginGroupVaultPreflight();
		return true;
	} else if (catchup.status == PublicJoinCatchupStatus::ForkDetected
		|| catchup.status == PublicJoinCatchupStatus::InvalidState) {
		_vaultState = DesktopVaultState::SecurityBlocked;
		_groupCreationState = DesktopGroupCreationState::LocalFailure;
		return false;
	} else if (catchup.status
			== PublicJoinCatchupStatus::PersistenceFailure
		|| catchup.status != PublicJoinCatchupStatus::Ready
		|| !catchup.bundle) {
		_groupCreationState = DesktopGroupCreationState::LocalFailure;
		return false;
	}
	auto bundle = std::move(*catchup.bundle);
	const auto installed = InstallClientKeyPackageForWelcome(
		bundle.targetKeyPackage,
		std::uint64_t(base::unixtime::now()),
		OpenMlsBridge(),
		_sha256,
		group.keyPackages,
		group.mlsState);
	if (installed != InstallClientKeyPackageStatus::Installed
		&& installed != InstallClientKeyPackageStatus::AlreadyInstalled) {
		_groupCreationState = DesktopGroupCreationState::LocalFailure;
		return false;
	}
	auto prepared = PrepareOpenMlsInboundJoin({
		.local = {
			.conversationId = conversationId,
			.accountId = *accountId,
			.clientId = metadata->clientId,
			.telegramPeerIdBinding = group.telegramPeerIdBinding,
		},
		.transitionEnvelope = std::move(bundle.transitionEnvelope),
		.commitEnvelope = std::move(bundle.commitEnvelope),
		.welcomeEnvelope = std::move(bundle.welcomeEnvelope),
		.archiveDistributionEnvelope =
			std::move(bundle.archiveDistributionEnvelope),
		.targetCredential = std::move(bundle.targetCredential),
		.targetKeyPackage = bundle.targetKeyPackage,
	},
	OpenMlsBridge(),
	MlsContextCodecV1(),
	MlsRosterCodecV1(),
	GroupControlCodecV1(),
	_sha256,
	group.mlsState,
	group.archiveState,
	group.groupLedger);
	if (prepared.status != OpenMlsInboundGroupChangeStatus::Prepared
		|| !prepared.prepared) {
		_groupCreationState = DesktopGroupCreationState::LocalFailure;
		return false;
	}
	auto coordinator = GroupChangeTransactionCoordinator(
		group.changeJournal,
		group.mlsState,
		group.archiveState,
		group.groupLedger,
		_sha256);
	const auto applied = coordinator.apply(
		std::move(prepared.prepared->transaction));
	if (applied != GroupChangeApplyStatus::Applied
		&& coordinator.recover() != GroupChangeApplyStatus::Recovered) {
		_groupCreationState = DesktopGroupCreationState::LocalFailure;
		return false;
	}
	const auto finalized = FinalizeClientKeyPackageWelcome(
		bundle.targetKeyPackage,
		OpenMlsBridge(),
		_sha256,
		group.keyPackages,
		group.mlsState);
	if (finalized != FinalizeClientKeyPackageStatus::Finalized
		&& finalized != FinalizeClientKeyPackageStatus::AlreadyFinalized) {
		_groupCreationState = DesktopGroupCreationState::LocalFailure;
		return false;
	}
	group.phase = PendingGroupCreation::Phase::Active;
	group.conversation.checkpoint = group.groupLedger.checkpoint();
	group.freshnessGate->requireFreshness(group.conversation.checkpoint);
	acceptObservedHistoryGrant(conversationId, objects);
	_pendingGroupCreation = std::move(i->second);
	_groups.erase(i);
	_pendingGroupCreation->vaultPreflightRequired = true;
	_groupCreationState = DesktopGroupCreationState::UpdatingVault;
	beginGroupVaultPreflight();
	return true;
}

bool DesktopService::acceptObservedHistoryGrant(
		ConversationId conversationId,
		const std::vector<TelegramTransport::UntrustedObject> &objects) {
	const auto i = _groups.find(conversationId);
	if (i == end(_groups) || !_vault) {
		return false;
	}
	auto &group = *i->second;
	const auto metadata = group.metadata.metadata();
	const auto accountId = DeriveAccountId(
		_vault->identity.credential,
		_sha256);
	if (!metadata || !accountId || metadata->accountId != *accountId) {
		return false;
	}
	for (const auto &object : objects) {
		const auto envelope = group.envelopeCodec.decodeUntrusted(
			object.bytes);
		if (!envelope
			|| envelope->objectKind != ObjectKind::HistoryGrant
			|| envelope->conversationId != conversationId
			|| envelope->telegramPeerIdBinding
				!= group.telegramPeerIdBinding
			|| object.observedTelegramPeerIdBinding
				!= group.telegramPeerIdBinding
			|| object.observedMessageId <= 0
			|| envelope->payloadHash != _sha256.digest(envelope->payload)) {
			continue;
		}
		const auto grant = EncryptedHistoryGrantCodecV1().decode(
			envelope->payload);
		const auto state = grant
			? group.groupLedger.stateAt(grant->groupGeneration)
			: std::nullopt;
		const auto issuer = state
			? state->member(grant->issuerAccountId)
			: nullptr;
		if (!grant
			|| grant->recipientAccountId != *accountId
			|| grant->grantId != envelope->objectId
			|| grant->issuerAccountId != envelope->senderAccountId
			|| grant->issuerClientId != envelope->senderClientId
			|| grant->groupGeneration != envelope->epochOrGeneration
			|| envelope->authenticationData != QByteArray(
				reinterpret_cast<const char*>(grant->signature.data()),
				int(grant->signature.size()))
			|| !issuer
			|| issuer->telegramUserIdBinding
				!= object.observedSenderTelegramUserIdBinding) {
			continue;
		}
		const auto accepted = AcceptAuthorizedHistoryGrant({
			.conversationId = conversationId,
			.telegramPeerIdBinding = group.telegramPeerIdBinding,
			.recipientAccountId = *accountId,
			.recipientArchivePrivateKey =
				&_vault->identity.archiveHpkePrivateKey,
			.grant = &*grant,
		},
		group.groupLedger,
		group.archiveState,
		_sha256,
		OpenMlsBridge());
		if (accepted == HistoryGrantServiceStatus::Accepted
			|| accepted == HistoryGrantServiceStatus::AlreadyAccepted) {
			return true;
		} else if (accepted == HistoryGrantServiceStatus::ArchiveConflict) {
			_vaultState = DesktopVaultState::SecurityBlocked;
			_groupCreationState = DesktopGroupCreationState::LocalFailure;
			setContentState(
				conversationId,
				DesktopContentState::SecurityBlocked);
			return false;
		} else if (accepted
				== HistoryGrantServiceStatus::PersistenceFailure) {
			_groupCreationState = DesktopGroupCreationState::LocalFailure;
			setContentState(
				conversationId,
				DesktopContentState::LocalFailure);
			return false;
		}
	}
	return false;
}

bool DesktopService::applyAdministrativeTransition(
		ConversationId conversationId,
		GroupTransition transition) {
	const auto i = _groups.find(conversationId);
	if (i == end(_groups) || !_vault || _pendingGroupCreation) {
		return false;
	}
	auto &group = *i->second;
	const auto state = group.groupLedger.state();
	const auto metadata = group.metadata.metadata();
	const auto actorAccountId = DeriveAccountId(
		_vault->identity.credential,
		_sha256);
	const auto removal = transition.kind == GroupTransitionKind::RemoveMember
		|| transition.kind == GroupTransitionKind::RemoveClient;
	const auto policy = transition.kind == GroupTransitionKind::SetRole
		|| transition.kind == GroupTransitionKind::TransferOwnership
		|| transition.kind == GroupTransitionKind::SetDefaultHistory
		|| transition.kind == GroupTransitionKind::SetMemberHistory;
	if ((!removal && !policy)
		|| !state
		|| !metadata
		|| !actorAccountId
		|| group.observation
		|| group.observationDirty
		|| group.phase != PendingGroupCreation::Phase::Active
		|| !group.freshnessGate
		|| !group.freshnessGate->administrationAllowed()
		|| metadata->accountId != *actorAccountId
		|| !state->memberByClient(metadata->clientId)
		|| state->generation()
			== std::numeric_limits<std::uint64_t>::max()) {
		return false;
	}
	const auto transitionId = RandomId<ObjectId>();
	const auto commitObjectId = RandomId<ObjectId>();
	const auto distributionObjectId = RandomId<ObjectId>();
	const auto nextArchiveKey = ArchiveEpochCrypto().generateKey();
	if (!transitionId
		|| !commitObjectId
		|| !distributionObjectId
		|| !nextArchiveKey) {
		return false;
	}
	transition.conversationId = conversationId;
	transition.transitionId = *transitionId;
	transition.previousGeneration = state->generation();
	transition.generation = state->generation() + 1;
	const auto context = OpenMlsClientContext{
		.conversationId = conversationId,
		.accountId = *actorAccountId,
		.clientId = metadata->clientId,
		.telegramPeerIdBinding = group.telegramPeerIdBinding,
	};
	auto prepared = removal
		? PrepareOpenMlsRemoval({
			.actor = context,
			.currentGroupState = state,
			.currentCheckpoint = group.groupLedger.checkpoint(),
			.transition = transition,
			.actorCredential = &_vault->identity.credential,
			.actorSigningPrivateKey = &_vault->identity.signingPrivateKey,
			.nextArchiveKey = &*nextArchiveKey,
			.mlsCommitObjectId = *commitObjectId,
			.archiveDistributionObjectId = *distributionObjectId,
		},
		OpenMlsBridge(),
		MlsContextCodecV1(),
		MlsRosterCodecV1(),
		GroupControlCodecV1(),
		group.envelopeCodec,
		_sha256,
		group.mlsState,
		group.archiveState,
		group.groupLedger)
		: PrepareOpenMlsPolicyChange({
			.actor = context,
			.currentGroupState = state,
			.currentCheckpoint = group.groupLedger.checkpoint(),
			.transition = transition,
			.actorCredential = &_vault->identity.credential,
			.actorSigningPrivateKey = &_vault->identity.signingPrivateKey,
			.nextArchiveKey = &*nextArchiveKey,
			.mlsCommitObjectId = *commitObjectId,
			.archiveDistributionObjectId = *distributionObjectId,
		},
		OpenMlsBridge(),
		MlsContextCodecV1(),
		MlsRosterCodecV1(),
		GroupControlCodecV1(),
		group.envelopeCodec,
		_sha256,
		group.mlsState,
		group.archiveState,
		group.groupLedger);
	if (prepared.status != OpenMlsGroupChangePrepareStatus::Prepared
		|| !prepared.prepared) {
		return false;
	}
	auto &preparedChange = *prepared.prepared;
	if (transition.kind == GroupTransitionKind::SetMemberHistory) {
		const auto grantId = RandomId<ObjectId>();
		auto grant = (grantId && preparedChange.transaction.archiveEpoch)
			? CreateAdmissionHistoryGrant({
				.grant = {
					.conversationId = conversationId,
					.grantId = *grantId,
					.issuerAccountId = *actorAccountId,
					.issuerClientId = metadata->clientId,
					.recipientAccountId = transition.targetAccountId,
					.telegramPeerIdBinding = group.telegramPeerIdBinding,
					.groupGeneration = transition.generation,
					.historyAccess = transition.historyAccess,
					.issuerSigningPrivateKey =
						&_vault->identity.signingPrivateKey,
				},
				.signedTransition =
					&preparedChange.transaction.signedTransition,
				.applied = &preparedChange.applied,
				.admittedCredential = nullptr,
				.archiveEpoch = &*preparedChange.transaction.archiveEpoch,
			},
			group.groupLedger,
			group.archiveState,
			_sha256,
			OpenMlsBridge())
			: CreateAuthorizedHistoryGrantOutcome();
		const auto payload = grant.grant
			? EncryptedHistoryGrantCodecV1().encode(*grant.grant)
			: std::nullopt;
		const auto envelope = (grantId && grant.grant && payload)
			? group.envelopeCodec.encode({
				.conversationId = conversationId,
				.objectKind = ObjectKind::HistoryGrant,
				.senderAccountId = *actorAccountId,
				.senderClientId = metadata->clientId,
				.telegramPeerIdBinding = group.telegramPeerIdBinding,
				.epochOrGeneration = transition.generation,
				.objectId = *grantId,
				.payloadHash = _sha256.digest(*payload),
				.payload = *payload,
				.authenticationData = QByteArray(
					reinterpret_cast<const char*>(
						grant.grant->signature.data()),
					int(grant.grant->signature.size())),
			})
			: std::nullopt;
		if (!envelope) {
			return false;
		}
		preparedChange.transaction.outboxEnvelopes.push_back(*envelope);
	}
	auto coordinator = GroupChangeTransactionCoordinator(
		group.changeJournal,
		group.mlsState,
		group.archiveState,
		group.groupLedger,
		group.outbox,
		_sha256);
	if (coordinator.apply(std::move(preparedChange.transaction))
			!= GroupChangeApplyStatus::Applied) {
		return false;
	}
	group.conversation.checkpoint = group.groupLedger.checkpoint();
	setContentState(conversationId, DesktopContentState::Synchronizing);
	_pendingGroupCreation = std::move(i->second);
	_groups.erase(i);
	_pendingGroupCreation->vaultPreflightRequired = true;
	_groupCreationState = DesktopGroupCreationState::UpdatingVault;
	beginGroupVaultPreflight();
	return true;
}

bool DesktopService::admitObservedClient(
		ConversationId conversationId,
		const std::vector<TelegramTransport::UntrustedObject> &objects) {
	const auto i = _groups.find(conversationId);
	if (i == end(_groups) || !_vault || _pendingGroupCreation) {
		return false;
	}
	auto &group = *i->second;
	const auto state = group.groupLedger.state();
	const auto metadata = group.metadata.metadata();
	const auto actorAccountId = DeriveAccountId(
		_vault->identity.credential,
		_sha256);
	if (!state
		|| !metadata
		|| !actorAccountId
		|| !group.freshnessGate
		|| !group.freshnessGate->administrationAllowed()
		|| metadata->accountId != *actorAccountId
		|| !state->memberByClient(metadata->clientId)) {
		return false;
	}
	for (const auto &object : objects) {
			auto observed = VerifyObservedClientKeyPackage(
			object,
			conversationId,
			group.telegramPeerIdBinding,
			state->generation(),
			std::uint64_t(base::unixtime::now()),
			group.envelopeCodec,
			_sha256);
		if (!observed.verified) {
			continue;
		}
		const auto &candidate = *observed.verified;
		const auto targetAccountId = candidate.envelope.senderAccountId;
		const auto targetClientId = candidate.envelope.senderClientId;
		const auto existingMember = state->member(targetAccountId);
		if (state->memberByClient(targetClientId)
			|| (existingMember
				&& existingMember->telegramUserIdBinding
					!= candidate.telegramUserIdBinding)
			|| (!existingMember
				&& state->memberByTelegramUserId(
					candidate.telegramUserIdBinding))) {
			continue;
		}
		if (state->generation()
			== std::numeric_limits<std::uint64_t>::max()) {
			_vaultState = DesktopVaultState::SecurityBlocked;
			_groupCreationState = DesktopGroupCreationState::LocalFailure;
			return false;
		}
		const auto transitionId = RandomId<ObjectId>();
		const auto commitObjectId = RandomId<ObjectId>();
		const auto distributionObjectId = RandomId<ObjectId>();
		const auto welcomeObjectId = RandomId<ObjectId>();
		const auto historyGrantObjectId = RandomId<ObjectId>();
		const auto nextArchiveKey = ArchiveEpochCrypto().generateKey();
		if (!transitionId
			|| !commitObjectId
			|| !distributionObjectId
			|| !welcomeObjectId
			|| !historyGrantObjectId
			|| !nextArchiveKey) {
			return false;
		}
		const auto historyAccess = existingMember
			? existingMember->historyAccess
			: state->policy().defaultHistoryAccess;
		const auto transition = GroupTransition{
			.conversationId = conversationId,
			.transitionId = *transitionId,
			.previousGeneration = state->generation(),
			.generation = state->generation() + 1,
			.kind = existingMember
				? GroupTransitionKind::AddClient
				: GroupTransitionKind::AddMember,
			.targetAccountId = targetAccountId,
			.targetClientId = targetClientId,
			.targetTelegramUserIdBinding = candidate.telegramUserIdBinding,
			.targetRole = GroupRole::Member,
			.targetAdminPermissions = 0,
			.historyAccess = historyAccess,
		};
		auto prepared = PrepareOpenMlsAdmission({
			.actor = {
				.conversationId = conversationId,
				.accountId = *actorAccountId,
				.clientId = metadata->clientId,
				.telegramPeerIdBinding = group.telegramPeerIdBinding,
			},
			.currentGroupState = state,
			.currentCheckpoint = group.groupLedger.checkpoint(),
			.transition = transition,
			.actorCredential = &_vault->identity.credential,
			.actorSigningPrivateKey = &_vault->identity.signingPrivateKey,
			.targetCredential = &candidate.publication.accountCredential,
			.targetClientAuthorization =
				&candidate.publication.authorization,
			.targetKeyPackage = candidate.publication.keyPackage,
			.nextArchiveKey = &*nextArchiveKey,
			.mlsCommitObjectId = *commitObjectId,
			.archiveDistributionObjectId = *distributionObjectId,
			.welcomeObjectId = *welcomeObjectId,
		},
		OpenMlsBridge(),
		MlsContextCodecV1(),
		MlsRosterCodecV1(),
		GroupControlCodecV1(),
		group.envelopeCodec,
		_sha256,
		group.mlsState,
		group.archiveState,
		group.groupLedger);
		if (!prepared.prepared) {
			continue;
		}
		auto &preparedChange = *prepared.prepared;
		auto grant = preparedChange.transaction.archiveEpoch
			? CreateAdmissionHistoryGrant({
				.grant = {
					.conversationId = conversationId,
					.grantId = *historyGrantObjectId,
					.issuerAccountId = *actorAccountId,
					.issuerClientId = metadata->clientId,
					.recipientAccountId = targetAccountId,
					.telegramPeerIdBinding =
						group.telegramPeerIdBinding,
					.groupGeneration = transition.generation,
					.historyAccess = historyAccess,
					.issuerSigningPrivateKey =
						&_vault->identity.signingPrivateKey,
				},
				.signedTransition =
					&preparedChange.transaction.signedTransition,
				.applied = &preparedChange.applied,
				.admittedCredential =
					&candidate.publication.accountCredential,
				.archiveEpoch = &*preparedChange.transaction.archiveEpoch,
			},
			group.groupLedger,
			group.archiveState,
			_sha256,
			OpenMlsBridge())
			: CreateAuthorizedHistoryGrantOutcome();
		const auto grantPayload = grant.grant
			? EncryptedHistoryGrantCodecV1().encode(*grant.grant)
			: std::nullopt;
		const auto grantEnvelope = (grant.grant && grantPayload)
			? group.envelopeCodec.encode({
				.conversationId = conversationId,
				.objectKind = ObjectKind::HistoryGrant,
				.senderAccountId = *actorAccountId,
				.senderClientId = metadata->clientId,
				.telegramPeerIdBinding = group.telegramPeerIdBinding,
				.epochOrGeneration = transition.generation,
				.objectId = *historyGrantObjectId,
				.payloadHash = _sha256.digest(*grantPayload),
				.payload = *grantPayload,
				.authenticationData = QByteArray(
					reinterpret_cast<const char*>(
						grant.grant->signature.data()),
					int(grant.grant->signature.size())),
			})
			: std::nullopt;
		if (!grantEnvelope) {
			_groupCreationState = DesktopGroupCreationState::LocalFailure;
			return false;
		}
		preparedChange.transaction.outboxEnvelopes.push_back(
			*grantEnvelope);
		auto coordinator = GroupChangeTransactionCoordinator(
			group.changeJournal,
			group.mlsState,
			group.archiveState,
			group.groupLedger,
			group.outbox,
			_sha256);
		if (coordinator.apply(std::move(
				preparedChange.transaction))
				!= GroupChangeApplyStatus::Applied) {
			_groupCreationState = DesktopGroupCreationState::LocalFailure;
			return false;
		}
		group.conversation.checkpoint = group.groupLedger.checkpoint();
		_pendingGroupCreation = std::move(i->second);
		_groups.erase(i);
		_pendingGroupCreation->vaultPreflightRequired = true;
		_groupCreationState = DesktopGroupCreationState::UpdatingVault;
		beginGroupVaultPreflight();
		return true;
	}
	return false;
}

DesktopService::LocalGroupRecoveryResult DesktopService::restoreLocalGroup(
		ConversationId conversationId,
		const CloudVaultConversation *indexedConversation) {
	auto localRecordKey = DeriveConversationLocalRecordKey(
		_vault->masterKey,
		_telegramUserIdBinding,
		conversationId);
	if (!localRecordKey) {
		return LocalGroupRecoveryResult::Invalid;
	}
	const auto directory = ConversationDirectory(
		_telegramUserIdBinding,
		conversationId);
	auto metadataBlob = FileAtomicBlobStore(
		directory + u"conversation.meta"_q);
	auto metadataProtector = AesGcmLocalRecordProtector(
		std::move(*localRecordKey));
	auto metadata = PersistentConversationMetadata(
		metadataBlob,
		metadataProtector);
	const auto metadataLoad = metadata.load(conversationId);
	if (metadataLoad == ConversationMetadataLoadResult::Missing) {
		return LocalGroupRecoveryResult::Missing;
	} else if (metadataLoad != ConversationMetadataLoadResult::Loaded
		|| !metadata.metadata()) {
		return LocalGroupRecoveryResult::Invalid;
	}
	const auto accountId = DeriveAccountId(
		_vault->identity.credential,
		_sha256);
	const auto &localMetadata = *metadata.metadata();
	if (!accountId
		|| localMetadata.accountId != *accountId
		|| !IsProtectedGroupPeerBinding(
			_session,
			localMetadata.telegramPeerIdBinding)
		|| (indexedConversation
			&& indexedConversation->telegramPeerIdBinding
				!= localMetadata.telegramPeerIdBinding)) {
		return LocalGroupRecoveryResult::Invalid;
	}
	auto operationKey = DeriveConversationLocalRecordKey(
		_vault->masterKey,
		_telegramUserIdBinding,
		conversationId);
	if (!operationKey) {
		return LocalGroupRecoveryResult::Invalid;
	}
	auto operation = std::make_unique<PendingGroupCreation>(
		directory,
		std::move(*operationKey),
		_session,
		localMetadata.telegramPeerIdBinding,
		conversationId,
		_sha256);
	const auto metadataReload = operation->metadata.load(conversationId);
	const auto journalLoad = operation->journal.load(conversationId);
	const auto mlsLoad = operation->mlsState.load(conversationId);
	const auto archiveLoad = operation->archiveState.load(conversationId);
	const auto groupLoad = operation->groupLedger.load(conversationId);
	const auto outboxLoad = operation->outbox.load();
	const auto changeJournalLoad = operation->changeJournal.load(
		conversationId);
	const auto keyPackageLoad = operation->keyPackages.load(
		conversationId,
		localMetadata.telegramPeerIdBinding);
	const auto freshnessTrustLoad = operation->freshnessTrust.load(
		conversationId);
	const auto inboundJournalLoad = operation->inboundJournal.load();
	const auto controlInboundJournalLoad = operation->controlInboundJournal.load();
	const auto contentStoreLoad = operation->contentStore.load();
	const auto controlSyncLoad = operation->controlSyncState.load(
		conversationId);
	const auto contentSyncLoad = operation->contentSyncState.load(
		conversationId);
	const auto fileTransferLoad = operation->fileTransfer.load(
		conversationId);
	if (metadataReload != ConversationMetadataLoadResult::Loaded
		|| journalLoad == GroupBootstrapJournalLoadResult::StorageError
		|| journalLoad
			== GroupBootstrapJournalLoadResult::AuthenticationFailed
		|| journalLoad == GroupBootstrapJournalLoadResult::InvalidSnapshot
		|| mlsLoad == MlsStateLoadResult::StorageError
		|| mlsLoad == MlsStateLoadResult::AuthenticationFailed
		|| mlsLoad == MlsStateLoadResult::InvalidSnapshot
		|| archiveLoad == ArchiveStateLoadResult::StorageError
		|| archiveLoad == ArchiveStateLoadResult::AuthenticationFailed
		|| archiveLoad == ArchiveStateLoadResult::InvalidSnapshot
		|| groupLoad == GroupLedgerLoadResult::StorageError
		|| groupLoad == GroupLedgerLoadResult::AuthenticationFailed
		|| groupLoad == GroupLedgerLoadResult::InvalidSnapshot
		|| outboxLoad == PersistentOutboxLoadResult::StorageError
		|| outboxLoad == PersistentOutboxLoadResult::AuthenticationFailed
		|| outboxLoad == PersistentOutboxLoadResult::InvalidSnapshot
		|| changeJournalLoad == GroupChangeJournalLoadResult::StorageError
		|| changeJournalLoad
			== GroupChangeJournalLoadResult::AuthenticationFailed
		|| changeJournalLoad == GroupChangeJournalLoadResult::InvalidSnapshot
		|| keyPackageLoad == KeyPackagePoolLoadResult::StorageError
		|| keyPackageLoad == KeyPackagePoolLoadResult::AuthenticationFailed
		|| keyPackageLoad == KeyPackagePoolLoadResult::InvalidSnapshot
		|| freshnessTrustLoad == FreshnessTrustLoadResult::StorageError
		|| freshnessTrustLoad
			== FreshnessTrustLoadResult::AuthenticationFailed
		|| freshnessTrustLoad == FreshnessTrustLoadResult::InvalidSnapshot) {
		return LocalGroupRecoveryResult::Invalid;
	}
	if (inboundJournalLoad == InboundJournalLoadResult::ReadFailed
		|| inboundJournalLoad
			== InboundJournalLoadResult::AuthenticationFailed
		|| inboundJournalLoad == InboundJournalLoadResult::InvalidSnapshot
		|| controlInboundJournalLoad == InboundJournalLoadResult::ReadFailed
		|| controlInboundJournalLoad
			== InboundJournalLoadResult::AuthenticationFailed
		|| controlInboundJournalLoad
			== InboundJournalLoadResult::InvalidSnapshot
		|| contentStoreLoad == ContentStoreLoadResult::ReadFailed
		|| contentStoreLoad == ContentStoreLoadResult::AuthenticationFailed
		|| contentStoreLoad == ContentStoreLoadResult::InvalidSnapshot
		|| controlSyncLoad == ContentSyncStateLoadResult::ReadFailed
		|| controlSyncLoad
			== ContentSyncStateLoadResult::AuthenticationFailed
		|| controlSyncLoad == ContentSyncStateLoadResult::InvalidSnapshot
		|| contentSyncLoad == ContentSyncStateLoadResult::ReadFailed
		|| contentSyncLoad
			== ContentSyncStateLoadResult::AuthenticationFailed
		|| contentSyncLoad == ContentSyncStateLoadResult::InvalidSnapshot) {
		return LocalGroupRecoveryResult::Invalid;
	}
	if (fileTransferLoad == FileTransferLoadResult::ReadFailed
		|| fileTransferLoad == FileTransferLoadResult::AuthenticationFailed
		|| fileTransferLoad == FileTransferLoadResult::InvalidSnapshot) {
		return LocalGroupRecoveryResult::Invalid;
	}
	if (journalLoad == GroupBootstrapJournalLoadResult::Pending) {
		const auto envelopeCodec = EnvelopeCodecV1();
		auto coordinator = GroupBootstrapTransactionCoordinator(
			operation->journal,
			operation->mlsState,
			operation->archiveState,
			operation->groupLedger,
			operation->outbox,
			envelopeCodec,
			_sha256);
		if (coordinator.recover() != GroupBootstrapApplyStatus::Recovered) {
			return LocalGroupRecoveryResult::Invalid;
		}
	}
	if (changeJournalLoad == GroupChangeJournalLoadResult::Pending) {
		auto coordinator = GroupChangeTransactionCoordinator(
			operation->changeJournal,
			operation->mlsState,
			operation->archiveState,
			operation->groupLedger,
			operation->outbox,
			_sha256);
		if (coordinator.recover() != GroupChangeApplyStatus::Recovered) {
			return LocalGroupRecoveryResult::Invalid;
		}
	}
	const auto receiptReconciliation = ReconcileMlsOutboxReceipts(
		operation->mlsState,
		operation->outbox,
		operation->envelopeCodec,
		operation->inboundJournal);
	if (receiptReconciliation != MlsReceiptReconcileResult::Reconciled
		&& receiptReconciliation != MlsReceiptReconcileResult::NothingToDo) {
		return LocalGroupRecoveryResult::Invalid;
	}
	const auto state = operation->groupLedger.state();
	const auto localMember = state ? state->member(*accountId) : nullptr;
	const auto activeClient = localMember && std::find(
		begin(localMember->clients),
		end(localMember->clients),
		localMetadata.clientId) != end(localMember->clients);
	const auto removed = operation->mlsState.removed()
		&& operation->mlsState.removalTombstone()
		&& !activeClient;
	const auto awaitingAdmission = !activeClient
		&& !removed
		&& !operation->mlsState.revision()
		&& !operation->archiveState.revision()
		&& !operation->keyPackages.entries().empty();
	if (freshnessTrustLoad == FreshnessTrustLoadResult::Missing) {
		const auto localIsGenesisOwner = state
			&& state->generation() == 1
			&& localMember
			&& localMember->role == GroupRole::Owner
			&& activeClient;
		if (operation->freshnessTrust.initialize(localIsGenesisOwner)
				!= FreshnessTrustCommitResult::Committed) {
			return LocalGroupRecoveryResult::Invalid;
		}
	}
	if (!state
		|| !operation->mlsState.loaded()
		|| (awaitingAdmission
			? archiveLoad != ArchiveStateLoadResult::Missing
			: !operation->archiveState.loaded())
		|| !operation->groupLedger.loaded()
		|| !operation->groupLedger.revision()
		|| !operation->outbox.loaded()
		|| (!awaitingAdmission
			&& ((!activeClient && !removed)
				|| !operation->mlsState.revision()
				|| !operation->archiveState.revision()))) {
		return LocalGroupRecoveryResult::Invalid;
	}
	const auto owner = std::find_if(
		begin(state->members()),
		end(state->members()),
		[](const GroupMember &member) {
			return member.role == GroupRole::Owner;
		});
	if (owner == end(state->members())) {
		return LocalGroupRecoveryResult::Invalid;
	}
	const auto localConversation = CloudVaultConversation{
		.conversationId = conversationId,
		.telegramPeerIdBinding = localMetadata.telegramPeerIdBinding,
		.checkpoint = operation->groupLedger.checkpoint(),
		.ownerAccountId = owner->accountId,
	};
	if (awaitingAdmission) {
		operation->phase = PendingGroupCreation::Phase::AwaitingAdmission;
	} else if (removed) {
		operation->phase = PendingGroupCreation::Phase::Removed;
	} else {
		operation->phase = PendingGroupCreation::Phase::Active;
	}
	operation->freshnessGate = std::make_unique<FreshnessGate>(
		operation->groupLedger.checkpoint(),
		operation->freshnessTrust.trusted() && !removed);
	const auto localAhead = indexedConversation
		&& indexedConversation->conversationId
			== localConversation.conversationId
		&& indexedConversation->telegramPeerIdBinding
			== localConversation.telegramPeerIdBinding
		&& indexedConversation->ownerAccountId
			== localConversation.ownerAccountId
		&& indexedConversation->checkpoint.generation
			< localConversation.checkpoint.generation;
	if (indexedConversation
		&& *indexedConversation != localConversation
		&& !localAhead) {
		return LocalGroupRecoveryResult::Invalid;
	} else if (indexedConversation
		&& !localAhead
		&& operation->phase == PendingGroupCreation::Phase::Active) {
		operation->conversation = *indexedConversation;
		_groups[conversationId] = std::move(operation);
		if (!initializeActivePipeline(*_groups[conversationId])) {
			_groups.erase(conversationId);
			return LocalGroupRecoveryResult::Invalid;
		}
		beginGroupObservation(conversationId);
		beginContentObservation(conversationId);
		pumpActiveOutbox(conversationId);
		return LocalGroupRecoveryResult::Complete;
	} else if (!operation->outbox.size()) {
		if (!indexedConversation || localAhead) {
			return LocalGroupRecoveryResult::Invalid;
		}
		operation->conversation = *indexedConversation;
		if (!awaitingAdmission && !operation->freshnessTrust.trusted()) {
			operation->vaultPreflightRequired = false;
			_pendingGroupCreation = std::move(operation);
			return LocalGroupRecoveryResult::Restored;
		}
		_groups[conversationId] = std::move(operation);
		if (!awaitingAdmission
			&& !removed
			&& !initializeActivePipeline(*_groups[conversationId])) {
			_groups.erase(conversationId);
			return LocalGroupRecoveryResult::Invalid;
		}
		if (awaitingAdmission) {
			_groupCreationState = DesktopGroupCreationState::AwaitingAdmission;
		}
		beginGroupObservation(conversationId);
		if (!awaitingAdmission) {
			beginContentObservation(conversationId);
		}
		return LocalGroupRecoveryResult::Complete;
	}
	operation->conversation = (indexedConversation && !localAhead)
		? *indexedConversation
		: localConversation;
	operation->vaultPreflightRequired = !indexedConversation || localAhead;
	_pendingGroupCreation = std::move(operation);
	return LocalGroupRecoveryResult::Restored;
}

bool DesktopService::commitVaultAnchor(const UnlockedCloudVault &vault) {
	const auto accountId = DeriveAccountId(
		vault.identity.credential,
		_sha256);
	if (!accountId) {
		return false;
	}
	const auto result = _vaultAnchor.commit({
		.generation = vault.generation,
		.blobDigest = vault.blobDigest,
		.accountId = *accountId,
	});
	return result == CloudVaultAnchorCommitResult::Committed
		|| result == CloudVaultAnchorCommitResult::AlreadyCommitted;
}

bool DesktopService::commitVaultAnchor(
		const PreparedCloudVaultUpdate &update,
		const AccountPrivateIdentity &identity) {
	const auto accountId = DeriveAccountId(identity.credential, _sha256);
	if (!accountId) {
		return false;
	}
	const auto result = _vaultAnchor.commit({
		.generation = update.generation,
		.blobDigest = update.blobDigest,
		.accountId = *accountId,
	});
	return result == CloudVaultAnchorCommitResult::Committed
		|| result == CloudVaultAnchorCommitResult::AlreadyCommitted;
}

} // namespace E2ECloud

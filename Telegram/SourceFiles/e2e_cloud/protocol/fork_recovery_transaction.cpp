/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "e2e_cloud/protocol/fork_recovery_transaction.h"

#include <openssl/crypto.h>

#include <algorithm>
#include <array>
#include <limits>
#include <set>
#include <utility>

namespace E2ECloud {
namespace {

inline constexpr auto kMagic = std::array<std::uint8_t, 8>{
	'T', 'D', 'E', '2', 'E', 'F', 'T', 'X',
};
inline constexpr auto kPurpose = "TDE2E/local-fork-recovery-transaction/v1";
inline constexpr auto kMaximumMlsStateSize = 64 * 1024 * 1024;
inline constexpr auto kMaximumEnvelopeSize = 18 * 1024 * 1024;
inline constexpr auto kMaximumOutboxEnvelopes = 8;
inline constexpr auto kMaximumSnapshotSize = 256 * 1024 * 1024;

struct Reader {
	const QByteArray &bytes;
	int offset = 0;
};

struct DecodedSnapshot {
	std::uint64_t revision = 0;
	std::optional<ForkRecoveryTransaction> transaction;
};

void AppendUint8(QByteArray &result, std::uint8_t value) {
	result.append(char(value));
}

void AppendUint16(QByteArray &result, std::uint16_t value) {
	result.append(char(value >> 8));
	result.append(char(value));
}

void AppendUint32(QByteArray &result, std::uint32_t value) {
	result.append(char(value >> 24));
	result.append(char(value >> 16));
	result.append(char(value >> 8));
	result.append(char(value));
}

void AppendUint64(QByteArray &result, std::uint64_t value) {
	for (auto shift = 56; shift >= 0; shift -= 8) {
		result.append(char(value >> shift));
	}
}

template <typename Array>
void AppendArray(QByteArray &result, const Array &value) {
	result.append(
		reinterpret_cast<const char*>(value.data()),
		int(value.size()));
}

void AppendBytes(QByteArray &result, const QByteArray &value) {
	AppendUint32(result, std::uint32_t(value.size()));
	result.append(value);
}

[[nodiscard]] bool ReadUint8(Reader &reader, std::uint8_t &value) {
	if (reader.offset == reader.bytes.size()) {
		return false;
	}
	value = std::uint8_t(reader.bytes[reader.offset++]);
	return true;
}

[[nodiscard]] bool ReadUint16(Reader &reader, std::uint16_t &value) {
	if (reader.bytes.size() - reader.offset < 2) {
		return false;
	}
	const auto data = reinterpret_cast<const std::uint8_t*>(
		reader.bytes.constData() + reader.offset);
	value = (std::uint16_t(data[0]) << 8) | std::uint16_t(data[1]);
	reader.offset += 2;
	return true;
}

[[nodiscard]] bool ReadUint32(Reader &reader, std::uint32_t &value) {
	if (reader.bytes.size() - reader.offset < 4) {
		return false;
	}
	const auto data = reinterpret_cast<const std::uint8_t*>(
		reader.bytes.constData() + reader.offset);
	value = (std::uint32_t(data[0]) << 24)
		| (std::uint32_t(data[1]) << 16)
		| (std::uint32_t(data[2]) << 8)
		| std::uint32_t(data[3]);
	reader.offset += 4;
	return true;
}

[[nodiscard]] bool ReadUint64(Reader &reader, std::uint64_t &value) {
	if (reader.bytes.size() - reader.offset < 8) {
		return false;
	}
	const auto data = reinterpret_cast<const std::uint8_t*>(
		reader.bytes.constData() + reader.offset);
	value = 0;
	for (auto i = 0; i != 8; ++i) {
		value = (value << 8) | std::uint64_t(data[i]);
	}
	reader.offset += 8;
	return true;
}

template <typename Array>
[[nodiscard]] bool ReadArray(Reader &reader, Array &value) {
	const auto size = int(value.size());
	if (reader.bytes.size() - reader.offset < size) {
		return false;
	}
	std::copy_n(
		reinterpret_cast<const std::uint8_t*>(
			reader.bytes.constData() + reader.offset),
		size,
		value.data());
	reader.offset += size;
	return true;
}

[[nodiscard]] bool ReadBytes(
		Reader &reader,
		int maximumSize,
		QByteArray &value) {
	auto size = std::uint32_t();
	if (!ReadUint32(reader, size)
		|| size > std::uint32_t(maximumSize)
		|| reader.bytes.size() - reader.offset < int(size)) {
		return false;
	}
	value = QByteArray(reader.bytes.constData() + reader.offset, int(size));
	reader.offset += int(size);
	return true;
}

void Cleanse(ForkRecoveryTransaction &transaction) {
	for (auto bytes : {
			&transaction.canonicalTargetKeyPackage,
			&transaction.canonicalMlsCommit,
			&transaction.canonicalArchiveDistribution,
		}) {
		if (!bytes->isEmpty()) {
			OPENSSL_cleanse(bytes->data(), bytes->size());
		}
		bytes->clear();
	}
	if (!transaction.nextMlsEngineState.isEmpty()) {
		OPENSSL_cleanse(
			transaction.nextMlsEngineState.data(),
			transaction.nextMlsEngineState.size());
	}
	transaction.nextMlsEngineState.clear();
}

[[nodiscard]] bool SameEpoch(
		const ArchiveEpochSecret &a,
		const ArchiveEpochSecret &b) {
	return a.generation == b.generation
		&& a.activationGroupGeneration == b.activationGroupGeneration
		&& a.activationEventId == b.activationEventId
		&& a.key.bytes() == b.key.bytes();
}

[[nodiscard]] bool ValidEnvelope(
		ConversationId conversationId,
		const EncodedEnvelope &envelope) {
	return envelope.conversationId == conversationId
		&& envelope.objectId
		&& !envelope.bytes.isEmpty()
		&& envelope.bytes.size() <= kMaximumEnvelopeSize;
}

[[nodiscard]] bool ValidTransaction(
		const ForkRecoveryTransaction &transaction) {
	const auto manifest = SignedForkRecoveryManifestCodecV1().encode(
		transaction.manifest);
	const auto canonicalTransition = transaction.canonicalTransition
		? SignedGroupTransitionCodecV1().encode(
			*transaction.canonicalTransition)
		: std::nullopt;
	const auto canonicalCredential = transaction.canonicalTargetCredential
		? AccountCredentialCodecV1().encode(
			*transaction.canonicalTargetCredential)
		: std::nullopt;
	const auto outbound = transaction.direction
		== ForkRecoveryTransactionDirection::Outbound;
	const auto inbound = transaction.direction
		== ForkRecoveryTransactionDirection::Inbound;
	if (!transaction.conversationId
		|| !transaction.transactionId
		|| transaction.transactionId != transaction.manifest.recoveryId
		|| (!outbound && !inbound)
		|| transaction.manifest.conversationId != transaction.conversationId
		|| !transaction.groupBaseRevision
		|| !transaction.archiveBaseRevision
		|| !transaction.mlsBaseRevision
		|| transaction.groupBaseRevision
			== std::numeric_limits<std::uint64_t>::max()
		|| transaction.archiveBaseRevision
			== std::numeric_limits<std::uint64_t>::max()
		|| transaction.mlsBaseRevision
			== std::numeric_limits<std::uint64_t>::max()
		|| transaction.forkLedgerBaseRevision
			== std::numeric_limits<std::uint64_t>::max()
		|| transaction.keyPackagePoolBaseRevision
			== std::numeric_limits<std::uint64_t>::max()
		|| !manifest
		|| (inbound != transaction.canonicalTransition.has_value())
		|| (inbound && !canonicalTransition)
		|| (transaction.canonicalTargetCredential
			&& !canonicalCredential)
		|| transaction.canonicalTargetKeyPackage.size()
			> kMaximumMlsStateSize
		|| transaction.canonicalMlsCommit.size()
			> kMaximumMlsStateSize
		|| transaction.canonicalArchiveDistribution.size()
			> kMaximumMlsStateSize
		|| (inbound
			&& (!transaction.consumedKeyPackageHash
				|| !transaction.keyPackagePoolBaseRevision
				|| transaction.canonicalMlsCommit.isEmpty()
				|| transaction.canonicalArchiveDistribution.isEmpty()))
		|| (outbound
			&& (transaction.canonicalTargetCredential
				|| !transaction.canonicalTargetKeyPackage.isEmpty()
				|| !transaction.canonicalMlsCommit.isEmpty()
				|| !transaction.canonicalArchiveDistribution.isEmpty()
				|| transaction.consumedKeyPackageHash
				|| transaction.keyPackagePoolBaseRevision))
		|| transaction.archiveEpoch.generation
			!= transaction.manifest.recoveryGeneration
		|| transaction.archiveEpoch.activationGroupGeneration
			!= transaction.manifest.recoveryGeneration
		|| transaction.archiveEpoch.activationEventId
			!= transaction.transactionId
		|| !transaction.archiveEpoch.key.valid()
		|| transaction.nextMlsEngineState.isEmpty()
		|| transaction.nextMlsEngineState.size() > kMaximumMlsStateSize
		|| (outbound != !transaction.outboxEnvelopes.empty())
		|| (outbound && transaction.outboxEnvelopes.size() != 4)
		|| transaction.outboxEnvelopes.size()
			> kMaximumOutboxEnvelopes) {
		return false;
	}
	auto objectIds = std::set<ObjectId>();
	for (const auto &envelope : transaction.outboxEnvelopes) {
		if (!ValidEnvelope(transaction.conversationId, envelope)
			|| !objectIds.emplace(envelope.objectId).second) {
			return false;
		}
	}
	return inbound || (objectIds.contains(transaction.manifest.recoveryId)
		&& objectIds.contains(transaction.manifest.recoveryCommitObjectId)
		&& objectIds.contains(transaction.manifest.recoveryWelcomeObjectId)
		&& objectIds.contains(
			transaction.manifest.archiveDistributionObjectId));
}

[[nodiscard]] QByteArray Purpose(ConversationId conversationId) {
	auto result = QByteArray(kPurpose);
	result.append('/');
	AppendArray(result, conversationId.bytes);
	return result;
}

[[nodiscard]] std::optional<QByteArray> EncodeSnapshot(
		ConversationId conversationId,
		std::uint64_t revision,
		const ForkRecoveryTransaction *transaction) {
	if (!conversationId
		|| !revision
		|| (transaction
			&& (transaction->conversationId != conversationId
				|| !ValidTransaction(*transaction)))) {
		return std::nullopt;
	}
	auto result = QByteArray();
	AppendArray(result, kMagic);
	AppendUint16(result, 2);
	AppendArray(result, conversationId.bytes);
	AppendUint64(result, revision);
	AppendUint8(result, transaction ? 1 : 0);
	if (!transaction) {
		return result;
	}
	const auto manifest = SignedForkRecoveryManifestCodecV1().encode(
		transaction->manifest);
	AppendArray(result, transaction->transactionId.bytes);
	AppendUint8(result, std::uint8_t(transaction->direction));
	AppendUint64(result, transaction->groupBaseRevision);
	AppendUint64(result, transaction->archiveBaseRevision);
	AppendUint64(result, transaction->mlsBaseRevision);
	AppendUint64(result, transaction->forkLedgerBaseRevision);
	AppendUint64(result, transaction->keyPackagePoolBaseRevision);
	AppendBytes(result, *manifest);
	AppendUint8(result, transaction->canonicalTransition ? 1 : 0);
	if (transaction->canonicalTransition) {
		result.append(*SignedGroupTransitionCodecV1().encode(
			*transaction->canonicalTransition));
	} else {
		auto zero = QByteArray();
		zero.resize(kSignedGroupTransitionEncodedSize);
		std::fill_n(zero.data(), zero.size(), char(0));
		result.append(zero);
	}
	AppendUint8(result, transaction->canonicalTargetCredential ? 1 : 0);
	if (transaction->canonicalTargetCredential) {
		result.append(*AccountCredentialCodecV1().encode(
			*transaction->canonicalTargetCredential));
	} else {
		auto zero = QByteArray();
		zero.resize(kAccountCredentialEncodedSize);
		std::fill_n(zero.data(), zero.size(), char(0));
		result.append(zero);
	}
	AppendBytes(result, transaction->canonicalTargetKeyPackage);
	AppendBytes(result, transaction->canonicalMlsCommit);
	AppendBytes(result, transaction->canonicalArchiveDistribution);
	AppendUint8(result, transaction->consumedKeyPackageHash ? 1 : 0);
	if (transaction->consumedKeyPackageHash) {
		AppendArray(result, transaction->consumedKeyPackageHash->bytes);
	} else {
		auto zero = std::array<std::uint8_t, 32>();
		AppendArray(result, zero);
	}
	AppendArray(result, transaction->archiveEpoch.key.bytes());
	AppendBytes(result, transaction->nextMlsEngineState);
	AppendUint16(result, std::uint16_t(transaction->outboxEnvelopes.size()));
	for (const auto &envelope : transaction->outboxEnvelopes) {
		AppendArray(result, envelope.conversationId.bytes);
		AppendArray(result, envelope.objectId.bytes);
		AppendBytes(result, envelope.bytes);
	}
	return result.size() <= kMaximumSnapshotSize
		? std::optional<QByteArray>(std::move(result))
		: std::nullopt;
}

[[nodiscard]] std::optional<DecodedSnapshot> DecodeSnapshot(
		const QByteArray &bytes) {
	if (bytes.size() < 8 + 2 + 32 + 8 + 1
		|| bytes.size() > kMaximumSnapshotSize) {
		return std::nullopt;
	}
	auto reader = Reader{ bytes };
	auto magic = std::array<std::uint8_t, 8>();
	auto version = std::uint16_t();
	auto conversationId = ConversationId();
	auto present = std::uint8_t();
	auto result = DecodedSnapshot();
	if (!ReadArray(reader, magic)
		|| !ReadUint16(reader, version)
		|| !ReadArray(reader, conversationId.bytes)
		|| !ReadUint64(reader, result.revision)
		|| !ReadUint8(reader, present)
		|| magic != kMagic
		|| version != 2
		|| !conversationId
		|| !result.revision
		|| present > 1) {
		return std::nullopt;
	} else if (!present) {
		return reader.offset == bytes.size()
			? std::optional<DecodedSnapshot>(std::move(result))
			: std::nullopt;
	}
	auto transaction = ForkRecoveryTransaction();
	transaction.conversationId = conversationId;
	auto direction = std::uint8_t();
	auto manifestBytes = QByteArray();
	auto canonicalPresent = std::uint8_t();
	auto canonicalBytes = QByteArray();
	auto credentialPresent = std::uint8_t();
	auto credentialBytes = QByteArray();
	auto consumedPresent = std::uint8_t();
	auto consumedHash = Digest();
	auto archiveKey = std::array<std::uint8_t, kArchiveKeySize>();
	auto outboxCount = std::uint16_t();
	if (!ReadArray(reader, transaction.transactionId.bytes)
		|| !ReadUint8(reader, direction)
		|| (direction
			!= std::uint8_t(ForkRecoveryTransactionDirection::Outbound)
			&& direction
				!= std::uint8_t(ForkRecoveryTransactionDirection::Inbound))
		|| !ReadUint64(reader, transaction.groupBaseRevision)
		|| !ReadUint64(reader, transaction.archiveBaseRevision)
		|| !ReadUint64(reader, transaction.mlsBaseRevision)
		|| !ReadUint64(reader, transaction.forkLedgerBaseRevision)
		|| !ReadUint64(reader, transaction.keyPackagePoolBaseRevision)
		|| !ReadBytes(
			reader,
			kMaximumForkRecoveryManifestSize,
			manifestBytes)) {
		return std::nullopt;
	}
	transaction.direction = ForkRecoveryTransactionDirection(direction);
	const auto manifest = SignedForkRecoveryManifestCodecV1().decode(
		manifestBytes);
	if (!manifest
		|| !ReadUint8(reader, canonicalPresent)
		|| canonicalPresent > 1
		|| reader.bytes.size() - reader.offset
			< kSignedGroupTransitionEncodedSize) {
		return std::nullopt;
	}
	canonicalBytes = QByteArray(
		reader.bytes.constData() + reader.offset,
		kSignedGroupTransitionEncodedSize);
	reader.offset += kSignedGroupTransitionEncodedSize;
	if (canonicalPresent) {
		transaction.canonicalTransition =
			SignedGroupTransitionCodecV1().decode(canonicalBytes);
		if (!transaction.canonicalTransition) {
			return std::nullopt;
		}
	} else if (std::any_of(
		canonicalBytes.constData(),
		canonicalBytes.constData() + canonicalBytes.size(),
		[](char value) { return value != 0; })) {
		return std::nullopt;
	}
	if (!ReadUint8(reader, credentialPresent)
		|| credentialPresent > 1
		|| reader.bytes.size() - reader.offset
			< kAccountCredentialEncodedSize) {
		return std::nullopt;
	}
	credentialBytes = QByteArray(
		reader.bytes.constData() + reader.offset,
		kAccountCredentialEncodedSize);
	reader.offset += kAccountCredentialEncodedSize;
	if (credentialPresent) {
		transaction.canonicalTargetCredential =
			AccountCredentialCodecV1().decode(credentialBytes);
		if (!transaction.canonicalTargetCredential) {
			return std::nullopt;
		}
	} else if (std::any_of(
		credentialBytes.constData(),
		credentialBytes.constData() + credentialBytes.size(),
		[](char value) { return value != 0; })) {
		return std::nullopt;
	}
	if (!ReadBytes(
			reader,
			kMaximumMlsStateSize,
			transaction.canonicalTargetKeyPackage)
		|| !ReadBytes(
			reader,
			kMaximumMlsStateSize,
			transaction.canonicalMlsCommit)
		|| !ReadBytes(
			reader,
			kMaximumMlsStateSize,
			transaction.canonicalArchiveDistribution)
		|| !ReadUint8(reader, consumedPresent)
		|| consumedPresent > 1
		|| !ReadArray(reader, consumedHash.bytes)
		|| !ReadArray(reader, archiveKey)
		|| !ReadBytes(
			reader,
			kMaximumMlsStateSize,
			transaction.nextMlsEngineState)
		|| !ReadUint16(reader, outboxCount)
		|| outboxCount > kMaximumOutboxEnvelopes) {
		OPENSSL_cleanse(archiveKey.data(), archiveKey.size());
		Cleanse(transaction);
		return std::nullopt;
	}
	if (consumedPresent) {
		transaction.consumedKeyPackageHash = consumedHash;
	} else if (consumedHash) {
		OPENSSL_cleanse(archiveKey.data(), archiveKey.size());
		Cleanse(transaction);
		return std::nullopt;
	}
	transaction.manifest = *manifest;
	transaction.archiveEpoch = {
		.generation = manifest->recoveryGeneration,
		.activationGroupGeneration = manifest->recoveryGeneration,
		.activationEventId = manifest->recoveryId,
		.key = ArchiveKey32(std::move(archiveKey)),
	};
	transaction.outboxEnvelopes.reserve(outboxCount);
	for (auto index = std::uint16_t(); index != outboxCount; ++index) {
		auto envelope = EncodedEnvelope();
		if (!ReadArray(reader, envelope.conversationId.bytes)
			|| !ReadArray(reader, envelope.objectId.bytes)
			|| !ReadBytes(reader, kMaximumEnvelopeSize, envelope.bytes)) {
			Cleanse(transaction);
			return std::nullopt;
		}
		transaction.outboxEnvelopes.push_back(std::move(envelope));
	}
	if (reader.offset != bytes.size() || !ValidTransaction(transaction)) {
		Cleanse(transaction);
		return std::nullopt;
	}
	result.transaction = std::move(transaction);
	return result;
}

} // namespace

PersistentForkRecoveryJournal::PersistentForkRecoveryJournal(
		AtomicBlobStore &blobStore,
		const LocalRecordProtector &protector)
: _blobStore(blobStore)
, _protector(protector) {
}

PersistentForkRecoveryJournal::~PersistentForkRecoveryJournal() {
	reset();
}

ForkRecoveryJournalLoadResult PersistentForkRecoveryJournal::load(
		ConversationId conversationId) {
	reset();
	if (!conversationId) {
		return ForkRecoveryJournalLoadResult::InvalidSnapshot;
	}
	_conversationId = conversationId;
	const auto stored = _blobStore.read();
	if (stored.status == BlobReadStatus::Error) {
		return ForkRecoveryJournalLoadResult::StorageError;
	} else if (stored.status == BlobReadStatus::Missing) {
		_loaded = true;
		return ForkRecoveryJournalLoadResult::Empty;
	}
	auto opened = _protector.open(Purpose(conversationId), stored.bytes);
	if (!opened) {
		return ForkRecoveryJournalLoadResult::AuthenticationFailed;
	}
	auto decoded = DecodeSnapshot(*opened);
	OPENSSL_cleanse(opened->data(), opened->size());
	if (!decoded
		|| (decoded->transaction
			&& decoded->transaction->conversationId != conversationId)) {
		return ForkRecoveryJournalLoadResult::InvalidSnapshot;
	}
	_revision = decoded->revision;
	_pending = std::move(decoded->transaction);
	_loaded = true;
	return _pending
		? ForkRecoveryJournalLoadResult::Pending
		: ForkRecoveryJournalLoadResult::Empty;
}

ForkRecoveryJournalCommitResult PersistentForkRecoveryJournal::prepare(
		ForkRecoveryTransaction transaction) {
	if (!_loaded) {
		Cleanse(transaction);
		return ForkRecoveryJournalCommitResult::NotLoaded;
	} else if (transaction.conversationId != _conversationId
		|| !ValidTransaction(transaction)
		|| _revision == std::numeric_limits<std::uint64_t>::max()) {
		Cleanse(transaction);
		return ForkRecoveryJournalCommitResult::InvalidTransaction;
	} else if (_pending) {
		auto current = EncodeSnapshot(_conversationId, 1, &*_pending);
		auto incoming = EncodeSnapshot(_conversationId, 1, &transaction);
		const auto same = current && incoming && *current == *incoming;
		if (current) {
			OPENSSL_cleanse(current->data(), current->size());
		}
		if (incoming) {
			OPENSSL_cleanse(incoming->data(), incoming->size());
		}
		Cleanse(transaction);
		return same
			? ForkRecoveryJournalCommitResult::AlreadyPrepared
			: ForkRecoveryJournalCommitResult::TransactionConflict;
	}
	const auto revision = _revision + 1;
	if (!persist(&transaction, revision)) {
		Cleanse(transaction);
		return ForkRecoveryJournalCommitResult::PersistenceFailed;
	}
	_pending = std::move(transaction);
	_revision = revision;
	return ForkRecoveryJournalCommitResult::Prepared;
}

ForkRecoveryJournalCommitResult PersistentForkRecoveryJournal::clear(
		ObjectId transactionId) {
	if (!_loaded) {
		return ForkRecoveryJournalCommitResult::NotLoaded;
	} else if (!_pending || _pending->transactionId != transactionId) {
		return ForkRecoveryJournalCommitResult::TransactionConflict;
	} else if (_revision == std::numeric_limits<std::uint64_t>::max()) {
		return ForkRecoveryJournalCommitResult::InvalidTransaction;
	}
	const auto revision = _revision + 1;
	if (!persist(nullptr, revision)) {
		return ForkRecoveryJournalCommitResult::PersistenceFailed;
	}
	Cleanse(*_pending);
	_pending.reset();
	_revision = revision;
	return ForkRecoveryJournalCommitResult::Cleared;
}

bool PersistentForkRecoveryJournal::loaded() const {
	return _loaded;
}

std::uint64_t PersistentForkRecoveryJournal::revision() const {
	return _revision;
}

const ForkRecoveryTransaction *PersistentForkRecoveryJournal::pending() const {
	return _pending ? &*_pending : nullptr;
}

bool PersistentForkRecoveryJournal::persist(
		const ForkRecoveryTransaction *transaction,
		std::uint64_t revision) const {
	auto plaintext = EncodeSnapshot(_conversationId, revision, transaction);
	if (!plaintext) {
		return false;
	}
	const auto encrypted = _protector.seal(Purpose(_conversationId), *plaintext);
	OPENSSL_cleanse(plaintext->data(), plaintext->size());
	return encrypted && _blobStore.writeAtomic(*encrypted);
}

void PersistentForkRecoveryJournal::reset() {
	if (_pending) {
		Cleanse(*_pending);
	}
	_pending.reset();
	_conversationId = {};
	_revision = 0;
	_loaded = false;
}

ForkRecoveryTransactionCoordinator::ForkRecoveryTransactionCoordinator(
		PersistentForkRecoveryJournal &journal,
		PersistentMlsStateStore &mlsState,
		PersistentArchiveState &archiveState,
		PersistentGroupLedger &groupLedger,
		PersistentForkRecoveryLedger &forkLedger,
		PersistentOutboxStore &outbox,
		const Sha256Provider &sha256)
: _journal(journal)
, _mlsState(mlsState)
, _archiveState(archiveState)
, _groupLedger(groupLedger)
, _forkLedger(forkLedger)
, _outbox(&outbox)
, _sha256(sha256) {
}

ForkRecoveryTransactionCoordinator::ForkRecoveryTransactionCoordinator(
		PersistentForkRecoveryJournal &journal,
		PersistentMlsStateStore &mlsState,
		PersistentArchiveState &archiveState,
		PersistentGroupLedger &groupLedger,
		PersistentForkRecoveryLedger &forkLedger,
		PersistentKeyPackagePool &keyPackagePool,
		const Sha256Provider &sha256)
: _journal(journal)
, _mlsState(mlsState)
, _archiveState(archiveState)
, _groupLedger(groupLedger)
, _forkLedger(forkLedger)
, _keyPackagePool(&keyPackagePool)
, _sha256(sha256) {
}

ForkRecoveryApplyStatus ForkRecoveryTransactionCoordinator::apply(
		ForkRecoveryTransaction transaction) {
	const auto prepared = _journal.prepare(std::move(transaction));
	if (prepared == ForkRecoveryJournalCommitResult::NotLoaded) {
		return ForkRecoveryApplyStatus::JournalUnavailable;
	} else if (prepared != ForkRecoveryJournalCommitResult::Prepared
		&& prepared != ForkRecoveryJournalCommitResult::AlreadyPrepared) {
		return prepared == ForkRecoveryJournalCommitResult::TransactionConflict
			? ForkRecoveryApplyStatus::RevisionConflict
			: ForkRecoveryApplyStatus::InvalidTransaction;
	}
	return replay(false);
}

ForkRecoveryApplyStatus ForkRecoveryTransactionCoordinator::recover() {
	return replay(true);
}

ForkRecoveryApplyStatus ForkRecoveryTransactionCoordinator::replay(
		bool recovery) {
	const auto transaction = _journal.pending();
	if (!transaction) {
		return ForkRecoveryApplyStatus::NoPendingTransaction;
	}
	const auto inbound = transaction->direction
		== ForkRecoveryTransactionDirection::Inbound;
	const auto outbound = transaction->direction
		== ForkRecoveryTransactionDirection::Outbound;
	if ((!inbound && !outbound)
		|| !_mlsState.loaded()
		|| !_archiveState.loaded()
		|| !_groupLedger.loaded()
		|| !_forkLedger.loaded()
		|| (outbound && (!_outbox || !_outbox->loaded()))
		|| (inbound
			&& (!_keyPackagePool || !_keyPackagePool->loaded()))
		|| _mlsState.conversationId() != transaction->conversationId
		|| _archiveState.conversationId() != transaction->conversationId
		|| !_groupLedger.state()
		|| _groupLedger.state()->conversationId()
			!= transaction->conversationId) {
		return ForkRecoveryApplyStatus::InvalidTransaction;
	}
	const auto mlsApplied = _mlsState.revision()
		== transaction->mlsBaseRevision + 1;
	const auto archiveApplied = _archiveState.revision()
		== transaction->archiveBaseRevision + 1;
	const auto groupApplied = _groupLedger.revision()
		== transaction->groupBaseRevision + 1;
	const auto forkLedgerApplied = _forkLedger.revision()
		== transaction->forkLedgerBaseRevision + 1;
	const auto keyPackagePoolApplied = inbound
		&& _keyPackagePool->revision()
			== transaction->keyPackagePoolBaseRevision + 1;
	if ((!mlsApplied
			&& _mlsState.revision() != transaction->mlsBaseRevision)
		|| (!archiveApplied
			&& _archiveState.revision() != transaction->archiveBaseRevision)
		|| (!groupApplied
			&& _groupLedger.revision() != transaction->groupBaseRevision)
		|| (!forkLedgerApplied
			&& _forkLedger.revision()
				!= transaction->forkLedgerBaseRevision)
		|| (inbound
			&& !keyPackagePoolApplied
			&& _keyPackagePool->revision()
				!= transaction->keyPackagePoolBaseRevision)) {
		return ForkRecoveryApplyStatus::RevisionConflict;
	}
	auto canonicalApplied = std::optional<AppliedSignedGroupTransition>();
	if (inbound && !groupApplied) {
		if (!transaction->canonicalTransition) {
			return ForkRecoveryApplyStatus::InvalidTransaction;
		}
		const auto commonState = _groupLedger.stateAt(
			transaction->manifest.commonGeneration);
		const auto commonCheckpoint = _groupLedger.checkpointAt(
			transaction->manifest.commonGeneration);
		const auto actorCredential = _groupLedger.credential(
			transaction->canonicalTransition->actorAccountId);
		auto verified = commonState && commonCheckpoint
			? VerifyAndApplySignedGroupTransition({
				.currentState = &*commonState,
				.currentCheckpoint = *commonCheckpoint,
				.signedTransition = &*transaction->canonicalTransition,
				.actorCredential = actorCredential,
				.targetCredential = transaction->canonicalTargetCredential
					? &*transaction->canonicalTargetCredential
					: nullptr,
				.mlsCommitObjectId = transaction
					->canonicalTransition->mlsCommitObjectId,
				.mlsCommit = transaction->canonicalMlsCommit,
				.nextArchiveKey = nullptr,
				.archiveDistributionObjectId = transaction
					->canonicalTransition->archiveDistributionObjectId,
				.archiveDistribution = transaction
					->canonicalArchiveDistribution,
				.targetKeyPackage = transaction
					->canonicalTargetKeyPackage,
				.allowMissingArchiveKey = true,
			}, _sha256)
			: VerifySignedGroupTransitionOutcome();
		if (verified.result != SignedGroupTransitionResult::Applied
			|| !verified.applied) {
			return ForkRecoveryApplyStatus::InvalidTransaction;
		}
		canonicalApplied.emplace(std::move(*verified.applied));
	}
	if (!mlsApplied) {
		const auto committed = _mlsState.commit({
			.baseRevision = transaction->mlsBaseRevision,
			.engineState = transaction->nextMlsEngineState,
			.receipt = std::nullopt,
			.inboundApplication = std::nullopt,
			.removalTombstone = std::nullopt,
		});
		if (committed != MlsStateCommitResult::Committed
			&& committed != MlsStateCommitResult::AlreadyCommitted) {
			return committed == MlsStateCommitResult::RevisionConflict
				? ForkRecoveryApplyStatus::RevisionConflict
				: ForkRecoveryApplyStatus::MlsPersistenceFailure;
		}
	} else if (_mlsState.engineState()
			!= transaction->nextMlsEngineState) {
		return ForkRecoveryApplyStatus::InvalidTransaction;
	}
	if (!archiveApplied) {
		auto epoch = ArchiveEpochSecret{
				.generation = transaction->archiveEpoch.generation,
				.activationGroupGeneration = transaction
					->archiveEpoch.activationGroupGeneration,
				.activationEventId = transaction
					->archiveEpoch.activationEventId,
				.key = transaction->archiveEpoch.key.clone(),
			};
		const auto committed = inbound
			? _archiveState.replaceForkEpochWithRecovery(
				transaction->archiveBaseRevision,
				transaction->manifest.resolvedGeneration,
				std::move(epoch))
			: _archiveState.appendEpoch(
				transaction->archiveBaseRevision,
				std::move(epoch));
		if (committed != ArchiveStateCommitResult::Committed
			&& committed != ArchiveStateCommitResult::AlreadyCommitted) {
			return committed == ArchiveStateCommitResult::RevisionConflict
				? ForkRecoveryApplyStatus::RevisionConflict
				: ForkRecoveryApplyStatus::ArchivePersistenceFailure;
		}
	} else {
		const auto epoch = _archiveState.epoch(
			transaction->archiveEpoch.generation);
		if (!epoch || !SameEpoch(*epoch, transaction->archiveEpoch)) {
			return ForkRecoveryApplyStatus::InvalidTransaction;
		}
	}
	if (!groupApplied) {
		const auto committed = inbound
			? _groupLedger.replaceForkBranchAndCommitRecovery(
				transaction->groupBaseRevision,
				*transaction->canonicalTransition,
				*canonicalApplied,
				transaction->canonicalTargetCredential
					? &*transaction->canonicalTargetCredential
					: nullptr,
				transaction->manifest,
				transaction->archiveEpoch)
			: _groupLedger.commitVerifiedForkRecovery(
				transaction->groupBaseRevision,
				transaction->manifest,
				transaction->archiveEpoch);
		if (committed != GroupLedgerCommitResult::Committed
			&& committed != GroupLedgerCommitResult::AlreadyCommitted) {
			return committed == GroupLedgerCommitResult::RevisionConflict
				? ForkRecoveryApplyStatus::RevisionConflict
				: ForkRecoveryApplyStatus::GroupPersistenceFailure;
		}
	} else if (_groupLedger.events().empty()
		|| _groupLedger.events().back().kind
			!= GroupLedgerEventKind::ForkRecovery
		|| _groupLedger.events().back().objectId
			!= transaction->transactionId) {
		return ForkRecoveryApplyStatus::InvalidTransaction;
	}
	if (!forkLedgerApplied) {
		const auto committed = _forkLedger.commitVerified(
			transaction->manifest);
		if (committed != ForkRecoveryLedgerCommitResult::Committed
			&& committed
				!= ForkRecoveryLedgerCommitResult::AlreadyCommitted) {
			return committed
				== ForkRecoveryLedgerCommitResult::OwnerEquivocation
				? ForkRecoveryApplyStatus::InvalidTransaction
				: ForkRecoveryApplyStatus::ForkLedgerPersistenceFailure;
		}
	} else {
		const auto record = _forkLedger.record(
			transaction->manifest.commonGeneration);
		if (!record || record->recoveryId != transaction->transactionId) {
			return ForkRecoveryApplyStatus::InvalidTransaction;
		}
	}
	if (inbound && !keyPackagePoolApplied) {
		if (!transaction->consumedKeyPackageHash
			|| _keyPackagePool->consume(
				*transaction->consumedKeyPackageHash)
				!= KeyPackagePoolMutationResult::Committed) {
			return ForkRecoveryApplyStatus::InvalidTransaction;
		}
	} else if (inbound && !_keyPackagePool->entries().empty()) {
		return ForkRecoveryApplyStatus::InvalidTransaction;
	}
	for (const auto &envelope : transaction->outboxEnvelopes) {
		if (!_outbox || !_outbox->appendSealed(envelope)) {
			return ForkRecoveryApplyStatus::OutboxPersistenceFailure;
		}
	}
	if (_journal.clear(transaction->transactionId)
			!= ForkRecoveryJournalCommitResult::Cleared) {
		return ForkRecoveryApplyStatus::JournalClearFailure;
	}
	return recovery
		? ForkRecoveryApplyStatus::Recovered
		: ForkRecoveryApplyStatus::Applied;
}

} // namespace E2ECloud

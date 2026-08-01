/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "e2e_cloud/protocol/group_change_transaction.h"

#include <openssl/crypto.h>

#include <algorithm>
#include <array>
#include <limits>
#include <set>
#include <utility>

namespace E2ECloud {
namespace {

inline constexpr auto kMagic = std::array<std::uint8_t, 8>{
	'T', 'D', 'E', '2', 'E', 'G', 'T', 'X',
};
inline constexpr auto kPurpose = "TDE2E/local-group-change-transaction/v1";
inline constexpr auto kMaximumKeyPackageSize = 1024 * 1024;
inline constexpr auto kMaximumMlsCommitSize = 4 * 1024 * 1024;
inline constexpr auto kMaximumMlsStateSize = 64 * 1024 * 1024;
inline constexpr auto kMaximumEnvelopeSize = 18 * 1024 * 1024;
inline constexpr auto kMaximumOutboxEnvelopes = 16;
inline constexpr auto kMaximumSnapshotSize = 256 * 1024 * 1024;

struct Reader {
	const QByteArray &bytes;
	int offset = 0;
};

struct DecodedSnapshot {
	std::uint64_t revision = 0;
	std::optional<GroupChangeTransaction> transaction;
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

void Cleanse(GroupChangeTransaction &transaction) {
	OPENSSL_cleanse(
		transaction.targetKeyPackage.data(),
		transaction.targetKeyPackage.size());
	OPENSSL_cleanse(transaction.mlsCommit.data(), transaction.mlsCommit.size());
	OPENSSL_cleanse(
		transaction.archiveDistribution.data(),
		transaction.archiveDistribution.size());
	OPENSSL_cleanse(
		transaction.nextMlsEngineState.data(),
		transaction.nextMlsEngineState.size());
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
		const GroupChangeTransaction &transaction) {
	const auto encodedTransition = SignedGroupTransitionCodecV1().encode(
		transaction.signedTransition);
	const auto encodedCredential = transaction.targetCredential
		? AccountCredentialCodecV1().encode(*transaction.targetCredential)
		: std::optional<QByteArray>();
	const auto outbound = transaction.direction
		== GroupChangeTransactionDirection::Outbound;
	const auto inbound = transaction.direction
		== GroupChangeTransactionDirection::Inbound;
	const auto inboundJoin = transaction.direction
		== GroupChangeTransactionDirection::InboundJoin;
	const auto inboundRemoval = transaction.direction
		== GroupChangeTransactionDirection::InboundRemoval;
	const auto inboundRejoin = transaction.direction
		== GroupChangeTransactionDirection::InboundRejoin;
	const auto admission = transaction.signedTransition.transition.kind
			== GroupTransitionKind::AddMember
		|| transaction.signedTransition.transition.kind
			== GroupTransitionKind::AddClient;
	if (!transaction.conversationId
		|| !transaction.transactionId
		|| (!outbound
			&& !inbound
			&& !inboundJoin
			&& !inboundRemoval
			&& !inboundRejoin)
		|| transaction.transactionId
			!= transaction.signedTransition.transition.transitionId
		|| transaction.signedTransition.transition.conversationId
			!= transaction.conversationId
		|| !transaction.groupBaseRevision
		|| (!inboundJoin && !transaction.archiveBaseRevision)
		|| (inboundJoin && transaction.archiveBaseRevision)
		|| ((inboundJoin || inboundRejoin) && !admission)
		|| !transaction.mlsBaseRevision
		|| transaction.groupBaseRevision
			== std::numeric_limits<std::uint64_t>::max()
		|| transaction.archiveBaseRevision
			== std::numeric_limits<std::uint64_t>::max()
		|| transaction.mlsBaseRevision
			== std::numeric_limits<std::uint64_t>::max()
		|| !encodedTransition
		|| (transaction.targetCredential && !encodedCredential)
		|| transaction.targetKeyPackage.size() > kMaximumKeyPackageSize
		|| transaction.mlsCommit.isEmpty()
		|| transaction.mlsCommit.size() > kMaximumMlsCommitSize
		|| transaction.archiveDistribution.isEmpty()
		|| transaction.archiveDistribution.size() > kMaximumMlsCommitSize
		|| (inboundRemoval
			? (!transaction.nextMlsEngineState.isEmpty()
				|| !transaction.removalTombstone)
			: (transaction.nextMlsEngineState.isEmpty()
				|| transaction.removalTombstone))
		|| transaction.nextMlsEngineState.size() > kMaximumMlsStateSize
		|| (outbound != transaction.mlsReceipt.has_value())
		|| (transaction.mlsReceipt
			&& (transaction.mlsReceipt->objectId
					!= transaction.signedTransition
						.archiveDistributionObjectId
				|| !transaction.mlsReceipt->requestHash
				|| !ValidEnvelope(
					transaction.conversationId,
					transaction.mlsReceipt->envelope)
				|| transaction.mlsReceipt->envelope.objectId
					!= transaction.mlsReceipt->objectId))
		|| (inboundRemoval != !transaction.archiveEpoch)
		|| (transaction.archiveEpoch
			&& (transaction.archiveEpoch->generation
					!= transaction.signedTransition.transition.generation
				|| transaction.archiveEpoch->activationGroupGeneration
					!= transaction.archiveEpoch->generation
				|| transaction.archiveEpoch->activationEventId
					!= transaction.transactionId
				|| !transaction.archiveEpoch->key.valid()))
		|| (transaction.removalTombstone
			&& (transaction.removalTombstone->transitionId
					!= transaction.transactionId
				|| transaction.removalTombstone->generation
					!= transaction.signedTransition.transition.generation
				|| transaction.removalTombstone->resultingStateHash
					!= transaction.signedTransition.resultingStateHash
				|| transaction.removalTombstone->mlsCommitHash
					!= transaction.signedTransition.mlsCommitHash
				|| transaction.removalTombstone->removedAccountId
					!= transaction.signedTransition.transition.targetAccountId
				|| (transaction.signedTransition.transition.kind
						== GroupTransitionKind::RemoveClient
					&& transaction.removalTombstone->removedClientId
						!= transaction.signedTransition.transition.targetClientId)
				|| (transaction.signedTransition.transition.kind
						!= GroupTransitionKind::RemoveMember
					&& transaction.signedTransition.transition.kind
						!= GroupTransitionKind::RemoveClient)))
		|| (outbound != !transaction.outboxEnvelopes.empty())
		|| transaction.outboxEnvelopes.size() > kMaximumOutboxEnvelopes) {
		return false;
	}
	auto objectIds = std::set<ObjectId>();
	auto containsMlsReceipt = false;
	auto containsMlsCommit = false;
	auto containsArchiveDistribution = false;
	for (const auto &envelope : transaction.outboxEnvelopes) {
		if (!ValidEnvelope(transaction.conversationId, envelope)
			|| !objectIds.emplace(envelope.objectId).second) {
			return false;
		}
		containsMlsReceipt = containsMlsReceipt
			|| (transaction.mlsReceipt
				&& envelope == transaction.mlsReceipt->envelope);
		containsMlsCommit = containsMlsCommit
			|| envelope.objectId
				== transaction.signedTransition.mlsCommitObjectId;
		containsArchiveDistribution = containsArchiveDistribution
			|| envelope.objectId
				== transaction.signedTransition.archiveDistributionObjectId;
	}
	return inbound || inboundJoin || inboundRemoval || inboundRejoin
		|| (containsMlsReceipt
		&& containsMlsCommit
		&& containsArchiveDistribution);
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
		const GroupChangeTransaction *transaction) {
	if (!conversationId
		|| !revision
		|| (transaction
			&& (transaction->conversationId != conversationId
				|| !ValidTransaction(*transaction)))) {
		return std::nullopt;
	}
	auto result = QByteArray();
	AppendArray(result, kMagic);
	AppendUint16(result, 3);
	AppendArray(result, conversationId.bytes);
	AppendUint64(result, revision);
	AppendUint8(result, transaction ? 1 : 0);
	if (!transaction) {
		return result;
	}
	const auto signedTransition = SignedGroupTransitionCodecV1().encode(
		transaction->signedTransition);
	AppendArray(result, transaction->transactionId.bytes);
	AppendUint8(result, std::uint8_t(transaction->direction));
	AppendUint64(result, transaction->groupBaseRevision);
	AppendUint64(result, transaction->archiveBaseRevision);
	AppendUint64(result, transaction->mlsBaseRevision);
	result.append(*signedTransition);
	AppendUint8(result, transaction->targetCredential ? 1 : 0);
	if (transaction->targetCredential) {
		result.append(*AccountCredentialCodecV1().encode(
			*transaction->targetCredential));
	} else {
		auto zero = std::array<std::uint8_t, kAccountCredentialEncodedSize>();
		AppendArray(result, zero);
	}
	AppendBytes(result, transaction->targetKeyPackage);
	AppendBytes(result, transaction->mlsCommit);
	AppendBytes(result, transaction->archiveDistribution);
	AppendBytes(result, transaction->nextMlsEngineState);
	AppendUint8(result, transaction->mlsReceipt ? 1 : 0);
	if (transaction->mlsReceipt) {
		AppendArray(result, transaction->mlsReceipt->objectId.bytes);
		AppendArray(result, transaction->mlsReceipt->requestHash.bytes);
		AppendArray(
			result,
			transaction->mlsReceipt->envelope.conversationId.bytes);
		AppendArray(result, transaction->mlsReceipt->envelope.objectId.bytes);
		AppendBytes(result, transaction->mlsReceipt->envelope.bytes);
	}
	AppendUint8(result, transaction->removalTombstone ? 1 : 0);
	if (transaction->removalTombstone) {
		AppendArray(result, transaction->removalTombstone->transitionId.bytes);
		AppendUint64(result, transaction->removalTombstone->generation);
		AppendArray(
			result,
			transaction->removalTombstone->resultingStateHash.bytes);
		AppendArray(result, transaction->removalTombstone->mlsCommitHash.bytes);
		AppendArray(
			result,
			transaction->removalTombstone->removedAccountId.bytes);
		AppendArray(result, transaction->removalTombstone->removedClientId.bytes);
	}
	AppendUint8(result, transaction->archiveEpoch ? 1 : 0);
	if (transaction->archiveEpoch) {
		AppendArray(result, transaction->archiveEpoch->key.bytes());
	} else {
		auto zero = std::array<std::uint8_t, kArchiveKeySize>();
		AppendArray(result, zero);
	}
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
	auto present = std::uint8_t();
	auto conversationId = ConversationId();
	auto result = DecodedSnapshot();
	if (!ReadArray(reader, magic)
		|| !ReadUint16(reader, version)
		|| !ReadArray(reader, conversationId.bytes)
		|| !ReadUint64(reader, result.revision)
		|| !ReadUint8(reader, present)
		|| magic != kMagic
		|| (version != 2 && version != 3)
		|| !conversationId
		|| !result.revision
		|| present > 1) {
		return std::nullopt;
	} else if (!present) {
		return reader.offset == bytes.size()
			? std::optional<DecodedSnapshot>(std::move(result))
			: std::nullopt;
	}
	auto transaction = GroupChangeTransaction();
	transaction.conversationId = conversationId;
	auto direction = std::uint8_t();
	auto transitionBytes = QByteArray();
	auto credentialPresent = std::uint8_t();
	auto credentialBytes = QByteArray();
	auto archiveKey = std::array<std::uint8_t, kArchiveKeySize>();
	auto outboxCount = std::uint16_t();
	if (!ReadArray(reader, transaction.transactionId.bytes)
		|| !ReadUint8(reader, direction)
		|| (direction
			!= std::uint8_t(GroupChangeTransactionDirection::Outbound)
			&& direction
				!= std::uint8_t(GroupChangeTransactionDirection::Inbound)
			&& direction
				!= std::uint8_t(
					GroupChangeTransactionDirection::InboundJoin)
			&& direction
				!= std::uint8_t(
					GroupChangeTransactionDirection::InboundRemoval)
			&& direction
				!= std::uint8_t(
					GroupChangeTransactionDirection::InboundRejoin))
		|| !ReadUint64(reader, transaction.groupBaseRevision)
		|| !ReadUint64(reader, transaction.archiveBaseRevision)
		|| !ReadUint64(reader, transaction.mlsBaseRevision)
		|| reader.bytes.size() - reader.offset
			< kSignedGroupTransitionEncodedSize) {
		return std::nullopt;
	}
	transaction.direction = GroupChangeTransactionDirection(direction);
	transitionBytes = QByteArray(
		reader.bytes.constData() + reader.offset,
		kSignedGroupTransitionEncodedSize);
	reader.offset += kSignedGroupTransitionEncodedSize;
	const auto signedTransition = SignedGroupTransitionCodecV1().decode(
		transitionBytes);
	if (!signedTransition
		|| !ReadUint8(reader, credentialPresent)
		|| credentialPresent > 1
		|| reader.bytes.size() - reader.offset
			< kAccountCredentialEncodedSize) {
		return std::nullopt;
	}
	transaction.signedTransition = *signedTransition;
	credentialBytes = QByteArray(
		reader.bytes.constData() + reader.offset,
		kAccountCredentialEncodedSize);
	reader.offset += kAccountCredentialEncodedSize;
	if (credentialPresent) {
		transaction.targetCredential = AccountCredentialCodecV1().decode(
			credentialBytes);
		if (!transaction.targetCredential) {
			return std::nullopt;
		}
	} else if (std::any_of(
		credentialBytes.constData(),
		credentialBytes.constData() + credentialBytes.size(),
		[](char value) { return value != 0; })) {
		return std::nullopt;
	}
	auto receiptPresent = std::uint8_t();
	if (!ReadBytes(reader, kMaximumKeyPackageSize, transaction.targetKeyPackage)
		|| !ReadBytes(reader, kMaximumMlsCommitSize, transaction.mlsCommit)
		|| !ReadBytes(
			reader,
			kMaximumMlsCommitSize,
			transaction.archiveDistribution)
		|| !ReadBytes(
			reader,
			kMaximumMlsStateSize,
			transaction.nextMlsEngineState)
		|| !ReadUint8(reader, receiptPresent)
		|| receiptPresent > 1) {
		OPENSSL_cleanse(archiveKey.data(), archiveKey.size());
		Cleanse(transaction);
		return std::nullopt;
	}
	if (receiptPresent) {
		auto receipt = MlsOperationReceipt();
		if (!ReadArray(reader, receipt.objectId.bytes)
			|| !ReadArray(reader, receipt.requestHash.bytes)
			|| !ReadArray(reader, receipt.envelope.conversationId.bytes)
			|| !ReadArray(reader, receipt.envelope.objectId.bytes)
			|| !ReadBytes(
				reader,
				kMaximumEnvelopeSize,
				receipt.envelope.bytes)) {
			OPENSSL_cleanse(archiveKey.data(), archiveKey.size());
			Cleanse(transaction);
			return std::nullopt;
		}
		transaction.mlsReceipt = std::move(receipt);
	}
	if (version == 3) {
		auto tombstonePresent = std::uint8_t();
		auto tombstone = MlsRemovalTombstone();
		auto archivePresent = std::uint8_t();
		if (!ReadUint8(reader, tombstonePresent)
			|| tombstonePresent > 1) {
			Cleanse(transaction);
			return std::nullopt;
		}
		if (tombstonePresent) {
			if (!ReadArray(reader, tombstone.transitionId.bytes)
				|| !ReadUint64(reader, tombstone.generation)
				|| !ReadArray(reader, tombstone.resultingStateHash.bytes)
				|| !ReadArray(reader, tombstone.mlsCommitHash.bytes)
				|| !ReadArray(reader, tombstone.removedAccountId.bytes)
				|| !ReadArray(reader, tombstone.removedClientId.bytes)) {
				Cleanse(transaction);
				return std::nullopt;
			}
			transaction.removalTombstone = tombstone;
		}
		if (!ReadUint8(reader, archivePresent)
			|| archivePresent > 1
			|| !ReadArray(reader, archiveKey)) {
			OPENSSL_cleanse(archiveKey.data(), archiveKey.size());
			Cleanse(transaction);
			return std::nullopt;
		}
		if (archivePresent) {
			transaction.archiveEpoch = ArchiveEpochSecret{
				.generation = transaction.signedTransition
					.transition.generation,
				.activationGroupGeneration = transaction.signedTransition
					.transition.generation,
				.activationEventId = transaction.transactionId,
				.key = ArchiveKey32(std::move(archiveKey)),
			};
		} else if (std::any_of(
			archiveKey.begin(),
			archiveKey.end(),
			[](std::uint8_t byte) { return byte != 0; })) {
			OPENSSL_cleanse(archiveKey.data(), archiveKey.size());
			Cleanse(transaction);
			return std::nullopt;
		}
	} else if (!ReadArray(reader, archiveKey)) {
		OPENSSL_cleanse(archiveKey.data(), archiveKey.size());
		Cleanse(transaction);
		return std::nullopt;
	} else {
		transaction.archiveEpoch = ArchiveEpochSecret{
			.generation = transaction.signedTransition.transition.generation,
			.activationGroupGeneration =
				transaction.signedTransition.transition.generation,
			.activationEventId = transaction.transactionId,
			.key = ArchiveKey32(std::move(archiveKey)),
		};
	}
	if (!ReadUint16(reader, outboxCount)
		|| outboxCount > kMaximumOutboxEnvelopes) {
		OPENSSL_cleanse(archiveKey.data(), archiveKey.size());
		Cleanse(transaction);
		return std::nullopt;
	}
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

[[nodiscard]] bool SameEpoch(
		const ArchiveEpochSecret &a,
		const ArchiveEpochSecret &b) {
	return a.generation == b.generation
		&& a.activationGroupGeneration == b.activationGroupGeneration
		&& a.activationEventId == b.activationEventId
		&& a.key.bytes() == b.key.bytes();
}

} // namespace

PersistentGroupChangeJournal::PersistentGroupChangeJournal(
		AtomicBlobStore &blobStore,
		const LocalRecordProtector &protector)
: _blobStore(blobStore)
, _protector(protector) {
}

PersistentGroupChangeJournal::~PersistentGroupChangeJournal() {
	reset();
}

GroupChangeJournalLoadResult PersistentGroupChangeJournal::load(
		ConversationId conversationId) {
	reset();
	if (!conversationId) {
		return GroupChangeJournalLoadResult::InvalidSnapshot;
	}
	_conversationId = conversationId;
	const auto stored = _blobStore.read();
	if (stored.status == BlobReadStatus::Error) {
		return GroupChangeJournalLoadResult::StorageError;
	} else if (stored.status == BlobReadStatus::Missing) {
		_loaded = true;
		return GroupChangeJournalLoadResult::Empty;
	}
	auto opened = _protector.open(Purpose(conversationId), stored.bytes);
	if (!opened) {
		return GroupChangeJournalLoadResult::AuthenticationFailed;
	}
	auto decoded = DecodeSnapshot(*opened);
	OPENSSL_cleanse(opened->data(), opened->size());
	if (!decoded
		|| (decoded->transaction
			&& decoded->transaction->conversationId != conversationId)) {
		return GroupChangeJournalLoadResult::InvalidSnapshot;
	}
	_revision = decoded->revision;
	_pending = std::move(decoded->transaction);
	_loaded = true;
	return _pending
		? GroupChangeJournalLoadResult::Pending
		: GroupChangeJournalLoadResult::Empty;
}

GroupChangeJournalCommitResult PersistentGroupChangeJournal::prepare(
		GroupChangeTransaction transaction) {
	if (!_loaded) {
		Cleanse(transaction);
		return GroupChangeJournalCommitResult::NotLoaded;
	} else if (transaction.conversationId != _conversationId
		|| !ValidTransaction(transaction)
		|| _revision == std::numeric_limits<std::uint64_t>::max()) {
		Cleanse(transaction);
		return GroupChangeJournalCommitResult::InvalidTransaction;
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
			? GroupChangeJournalCommitResult::AlreadyPrepared
			: GroupChangeJournalCommitResult::TransactionConflict;
	}
	const auto revision = _revision + 1;
	if (!persist(&transaction, revision)) {
		Cleanse(transaction);
		return GroupChangeJournalCommitResult::PersistenceFailed;
	}
	_pending = std::move(transaction);
	_revision = revision;
	return GroupChangeJournalCommitResult::Prepared;
}

GroupChangeJournalCommitResult PersistentGroupChangeJournal::clear(
		ObjectId transactionId) {
	if (!_loaded) {
		return GroupChangeJournalCommitResult::NotLoaded;
	} else if (!_pending || _pending->transactionId != transactionId) {
		return GroupChangeJournalCommitResult::TransactionConflict;
	} else if (_revision == std::numeric_limits<std::uint64_t>::max()) {
		return GroupChangeJournalCommitResult::InvalidTransaction;
	}
	const auto revision = _revision + 1;
	if (!persist(nullptr, revision)) {
		return GroupChangeJournalCommitResult::PersistenceFailed;
	}
	Cleanse(*_pending);
	_pending.reset();
	_revision = revision;
	return GroupChangeJournalCommitResult::Cleared;
}

bool PersistentGroupChangeJournal::loaded() const {
	return _loaded;
}

std::uint64_t PersistentGroupChangeJournal::revision() const {
	return _revision;
}

const GroupChangeTransaction *PersistentGroupChangeJournal::pending() const {
	return _pending ? &*_pending : nullptr;
}

bool PersistentGroupChangeJournal::persist(
		const GroupChangeTransaction *transaction,
		std::uint64_t revision) const {
	auto plaintext = EncodeSnapshot(_conversationId, revision, transaction);
	if (!plaintext) {
		return false;
	}
	const auto encrypted = _protector.seal(
		Purpose(_conversationId),
		*plaintext);
	OPENSSL_cleanse(plaintext->data(), plaintext->size());
	return encrypted && _blobStore.writeAtomic(*encrypted);
}

void PersistentGroupChangeJournal::reset() {
	if (_pending) {
		Cleanse(*_pending);
	}
	_pending.reset();
	_conversationId = {};
	_revision = 0;
	_loaded = false;
}

GroupChangeTransactionCoordinator::GroupChangeTransactionCoordinator(
		PersistentGroupChangeJournal &journal,
		PersistentMlsStateStore &mlsState,
		PersistentArchiveState &archiveState,
		PersistentGroupLedger &groupLedger,
		PersistentOutboxStore &outbox,
		const Sha256Provider &sha256)
: _journal(journal)
, _mlsState(mlsState)
, _archiveState(archiveState)
, _groupLedger(groupLedger)
, _outbox(&outbox)
, _sha256(sha256) {
}

GroupChangeTransactionCoordinator::GroupChangeTransactionCoordinator(
		PersistentGroupChangeJournal &journal,
		PersistentMlsStateStore &mlsState,
		PersistentArchiveState &archiveState,
		PersistentGroupLedger &groupLedger,
		const Sha256Provider &sha256)
: _journal(journal)
, _mlsState(mlsState)
, _archiveState(archiveState)
, _groupLedger(groupLedger)
, _sha256(sha256) {
}

GroupChangeApplyStatus GroupChangeTransactionCoordinator::apply(
		GroupChangeTransaction transaction) {
	const auto prepared = _journal.prepare(std::move(transaction));
	if (prepared == GroupChangeJournalCommitResult::NotLoaded) {
		return GroupChangeApplyStatus::JournalUnavailable;
	} else if (prepared != GroupChangeJournalCommitResult::Prepared
		&& prepared != GroupChangeJournalCommitResult::AlreadyPrepared) {
		return (prepared == GroupChangeJournalCommitResult::TransactionConflict)
			? GroupChangeApplyStatus::RevisionConflict
			: GroupChangeApplyStatus::InvalidTransaction;
	}
	return replay(false);
}

GroupChangeApplyStatus GroupChangeTransactionCoordinator::recover() {
	return replay(true);
}

GroupChangeApplyStatus GroupChangeTransactionCoordinator::replay(
		bool recovery) {
	const auto transaction = _journal.pending();
	if (!transaction) {
		return GroupChangeApplyStatus::NoPendingTransaction;
	}
	const auto inboundJoin = transaction->direction
		== GroupChangeTransactionDirection::InboundJoin;
	const auto inboundRemoval = transaction->direction
		== GroupChangeTransactionDirection::InboundRemoval;
	const auto inboundRejoin = transaction->direction
		== GroupChangeTransactionDirection::InboundRejoin;
	const auto archiveAvailable = inboundJoin
		? ((!_archiveState.loaded() && !_archiveState.revision())
			|| (_archiveState.loaded()
				&& _archiveState.revision()
					== transaction->archiveBaseRevision + 1))
		: _archiveState.loaded();
	if (!_mlsState.loaded()
		|| !archiveAvailable
		|| !_groupLedger.loaded()
		|| (transaction->direction
				== GroupChangeTransactionDirection::Outbound
			&& (!_outbox || !_outbox->loaded()))
		|| _mlsState.conversationId() != transaction->conversationId
		|| _archiveState.conversationId() != transaction->conversationId
		|| _groupLedger.state()->conversationId()
			!= transaction->conversationId) {
		return GroupChangeApplyStatus::InvalidTransaction;
	}
	const auto groupAlreadyApplied = _groupLedger.revision()
		== transaction->groupBaseRevision + 1;
	const auto archiveAlreadyApplied = inboundRemoval
		? (_archiveState.revision() == transaction->archiveBaseRevision)
		: (_archiveState.revision()
			== transaction->archiveBaseRevision + 1);
	const auto mlsAlreadyApplied = _mlsState.revision()
		== transaction->mlsBaseRevision + 1;
	if ((!groupAlreadyApplied
			&& _groupLedger.revision() != transaction->groupBaseRevision)
		|| (!archiveAlreadyApplied
			&& _archiveState.revision() != transaction->archiveBaseRevision)
		|| (!mlsAlreadyApplied
			&& _mlsState.revision() != transaction->mlsBaseRevision)) {
		return GroupChangeApplyStatus::RevisionConflict;
	}
	const auto actorCredential = _groupLedger.credential(
		transaction->signedTransition.actorAccountId);
	auto applied = std::optional<AppliedSignedGroupTransition>();
	if (!groupAlreadyApplied) {
		auto verified = VerifyAndApplySignedGroupTransition({
			.currentState = _groupLedger.state(),
			.currentCheckpoint = _groupLedger.checkpoint(),
			.signedTransition = &transaction->signedTransition,
			.actorCredential = actorCredential,
			.targetCredential = transaction->targetCredential
				? &*transaction->targetCredential
				: nullptr,
			.mlsCommitObjectId = transaction
				->signedTransition.mlsCommitObjectId,
			.mlsCommit = transaction->mlsCommit,
			.nextArchiveKey = transaction->archiveEpoch
				? &transaction->archiveEpoch->key
				: nullptr,
			.archiveDistributionObjectId = transaction
				->signedTransition.archiveDistributionObjectId,
			.archiveDistribution = transaction->archiveDistribution,
			.targetKeyPackage = transaction->targetKeyPackage,
			.allowMissingArchiveKey = inboundRemoval,
		}, _sha256);
		if (verified.result != SignedGroupTransitionResult::Applied
			|| !verified.applied) {
			return GroupChangeApplyStatus::InvalidTransaction;
		}
		applied.emplace(std::move(*verified.applied));
	}
	if (!mlsAlreadyApplied) {
		const auto committed = _mlsState.commit({
			.baseRevision = transaction->mlsBaseRevision,
			.engineState = transaction->nextMlsEngineState,
			.receipt = transaction->mlsReceipt,
			.inboundApplication = std::nullopt,
			.removalTombstone = transaction->removalTombstone,
		});
		if (committed != MlsStateCommitResult::Committed
			&& committed != MlsStateCommitResult::AlreadyCommitted) {
			return (committed == MlsStateCommitResult::RevisionConflict)
				? GroupChangeApplyStatus::RevisionConflict
				: GroupChangeApplyStatus::MlsPersistenceFailure;
		}
	} else {
		const auto matchesReceipt = transaction->removalTombstone
			? (_mlsState.removalTombstone()
				== transaction->removalTombstone)
			: transaction->mlsReceipt
			? (_mlsState.receipt(transaction->mlsReceipt->objectId)
				== transaction->mlsReceipt)
			: (_mlsState.engineState()
				== transaction->nextMlsEngineState);
		if (!matchesReceipt) {
			return GroupChangeApplyStatus::InvalidTransaction;
		}
	}
	if (!archiveAlreadyApplied) {
		auto epoch = ArchiveEpochSecret{
				.generation = transaction->archiveEpoch->generation,
				.activationGroupGeneration = transaction
					->archiveEpoch->activationGroupGeneration,
				.activationEventId = transaction
					->archiveEpoch->activationEventId,
				.key = transaction->archiveEpoch->key.clone(),
			};
		const auto committed = transaction->archiveBaseRevision
			? _archiveState.appendEpoch(
				transaction->archiveBaseRevision,
				std::move(epoch),
				inboundRejoin
					? ArchiveEpochAppendMode::RejoinGap
					: ArchiveEpochAppendMode::Contiguous)
			: _archiveState.initialize(std::move(epoch));
		if (committed != ArchiveStateCommitResult::Committed
			&& committed != ArchiveStateCommitResult::AlreadyCommitted) {
			return (committed == ArchiveStateCommitResult::RevisionConflict)
				? GroupChangeApplyStatus::RevisionConflict
				: GroupChangeApplyStatus::ArchivePersistenceFailure;
		}
	} else if (!inboundRemoval) {
		const auto epoch = _archiveState.epoch(
			transaction->archiveEpoch->generation);
		if (!epoch || !SameEpoch(*epoch, *transaction->archiveEpoch)) {
			return GroupChangeApplyStatus::InvalidTransaction;
		}
	}
	if (!groupAlreadyApplied) {
		const auto committed = _groupLedger.commitTransition(
			transaction->groupBaseRevision,
			transaction->signedTransition,
			*applied,
			transaction->targetCredential
				? &*transaction->targetCredential
				: nullptr);
		if (committed != GroupLedgerCommitResult::Committed
			&& committed != GroupLedgerCommitResult::AlreadyCommitted) {
			return (committed == GroupLedgerCommitResult::RevisionConflict)
				? GroupChangeApplyStatus::RevisionConflict
				: GroupChangeApplyStatus::GroupPersistenceFailure;
		}
	}
	for (const auto &envelope : transaction->outboxEnvelopes) {
		if (!_outbox || !_outbox->appendSealed(envelope)) {
			return GroupChangeApplyStatus::OutboxPersistenceFailure;
		}
	}
	if (_journal.clear(transaction->transactionId)
			!= GroupChangeJournalCommitResult::Cleared) {
		return GroupChangeApplyStatus::JournalClearFailure;
	}
	return recovery
		? GroupChangeApplyStatus::Recovered
		: GroupChangeApplyStatus::Applied;
}

} // namespace E2ECloud

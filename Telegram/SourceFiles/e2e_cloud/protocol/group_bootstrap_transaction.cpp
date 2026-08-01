/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "e2e_cloud/protocol/group_bootstrap_transaction.h"

#include "e2e_cloud/mls/openmls_application_engine.h"

#include <openssl/crypto.h>

#include <algorithm>
#include <array>
#include <limits>
#include <set>
#include <utility>

namespace E2ECloud {
namespace {

inline constexpr auto kMagic = std::array<std::uint8_t, 8>{
	'T', 'D', 'E', '2', 'E', 'G', 'B', 'T',
};
inline constexpr auto kMaximumMlsStateSize = 64 * 1024 * 1024;
inline constexpr auto kMaximumPublicObjectSize = 16 * 1024 * 1024;
inline constexpr auto kMaximumEnvelopeSize = 18 * 1024 * 1024;
inline constexpr auto kMaximumSnapshotSize = 128 * 1024 * 1024;

struct Reader {
	const QByteArray &bytes;
	int offset = 0;
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
	value = 0;
	for (auto i = 0; i != 8; ++i) {
		value = (value << 8)
			| std::uint8_t(reader.bytes[reader.offset + i]);
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

[[nodiscard]] QByteArray Purpose(ConversationId conversationId) {
	auto result = QByteArray("TDE2E/group-bootstrap-transaction/v1");
	result.append(char(0));
	AppendArray(result, conversationId.bytes);
	return result;
}

void Cleanse(QByteArray &bytes) {
	if (!bytes.isEmpty()) {
		OPENSSL_cleanse(bytes.data(), bytes.size());
	}
	bytes.clear();
}

template <typename Value>
void Cleanse(Value &value) {
	OPENSSL_cleanse(value.data(), value.size());
}

[[nodiscard]] bool SameArchiveEpoch(
		const ArchiveEpochSecret &a,
		const ArchiveEpochSecret &b) {
	return a.generation == b.generation
		&& a.activationGroupGeneration == b.activationGroupGeneration
		&& a.activationEventId == b.activationEventId
		&& a.key.valid()
		&& b.key.valid()
		&& a.key.bytes() == b.key.bytes();
}

[[nodiscard]] bool BasicTransactionStructure(
		const GroupBootstrapTransaction &transaction) {
	if (!transaction.conversationId
		|| transaction.genesis.conversationId != transaction.conversationId
		|| transaction.genesis.genesisObjectId == ObjectId()
		|| transaction.initialMlsPublicObject.isEmpty()
		|| transaction.initialMlsPublicObject.size()
			> kMaximumPublicObjectSize
		|| transaction.archiveEpoch.generation != 1
		|| transaction.archiveEpoch.activationGroupGeneration != 1
		|| !transaction.archiveEpoch.activationEventId
		|| !transaction.archiveEpoch.key.valid()
		|| transaction.mlsEngineState.isEmpty()
		|| transaction.mlsEngineState.size() > kMaximumMlsStateSize
		|| transaction.outboxEnvelopes.size() != 4) {
		return false;
	}
	auto objectIds = std::set<ObjectId>();
	for (const auto &envelope : transaction.outboxEnvelopes) {
		if (envelope.conversationId != transaction.conversationId
			|| !envelope.objectId
			|| envelope.objectId
				== transaction.archiveEpoch.activationEventId
			|| envelope.bytes.isEmpty()
			|| envelope.bytes.size() > kMaximumEnvelopeSize
			|| !objectIds.emplace(envelope.objectId).second) {
			return false;
		}
	}
	return true;
}

[[nodiscard]] QByteArray EncodeSnapshot(
		ConversationId conversationId,
		std::uint64_t revision,
		const GroupBootstrapTransaction *transaction) {
	auto result = QByteArray();
	AppendArray(result, kMagic);
	AppendUint16(result, 1);
	AppendArray(result, conversationId.bytes);
	AppendUint64(result, revision);
	AppendUint8(result, transaction ? 1 : 0);
	if (!transaction) {
		return result;
	}
	const auto genesis = SignedGroupGenesisCodecV1().encode(
		transaction->genesis);
	const auto credential = AccountCredentialCodecV1().encode(
		transaction->ownerCredential);
	if (!genesis || !credential) {
		return {};
	}
	AppendUint64(result, transaction->outboxBaseRevision);
	AppendBytes(result, *genesis);
	AppendBytes(result, *credential);
	AppendBytes(result, transaction->initialMlsPublicObject);
	AppendUint64(result, transaction->archiveEpoch.generation);
	AppendUint64(
		result,
		transaction->archiveEpoch.activationGroupGeneration);
	AppendArray(result, transaction->archiveEpoch.activationEventId.bytes);
	AppendArray(result, transaction->archiveEpoch.key.bytes());
	AppendBytes(result, transaction->mlsEngineState);
	AppendUint16(result, std::uint16_t(transaction->outboxEnvelopes.size()));
	for (const auto &envelope : transaction->outboxEnvelopes) {
		AppendArray(result, envelope.conversationId.bytes);
		AppendArray(result, envelope.objectId.bytes);
		AppendBytes(result, envelope.bytes);
	}
	return (result.size() <= kMaximumSnapshotSize) ? result : QByteArray();
}

[[nodiscard]] bool SameTransaction(
		const GroupBootstrapTransaction &a,
		const GroupBootstrapTransaction &b) {
	auto encodedA = EncodeSnapshot(a.conversationId, 1, &a);
	auto encodedB = EncodeSnapshot(b.conversationId, 1, &b);
	const auto same = !encodedA.isEmpty()
		&& encodedA.size() == encodedB.size()
		&& CRYPTO_memcmp(
			encodedA.constData(),
			encodedB.constData(),
			encodedA.size()) == 0;
	Cleanse(encodedA);
	Cleanse(encodedB);
	return same;
}

struct DecodedSnapshot {
	std::uint64_t revision = 0;
	std::optional<GroupBootstrapTransaction> transaction;
};

[[nodiscard]] std::optional<DecodedSnapshot> DecodeSnapshot(
		const QByteArray &bytes,
		ConversationId expectedConversationId) {
	if (bytes.isEmpty() || bytes.size() > kMaximumSnapshotSize) {
		return std::nullopt;
	}
	auto reader = Reader{ bytes };
	auto magic = std::array<std::uint8_t, 8>();
	auto version = std::uint16_t();
	auto conversationId = ConversationId();
	auto revision = std::uint64_t();
	auto present = std::uint8_t();
	if (!ReadArray(reader, magic)
		|| !ReadUint16(reader, version)
		|| !ReadArray(reader, conversationId.bytes)
		|| !ReadUint64(reader, revision)
		|| !ReadUint8(reader, present)
		|| magic != kMagic
		|| version != 1
		|| conversationId != expectedConversationId
		|| !revision
		|| present > 1) {
		return std::nullopt;
	} else if (!present) {
		return (reader.offset == bytes.size())
			? std::optional<DecodedSnapshot>({
				.revision = revision,
				.transaction = std::nullopt,
			})
			: std::nullopt;
	}
	auto transaction = GroupBootstrapTransaction();
	transaction.conversationId = conversationId;
	auto genesisBytes = QByteArray();
	auto credentialBytes = QByteArray();
	auto archiveKey = std::array<std::uint8_t, kArchiveKeySize>();
	auto envelopeCount = std::uint16_t();
	if (!ReadUint64(reader, transaction.outboxBaseRevision)
		|| !ReadBytes(
			reader,
			kSignedGroupGenesisEncodedSize,
			genesisBytes)
		|| !ReadBytes(
			reader,
			kAccountCredentialEncodedSize,
			credentialBytes)
		|| !ReadBytes(
			reader,
			kMaximumPublicObjectSize,
			transaction.initialMlsPublicObject)
		|| !ReadUint64(reader, transaction.archiveEpoch.generation)
		|| !ReadUint64(
			reader,
			transaction.archiveEpoch.activationGroupGeneration)
		|| !ReadArray(
			reader,
			transaction.archiveEpoch.activationEventId.bytes)
		|| !ReadArray(reader, archiveKey)
		|| !ReadBytes(
			reader,
			kMaximumMlsStateSize,
			transaction.mlsEngineState)
		|| !ReadUint16(reader, envelopeCount)
		|| envelopeCount != 4) {
		Cleanse(transaction.mlsEngineState);
		Cleanse(archiveKey);
		return std::nullopt;
	}
	transaction.genesis = SignedGroupGenesisCodecV1().decode(
		genesisBytes).value_or(SignedGroupGenesis());
	transaction.ownerCredential = AccountCredentialCodecV1().decode(
		credentialBytes).value_or(AccountCredentialPublic());
	transaction.archiveEpoch.key = ArchiveKey32(std::move(archiveKey));
	for (auto i = std::uint16_t(0); i != envelopeCount; ++i) {
		auto envelope = EncodedEnvelope();
		if (!ReadArray(reader, envelope.conversationId.bytes)
			|| !ReadArray(reader, envelope.objectId.bytes)
			|| !ReadBytes(reader, kMaximumEnvelopeSize, envelope.bytes)) {
			Cleanse(transaction.mlsEngineState);
			return std::nullopt;
		}
		transaction.outboxEnvelopes.push_back(std::move(envelope));
	}
	if (reader.offset != bytes.size()
		|| !BasicTransactionStructure(transaction)) {
		Cleanse(transaction.mlsEngineState);
		return std::nullopt;
	}
	return DecodedSnapshot{
		.revision = revision,
		.transaction = std::move(transaction),
	};
}

[[nodiscard]] bool ValidBootstrapBundle(
		const GroupBootstrapTransaction &transaction,
		const EnvelopeCodecV1 &envelopeCodec,
		const Sha256Provider &sha256,
		VerifySignedGroupGenesisOutcome &verified) {
	if (!BasicTransactionStructure(transaction)) {
		return false;
	}
	verified = VerifySignedGroupGenesis({
		.genesis = &transaction.genesis,
		.ownerCredential = &transaction.ownerCredential,
		.genesisObjectId = transaction.genesis.genesisObjectId,
		.initialMlsPublicObjectId =
			transaction.genesis.initialMlsPublicObjectId,
		.initialMlsPublicObject = transaction.initialMlsPublicObject,
		.initialArchiveKey = &transaction.archiveEpoch.key,
	}, sha256);
	if (!verified.verified
		|| transaction.archiveEpoch.activationEventId
			!= transaction.genesis.archiveActivationEventId) {
		return false;
	}
	auto kinds = std::set<ObjectKind>();
	for (const auto &encoded : transaction.outboxEnvelopes) {
		const auto envelope = envelopeCodec.decode(encoded);
		if (!envelope
			|| envelope->senderAccountId
				!= transaction.genesis.ownerAccountId
			|| envelope->senderClientId
				!= transaction.genesis.ownerClientId
			|| envelope->telegramPeerIdBinding
				!= transaction.genesis.telegramPeerIdBinding
			|| envelope->payloadHash != sha256.digest(envelope->payload)
			|| !kinds.emplace(envelope->objectKind).second) {
			return false;
		}
		switch (envelope->objectKind) {
		case ObjectKind::AccountCredential:
			if (envelope->payload != *AccountCredentialCodecV1().encode(
				transaction.ownerCredential)) {
				return false;
			}
			break;
		case ObjectKind::MlsGroupInfo:
			if (envelope->objectId
					!= transaction.genesis.initialMlsPublicObjectId
				|| envelope->payload != transaction.initialMlsPublicObject) {
				return false;
			}
			break;
		case ObjectKind::InitialGroupState:
			if (envelope->objectId != transaction.genesis.genesisObjectId
				|| envelope->payload
					!= *SignedGroupGenesisCodecV1().encode(
						transaction.genesis)) {
				return false;
			}
			break;
		case ObjectKind::HistoryGrant: {
			const auto grant = EncryptedHistoryGrantCodecV1().decode(
				envelope->payload);
			if (!grant
				|| grant->conversationId != transaction.conversationId
				|| grant->grantId != envelope->objectId
				|| grant->issuerAccountId
					!= transaction.genesis.ownerAccountId
				|| grant->issuerClientId
					!= transaction.genesis.ownerClientId
				|| grant->recipientAccountId
					!= transaction.genesis.ownerAccountId
				|| grant->telegramPeerIdBinding
					!= transaction.genesis.telegramPeerIdBinding
				|| grant->groupGeneration != 1
				|| grant->historyAccess != HistoryAccess{
					.mode = HistoryAccessMode::Full,
					.boundaryEventId = {},
				}
				|| envelope->authenticationData != QByteArray(
					reinterpret_cast<const char*>(grant->signature.data()),
					int(grant->signature.size()))
				|| !VerifyEncryptedHistoryGrantSignature(
					*grant,
					transaction.ownerCredential,
					sha256)) {
				return false;
			}
			break;
		}
		default:
			return false;
		}
	}
	return kinds == std::set<ObjectKind>{
		ObjectKind::AccountCredential,
		ObjectKind::MlsGroupInfo,
		ObjectKind::InitialGroupState,
		ObjectKind::HistoryGrant,
	};
}

} // namespace

PersistentGroupBootstrapJournal::PersistentGroupBootstrapJournal(
		AtomicBlobStore &blobStore,
		const LocalRecordProtector &protector)
: _blobStore(blobStore)
, _protector(protector) {
}

PersistentGroupBootstrapJournal::~PersistentGroupBootstrapJournal() {
	reset();
}

GroupBootstrapJournalLoadResult PersistentGroupBootstrapJournal::load(
		ConversationId conversationId) {
	reset();
	if (!conversationId) {
		return GroupBootstrapJournalLoadResult::InvalidSnapshot;
	}
	_conversationId = conversationId;
	const auto stored = _blobStore.read();
	if (stored.status == BlobReadStatus::Missing) {
		_loaded = true;
		return GroupBootstrapJournalLoadResult::Empty;
	} else if (stored.status != BlobReadStatus::Found) {
		reset();
		return GroupBootstrapJournalLoadResult::StorageError;
	}
	auto plaintext = _protector.open(Purpose(conversationId), stored.bytes);
	if (!plaintext) {
		reset();
		return GroupBootstrapJournalLoadResult::AuthenticationFailed;
	}
	auto decoded = DecodeSnapshot(*plaintext, conversationId);
	Cleanse(*plaintext);
	if (!decoded) {
		reset();
		return GroupBootstrapJournalLoadResult::InvalidSnapshot;
	}
	_revision = decoded->revision;
	_pending = std::move(decoded->transaction);
	_loaded = true;
	return _pending
		? GroupBootstrapJournalLoadResult::Pending
		: GroupBootstrapJournalLoadResult::Empty;
}

GroupBootstrapJournalCommitResult PersistentGroupBootstrapJournal::prepare(
		GroupBootstrapTransaction transaction) {
	if (!_loaded) {
		return GroupBootstrapJournalCommitResult::NotLoaded;
	} else if (!BasicTransactionStructure(transaction)
		|| transaction.conversationId != _conversationId
		|| _revision == std::numeric_limits<std::uint64_t>::max()) {
		return GroupBootstrapJournalCommitResult::InvalidTransaction;
	} else if (_pending) {
		return SameTransaction(*_pending, transaction)
			? GroupBootstrapJournalCommitResult::AlreadyPrepared
			: GroupBootstrapJournalCommitResult::TransactionConflict;
	}
	const auto revision = _revision + 1;
	if (!persist(&transaction, revision)) {
		return GroupBootstrapJournalCommitResult::PersistenceFailed;
	}
	_pending = std::move(transaction);
	_revision = revision;
	return GroupBootstrapJournalCommitResult::Prepared;
}

GroupBootstrapJournalCommitResult PersistentGroupBootstrapJournal::clear(
		ObjectId genesisObjectId) {
	if (!_loaded) {
		return GroupBootstrapJournalCommitResult::NotLoaded;
	} else if (!_pending
		|| _pending->genesis.genesisObjectId != genesisObjectId
		|| _revision == std::numeric_limits<std::uint64_t>::max()) {
		return GroupBootstrapJournalCommitResult::TransactionConflict;
	}
	const auto revision = _revision + 1;
	if (!persist(nullptr, revision)) {
		return GroupBootstrapJournalCommitResult::PersistenceFailed;
	}
	_pending.reset();
	_revision = revision;
	return GroupBootstrapJournalCommitResult::Cleared;
}

bool PersistentGroupBootstrapJournal::loaded() const {
	return _loaded;
}

const GroupBootstrapTransaction *PersistentGroupBootstrapJournal::pending()
		const {
	return _pending ? &*_pending : nullptr;
}

bool PersistentGroupBootstrapJournal::persist(
		const GroupBootstrapTransaction *transaction,
		std::uint64_t revision) const {
	if (!_conversationId || !revision) {
		return false;
	}
	auto plaintext = EncodeSnapshot(_conversationId, revision, transaction);
	if (plaintext.isEmpty()) {
		return false;
	}
	const auto protectedBytes = _protector.seal(
		Purpose(_conversationId),
		plaintext);
	Cleanse(plaintext);
	return protectedBytes && _blobStore.writeAtomic(*protectedBytes);
}

void PersistentGroupBootstrapJournal::reset() {
	_pending.reset();
	_conversationId = {};
	_revision = 0;
	_loaded = false;
}

GroupBootstrapTransactionCoordinator::GroupBootstrapTransactionCoordinator(
		PersistentGroupBootstrapJournal &journal,
		PersistentMlsStateStore &mlsState,
		PersistentArchiveState &archiveState,
		PersistentGroupLedger &groupLedger,
		PersistentOutboxStore &outbox,
		const EnvelopeCodecV1 &envelopeCodec,
		const Sha256Provider &sha256)
: _journal(journal)
, _mlsState(mlsState)
, _archiveState(archiveState)
, _groupLedger(groupLedger)
, _outbox(outbox)
, _envelopeCodec(envelopeCodec)
, _sha256(sha256) {
}

GroupBootstrapApplyStatus GroupBootstrapTransactionCoordinator::apply(
		GroupBootstrapTransaction transaction) {
	if (!_journal.loaded()
		|| !_mlsState.loaded()
		|| !_outbox.loaded()) {
		return GroupBootstrapApplyStatus::JournalUnavailable;
	} else if (transaction.outboxBaseRevision != _outbox.revision()) {
		return GroupBootstrapApplyStatus::RevisionConflict;
	}
	auto verified = VerifySignedGroupGenesisOutcome();
	if (!ValidBootstrapBundle(
		transaction,
		_envelopeCodec,
		_sha256,
		verified)) {
		return GroupBootstrapApplyStatus::InvalidTransaction;
	}
	switch (_journal.prepare(std::move(transaction))) {
	case GroupBootstrapJournalCommitResult::Prepared:
	case GroupBootstrapJournalCommitResult::AlreadyPrepared:
		return replay(false);
	case GroupBootstrapJournalCommitResult::NotLoaded:
		return GroupBootstrapApplyStatus::JournalUnavailable;
	case GroupBootstrapJournalCommitResult::InvalidTransaction:
		return GroupBootstrapApplyStatus::InvalidTransaction;
	case GroupBootstrapJournalCommitResult::TransactionConflict:
		return GroupBootstrapApplyStatus::RevisionConflict;
	case GroupBootstrapJournalCommitResult::PersistenceFailed:
	case GroupBootstrapJournalCommitResult::Cleared:
		return GroupBootstrapApplyStatus::JournalClearFailure;
	}
	return GroupBootstrapApplyStatus::InvalidTransaction;
}

GroupBootstrapApplyStatus GroupBootstrapTransactionCoordinator::recover() {
	return replay(true);
}

GroupBootstrapApplyStatus GroupBootstrapTransactionCoordinator::replay(
		bool recovery) {
	const auto transaction = _journal.pending();
	if (!transaction) {
		return GroupBootstrapApplyStatus::NoPendingTransaction;
	}
	auto verified = VerifySignedGroupGenesisOutcome();
	if (!ValidBootstrapBundle(
		*transaction,
		_envelopeCodec,
		_sha256,
		verified)
		|| !verified.verified) {
		return GroupBootstrapApplyStatus::InvalidTransaction;
	}
	if (_mlsState.revision() == 0) {
		if (_mlsState.initialize(
			OpenMlsEngineId(),
			transaction->mlsEngineState)
				!= MlsStateCommitResult::Committed) {
			return GroupBootstrapApplyStatus::MlsPersistenceFailure;
		}
	} else if (_mlsState.revision() != 1
		|| _mlsState.engineId() != OpenMlsEngineId()
		|| _mlsState.engineState() != transaction->mlsEngineState) {
		return GroupBootstrapApplyStatus::RevisionConflict;
	}
	if (_archiveState.revision() == 0) {
		if (_archiveState.initialize({
			.generation = transaction->archiveEpoch.generation,
			.activationGroupGeneration =
				transaction->archiveEpoch.activationGroupGeneration,
			.activationEventId =
				transaction->archiveEpoch.activationEventId,
			.key = transaction->archiveEpoch.key.clone(),
		}) != ArchiveStateCommitResult::Committed) {
			return GroupBootstrapApplyStatus::ArchivePersistenceFailure;
		}
	} else if (_archiveState.revision() != 1
		|| !_archiveState.currentEpoch()
		|| !SameArchiveEpoch(
			*_archiveState.currentEpoch(),
			transaction->archiveEpoch)) {
		return GroupBootstrapApplyStatus::RevisionConflict;
	}
	if (_groupLedger.revision() == 0) {
		if (_groupLedger.initialize(
			transaction->genesis,
			verified.verified->state,
			verified.verified->checkpoint,
			transaction->ownerCredential)
				!= GroupLedgerCommitResult::Committed) {
			return GroupBootstrapApplyStatus::GroupPersistenceFailure;
		}
	} else if (_groupLedger.revision() != 1
		|| _groupLedger.checkpoint() != verified.verified->checkpoint
		|| _groupLedger.events() != std::vector<GroupLedgerEvent>{ {
			.kind = GroupLedgerEventKind::Genesis,
			.generation = 1,
			.objectId = transaction->genesis.genesisObjectId,
			.bytes = *SignedGroupGenesisCodecV1().encode(
				transaction->genesis),
		} }) {
		return GroupBootstrapApplyStatus::RevisionConflict;
	}
	for (auto i = std::size_t(0);
			i != transaction->outboxEnvelopes.size();
			++i) {
		const auto &expected = transaction->outboxEnvelopes[i];
		const auto existing = _outbox.item(expected.objectId);
		if (existing) {
			if (existing->stage != OutboxItemStage::Sealed
				|| existing->sealed != expected) {
				return GroupBootstrapApplyStatus::RevisionConflict;
			}
			continue;
		} else if (_outbox.revision()
				!= transaction->outboxBaseRevision + i
			|| !_outbox.appendSealed(expected)) {
			return GroupBootstrapApplyStatus::OutboxPersistenceFailure;
		}
	}
	if (_journal.clear(transaction->genesis.genesisObjectId)
			!= GroupBootstrapJournalCommitResult::Cleared) {
		return GroupBootstrapApplyStatus::JournalClearFailure;
	}
	return recovery
		? GroupBootstrapApplyStatus::Recovered
		: GroupBootstrapApplyStatus::Applied;
}

GroupBootstrapTransaction MakeGroupBootstrapTransaction(
		PreparedProtectedGroupBootstrap &&prepared,
		const AccountCredentialPublic &ownerCredential,
		std::uint64_t outboxBaseRevision) {
	return {
		.conversationId = prepared.conversationId,
		.outboxBaseRevision = outboxBaseRevision,
		.genesis = prepared.genesis,
		.ownerCredential = ownerCredential,
		.initialMlsPublicObject =
			std::move(prepared.initialMlsPublicObject),
		.archiveEpoch = {
			.generation = prepared.archiveEpoch.generation,
			.activationGroupGeneration =
				prepared.archiveEpoch.activationGroupGeneration,
			.activationEventId = prepared.archiveEpoch.activationEventId,
			.key = std::move(prepared.archiveEpoch.key),
		},
		.mlsEngineState = std::move(prepared.mlsEngineState),
		.outboxEnvelopes = std::move(prepared.outboxEnvelopes),
	};
}

} // namespace E2ECloud

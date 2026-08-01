/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "e2e_cloud/protocol/group_change_inbox.h"

#include "e2e_cloud/mls/client_key_package.h"

#include <openssl/crypto.h>

#include <algorithm>
#include <array>
#include <limits>
#include <set>
#include <utility>

namespace E2ECloud {
namespace {

inline constexpr auto kMagic = std::array<std::uint8_t, 8>{
	'T', 'D', 'E', '2', 'E', 'G', 'I', 'B',
};
inline constexpr auto kPurpose = "TDE2E/local-group-change-inbox/v1";
inline constexpr auto kMaximumEnvelopes = std::size_t(4096);
inline constexpr auto kMaximumEnvelopeSize = 18 * 1024 * 1024;
inline constexpr auto kMaximumSnapshotSize = 64 * 1024 * 1024;

struct Reader {
	const QByteArray &bytes;
	int offset = 0;
};

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

void Cleanse(QByteArray &bytes) {
	if (!bytes.isEmpty()) {
		OPENSSL_cleanse(bytes.data(), bytes.size());
	}
	bytes.clear();
}

[[nodiscard]] QByteArray Purpose(ConversationId conversationId) {
	auto result = QByteArray(kPurpose);
	result.append('/');
	AppendArray(result, conversationId.bytes);
	return result;
}

[[nodiscard]] bool SupportedKind(ObjectKind kind) {
	return kind == ObjectKind::SignedGroupTransition
		|| kind == ObjectKind::MlsCommit
		|| kind == ObjectKind::ArchiveEpoch
		|| kind == ObjectKind::ClientKeyPackage
		|| kind == ObjectKind::MlsWelcome
		|| kind == ObjectKind::HistoryGrant;
}

[[nodiscard]] const StagedGroupChangeEnvelope *FindRecord(
		const std::vector<StagedGroupChangeEnvelope> &records,
		ObjectId objectId) {
	const auto i = std::find_if(
		std::begin(records),
		std::end(records),
		[&](const StagedGroupChangeEnvelope &record) {
			return record.envelope.objectId == objectId;
		});
	return (i == std::end(records)) ? nullptr : &*i;
}

[[nodiscard]] bool AadMatchesEnvelope(
		const MlsTransportAad &aad,
		const TransportEnvelope &envelope) {
	return aad.conversationId == envelope.conversationId
		&& aad.objectKind == envelope.objectKind
		&& aad.senderAccountId == envelope.senderAccountId
		&& aad.senderClientId == envelope.senderClientId
		&& aad.telegramPeerIdBinding == envelope.telegramPeerIdBinding
		&& aad.objectId == envelope.objectId;
}

} // namespace

PersistentGroupChangeInbox::PersistentGroupChangeInbox(
		AtomicBlobStore &blobStore,
		const LocalRecordProtector &protector,
		const EnvelopeCodec &envelopeCodec,
		const Sha256Provider &sha256)
: _blobStore(blobStore)
, _protector(protector)
, _envelopeCodec(envelopeCodec)
, _sha256(sha256) {
}

GroupChangeInboxLoadResult PersistentGroupChangeInbox::load(
		ConversationId conversationId) {
	_conversationId = {};
	_records.clear();
	_revision = 0;
	_loaded = false;
	if (!conversationId) {
		return GroupChangeInboxLoadResult::InvalidSnapshot;
	}
	const auto stored = _blobStore.read();
	if (stored.status == BlobReadStatus::Error) {
		return GroupChangeInboxLoadResult::StorageError;
	} else if (stored.status == BlobReadStatus::Missing) {
		_conversationId = conversationId;
		_loaded = true;
		return GroupChangeInboxLoadResult::Missing;
	}
	auto opened = _protector.open(Purpose(conversationId), stored.bytes);
	if (!opened) {
		return GroupChangeInboxLoadResult::AuthenticationFailed;
	}
	auto reader = Reader{ *opened };
	auto magic = std::array<std::uint8_t, 8>();
	auto version = std::uint16_t();
	auto storedConversationId = ConversationId();
	auto revision = std::uint64_t();
	auto count = std::uint32_t();
	if (!ReadArray(reader, magic)
		|| !ReadUint16(reader, version)
		|| !ReadArray(reader, storedConversationId.bytes)
		|| !ReadUint64(reader, revision)
		|| !ReadUint32(reader, count)
		|| magic != kMagic
		|| (version != 1 && version != 2)
		|| storedConversationId != conversationId
		|| !revision
		|| count > kMaximumEnvelopes) {
		Cleanse(*opened);
		return GroupChangeInboxLoadResult::InvalidSnapshot;
	}
	_conversationId = conversationId;
	auto records = std::vector<StagedGroupChangeEnvelope>();
	records.reserve(count);
	auto objectIds = std::set<ObjectId>();
	for (auto index = std::uint32_t(); index != count; ++index) {
		auto objectId = ObjectId();
		auto payloadHash = Digest();
		auto observedSenderTelegramUserIdBinding = std::uint64_t();
		auto encodedBytes = QByteArray();
		if (!ReadArray(reader, objectId.bytes)
			|| !ReadArray(reader, payloadHash.bytes)
			|| (version == 2
				&& !ReadUint64(
					reader,
					observedSenderTelegramUserIdBinding))
			|| !ReadBytes(reader, kMaximumEnvelopeSize, encodedBytes)) {
			Cleanse(*opened);
			return GroupChangeInboxLoadResult::InvalidSnapshot;
		}
		const auto envelope = _envelopeCodec.decode({
			.conversationId = conversationId,
			.objectId = objectId,
			.bytes = std::move(encodedBytes),
		});
		if (!envelope
			|| envelope->payloadHash != payloadHash
			|| !validEnvelope(*envelope)
			|| !objectIds.emplace(objectId).second) {
			Cleanse(*opened);
			return GroupChangeInboxLoadResult::InvalidSnapshot;
		}
		records.push_back({
			.envelope = *envelope,
			.observedSenderTelegramUserIdBinding
				= observedSenderTelegramUserIdBinding,
		});
	}
	const auto complete = reader.offset == reader.bytes.size();
	Cleanse(*opened);
	if (!complete) {
		return GroupChangeInboxLoadResult::InvalidSnapshot;
	}
	_records = std::move(records);
	_revision = revision;
	_loaded = true;
	return GroupChangeInboxLoadResult::Loaded;
}

GroupChangeInboxStageResult PersistentGroupChangeInbox::stage(
		const TransportEnvelope &envelope) {
	return stageRecord({ .envelope = envelope });
}

GroupChangeInboxStageResult PersistentGroupChangeInbox::stageObserved(
		const TransportEnvelope &envelope,
		std::uint64_t observedSenderTelegramUserIdBinding) {
	if (!observedSenderTelegramUserIdBinding) {
		return GroupChangeInboxStageResult::InvalidEnvelope;
	}
	return stageRecord({
		.envelope = envelope,
		.observedSenderTelegramUserIdBinding
			= observedSenderTelegramUserIdBinding,
	});
}

GroupChangeInboxStageResult PersistentGroupChangeInbox::stageRecord(
		StagedGroupChangeEnvelope record) {
	if (!_loaded) {
		return GroupChangeInboxStageResult::NotLoaded;
	} else if (!validEnvelope(record.envelope)) {
		return GroupChangeInboxStageResult::InvalidEnvelope;
	}
	const auto current = FindRecord(_records, record.envelope.objectId);
	if (current) {
		return (*current == record)
			? GroupChangeInboxStageResult::Duplicate
			: GroupChangeInboxStageResult::ObjectIdConflict;
	}
	const auto existing = lookup(
		record.envelope.objectId,
		record.envelope.payloadHash);
	if (existing == GroupChangeInboxLookup::Present) {
		return GroupChangeInboxStageResult::Duplicate;
	} else if (existing == GroupChangeInboxLookup::ObjectIdConflict) {
		return GroupChangeInboxStageResult::ObjectIdConflict;
	} else if (existing == GroupChangeInboxLookup::Unavailable) {
		return GroupChangeInboxStageResult::NotLoaded;
	} else if (_records.size() == kMaximumEnvelopes
		|| _revision == std::numeric_limits<std::uint64_t>::max()) {
		return GroupChangeInboxStageResult::CapacityExceeded;
	}
	auto records = _records;
	records.push_back(std::move(record));
	const auto revision = _revision + 1;
	if (!persist(records, revision)) {
		return GroupChangeInboxStageResult::PersistenceFailed;
	}
	_records = std::move(records);
	_revision = revision;
	return GroupChangeInboxStageResult::Staged;
}

GroupChangeInboxLookup PersistentGroupChangeInbox::lookup(
		ObjectId objectId,
		Digest payloadHash) const {
	if (!_loaded || !objectId || !payloadHash) {
		return GroupChangeInboxLookup::Unavailable;
	}
	const auto record = FindRecord(_records, objectId);
	if (!record) {
		return GroupChangeInboxLookup::Missing;
	}
	return (record->envelope.payloadHash == payloadHash)
		? GroupChangeInboxLookup::Present
		: GroupChangeInboxLookup::ObjectIdConflict;
}

GroupChangeInboxReadyResult PersistentGroupChangeInbox::ready(
		std::uint64_t previousGeneration) const {
	if (!_loaded || !previousGeneration) {
		return {
			.status = GroupChangeInboxReadyStatus::Unavailable,
			.bundle = std::nullopt,
		};
	}
	auto candidates = std::vector<
		std::pair<const TransportEnvelope*, SignedGroupTransition>>();
	for (const auto &record : _records) {
		const auto &envelope = record.envelope;
		if (envelope.objectKind != ObjectKind::SignedGroupTransition) {
			continue;
		}
		const auto transition = SignedGroupTransitionCodecV1().decode(
			envelope.payload);
		if (transition
			&& transition->transition.previousGeneration
				== previousGeneration
			&& transition->transition.generation
				== previousGeneration + 1) {
			candidates.emplace_back(&envelope, *transition);
		}
	}
	if (candidates.empty()) {
		return {
			.status = GroupChangeInboxReadyStatus::Incomplete,
			.bundle = std::nullopt,
		};
	} else if (candidates.size() != 1) {
		return {
			.status = GroupChangeInboxReadyStatus::ForkDetected,
			.bundle = std::nullopt,
		};
	}
	const auto &[transitionEnvelope, signedTransition] = candidates.front();
	const auto commitRecord = FindRecord(
		_records,
		signedTransition.mlsCommitObjectId);
	const auto distributionRecord = FindRecord(
		_records,
		signedTransition.archiveDistributionObjectId);
	if (!commitRecord || !distributionRecord) {
		return {
			.status = GroupChangeInboxReadyStatus::Incomplete,
			.bundle = std::nullopt,
		};
	}
	const auto &commitEnvelope = commitRecord->envelope;
	const auto &distributionEnvelope = distributionRecord->envelope;
	if (transitionEnvelope->objectId
			!= signedTransition.transition.transitionId
		|| transitionEnvelope->payloadHash
			!= _sha256.digest(transitionEnvelope->payload)
		|| commitEnvelope.objectKind != ObjectKind::MlsCommit
		|| commitEnvelope.payloadHash != signedTransition.mlsCommitHash
		|| distributionEnvelope.objectKind != ObjectKind::ArchiveEpoch
		|| distributionEnvelope.payloadHash
			!= signedTransition.archiveDistributionHash) {
		return {
			.status = GroupChangeInboxReadyStatus::ForkDetected,
			.bundle = std::nullopt,
		};
	}
	return {
		.status = GroupChangeInboxReadyStatus::Ready,
		.bundle = GroupChangeInboxBundle{
			.signedTransition = signedTransition,
			.transitionEnvelope = *transitionEnvelope,
			.commitEnvelope = commitEnvelope,
			.archiveDistributionEnvelope = distributionEnvelope,
		},
	};
}

std::vector<ForkRecoveryCandidate> PersistentGroupChangeInbox::candidates(
		std::uint64_t previousGeneration) const {
	if (!_loaded || !previousGeneration) {
		return {};
	}
	auto result = std::vector<ForkRecoveryCandidate>();
	for (const auto &record : _records) {
		const auto &envelope = record.envelope;
		if (envelope.objectKind != ObjectKind::SignedGroupTransition) {
			continue;
		}
		const auto transition = SignedGroupTransitionCodecV1().decode(
			envelope.payload);
		if (transition
			&& transition->transition.transitionId == envelope.objectId
			&& transition->transition.previousGeneration
				== previousGeneration
			&& transition->transition.generation
				== previousGeneration + 1
			&& envelope.payloadHash == _sha256.digest(envelope.payload)) {
			result.push_back({
				.transitionId = envelope.objectId,
				.transitionPayloadHash = envelope.payloadHash,
			});
		}
	}
	std::sort(
		begin(result),
		end(result),
		[](const auto &a, const auto &b) {
			return (a.transitionId != b.transitionId)
				? a.transitionId < b.transitionId
				: a.transitionPayloadHash < b.transitionPayloadHash;
		});
	return result;
}

bool PersistentGroupChangeInbox::discardBundle(ObjectId transitionId) {
	if (!_loaded || !transitionId) {
		return false;
	}
	const auto transitionRecord = FindRecord(_records, transitionId);
	if (!transitionRecord) {
		return true;
	}
	const auto transition = SignedGroupTransitionCodecV1().decode(
		transitionRecord->envelope.payload);
	if (!transition
		|| transition->transition.transitionId != transitionId
		|| _revision == std::numeric_limits<std::uint64_t>::max()) {
		return false;
	}
	auto objectIds = std::set<ObjectId>{
		transitionId,
		transition->mlsCommitObjectId,
		transition->archiveDistributionObjectId,
	};
	if (transition->targetClientAuthorization) {
		objectIds.emplace(
			transition->targetClientAuthorization->authorizationId);
	}
	const auto transitionPayload = transitionRecord->envelope.payload;
	auto records = _records;
	records.erase(
		std::remove_if(
			std::begin(records),
			std::end(records),
			[&](const StagedGroupChangeEnvelope &record) {
				return objectIds.contains(record.envelope.objectId)
					|| (record.envelope.objectKind
							== ObjectKind::MlsWelcome
						&& record.envelope.authenticationData
							== transitionPayload);
			}),
		std::end(records));
	const auto revision = _revision + 1;
	if (!persist(records, revision)) {
		return false;
	}
	_records = std::move(records);
	_revision = revision;
	return true;
}

bool PersistentGroupChangeInbox::discardAppliedTransitions(
		std::uint64_t generation) {
	if (!_loaded || !generation) {
		return false;
	}
	auto objectIds = std::set<ObjectId>();
	auto transitionPayloads = std::vector<QByteArray>();
	for (const auto &record : _records) {
		if (record.envelope.objectKind
				!= ObjectKind::SignedGroupTransition) {
			continue;
		}
		const auto transition = SignedGroupTransitionCodecV1().decode(
			record.envelope.payload);
		if (!transition
			|| transition->transition.generation > generation) {
			continue;
		}
		objectIds.emplace(record.envelope.objectId);
		objectIds.emplace(transition->mlsCommitObjectId);
		objectIds.emplace(transition->archiveDistributionObjectId);
		if (transition->targetClientAuthorization) {
			objectIds.emplace(
				transition->targetClientAuthorization->authorizationId);
		}
		transitionPayloads.push_back(record.envelope.payload);
	}
	if (objectIds.empty()) {
		return true;
	}
	auto records = _records;
	records.erase(
		std::remove_if(
			std::begin(records),
			std::end(records),
			[&](const StagedGroupChangeEnvelope &record) {
				return objectIds.contains(record.envelope.objectId)
					|| (record.envelope.objectKind
							== ObjectKind::MlsWelcome
						&& std::find(
							std::begin(transitionPayloads),
							std::end(transitionPayloads),
							record.envelope.authenticationData)
							!= std::end(transitionPayloads));
			}),
		std::end(records));
	if (_revision == std::numeric_limits<std::uint64_t>::max()) {
		return false;
	}
	const auto revision = _revision + 1;
	if (!persist(records, revision)) {
		return false;
	}
	_records = std::move(records);
	_revision = revision;
	return true;
}

bool PersistentGroupChangeInbox::discardExpiredKeyPackages(
		std::uint64_t currentTime) {
	if (!_loaded || !currentTime) {
		return false;
	}
	auto referenced = std::set<ObjectId>();
	for (const auto &record : _records) {
		if (record.envelope.objectKind
				!= ObjectKind::SignedGroupTransition) {
			continue;
		}
		const auto transition = SignedGroupTransitionCodecV1().decode(
			record.envelope.payload);
		if (transition && transition->targetClientAuthorization) {
			referenced.emplace(
				transition->targetClientAuthorization->authorizationId);
		}
	}
	auto records = _records;
	records.erase(
		std::remove_if(
			std::begin(records),
			std::end(records),
			[&](const StagedGroupChangeEnvelope &record) {
				if (record.envelope.objectKind
						!= ObjectKind::ClientKeyPackage
					|| referenced.contains(record.envelope.objectId)) {
					return false;
				}
				const auto publication
					= ClientKeyPackagePublicationCodecV1().decode(
						record.envelope.payload);
				return !publication
					|| publication->authorization.expiresAt <= currentTime;
			}),
		std::end(records));
	if (records.size() == _records.size()) {
		return true;
	} else if (_revision == std::numeric_limits<std::uint64_t>::max()) {
		return false;
	}
	const auto revision = _revision + 1;
	if (!persist(records, revision)) {
		return false;
	}
	_records = std::move(records);
	_revision = revision;
	return true;
}

bool PersistentGroupChangeInbox::discardJoinOnlyObjects() {
	if (!_loaded) {
		return false;
	}
	auto records = _records;
	records.erase(
		std::remove_if(
			std::begin(records),
			std::end(records),
			[](const StagedGroupChangeEnvelope &record) {
				return record.envelope.objectKind == ObjectKind::MlsWelcome
					|| record.envelope.objectKind
						== ObjectKind::HistoryGrant;
			}),
		std::end(records));
	if (records.size() == _records.size()) {
		return true;
	} else if (_revision == std::numeric_limits<std::uint64_t>::max()) {
		return false;
	}
	const auto revision = _revision + 1;
	if (!persist(records, revision)) {
		return false;
	}
	_records = std::move(records);
	_revision = revision;
	return true;
}

bool PersistentGroupChangeInbox::loaded() const {
	return _loaded;
}

std::size_t PersistentGroupChangeInbox::size() const {
	return _records.size();
}

std::uint64_t PersistentGroupChangeInbox::revision() const {
	return _revision;
}

auto PersistentGroupChangeInbox::records() const
-> const std::vector<StagedGroupChangeEnvelope> & {
	return _records;
}

bool PersistentGroupChangeInbox::persist(
		const std::vector<StagedGroupChangeEnvelope> &records,
		std::uint64_t revision) const {
	if (!_conversationId
		|| !revision
		|| records.size() > kMaximumEnvelopes) {
		return false;
	}
	auto plaintext = QByteArray();
	AppendArray(plaintext, kMagic);
	AppendUint16(plaintext, 2);
	AppendArray(plaintext, _conversationId.bytes);
	AppendUint64(plaintext, revision);
	AppendUint32(plaintext, std::uint32_t(records.size()));
	auto objectIds = std::set<ObjectId>();
	for (const auto &record : records) {
		const auto &envelope = record.envelope;
		const auto encoded = _envelopeCodec.encode(envelope);
		if (!validEnvelope(envelope)
			|| !objectIds.emplace(envelope.objectId).second
			|| !encoded
			|| encoded->bytes.size() > kMaximumEnvelopeSize) {
			Cleanse(plaintext);
			return false;
		}
		AppendArray(plaintext, envelope.objectId.bytes);
		AppendArray(plaintext, envelope.payloadHash.bytes);
		AppendUint64(
			plaintext,
			record.observedSenderTelegramUserIdBinding);
		AppendBytes(plaintext, encoded->bytes);
		if (plaintext.size() > kMaximumSnapshotSize) {
			Cleanse(plaintext);
			return false;
		}
	}
	const auto protectedBytes = _protector.seal(
		Purpose(_conversationId),
		plaintext);
	Cleanse(plaintext);
	return protectedBytes && _blobStore.writeAtomic(*protectedBytes);
}

bool PersistentGroupChangeInbox::validEnvelope(
		const TransportEnvelope &envelope) const {
	return envelope.conversationId == _conversationId
		&& SupportedKind(envelope.objectKind)
		&& ValidateEnvelope(envelope) == EnvelopeValidationError::None
		&& envelope.payloadHash == _sha256.digest(envelope.payload)
		&& envelope.payload.size() <= kMaximumEnvelopeSize;
}

GroupChangeInboxApplier::GroupChangeInboxApplier(
		PersistentGroupChangeInbox &inbox,
		const PersistentForkRecoveryLedger *forkLedger)
: _inbox(inbox)
, _forkLedger(forkLedger) {
}

InboundApplyResult GroupChangeInboxApplier::apply(
		const TransportEnvelope &envelope) {
	if (_forkLedger
		&& envelope.objectKind == ObjectKind::SignedGroupTransition) {
		const auto transition = SignedGroupTransitionCodecV1().decode(
			envelope.payload);
		if (!transition) {
			return InboundApplyResult::Rejected;
		}
		switch (_forkLedger->observe(
			transition->transition.previousGeneration,
			{
				.transitionId = envelope.objectId,
				.transitionPayloadHash = envelope.payloadHash,
			})) {
		case ForkRecoveryCandidateObservation::Known:
		case ForkRecoveryCandidateObservation::Unresolved:
			break;
		case ForkRecoveryCandidateObservation::HiddenCandidate:
		case ForkRecoveryCandidateObservation::ObjectIdConflict:
			return InboundApplyResult::ForkDetected;
		case ForkRecoveryCandidateObservation::Unavailable:
			return InboundApplyResult::Deferred;
		}
	}
	switch (_inbox.stage(envelope)) {
	case GroupChangeInboxStageResult::Staged:
	case GroupChangeInboxStageResult::Duplicate:
		return InboundApplyResult::Applied;
	case GroupChangeInboxStageResult::ObjectIdConflict:
		return InboundApplyResult::ForkDetected;
	case GroupChangeInboxStageResult::InvalidEnvelope:
		return InboundApplyResult::Rejected;
	case GroupChangeInboxStageResult::CapacityExceeded:
	case GroupChangeInboxStageResult::NotLoaded:
	case GroupChangeInboxStageResult::PersistenceFailed:
		return InboundApplyResult::Deferred;
	}
	return InboundApplyResult::Rejected;
}

InboundRecoveryResult GroupChangeInboxApplier::recover(
		const TransportEnvelope &envelope) const {
	switch (_inbox.lookup(envelope.objectId, envelope.payloadHash)) {
	case GroupChangeInboxLookup::Present:
		return InboundRecoveryResult::Applied;
	case GroupChangeInboxLookup::Missing:
		return InboundRecoveryResult::NotApplied;
	case GroupChangeInboxLookup::ObjectIdConflict:
	case GroupChangeInboxLookup::Unavailable:
		return InboundRecoveryResult::Unknown;
	}
	return InboundRecoveryResult::Unknown;
}

OpenMlsGroupChangeEnvelopeAuthenticator::
OpenMlsGroupChangeEnvelopeAuthenticator(
		const MlsContextCodecV1 &contextCodec,
		const GroupControlCodecV1 &controlCodec,
		const PersistentGroupLedger &groupLedger,
		const Sha256Provider &sha256)
: _contextCodec(contextCodec)
, _controlCodec(controlCodec)
, _groupLedger(groupLedger)
, _sha256(sha256) {
}

bool OpenMlsGroupChangeEnvelopeAuthenticator::authenticate(
		const TransportEnvelope &envelope) const {
	if (!_groupLedger.loaded()
		|| !_groupLedger.state()
		|| envelope.conversationId
			!= _groupLedger.state()->conversationId()
		|| envelope.payloadHash != _sha256.digest(envelope.payload)) {
		return false;
	}
	if (envelope.objectKind == ObjectKind::SignedGroupTransition) {
		const auto transition = SignedGroupTransitionCodecV1().decode(
			envelope.payload);
		if (!transition
			|| transition->transition.transitionId != envelope.objectId
			|| transition->transition.conversationId
				!= envelope.conversationId
			|| transition->transition.generation
				!= envelope.epochOrGeneration
			|| transition->actorAccountId != envelope.senderAccountId
			|| transition->actorClientId != envelope.senderClientId
			|| envelope.authenticationData.size()
				!= int(transition->actorSignature.size())
			|| !std::equal(
				std::begin(transition->actorSignature),
				std::end(transition->actorSignature),
				reinterpret_cast<const std::uint8_t*>(
					envelope.authenticationData.constData()))
			|| !_groupLedger.wasClientActiveAt(
				transition->actorAccountId,
				transition->actorClientId,
				transition->transition.previousGeneration)) {
			return false;
		}
		const auto credential = _groupLedger.credential(
			transition->actorAccountId);
		const auto signedBody = QByteArray(
			envelope.payload.constData(),
			envelope.payload.size() - int(transition->actorSignature.size()));
		return credential && VerifyAccountSignature(
			*credential,
			AccountSignatureDomain::GroupTransition,
			signedBody,
			transition->actorSignature);
	}
	if (envelope.objectKind != ObjectKind::MlsCommit
		&& envelope.objectKind != ObjectKind::ArchiveEpoch) {
		return false;
	}
	const auto aad = _contextCodec.decodeAad(envelope.authenticationData);
	if (!aad || !AadMatchesEnvelope(*aad, envelope)) {
		return false;
	}
	const auto preludeBytes = (envelope.objectKind == ObjectKind::MlsCommit)
		? aad->context
		: (aad->context.size() == kGroupChangePreludeEncodedSize + 32)
			? QByteArray(
				aad->context.constData(),
				kGroupChangePreludeEncodedSize)
			: QByteArray();
	const auto prelude = _controlCodec.decodePrelude(preludeBytes);
	return prelude
		&& prelude->transition.conversationId == envelope.conversationId
		&& prelude->actorAccountId == envelope.senderAccountId
		&& prelude->actorClientId == envelope.senderClientId
		&& _groupLedger.wasClientActiveAt(
			prelude->actorAccountId,
			prelude->actorClientId,
			prelude->transition.previousGeneration);
}

} // namespace E2ECloud

/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "e2e_cloud/protocol/group_change_inbox.h"

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
inline constexpr auto kMaximumEnvelopes = std::size_t(256);
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
		|| kind == ObjectKind::ArchiveEpoch;
}

[[nodiscard]] const TransportEnvelope *FindEnvelope(
		const std::vector<TransportEnvelope> &envelopes,
		ObjectId objectId) {
	const auto i = std::find_if(
		std::begin(envelopes),
		std::end(envelopes),
		[&](const TransportEnvelope &envelope) {
			return envelope.objectId == objectId;
		});
	return (i == std::end(envelopes)) ? nullptr : &*i;
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
	_envelopes.clear();
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
		|| version != 1
		|| storedConversationId != conversationId
		|| !revision
		|| count > kMaximumEnvelopes) {
		Cleanse(*opened);
		return GroupChangeInboxLoadResult::InvalidSnapshot;
	}
	_conversationId = conversationId;
	auto envelopes = std::vector<TransportEnvelope>();
	envelopes.reserve(count);
	auto objectIds = std::set<ObjectId>();
	for (auto index = std::uint32_t(); index != count; ++index) {
		auto objectId = ObjectId();
		auto payloadHash = Digest();
		auto encodedBytes = QByteArray();
		if (!ReadArray(reader, objectId.bytes)
			|| !ReadArray(reader, payloadHash.bytes)
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
		envelopes.push_back(*envelope);
	}
	const auto complete = reader.offset == reader.bytes.size();
	Cleanse(*opened);
	if (!complete) {
		return GroupChangeInboxLoadResult::InvalidSnapshot;
	}
	_envelopes = std::move(envelopes);
	_revision = revision;
	_loaded = true;
	return GroupChangeInboxLoadResult::Loaded;
}

GroupChangeInboxStageResult PersistentGroupChangeInbox::stage(
		const TransportEnvelope &envelope) {
	if (!_loaded) {
		return GroupChangeInboxStageResult::NotLoaded;
	} else if (!validEnvelope(envelope)) {
		return GroupChangeInboxStageResult::InvalidEnvelope;
	}
	const auto existing = lookup(envelope.objectId, envelope.payloadHash);
	if (existing == GroupChangeInboxLookup::Present) {
		return GroupChangeInboxStageResult::Duplicate;
	} else if (existing == GroupChangeInboxLookup::ObjectIdConflict) {
		return GroupChangeInboxStageResult::ObjectIdConflict;
	} else if (existing == GroupChangeInboxLookup::Unavailable) {
		return GroupChangeInboxStageResult::NotLoaded;
	} else if (_envelopes.size() == kMaximumEnvelopes
		|| _revision == std::numeric_limits<std::uint64_t>::max()) {
		return GroupChangeInboxStageResult::CapacityExceeded;
	}
	auto envelopes = _envelopes;
	envelopes.push_back(envelope);
	const auto revision = _revision + 1;
	if (!persist(envelopes, revision)) {
		return GroupChangeInboxStageResult::PersistenceFailed;
	}
	_envelopes = std::move(envelopes);
	_revision = revision;
	return GroupChangeInboxStageResult::Staged;
}

GroupChangeInboxLookup PersistentGroupChangeInbox::lookup(
		ObjectId objectId,
		Digest payloadHash) const {
	if (!_loaded || !objectId || !payloadHash) {
		return GroupChangeInboxLookup::Unavailable;
	}
	const auto envelope = FindEnvelope(_envelopes, objectId);
	if (!envelope) {
		return GroupChangeInboxLookup::Missing;
	}
	return (envelope->payloadHash == payloadHash)
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
	for (const auto &envelope : _envelopes) {
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
	const auto commitEnvelope = FindEnvelope(
		_envelopes,
		signedTransition.mlsCommitObjectId);
	const auto distributionEnvelope = FindEnvelope(
		_envelopes,
		signedTransition.archiveDistributionObjectId);
	if (!commitEnvelope || !distributionEnvelope) {
		return {
			.status = GroupChangeInboxReadyStatus::Incomplete,
			.bundle = std::nullopt,
		};
	} else if (transitionEnvelope->objectId
			!= signedTransition.transition.transitionId
		|| transitionEnvelope->payloadHash
			!= _sha256.digest(transitionEnvelope->payload)
		|| commitEnvelope->objectKind != ObjectKind::MlsCommit
		|| commitEnvelope->payloadHash != signedTransition.mlsCommitHash
		|| distributionEnvelope->objectKind != ObjectKind::ArchiveEpoch
		|| distributionEnvelope->payloadHash
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
			.commitEnvelope = *commitEnvelope,
			.archiveDistributionEnvelope = *distributionEnvelope,
		},
	};
}

std::vector<ForkRecoveryCandidate> PersistentGroupChangeInbox::candidates(
		std::uint64_t previousGeneration) const {
	if (!_loaded || !previousGeneration) {
		return {};
	}
	auto result = std::vector<ForkRecoveryCandidate>();
	for (const auto &envelope : _envelopes) {
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
	const auto transitionEnvelope = FindEnvelope(_envelopes, transitionId);
	if (!transitionEnvelope) {
		return true;
	}
	const auto transition = SignedGroupTransitionCodecV1().decode(
		transitionEnvelope->payload);
	if (!transition
		|| transition->transition.transitionId != transitionId
		|| _revision == std::numeric_limits<std::uint64_t>::max()) {
		return false;
	}
	const auto objectIds = std::set<ObjectId>{
		transitionId,
		transition->mlsCommitObjectId,
		transition->archiveDistributionObjectId,
	};
	auto envelopes = _envelopes;
	envelopes.erase(
		std::remove_if(
			std::begin(envelopes),
			std::end(envelopes),
			[&](const TransportEnvelope &envelope) {
				return objectIds.contains(envelope.objectId);
			}),
		std::end(envelopes));
	const auto revision = _revision + 1;
	if (!persist(envelopes, revision)) {
		return false;
	}
	_envelopes = std::move(envelopes);
	_revision = revision;
	return true;
}

bool PersistentGroupChangeInbox::loaded() const {
	return _loaded;
}

std::size_t PersistentGroupChangeInbox::size() const {
	return _envelopes.size();
}

std::uint64_t PersistentGroupChangeInbox::revision() const {
	return _revision;
}

bool PersistentGroupChangeInbox::persist(
		const std::vector<TransportEnvelope> &envelopes,
		std::uint64_t revision) const {
	if (!_conversationId
		|| !revision
		|| envelopes.size() > kMaximumEnvelopes) {
		return false;
	}
	auto plaintext = QByteArray();
	AppendArray(plaintext, kMagic);
	AppendUint16(plaintext, 1);
	AppendArray(plaintext, _conversationId.bytes);
	AppendUint64(plaintext, revision);
	AppendUint32(plaintext, std::uint32_t(envelopes.size()));
	auto objectIds = std::set<ObjectId>();
	for (const auto &envelope : envelopes) {
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

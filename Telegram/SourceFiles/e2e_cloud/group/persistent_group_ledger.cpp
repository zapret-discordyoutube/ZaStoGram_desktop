/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "e2e_cloud/group/persistent_group_ledger.h"

#include "e2e_cloud/group/group_state_codec.h"

#include <algorithm>
#include <array>
#include <limits>
#include <set>
#include <utility>

namespace E2ECloud {
namespace {

inline constexpr auto kMagic = std::array<std::uint8_t, 8>{
	'T', 'D', 'E', '2', 'E', 'G', 'L', 'D',
};
inline constexpr auto kPurpose = "TDE2E/local-group-ledger/v1";
inline constexpr auto kMaximumCredentials = 4096;
inline constexpr auto kMaximumEvents = 65'536;
inline constexpr auto kMaximumStateSize = 16 * 1024 * 1024;
inline constexpr auto kMaximumEventSize = kMaximumForkRecoveryManifestSize;
inline constexpr auto kMaximumSnapshotSize = 64 * 1024 * 1024;

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

[[nodiscard]] QByteArray Purpose(ConversationId conversationId) {
	auto result = QByteArray(kPurpose);
	result.append('/');
	AppendArray(result, conversationId.bytes);
	return result;
}

[[nodiscard]] std::optional<Digest> EventStateHash(
		const GroupLedgerEvent &event,
		const Sha256Provider &sha256) {
	switch (event.kind) {
	case GroupLedgerEventKind::Genesis:
		return sha256.digest(event.bytes);
	case GroupLedgerEventKind::Transition: {
		const auto transition = SignedGroupTransitionCodecV1().decode(
			event.bytes);
		const auto checkpoint = transition
			? DeriveSignedGroupTransitionCheckpoint(*transition, sha256)
			: std::nullopt;
		return checkpoint
			? std::optional<Digest>(checkpoint->stateHash)
			: std::nullopt;
	}
	case GroupLedgerEventKind::ForkRecovery:
		return SignedForkRecoveryManifestCodecV1().decode(event.bytes)
			? std::optional<Digest>(sha256.digest(event.bytes))
			: std::nullopt;
	}
	return std::nullopt;
}

} // namespace

PersistentGroupLedger::PersistentGroupLedger(
		AtomicBlobStore &blobStore,
		const LocalRecordProtector &protector,
		const Sha256Provider &sha256)
: _blobStore(blobStore)
, _protector(protector)
, _sha256(sha256) {
}

GroupLedgerLoadResult PersistentGroupLedger::load(
		ConversationId conversationId) {
	clear();
	if (!conversationId) {
		return GroupLedgerLoadResult::InvalidSnapshot;
	}
	const auto stored = _blobStore.read();
	if (stored.status == BlobReadStatus::Error) {
		return GroupLedgerLoadResult::StorageError;
	} else if (stored.status == BlobReadStatus::Missing) {
		_conversationId = conversationId;
		return GroupLedgerLoadResult::Missing;
	}
	auto opened = _protector.open(Purpose(conversationId), stored.bytes);
	if (!opened) {
		return GroupLedgerLoadResult::AuthenticationFailed;
	}
	auto reader = Reader{ *opened };
	auto magic = std::array<std::uint8_t, 8>();
	auto version = std::uint16_t();
	auto revision = std::uint64_t();
	auto storedConversationId = ConversationId();
	auto checkpoint = Checkpoint();
	auto stateBytes = QByteArray();
	auto credentialCount = std::uint32_t();
	if (!ReadArray(reader, magic)
		|| !ReadUint16(reader, version)
		|| !ReadArray(reader, storedConversationId.bytes)
		|| !ReadUint64(reader, revision)
		|| !ReadUint64(reader, checkpoint.generation)
		|| !ReadArray(reader, checkpoint.stateHash.bytes)
		|| !ReadBytes(reader, kMaximumStateSize, stateBytes)
		|| !ReadUint32(reader, credentialCount)
		|| magic != kMagic
		|| version != 1
		|| storedConversationId != conversationId
		|| !revision
		|| !checkpoint.generation
		|| !checkpoint.stateHash
		|| !credentialCount
		|| credentialCount > kMaximumCredentials) {
		std::fill_n(opened->data(), opened->size(), char(0));
		return GroupLedgerLoadResult::InvalidSnapshot;
	}
	checkpoint.conversationId = conversationId;
	auto state = ProtectedGroupStateCodecV1().decode(stateBytes);
	if (!state) {
		std::fill_n(opened->data(), opened->size(), char(0));
		return GroupLedgerLoadResult::InvalidSnapshot;
	}
	auto credentials = std::vector<CredentialRecord>();
	credentials.reserve(credentialCount);
	auto accountIds = std::set<AccountId>();
	for (auto index = std::uint32_t(); index != credentialCount; ++index) {
		auto accountId = AccountId();
		auto credentialBytes = QByteArray();
		if (!ReadArray(reader, accountId.bytes)
			|| !ReadBytes(
				reader,
				kAccountCredentialEncodedSize,
				credentialBytes)
			|| credentialBytes.size() != kAccountCredentialEncodedSize) {
			std::fill_n(opened->data(), opened->size(), char(0));
			return GroupLedgerLoadResult::InvalidSnapshot;
		}
		const auto credential = AccountCredentialCodecV1().decode(
			credentialBytes);
		const auto derived = credential
			? DeriveAccountId(*credential, _sha256)
			: std::nullopt;
		if (!credential
			|| !derived
			|| *derived != accountId
			|| !accountIds.emplace(accountId).second) {
			std::fill_n(opened->data(), opened->size(), char(0));
			return GroupLedgerLoadResult::InvalidSnapshot;
		}
		credentials.push_back({ accountId, *credential });
	}
	auto eventCount = std::uint32_t();
	if (!ReadUint32(reader, eventCount)
		|| !eventCount
		|| eventCount > kMaximumEvents) {
		std::fill_n(opened->data(), opened->size(), char(0));
		return GroupLedgerLoadResult::InvalidSnapshot;
	}
	auto events = std::vector<GroupLedgerEvent>();
	events.reserve(eventCount);
	for (auto index = std::uint32_t(); index != eventCount; ++index) {
		auto kind = std::uint8_t();
		auto event = GroupLedgerEvent();
		if (!ReadUint8(reader, kind)
			|| !ReadUint64(reader, event.generation)
			|| !ReadArray(reader, event.objectId.bytes)
			|| !ReadBytes(reader, kMaximumEventSize, event.bytes)
			|| (kind != std::uint8_t(GroupLedgerEventKind::Genesis)
				&& kind != std::uint8_t(
					GroupLedgerEventKind::Transition)
				&& kind != std::uint8_t(
					GroupLedgerEventKind::ForkRecovery))) {
			std::fill_n(opened->data(), opened->size(), char(0));
			return GroupLedgerLoadResult::InvalidSnapshot;
		}
		event.kind = GroupLedgerEventKind(kind);
		events.push_back(std::move(event));
	}
	std::fill_n(opened->data(), opened->size(), char(0));
	if (reader.offset != reader.bytes.size()
		|| state->conversationId() != conversationId
		|| checkpoint.generation != state->generation()
		|| events.size() != state->generation()
		|| events.front().kind != GroupLedgerEventKind::Genesis
		|| events.front().generation != 1) {
		return GroupLedgerLoadResult::InvalidSnapshot;
	}
	const auto genesis = SignedGroupGenesisCodecV1().decode(
		events.front().bytes);
	if (!genesis
		|| genesis->conversationId != conversationId
		|| genesis->genesisObjectId != events.front().objectId) {
		return GroupLedgerLoadResult::InvalidSnapshot;
	}
	auto running = _sha256.digest(events.front().bytes);
	for (auto index = std::size_t(1); index != events.size(); ++index) {
		const auto &event = events[index];
		if (event.generation != index + 1) {
			return GroupLedgerLoadResult::InvalidSnapshot;
		}
		if (event.kind == GroupLedgerEventKind::Transition) {
			const auto transition = SignedGroupTransitionCodecV1().decode(
				event.bytes);
			const auto derived = transition
				? DeriveSignedGroupTransitionCheckpoint(
					*transition,
					_sha256)
				: std::nullopt;
			if (!transition
				|| transition->transition.transitionId != event.objectId
				|| transition->previousStateHash != running
				|| !derived) {
				return GroupLedgerLoadResult::InvalidSnapshot;
			}
			running = derived->stateHash;
		} else if (event.kind == GroupLedgerEventKind::ForkRecovery) {
			const auto manifest = SignedForkRecoveryManifestCodecV1().decode(
				event.bytes);
			const auto &canonicalEvent = events[index - 1];
			const auto commonHash = manifest
				&& manifest->commonGeneration
				&& manifest->commonGeneration <= index
				? EventStateHash(
					events[manifest->commonGeneration - 1],
					_sha256)
				: std::nullopt;
			const auto ownerCredential = manifest
				? std::find_if(
					begin(credentials),
					end(credentials),
					[&](const auto &record) {
						return record.accountId
							== manifest->ownerAccountId;
					})
				: end(credentials);
			if (!manifest
				|| manifest->recoveryId != event.objectId
				|| manifest->recoveryGeneration != event.generation
				|| manifest->resolvedGeneration + 1
					!= manifest->recoveryGeneration
				|| manifest->resolvedGeneration != canonicalEvent.generation
				|| canonicalEvent.kind
					!= GroupLedgerEventKind::Transition
				|| manifest->canonicalTransitionId
					!= canonicalEvent.objectId
				|| manifest->canonicalTransitionPayloadHash
					!= _sha256.digest(canonicalEvent.bytes)
				|| manifest->canonicalStateHash != running
				|| !commonHash
				|| *commonHash != manifest->commonStateHash
				|| ownerCredential == end(credentials)
				|| !VerifySignedForkRecoveryManifestSignature(
					*manifest,
					ownerCredential->credential,
					_sha256)) {
				return GroupLedgerLoadResult::InvalidSnapshot;
			}
			running = _sha256.digest(event.bytes);
		} else {
			return GroupLedgerLoadResult::InvalidSnapshot;
		}
	}
	if (running != checkpoint.stateHash
		|| (state->generation() > 1
			&& state->lastTransitionId() != events.back().objectId)) {
		return GroupLedgerLoadResult::InvalidSnapshot;
	}
	for (const auto &member : state->members()) {
		if (!accountIds.contains(member.accountId)) {
			return GroupLedgerLoadResult::InvalidSnapshot;
		}
	}
	_conversationId = conversationId;
	_state = std::move(*state);
	_checkpoint = checkpoint;
	_credentials = std::move(credentials);
	_events = std::move(events);
	_revision = revision;
	_loaded = true;
	const auto replayed = stateAt(_checkpoint.generation);
	if (!replayed || replayed->snapshot() != _state->snapshot()) {
		clear();
		return GroupLedgerLoadResult::InvalidSnapshot;
	}
	for (const auto &event : _events) {
		if (event.kind != GroupLedgerEventKind::ForkRecovery) {
			continue;
		}
		const auto manifest = SignedForkRecoveryManifestCodecV1().decode(
			event.bytes);
		const auto commonState = manifest
			? stateAt(manifest->commonGeneration)
			: std::nullopt;
		const auto owner = commonState && manifest
			? commonState->member(manifest->ownerAccountId)
			: nullptr;
		if (!manifest
			|| !owner
			|| owner->role != GroupRole::Owner
			|| std::find(
				begin(owner->clients),
				end(owner->clients),
				manifest->ownerClientId) == end(owner->clients)) {
			clear();
			return GroupLedgerLoadResult::InvalidSnapshot;
		}
	}
	return GroupLedgerLoadResult::Loaded;
}

GroupLedgerCommitResult PersistentGroupLedger::initialize(
		const SignedGroupGenesis &genesis,
		const ProtectedGroupState &state,
		const Checkpoint &checkpoint,
		const AccountCredentialPublic &ownerCredential) {
	const auto encoded = SignedGroupGenesisCodecV1().encode(genesis);
	const auto ownerAccountId = DeriveAccountId(ownerCredential, _sha256);
	if (_loaded
		|| !_conversationId
		|| !encoded
		|| genesis.conversationId != _conversationId
		|| state.conversationId() != _conversationId
		|| state.generation() != 1
		|| checkpoint.conversationId != _conversationId
		|| checkpoint.generation != 1
		|| checkpoint.stateHash != _sha256.digest(*encoded)
		|| !ownerAccountId
		|| *ownerAccountId != genesis.ownerAccountId
		|| !state.member(*ownerAccountId)) {
		return GroupLedgerCommitResult::InvalidMutation;
	}
	auto credentials = std::vector<CredentialRecord>{
		{ *ownerAccountId, ownerCredential },
	};
	auto events = std::vector<GroupLedgerEvent>{
		{
			.kind = GroupLedgerEventKind::Genesis,
			.generation = 1,
			.objectId = genesis.genesisObjectId,
			.bytes = *encoded,
		},
	};
	if (!persist(state, checkpoint, credentials, events, 1)) {
		return GroupLedgerCommitResult::PersistenceFailed;
	}
	_state = state;
	_checkpoint = checkpoint;
	_credentials = std::move(credentials);
	_events = std::move(events);
	_revision = 1;
	_loaded = true;
	return GroupLedgerCommitResult::Committed;
}

GroupLedgerCommitResult PersistentGroupLedger::commitTransition(
		std::uint64_t baseRevision,
		const SignedGroupTransition &signedTransition,
		const AppliedSignedGroupTransition &applied,
		const AccountCredentialPublic *admittedCredential) {
	if (!_loaded || !_state) {
		return GroupLedgerCommitResult::NotLoaded;
	}
	const auto encoded = SignedGroupTransitionCodecV1().encode(
		signedTransition);
	if (!encoded) {
		return GroupLedgerCommitResult::InvalidMutation;
	}
	if (signedTransition.transition.generation <= _checkpoint.generation) {
		return (!_events.empty()
			&& _events.back().generation
				== signedTransition.transition.generation
			&& _events.back().bytes == *encoded)
			? GroupLedgerCommitResult::AlreadyCommitted
			: GroupLedgerCommitResult::HistoryConflict;
	} else if (baseRevision != _revision) {
		return GroupLedgerCommitResult::RevisionConflict;
	} else if (_revision == std::numeric_limits<std::uint64_t>::max()
		|| _events.size() >= kMaximumEvents
		|| signedTransition.transition.generation
			!= _checkpoint.generation + 1
		|| signedTransition.previousStateHash != _checkpoint.stateHash
		|| applied.state.conversationId() != _conversationId
		|| applied.state.generation()
			!= signedTransition.transition.generation
		|| applied.state.lastTransitionId()
			!= signedTransition.transition.transitionId
		|| applied.checkpoint.conversationId != _conversationId
		|| applied.checkpoint.generation != applied.state.generation()
		|| applied.checkpoint.stateHash
			!= signedTransition.resultingStateHash
		|| (applied.archiveEpoch
			&& (applied.archiveEpoch->generation
					!= signedTransition.transition.generation
				|| applied.archiveEpoch->activationGroupGeneration
					!= signedTransition.transition.generation
				|| applied.archiveEpoch->activationEventId
					!= signedTransition.transition.transitionId
				|| DeriveArchiveKeyCommitment(
					signedTransition.transition.conversationId,
					applied.archiveEpoch->generation,
					applied.archiveEpoch->activationGroupGeneration,
					applied.archiveEpoch->activationEventId,
					applied.archiveEpoch->key,
					_sha256) != signedTransition.archiveKeyCommitment))) {
		return GroupLedgerCommitResult::InvalidMutation;
	}
	auto credentials = _credentials;
	if (signedTransition.transition.kind == GroupTransitionKind::AddMember) {
		if (!admittedCredential) {
			return GroupLedgerCommitResult::InvalidMutation;
		}
		const auto accountId = DeriveAccountId(*admittedCredential, _sha256);
		if (!accountId
			|| *accountId != signedTransition.transition.targetAccountId) {
			return GroupLedgerCommitResult::InvalidMutation;
		}
		const auto existing = std::find_if(
			credentials.begin(),
			credentials.end(),
			[&](const auto &record) {
				return record.accountId == *accountId;
			});
		if (existing == credentials.end()) {
			credentials.push_back({ *accountId, *admittedCredential });
		} else if (existing->credential != *admittedCredential) {
			return GroupLedgerCommitResult::HistoryConflict;
		}
	}
	auto events = _events;
	events.push_back({
		.kind = GroupLedgerEventKind::Transition,
		.generation = signedTransition.transition.generation,
		.objectId = signedTransition.transition.transitionId,
		.bytes = *encoded,
	});
	const auto revision = _revision + 1;
	if (!persist(
			applied.state,
			applied.checkpoint,
			credentials,
			events,
			revision)) {
		return GroupLedgerCommitResult::PersistenceFailed;
	}
	_state = applied.state;
	_checkpoint = applied.checkpoint;
	_credentials = std::move(credentials);
	_events = std::move(events);
	_revision = revision;
	return GroupLedgerCommitResult::Committed;
}

GroupLedgerCommitResult PersistentGroupLedger::commitVerifiedForkRecovery(
		std::uint64_t baseRevision,
		const SignedForkRecoveryManifest &manifest,
		const ArchiveEpochSecret &archiveEpoch) {
	if (!_loaded || !_state) {
		return GroupLedgerCommitResult::NotLoaded;
	}
	const auto encoded = SignedForkRecoveryManifestCodecV1().encode(manifest);
	if (!encoded) {
		return GroupLedgerCommitResult::InvalidMutation;
	}
	if (manifest.recoveryGeneration <= _checkpoint.generation) {
		return (!_events.empty()
			&& _events.back().generation == manifest.recoveryGeneration
			&& _events.back().bytes == *encoded)
			? GroupLedgerCommitResult::AlreadyCommitted
			: GroupLedgerCommitResult::HistoryConflict;
	} else if (baseRevision != _revision) {
		return GroupLedgerCommitResult::RevisionConflict;
	}
	if (_revision == std::numeric_limits<std::uint64_t>::max()
		|| _events.size() >= kMaximumEvents
		|| manifest.conversationId != _conversationId
		|| manifest.commonGeneration + 1 != _checkpoint.generation
		|| manifest.resolvedGeneration != _checkpoint.generation
		|| manifest.recoveryGeneration != _checkpoint.generation + 1
		|| manifest.canonicalStateHash != _checkpoint.stateHash
		|| _events.size() < 2
		|| manifest.commonGeneration > _events.size()) {
		return GroupLedgerCommitResult::InvalidMutation;
	}
	const auto &canonicalEvent = _events.back();
	const auto commonHash = EventStateHash(
		_events[manifest.commonGeneration - 1],
		_sha256);
	const auto commonState = stateAt(manifest.commonGeneration);
	const auto owner = commonState
		? commonState->member(manifest.ownerAccountId)
		: nullptr;
	const auto ownerCredential = credential(manifest.ownerAccountId);
	if (canonicalEvent.kind != GroupLedgerEventKind::Transition
		|| canonicalEvent.objectId != manifest.canonicalTransitionId
		|| _sha256.digest(canonicalEvent.bytes)
			!= manifest.canonicalTransitionPayloadHash
		|| !commonHash
		|| *commonHash != manifest.commonStateHash
		|| !owner
		|| owner->role != GroupRole::Owner
		|| std::find(
			begin(owner->clients),
			end(owner->clients),
			manifest.ownerClientId) == end(owner->clients)
		|| !ownerCredential
		|| !VerifySignedForkRecoveryManifestSignature(
			manifest,
			*ownerCredential,
			_sha256)
		|| archiveEpoch.generation != manifest.recoveryGeneration
		|| archiveEpoch.activationGroupGeneration
			!= manifest.recoveryGeneration
		|| archiveEpoch.activationEventId != manifest.recoveryId
		|| !archiveEpoch.key.valid()
		|| DeriveArchiveKeyCommitment(
			manifest.conversationId,
			manifest.recoveryGeneration,
			manifest.recoveryGeneration,
			manifest.recoveryId,
			archiveEpoch.key,
			_sha256) != manifest.archiveKeyCommitment) {
		return GroupLedgerCommitResult::InvalidMutation;
	}
	auto state = *_state;
	if (!state.applyVerifiedForkRecovery(
			manifest.recoveryId,
			manifest.resolvedGeneration)
		|| state.generation() != manifest.recoveryGeneration) {
		return GroupLedgerCommitResult::InvalidMutation;
	}
	auto events = _events;
	events.push_back({
		.kind = GroupLedgerEventKind::ForkRecovery,
		.generation = manifest.recoveryGeneration,
		.objectId = manifest.recoveryId,
		.bytes = *encoded,
	});
	const auto checkpoint = Checkpoint{
		.conversationId = _conversationId,
		.generation = manifest.recoveryGeneration,
		.stateHash = _sha256.digest(*encoded),
	};
	const auto revision = _revision + 1;
	if (!persist(
			state,
			checkpoint,
			_credentials,
			events,
			revision)) {
		return GroupLedgerCommitResult::PersistenceFailed;
	}
	_state = std::move(state);
	_checkpoint = checkpoint;
	_events = std::move(events);
	_revision = revision;
	return GroupLedgerCommitResult::Committed;
}

GroupLedgerCommitResult
PersistentGroupLedger::replaceForkBranchAndCommitRecovery(
		std::uint64_t baseRevision,
		const SignedGroupTransition &canonicalTransition,
		const AppliedSignedGroupTransition &canonicalApplied,
		const AccountCredentialPublic *admittedCredential,
		const SignedForkRecoveryManifest &manifest,
		const ArchiveEpochSecret &archiveEpoch) {
	if (!_loaded || !_state) {
		return GroupLedgerCommitResult::NotLoaded;
	}
	const auto encodedTransition = SignedGroupTransitionCodecV1().encode(
		canonicalTransition);
	const auto encodedManifest = SignedForkRecoveryManifestCodecV1().encode(
		manifest);
	if (!encodedTransition || !encodedManifest) {
		return GroupLedgerCommitResult::InvalidMutation;
	}
	if (manifest.recoveryGeneration <= _checkpoint.generation) {
		return (!_events.empty()
			&& _events.back().generation == manifest.recoveryGeneration
			&& _events.back().bytes == *encodedManifest)
			? GroupLedgerCommitResult::AlreadyCommitted
			: GroupLedgerCommitResult::HistoryConflict;
	} else if (baseRevision != _revision) {
		return GroupLedgerCommitResult::RevisionConflict;
	}
	if (_revision == std::numeric_limits<std::uint64_t>::max()
		|| _events.size() >= kMaximumEvents
		|| manifest.conversationId != _conversationId
		|| manifest.resolvedGeneration != _checkpoint.generation
		|| manifest.commonGeneration + 1 != manifest.resolvedGeneration
		|| manifest.recoveryGeneration != manifest.resolvedGeneration + 1
		|| _events.size() != manifest.resolvedGeneration
		|| _events.size() < 2
		|| _events.back().kind != GroupLedgerEventKind::Transition) {
		return GroupLedgerCommitResult::InvalidMutation;
	}
	const auto currentCandidate = ForkRecoveryCandidate{
		.transitionId = _events.back().objectId,
		.transitionPayloadHash = _sha256.digest(_events.back().bytes),
	};
	const auto canonicalCandidate = ForkRecoveryCandidate{
		.transitionId = canonicalTransition.transition.transitionId,
		.transitionPayloadHash = _sha256.digest(*encodedTransition),
	};
	const auto commonHash = EventStateHash(
		_events[manifest.commonGeneration - 1],
		_sha256);
	const auto commonState = stateAt(manifest.commonGeneration);
	const auto owner = commonState
		? commonState->member(manifest.ownerAccountId)
		: nullptr;
	const auto ownerCredential = credential(manifest.ownerAccountId);
	if (std::find(
			begin(manifest.candidates),
			end(manifest.candidates),
			currentCandidate) == end(manifest.candidates)
		|| canonicalCandidate.transitionId
			!= manifest.canonicalTransitionId
		|| canonicalCandidate.transitionPayloadHash
			!= manifest.canonicalTransitionPayloadHash
		|| std::find(
			begin(manifest.candidates),
			end(manifest.candidates),
			canonicalCandidate) == end(manifest.candidates)
		|| canonicalTransition.transition.previousGeneration
			!= manifest.commonGeneration
		|| canonicalTransition.transition.generation
			!= manifest.resolvedGeneration
		|| canonicalTransition.previousStateHash != manifest.commonStateHash
		|| canonicalTransition.resultingStateHash
			!= manifest.canonicalStateHash
		|| canonicalApplied.state.conversationId() != _conversationId
		|| canonicalApplied.state.generation()
			!= manifest.resolvedGeneration
		|| canonicalApplied.state.lastTransitionId()
			!= manifest.canonicalTransitionId
		|| canonicalApplied.checkpoint.conversationId != _conversationId
		|| canonicalApplied.checkpoint.generation
			!= manifest.resolvedGeneration
		|| canonicalApplied.checkpoint.stateHash
			!= manifest.canonicalStateHash
		|| !commonHash
		|| *commonHash != manifest.commonStateHash
		|| !owner
		|| owner->role != GroupRole::Owner
		|| std::find(
			begin(owner->clients),
			end(owner->clients),
			manifest.ownerClientId) == end(owner->clients)
		|| !ownerCredential
		|| !VerifySignedForkRecoveryManifestSignature(
			manifest,
			*ownerCredential,
			_sha256)
		|| archiveEpoch.generation != manifest.recoveryGeneration
		|| archiveEpoch.activationGroupGeneration
			!= manifest.recoveryGeneration
		|| archiveEpoch.activationEventId != manifest.recoveryId
		|| !archiveEpoch.key.valid()
		|| DeriveArchiveKeyCommitment(
			manifest.conversationId,
			manifest.recoveryGeneration,
			manifest.recoveryGeneration,
			manifest.recoveryId,
			archiveEpoch.key,
			_sha256) != manifest.archiveKeyCommitment) {
		return GroupLedgerCommitResult::InvalidMutation;
	}
	auto credentials = _credentials;
	if (canonicalTransition.transition.kind
			== GroupTransitionKind::AddMember) {
		if (!admittedCredential) {
			return GroupLedgerCommitResult::InvalidMutation;
		}
		const auto accountId = DeriveAccountId(*admittedCredential, _sha256);
		if (!accountId
			|| *accountId
				!= canonicalTransition.transition.targetAccountId) {
			return GroupLedgerCommitResult::InvalidMutation;
		}
		const auto existing = std::find_if(
			begin(credentials),
			end(credentials),
			[&](const auto &record) {
				return record.accountId == *accountId;
			});
		if (existing == end(credentials)) {
			credentials.push_back({ *accountId, *admittedCredential });
		} else if (existing->credential != *admittedCredential) {
			return GroupLedgerCommitResult::HistoryConflict;
		}
	}
	auto state = canonicalApplied.state;
	if (!state.applyVerifiedForkRecovery(
			manifest.recoveryId,
			manifest.resolvedGeneration)
		|| state.generation() != manifest.recoveryGeneration) {
		return GroupLedgerCommitResult::InvalidMutation;
	}
	auto events = std::vector<GroupLedgerEvent>(
		begin(_events),
		begin(_events) + manifest.commonGeneration);
	events.push_back({
		.kind = GroupLedgerEventKind::Transition,
		.generation = manifest.resolvedGeneration,
		.objectId = canonicalTransition.transition.transitionId,
		.bytes = *encodedTransition,
	});
	events.push_back({
		.kind = GroupLedgerEventKind::ForkRecovery,
		.generation = manifest.recoveryGeneration,
		.objectId = manifest.recoveryId,
		.bytes = *encodedManifest,
	});
	const auto checkpoint = Checkpoint{
		.conversationId = _conversationId,
		.generation = manifest.recoveryGeneration,
		.stateHash = _sha256.digest(*encodedManifest),
	};
	const auto revision = _revision + 1;
	if (!persist(
			state,
			checkpoint,
			credentials,
			events,
			revision)) {
		return GroupLedgerCommitResult::PersistenceFailed;
	}
	_state = std::move(state);
	_checkpoint = checkpoint;
	_credentials = std::move(credentials);
	_events = std::move(events);
	_revision = revision;
	return GroupLedgerCommitResult::Committed;
}

bool PersistentGroupLedger::loaded() const {
	return _loaded;
}

std::uint64_t PersistentGroupLedger::revision() const {
	return _revision;
}

const ProtectedGroupState *PersistentGroupLedger::state() const {
	return _state ? &*_state : nullptr;
}

Checkpoint PersistentGroupLedger::checkpoint() const {
	return _checkpoint;
}

const AccountCredentialPublic *PersistentGroupLedger::credential(
		AccountId accountId) const {
	const auto i = std::find_if(
		_credentials.begin(),
		_credentials.end(),
		[&](const auto &record) {
			return record.accountId == accountId;
		});
	return (i == _credentials.end()) ? nullptr : &i->credential;
}

std::optional<ProtectedGroupState> PersistentGroupLedger::stateAt(
		std::uint64_t generation) const {
	if (!_loaded
		|| !_state
		|| !generation
		|| generation > _checkpoint.generation
		|| _events.empty()) {
		return std::nullopt;
	}
	const auto genesis = SignedGroupGenesisCodecV1().decode(
		_events.front().bytes);
	auto result = genesis
		? ProtectedGroupState::Create({
			.conversationId = genesis->conversationId,
			.ownerAccountId = genesis->ownerAccountId,
			.ownerClientId = genesis->ownerClientId,
			.ownerTelegramUserIdBinding =
				genesis->ownerTelegramUserIdBinding,
			.policy = genesis->policy,
		})
		: std::nullopt;
	if (!result) {
		return std::nullopt;
	}
	for (auto index = std::size_t(1);
			index < _events.size() && _events[index].generation <= generation;
			++index) {
		if (_events[index].kind == GroupLedgerEventKind::ForkRecovery) {
			const auto manifest =
				SignedForkRecoveryManifestCodecV1().decode(
					_events[index].bytes);
			if (!manifest
				|| manifest->recoveryId != _events[index].objectId
				|| manifest->resolvedGeneration != result->generation()
				|| !result->applyVerifiedForkRecovery(
					manifest->recoveryId,
					manifest->resolvedGeneration)) {
				return std::nullopt;
			}
			continue;
		} else if (_events[index].kind
				!= GroupLedgerEventKind::Transition) {
			return std::nullopt;
		}
		const auto signedTransition = SignedGroupTransitionCodecV1().decode(
			_events[index].bytes);
		if (!signedTransition) {
			return std::nullopt;
		}
		const auto &transition = signedTransition->transition;
		auto authentication = GroupTransitionAuthentication{
			.actor = {
				.accountId = signedTransition->actorAccountId,
				.clientId = signedTransition->actorClientId,
			},
			.targetClientAuthorization = std::nullopt,
		};
		if (signedTransition->targetClientAuthorization) {
			authentication.targetClientAuthorization =
				VerifiedClientAuthorization{
					.accountId = signedTransition
						->targetClientAuthorization->accountId,
					.clientId = signedTransition
						->targetClientAuthorization->clientId,
				};
		}
		if (result->applyVerified(transition, authentication)
				!= GroupTransitionResult::Allowed) {
			return std::nullopt;
		}
	}
	return result->generation() == generation
		? std::optional<ProtectedGroupState>(std::move(*result))
		: std::nullopt;
}

std::optional<Checkpoint> PersistentGroupLedger::checkpointAt(
		std::uint64_t generation) const {
	if (!_loaded
		|| !generation
		|| generation > _events.size()) {
		return std::nullopt;
	}
	const auto hash = EventStateHash(_events[generation - 1], _sha256);
	return hash
		? std::optional<Checkpoint>({
			.conversationId = _conversationId,
			.generation = generation,
			.stateHash = *hash,
		})
		: std::nullopt;
}

bool PersistentGroupLedger::wasMemberAt(
		AccountId accountId,
		std::uint64_t generation) const {
	if (!_loaded
		|| !_state
		|| !accountId
		|| !generation
		|| generation > _checkpoint.generation
		|| _events.empty()) {
		return false;
	}
	const auto genesis = SignedGroupGenesisCodecV1().decode(
		_events.front().bytes);
	auto active = genesis && genesis->ownerAccountId == accountId;
	for (auto index = std::size_t(1);
			index < _events.size() && _events[index].generation <= generation;
			++index) {
		if (_events[index].kind == GroupLedgerEventKind::ForkRecovery) {
			continue;
		} else if (_events[index].kind
				!= GroupLedgerEventKind::Transition) {
			return false;
		}
		const auto signedTransition = SignedGroupTransitionCodecV1().decode(
			_events[index].bytes);
		if (!signedTransition) {
			return false;
		}
		const auto &transition = signedTransition->transition;
		if (transition.targetAccountId == accountId) {
			if (transition.kind == GroupTransitionKind::AddMember) {
				active = true;
			} else if (transition.kind == GroupTransitionKind::RemoveMember) {
				active = false;
			}
		}
	}
	return active;
}

bool PersistentGroupLedger::wasClientActiveAt(
		AccountId accountId,
		ClientId clientId,
		std::uint64_t generation) const {
	if (!wasMemberAt(accountId, generation) || !clientId) {
		return false;
	}
	const auto genesis = SignedGroupGenesisCodecV1().decode(
		_events.front().bytes);
	auto active = genesis
		&& genesis->ownerAccountId == accountId
		&& genesis->ownerClientId == clientId;
	for (auto index = std::size_t(1);
			index < _events.size() && _events[index].generation <= generation;
			++index) {
		if (_events[index].kind == GroupLedgerEventKind::ForkRecovery) {
			continue;
		} else if (_events[index].kind
				!= GroupLedgerEventKind::Transition) {
			return false;
		}
		const auto signedTransition = SignedGroupTransitionCodecV1().decode(
			_events[index].bytes);
		if (!signedTransition) {
			return false;
		}
		const auto &transition = signedTransition->transition;
		if (transition.targetAccountId != accountId) {
			continue;
		}
		if (transition.kind == GroupTransitionKind::AddMember) {
			active = transition.targetClientId == clientId;
		} else if (transition.kind == GroupTransitionKind::RemoveMember) {
			active = false;
		} else if (transition.targetClientId == clientId
			&& transition.kind == GroupTransitionKind::AddClient) {
			active = true;
		} else if (transition.targetClientId == clientId
			&& transition.kind == GroupTransitionKind::RemoveClient) {
			active = false;
		}
	}
	return active;
}

bool PersistentGroupLedger::verifiesArchiveEpoch(
		const ArchiveEpochSecret &epoch) const {
	if (!_loaded
		|| !_state
		|| !epoch.generation
		|| epoch.generation > _events.size()
		|| epoch.activationGroupGeneration != epoch.generation
		|| !epoch.activationEventId
		|| !epoch.key.valid()) {
		return false;
	}
	if (epoch.generation == 1) {
		const auto genesis = SignedGroupGenesisCodecV1().decode(
			_events.front().bytes);
		return genesis
			&& epoch.activationEventId
				== genesis->archiveActivationEventId
			&& DeriveArchiveKeyCommitment(
				genesis->conversationId,
				1,
				1,
				epoch.activationEventId,
				epoch.key,
				_sha256) == genesis->archiveKeyCommitment;
	}
	const auto &event = _events[epoch.generation - 1];
	if (event.kind == GroupLedgerEventKind::ForkRecovery) {
		const auto manifest = SignedForkRecoveryManifestCodecV1().decode(
			event.bytes);
		return manifest
			&& event.generation == epoch.generation
			&& manifest->recoveryGeneration == epoch.generation
			&& manifest->recoveryId == epoch.activationEventId
			&& DeriveArchiveKeyCommitment(
				manifest->conversationId,
				epoch.generation,
				epoch.activationGroupGeneration,
				epoch.activationEventId,
				epoch.key,
				_sha256) == manifest->archiveKeyCommitment;
	}
	const auto transition = SignedGroupTransitionCodecV1().decode(event.bytes);
	return event.kind == GroupLedgerEventKind::Transition
		&& transition
		&& event.generation == epoch.generation
		&& transition->transition.generation == epoch.generation
		&& transition->transition.transitionId == epoch.activationEventId
		&& DeriveArchiveKeyCommitment(
			transition->transition.conversationId,
			epoch.generation,
			epoch.activationGroupGeneration,
			epoch.activationEventId,
			epoch.key,
			_sha256) == transition->archiveKeyCommitment;
}

const std::vector<GroupLedgerEvent> &PersistentGroupLedger::events() const {
	return _events;
}

bool PersistentGroupLedger::persist(
		const ProtectedGroupState &state,
		const Checkpoint &checkpoint,
		const std::vector<CredentialRecord> &credentials,
		const std::vector<GroupLedgerEvent> &events,
		std::uint64_t revision) const {
	const auto stateBytes = ProtectedGroupStateCodecV1().encode(state);
	if (!stateBytes
		|| !revision
		|| checkpoint.conversationId != _conversationId
		|| checkpoint.generation != state.generation()
		|| !checkpoint.stateHash
		|| credentials.empty()
		|| credentials.size() > kMaximumCredentials
		|| events.empty()
		|| events.size() > kMaximumEvents) {
		return false;
	}
	auto encoded = QByteArray();
	encoded.reserve(stateBytes->size() + int(events.size()) * 768 + 1024);
	AppendArray(encoded, kMagic);
	AppendUint16(encoded, 1);
	AppendArray(encoded, _conversationId.bytes);
	AppendUint64(encoded, revision);
	AppendUint64(encoded, checkpoint.generation);
	AppendArray(encoded, checkpoint.stateHash.bytes);
	AppendBytes(encoded, *stateBytes);
	AppendUint32(encoded, std::uint32_t(credentials.size()));
	for (const auto &record : credentials) {
		const auto credential = AccountCredentialCodecV1().encode(
			record.credential);
		if (!record.accountId || !credential) {
			return false;
		}
		AppendArray(encoded, record.accountId.bytes);
		AppendBytes(encoded, *credential);
	}
	AppendUint32(encoded, std::uint32_t(events.size()));
	for (const auto &event : events) {
		if (!event.generation
			|| !event.objectId
			|| event.bytes.isEmpty()
			|| event.bytes.size() > kMaximumEventSize) {
			return false;
		}
		AppendUint8(encoded, std::uint8_t(event.kind));
		AppendUint64(encoded, event.generation);
		AppendArray(encoded, event.objectId.bytes);
		AppendBytes(encoded, event.bytes);
	}
	if (encoded.size() > kMaximumSnapshotSize) {
		return false;
	}
	const auto protectedBytes = _protector.seal(
		Purpose(_conversationId),
		encoded);
	std::fill_n(encoded.data(), encoded.size(), char(0));
	return protectedBytes && _blobStore.writeAtomic(*protectedBytes);
}

void PersistentGroupLedger::clear() {
	_conversationId = {};
	_state.reset();
	_checkpoint = {};
	_credentials.clear();
	_events.clear();
	_revision = 0;
	_loaded = false;
}

} // namespace E2ECloud

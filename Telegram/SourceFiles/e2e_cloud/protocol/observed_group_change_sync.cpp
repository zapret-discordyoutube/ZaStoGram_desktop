/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "e2e_cloud/protocol/observed_group_change_sync.h"

#include "e2e_cloud/core/envelope_codec.h"
#include "e2e_cloud/mls/observed_key_package.h"

#include <map>
#include <optional>
#include <set>
#include <utility>

namespace E2ECloud {
namespace {

inline constexpr auto kMaximumObjects = std::size_t(65'536);
inline constexpr auto kMaximumBytes = std::uint64_t(512 * 1024 * 1024);

struct ObservedEnvelope {
	TransportEnvelope envelope;
	std::uint64_t observedSenderTelegramUserIdBinding = 0;
};

struct Candidate {
	SignedGroupTransition transition;
	TransportEnvelope transitionEnvelope;
};

enum class CandidateStatus {
	Ignored,
	Verified,
	SecurityFailure,
};

struct CandidateOutcome {
	CandidateStatus status = CandidateStatus::Ignored;
	std::optional<Candidate> candidate;
};

[[nodiscard]] bool AdmissionKind(GroupTransitionKind kind) {
	return kind == GroupTransitionKind::AddMember
		|| kind == GroupTransitionKind::AddClient;
}

[[nodiscard]] const ObservedEnvelope *Find(
		const std::map<ObjectId, ObservedEnvelope> &records,
		ObjectId objectId) {
	const auto i = records.find(objectId);
	return (i == end(records)) ? nullptr : &i->second;
}

[[nodiscard]] bool SameObservedActor(
		const ObservedEnvelope &record,
		const SignedGroupTransition &transition,
		std::uint64_t telegramUserIdBinding) {
	return record.envelope.senderAccountId == transition.actorAccountId
		&& record.envelope.senderClientId == transition.actorClientId
		&& record.observedSenderTelegramUserIdBinding
			== telegramUserIdBinding;
}

[[nodiscard]] std::optional<std::uint64_t> ActorGeneration(
		const TransportEnvelope &envelope,
		const MlsContextCodecV1 &contextCodec,
		const GroupControlCodecV1 &controlCodec) {
	if (envelope.objectKind == ObjectKind::SignedGroupTransition) {
		const auto transition = SignedGroupTransitionCodecV1().decode(
			envelope.payload);
		return transition
			? std::optional<std::uint64_t>(
				transition->transition.previousGeneration)
			: std::nullopt;
	} else if (envelope.objectKind != ObjectKind::MlsCommit
		&& envelope.objectKind != ObjectKind::ArchiveEpoch) {
		return std::nullopt;
	}
	const auto aad = contextCodec.decodeAad(envelope.authenticationData);
	const auto preludeBytes = aad
		? (envelope.objectKind == ObjectKind::MlsCommit)
			? aad->context
			: (aad->context.size()
					== kGroupChangePreludeEncodedSize + 32)
				? QByteArray(
					aad->context.constData(),
					kGroupChangePreludeEncodedSize)
				: QByteArray()
		: QByteArray();
	const auto prelude = controlCodec.decodePrelude(preludeBytes);
	return prelude
		? std::optional<std::uint64_t>(
			prelude->transition.previousGeneration)
		: std::nullopt;
}

enum class StageObservedStatus {
	Ignored,
	Staged,
	ForkDetected,
	PersistenceFailure,
};

[[nodiscard]] StageObservedStatus StageObservedObject(
		const TelegramTransport::UntrustedObject &object,
		const OpenMlsClientContext &local,
		std::uint64_t currentTime,
		const EnvelopeCodec &envelopeCodec,
		const MlsContextCodecV1 &contextCodec,
		const GroupControlCodecV1 &controlCodec,
		const Sha256Provider &sha256,
		const PersistentGroupLedger &groupLedger,
		PersistentGroupChangeInbox &inbox) {
	const auto envelope = envelopeCodec.decodeUntrusted(object.bytes);
	if (!envelope
		|| envelope->conversationId != local.conversationId
		|| envelope->telegramPeerIdBinding
			!= local.telegramPeerIdBinding
		|| object.observedTelegramPeerIdBinding
			!= local.telegramPeerIdBinding
		|| !object.observedSenderTelegramUserIdBinding
		|| object.observedMessageId <= 0) {
		return StageObservedStatus::Ignored;
	}
	auto authenticated = false;
	if (envelope->objectKind == ObjectKind::ClientKeyPackage) {
		const auto verified = VerifyClientKeyPackageEnvelope(
			*envelope,
			local.conversationId,
			local.telegramPeerIdBinding,
			envelope->epochOrGeneration,
			sha256);
		authenticated = verified.result
				== ClientKeyPackageEnvelopeResult::Verified
			&& verified.publication
			&& ClientAuthorizationUsableAt(
				verified.publication->authorization,
				currentTime);
	} else {
		const auto authenticator = OpenMlsGroupChangeEnvelopeAuthenticator(
			contextCodec,
			controlCodec,
			groupLedger,
			sha256);
		if (!authenticator.authenticate(*envelope)) {
			return StageObservedStatus::Ignored;
		}
		const auto generation = ActorGeneration(
			*envelope,
			contextCodec,
			controlCodec);
		const auto state = generation
			? groupLedger.stateAt(*generation)
			: std::nullopt;
		const auto actor = state
			? state->memberByClient(envelope->senderClientId)
			: nullptr;
		if (!actor || actor->accountId != envelope->senderAccountId) {
			return StageObservedStatus::Ignored;
		} else if (actor->telegramUserIdBinding
				!= object.observedSenderTelegramUserIdBinding) {
			return StageObservedStatus::ForkDetected;
		}
		authenticated = true;
	}
	if (!authenticated) {
		return StageObservedStatus::Ignored;
	}
	switch (inbox.stageObserved(
		*envelope,
		object.observedSenderTelegramUserIdBinding)) {
	case GroupChangeInboxStageResult::Staged:
	case GroupChangeInboxStageResult::Duplicate:
		return StageObservedStatus::Staged;
	case GroupChangeInboxStageResult::ObjectIdConflict:
		return StageObservedStatus::ForkDetected;
	case GroupChangeInboxStageResult::InvalidEnvelope:
		return StageObservedStatus::Ignored;
	case GroupChangeInboxStageResult::CapacityExceeded:
	case GroupChangeInboxStageResult::NotLoaded:
	case GroupChangeInboxStageResult::PersistenceFailed:
		return StageObservedStatus::PersistenceFailure;
	}
	return StageObservedStatus::Ignored;
}

[[nodiscard]] CandidateOutcome VerifyTransitionCandidate(
		const ObservedEnvelope &record,
		const OpenMlsClientContext &local,
		const PersistentGroupLedger &groupLedger,
		const Sha256Provider &sha256) {
	const auto &envelope = record.envelope;
	const auto transition = SignedGroupTransitionCodecV1().decode(
		envelope.payload);
	if (!transition
		|| ValidateEnvelope(envelope) != EnvelopeValidationError::None
		|| envelope.objectKind != ObjectKind::SignedGroupTransition
		|| envelope.conversationId != local.conversationId
		|| envelope.telegramPeerIdBinding != local.telegramPeerIdBinding
		|| envelope.payloadHash != sha256.digest(envelope.payload)
		|| transition->transition.previousGeneration
			!= groupLedger.checkpoint().generation
		|| transition->transition.generation
			!= groupLedger.checkpoint().generation + 1
		|| transition->previousStateHash
			!= groupLedger.checkpoint().stateHash
		|| !DeriveSignedGroupTransitionCheckpoint(*transition, sha256)) {
		return {};
	}
	const auto actor = groupLedger.state()->memberByClient(
		transition->actorClientId);
	const auto credential = groupLedger.credential(
		transition->actorAccountId);
	if (!actor
		|| actor->accountId != transition->actorAccountId
		|| !credential
		|| !VerifySignedGroupTransitionActor(
			*transition,
			*credential,
			sha256)) {
		return {};
	}
	const auto proof = transition->targetClientAuthorization;
	const auto authentication = GroupTransitionAuthentication{
		.actor = {
			.accountId = transition->actorAccountId,
			.clientId = transition->actorClientId,
		},
		.targetClientAuthorization = AdmissionKind(
				transition->transition.kind)
			&& proof
			&& proof->accountId == transition->transition.targetAccountId
			&& proof->clientId == transition->transition.targetClientId
			? std::optional<VerifiedClientAuthorization>({
				.accountId = proof->accountId,
				.clientId = proof->clientId,
			})
			: std::nullopt,
	};
	if (groupLedger.state()->validate(
			transition->transition,
			authentication) != GroupTransitionResult::Allowed) {
		return {};
	}
	if (envelope.objectId != transition->transition.transitionId
		|| envelope.epochOrGeneration
			!= transition->transition.generation
		|| envelope.authenticationData != QByteArray(
			reinterpret_cast<const char*>(
				transition->actorSignature.data()),
			int(transition->actorSignature.size()))
		|| !SameObservedActor(
			record,
			*transition,
			actor->telegramUserIdBinding)) {
		return {
			.status = CandidateStatus::SecurityFailure,
			.candidate = std::nullopt,
		};
	}
	return {
		.status = CandidateStatus::Verified,
		.candidate = Candidate{
			.transition = *transition,
			.transitionEnvelope = envelope,
		},
	};
}

[[nodiscard]] bool ValidBoundObject(
		const ObservedEnvelope &record,
		const SignedGroupTransition &transition,
		ObjectKind kind,
		ObjectId objectId,
		Digest payloadHash,
		std::uint64_t telegramUserIdBinding,
		const Sha256Provider &sha256) {
	return ValidateEnvelope(record.envelope)
			== EnvelopeValidationError::None
		&& record.envelope.objectKind == kind
		&& record.envelope.objectId == objectId
		&& record.envelope.payloadHash == payloadHash
		&& record.envelope.payloadHash
			== sha256.digest(record.envelope.payload)
		&& SameObservedActor(
			record,
			transition,
			telegramUserIdBinding);
}

[[nodiscard]] std::optional<ClientKeyPackagePublication>
VerifyAdmissionMaterial(
		const ObservedEnvelope &record,
		const SignedGroupTransition &transition,
		const OpenMlsClientContext &local,
		std::uint64_t currentTime,
		const Sha256Provider &sha256) {
	const auto verified = VerifyClientKeyPackageEnvelope(
		record.envelope,
		local.conversationId,
		local.telegramPeerIdBinding,
		record.envelope.epochOrGeneration,
		sha256);
	return (verified.result == ClientKeyPackageEnvelopeResult::Verified
		&& verified.publication
		&& record.envelope.epochOrGeneration
		&& record.envelope.epochOrGeneration
			<= transition.transition.previousGeneration
		&& ClientAuthorizationUsableAt(
			verified.publication->authorization,
			currentTime)
		&& transition.targetClientAuthorization
		&& record.observedSenderTelegramUserIdBinding
			== transition.transition.targetTelegramUserIdBinding
		&& record.envelope.senderAccountId
			== transition.transition.targetAccountId
		&& record.envelope.senderClientId
			== transition.transition.targetClientId
		&& verified.publication->authorization
			== *transition.targetClientAuthorization)
		? std::optional<ClientKeyPackagePublication>(
			*verified.publication)
		: std::nullopt;
}

[[nodiscard]] ObservedGroupChangeSyncOutcome Outcome(
		ObservedGroupChangeSyncStatus status,
		std::uint64_t appliedTransitions) {
	return {
		.status = status,
		.appliedTransitions = appliedTransitions,
	};
}

} // namespace

ObservedGroupChangeSyncOutcome SynchronizeObservedGroupChanges(
		const std::vector<TelegramTransport::UntrustedObject> &objects,
		OpenMlsClientContext local,
		std::uint64_t currentTime,
		const EnvelopeCodec &envelopeCodec,
		const OpenMlsBridge &bridge,
		const MlsContextCodecV1 &contextCodec,
		const MlsRosterCodecV1 &rosterCodec,
		const GroupControlCodecV1 &controlCodec,
		const Sha256Provider &sha256,
		PersistentMlsStateStore &mlsState,
		PersistentArchiveState &archiveState,
		PersistentGroupLedger &groupLedger,
		PersistentGroupChangeJournal &journal,
		PersistentGroupChangeInbox &inbox) {
	if (!local.conversationId
		|| !local.accountId
		|| !local.clientId
		|| !local.telegramPeerIdBinding
		|| !currentTime
		|| !mlsState.loaded()
		|| !archiveState.loaded()
		|| !groupLedger.loaded()
		|| !groupLedger.state()
		|| !journal.loaded()
		|| !inbox.loaded()
		|| mlsState.removed()
		|| mlsState.conversationId() != local.conversationId
		|| archiveState.conversationId() != local.conversationId
		|| groupLedger.state()->conversationId() != local.conversationId
		|| !groupLedger.state()->memberByClient(local.clientId)) {
		return Outcome(ObservedGroupChangeSyncStatus::InvalidState, 0);
	}
	auto staleTransitions = std::vector<ObjectId>();
	for (const auto &record : inbox.records()) {
		if (record.envelope.objectKind
				!= ObjectKind::SignedGroupTransition) {
			continue;
		}
		const auto transition = SignedGroupTransitionCodecV1().decode(
			record.envelope.payload);
		if (transition
			&& transition->transition.generation
				<= groupLedger.checkpoint().generation) {
			staleTransitions.push_back(record.envelope.objectId);
		}
	}
	for (const auto transitionId : staleTransitions) {
		if (!inbox.discardBundle(transitionId)) {
			return Outcome(
				ObservedGroupChangeSyncStatus::PersistenceFailure,
				0);
		}
	}
	if (!inbox.discardExpiredKeyPackages(currentTime)) {
		return Outcome(
			ObservedGroupChangeSyncStatus::PersistenceFailure,
			0);
	}
	for (const auto &object : objects) {
		switch (StageObservedObject(
			object,
			local,
			currentTime,
			envelopeCodec,
			contextCodec,
			controlCodec,
			sha256,
			groupLedger,
			inbox)) {
		case StageObservedStatus::Ignored:
		case StageObservedStatus::Staged:
			break;
		case StageObservedStatus::ForkDetected:
			return Outcome(ObservedGroupChangeSyncStatus::ForkDetected, 0);
		case StageObservedStatus::PersistenceFailure:
			return Outcome(
				ObservedGroupChangeSyncStatus::PersistenceFailure,
				0);
		}
	}
	if (inbox.records().size() > kMaximumObjects) {
		return Outcome(ObservedGroupChangeSyncStatus::InvalidState, 0);
	}
	auto totalBytes = std::uint64_t();
	auto records = std::map<ObjectId, ObservedEnvelope>();
	for (const auto &record : inbox.records()) {
		if (record.envelope.payload.size() < 0
			|| totalBytes > kMaximumBytes
				- std::uint64_t(record.envelope.payload.size())) {
			return Outcome(ObservedGroupChangeSyncStatus::InvalidState, 0);
		}
		totalBytes += std::uint64_t(record.envelope.payload.size());
		records.emplace(record.envelope.objectId, ObservedEnvelope{
			.envelope = record.envelope,
			.observedSenderTelegramUserIdBinding
				= record.observedSenderTelegramUserIdBinding,
		});
	}
	auto appliedTransitions = std::uint64_t();
	while (true) {
		auto candidates = std::vector<Candidate>();
		for (const auto &[objectId, record] : records) {
			(void)objectId;
			if (record.envelope.objectKind
					!= ObjectKind::SignedGroupTransition) {
				continue;
			}
			auto candidate = VerifyTransitionCandidate(
				record,
				local,
				groupLedger,
				sha256);
			if (candidate.status == CandidateStatus::SecurityFailure) {
				return Outcome(
					ObservedGroupChangeSyncStatus::ForkDetected,
					appliedTransitions);
			} else if (candidate.candidate) {
				candidates.push_back(std::move(*candidate.candidate));
			}
		}
		if (candidates.empty()) {
			return Outcome(
				appliedTransitions
					? ObservedGroupChangeSyncStatus::Updated
					: ObservedGroupChangeSyncStatus::NoChange,
				appliedTransitions);
		} else if (candidates.size() != 1) {
			return Outcome(
				ObservedGroupChangeSyncStatus::ForkDetected,
				appliedTransitions);
		}
		auto candidate = std::move(candidates.front());
		const auto actor = groupLedger.state()->memberByClient(
			candidate.transition.actorClientId);
		const auto commit = Find(
			records,
			candidate.transition.mlsCommitObjectId);
		const auto distribution = Find(
			records,
			candidate.transition.archiveDistributionObjectId);
		if (!actor || !commit || !distribution) {
			return Outcome(
				ObservedGroupChangeSyncStatus::WaitingForObjects,
				appliedTransitions);
		}
		if (!ValidBoundObject(
				*commit,
				candidate.transition,
				ObjectKind::MlsCommit,
				candidate.transition.mlsCommitObjectId,
				candidate.transition.mlsCommitHash,
				actor->telegramUserIdBinding,
				sha256)
			|| !ValidBoundObject(
				*distribution,
				candidate.transition,
				ObjectKind::ArchiveEpoch,
				candidate.transition.archiveDistributionObjectId,
				candidate.transition.archiveDistributionHash,
				actor->telegramUserIdBinding,
				sha256)) {
			return Outcome(
				ObservedGroupChangeSyncStatus::ForkDetected,
				appliedTransitions);
		}
		auto publication = std::optional<ClientKeyPackagePublication>();
		if (AdmissionKind(candidate.transition.transition.kind)) {
			const auto proof = candidate.transition.targetClientAuthorization;
			const auto keyPackage = proof
				? Find(records, proof->authorizationId)
				: nullptr;
			if (!keyPackage) {
				return Outcome(
					ObservedGroupChangeSyncStatus::WaitingForObjects,
					appliedTransitions);
			}
			publication = VerifyAdmissionMaterial(
				*keyPackage,
				candidate.transition,
				local,
				currentTime,
				sha256);
			if (!publication) {
				return Outcome(
					ObservedGroupChangeSyncStatus::ForkDetected,
					appliedTransitions);
			}
		}
		auto prepared = PrepareOpenMlsInboundGroupChange({
			.local = local,
			.transitionEnvelope = std::move(
				candidate.transitionEnvelope),
			.commitEnvelope = commit->envelope,
			.archiveDistributionEnvelope = distribution->envelope,
			.targetCredential = publication
				? std::optional<AccountCredentialPublic>(
					publication->accountCredential)
				: std::nullopt,
			.targetKeyPackage = publication
				? publication->keyPackage
				: QByteArray(),
		},
		bridge,
		contextCodec,
		rosterCodec,
		controlCodec,
		sha256,
		mlsState,
		archiveState,
		groupLedger);
		if (prepared.status
				== OpenMlsInboundGroupChangeStatus::CommitDeferred
			|| prepared.status
				== OpenMlsInboundGroupChangeStatus::DistributionDeferred) {
			return Outcome(
				ObservedGroupChangeSyncStatus::WaitingForObjects,
				appliedTransitions);
		} else if (prepared.status
				!= OpenMlsInboundGroupChangeStatus::Prepared
			|| !prepared.prepared) {
			return Outcome(
				ObservedGroupChangeSyncStatus::ForkDetected,
				appliedTransitions);
		}
		const auto localRemoved = prepared.prepared->transaction.direction
			== GroupChangeTransactionDirection::InboundRemoval;
		auto consumedObjectIds = std::set<ObjectId>{
			candidate.transition.transition.transitionId,
			candidate.transition.mlsCommitObjectId,
			candidate.transition.archiveDistributionObjectId,
		};
		if (candidate.transition.targetClientAuthorization) {
			consumedObjectIds.emplace(
				candidate.transition.targetClientAuthorization
					->authorizationId);
		}
		auto coordinator = GroupChangeTransactionCoordinator(
			journal,
			mlsState,
			archiveState,
			groupLedger,
			sha256);
		if (coordinator.apply(std::move(
			prepared.prepared->transaction))
				!= GroupChangeApplyStatus::Applied) {
			return Outcome(
				ObservedGroupChangeSyncStatus::PersistenceFailure,
				appliedTransitions);
		}
		++appliedTransitions;
		if (!inbox.discardBundle(
				candidate.transition.transition.transitionId)) {
			return Outcome(
				ObservedGroupChangeSyncStatus::PersistenceFailure,
					appliedTransitions);
		}
		for (const auto objectId : consumedObjectIds) {
			records.erase(objectId);
		}
		if (localRemoved) {
			return Outcome(
				ObservedGroupChangeSyncStatus::LocalClientRemoved,
				appliedTransitions);
		}
	}
}

} // namespace E2ECloud

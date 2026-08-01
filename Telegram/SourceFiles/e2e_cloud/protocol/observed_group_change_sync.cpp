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
#include <utility>

namespace E2ECloud {
namespace {

inline constexpr auto kMaximumObjects = std::size_t(65'536);
inline constexpr auto kMaximumBytes = std::uint64_t(512 * 1024 * 1024);

struct ObservedEnvelope {
	TelegramTransport::UntrustedObject observed;
	TransportEnvelope envelope;
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
		&& record.observed.observedSenderTelegramUserIdBinding
			== telegramUserIdBinding;
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
		const EnvelopeCodec &envelopeCodec,
		const Sha256Provider &sha256) {
	const auto verified = VerifyObservedClientKeyPackage(
		record.observed,
		local.conversationId,
		local.telegramPeerIdBinding,
		transition.transition.previousGeneration,
		currentTime,
		envelopeCodec,
		sha256);
	return (verified.verified
		&& transition.targetClientAuthorization
		&& verified.verified->telegramUserIdBinding
			== transition.transition.targetTelegramUserIdBinding
		&& verified.verified->envelope.senderAccountId
			== transition.transition.targetAccountId
		&& verified.verified->envelope.senderClientId
			== transition.transition.targetClientId
		&& verified.verified->publication.authorization
			== *transition.targetClientAuthorization)
		? std::optional<ClientKeyPackagePublication>(
			std::move(verified.verified->publication))
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
		PersistentGroupChangeJournal &journal) {
	if (!local.conversationId
		|| !local.accountId
		|| !local.clientId
		|| !local.telegramPeerIdBinding
		|| !currentTime
		|| objects.size() > kMaximumObjects
		|| !mlsState.loaded()
		|| !archiveState.loaded()
		|| !groupLedger.loaded()
		|| !groupLedger.state()
		|| !journal.loaded()
		|| mlsState.removed()
		|| mlsState.conversationId() != local.conversationId
		|| archiveState.conversationId() != local.conversationId
		|| groupLedger.state()->conversationId() != local.conversationId
		|| !groupLedger.state()->memberByClient(local.clientId)) {
		return Outcome(ObservedGroupChangeSyncStatus::InvalidState, 0);
	}
	auto totalBytes = std::uint64_t();
	auto records = std::map<ObjectId, ObservedEnvelope>();
	for (const auto &object : objects) {
		if (object.bytes.size() < 0
			|| totalBytes > kMaximumBytes
				- std::uint64_t(object.bytes.size())) {
			return Outcome(ObservedGroupChangeSyncStatus::InvalidState, 0);
		}
		totalBytes += std::uint64_t(object.bytes.size());
		if (totalBytes > kMaximumBytes) {
			return Outcome(ObservedGroupChangeSyncStatus::InvalidState, 0);
		}
		const auto envelope = envelopeCodec.decodeUntrusted(object.bytes);
		if (!envelope
			|| envelope->conversationId != local.conversationId
			|| envelope->telegramPeerIdBinding
				!= local.telegramPeerIdBinding
			|| object.observedTelegramPeerIdBinding
				!= local.telegramPeerIdBinding
			|| !object.observedSenderTelegramUserIdBinding
			|| object.observedMessageId <= 0) {
			continue;
		}
		const auto i = records.find(envelope->objectId);
		if (i != end(records)) {
			if (i->second.observed.bytes != object.bytes
				|| i->second.observed
					.observedSenderTelegramUserIdBinding
					!= object.observedSenderTelegramUserIdBinding) {
				return Outcome(
					ObservedGroupChangeSyncStatus::ForkDetected,
					0);
			}
			continue;
		}
		records.emplace(envelope->objectId, ObservedEnvelope{
			.observed = object,
			.envelope = *envelope,
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
				envelopeCodec,
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
		if (localRemoved) {
			return Outcome(
				ObservedGroupChangeSyncStatus::LocalClientRemoved,
				appliedTransitions);
		}
	}
}

} // namespace E2ECloud

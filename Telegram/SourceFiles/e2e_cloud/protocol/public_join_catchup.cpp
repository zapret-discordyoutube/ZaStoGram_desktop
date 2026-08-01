/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "e2e_cloud/protocol/public_join_catchup.h"

#include "e2e_cloud/core/envelope_codec.h"
#include "e2e_cloud/mls/client_key_package.h"

#include <algorithm>
#include <map>
#include <utility>

namespace E2ECloud {
namespace {

struct ObservedEnvelope {
	TransportEnvelope envelope;
	std::uint64_t senderTelegramUserIdBinding = 0;
};

struct AdmissionMaterial {
	AccountCredentialPublic credential;
	QByteArray keyPackage;
};

struct Candidate {
	SignedGroupTransition transition;
	AppliedSignedGroupTransition applied;
	TransportEnvelope transitionEnvelope;
	TransportEnvelope commitEnvelope;
	TransportEnvelope distributionEnvelope;
	std::optional<AccountCredentialPublic> admittedCredential;
	QByteArray targetKeyPackage;
};

[[nodiscard]] bool AdmissionKind(GroupTransitionKind kind) {
	return kind == GroupTransitionKind::AddMember
		|| kind == GroupTransitionKind::AddClient;
}

[[nodiscard]] bool JoinRelevantKind(ObjectKind kind) {
	switch (kind) {
	case ObjectKind::InitialGroupState:
	case ObjectKind::AccountCredential:
	case ObjectKind::ClientKeyPackage:
	case ObjectKind::MlsCommit:
	case ObjectKind::MlsWelcome:
	case ObjectKind::ArchiveEpoch:
	case ObjectKind::HistoryGrant:
	case ObjectKind::SignedGroupTransition:
	case ObjectKind::MlsGroupInfo:
		return true;
	default:
		return false;
	}
}

[[nodiscard]] bool ValidPayload(const TransportEnvelope &envelope,
		const Sha256Provider &sha256) {
	return ValidateEnvelope(envelope) == EnvelopeValidationError::None
		&& envelope.payloadHash == sha256.digest(envelope.payload);
}

[[nodiscard]] bool SameActor(
		const ObservedEnvelope &record,
		const SignedGroupTransition &transition,
		std::uint64_t telegramUserIdBinding) {
	return record.envelope.senderAccountId == transition.actorAccountId
		&& record.envelope.senderClientId == transition.actorClientId
		&& record.senderTelegramUserIdBinding == telegramUserIdBinding;
}

[[nodiscard]] const ObservedEnvelope *Find(
		const std::map<ObjectId, ObservedEnvelope> &records,
		ObjectId objectId) {
	const auto i = records.find(objectId);
	return (i == end(records)) ? nullptr : &i->second;
}

[[nodiscard]] std::optional<AdmissionMaterial> RemoteAdmissionMaterial(
		const std::map<ObjectId, ObservedEnvelope> &records,
		const SignedGroupTransition &transition,
		std::uint64_t telegramPeerIdBinding,
		std::uint64_t currentTime,
		const Sha256Provider &sha256) {
	if (!transition.targetClientAuthorization) {
		return std::nullopt;
	}
	const auto &proof = *transition.targetClientAuthorization;
	const auto record = Find(records, proof.authorizationId);
	if (!record
		|| record->senderTelegramUserIdBinding
			!= transition.transition.targetTelegramUserIdBinding
		|| record->envelope.senderAccountId
			!= transition.transition.targetAccountId
		|| record->envelope.senderClientId
			!= transition.transition.targetClientId
		|| record->envelope.epochOrGeneration
			> transition.transition.previousGeneration) {
		return std::nullopt;
	}
	const auto verified = VerifyClientKeyPackageEnvelope(
		record->envelope,
		transition.transition.conversationId,
		telegramPeerIdBinding,
		record->envelope.epochOrGeneration,
		sha256);
	return (verified.result == ClientKeyPackageEnvelopeResult::Verified
		&& verified.publication
		&& ClientAuthorizationUsableAt(
			verified.publication->authorization,
			currentTime)
		&& verified.publication->authorization == proof)
		? std::optional<AdmissionMaterial>({
			.credential = verified.publication->accountCredential,
			.keyPackage = verified.publication->keyPackage,
		})
		: std::nullopt;
}

[[nodiscard]] std::optional<AdmissionMaterial> LocalAdmissionMaterial(
		const SignedGroupTransition &transition,
		const AccountCredentialPublic &localCredential,
		std::uint64_t telegramPeerIdBinding,
		std::uint64_t currentTime,
		const EnvelopeCodec &envelopeCodec,
		const Sha256Provider &sha256,
		const PersistentKeyPackagePool &keyPackages) {
	if (!transition.targetClientAuthorization || !currentTime) {
		return std::nullopt;
	}
	const auto &proof = *transition.targetClientAuthorization;
	const auto entry = keyPackages.find(proof.keyPackageHash, currentTime);
	const auto envelope = entry
		? envelopeCodec.decode(entry->publicationEnvelope)
		: std::nullopt;
	const auto verified = envelope
		? VerifyClientKeyPackageEnvelope(
			*envelope,
			transition.transition.conversationId,
			telegramPeerIdBinding,
			envelope->epochOrGeneration,
			sha256)
		: VerifyClientKeyPackageEnvelopeOutcome();
	return (verified.result == ClientKeyPackageEnvelopeResult::Verified
		&& verified.publication
		&& ClientAuthorizationUsableAt(
			verified.publication->authorization,
			currentTime)
		&& verified.publication->authorization == proof
		&& verified.publication->accountCredential == localCredential)
		? std::optional<AdmissionMaterial>({
			.credential = localCredential,
			.keyPackage = verified.publication->keyPackage,
		})
		: std::nullopt;
}

[[nodiscard]] std::optional<Candidate> VerifyCandidate(
		const ObservedEnvelope &transitionRecord,
		const std::map<ObjectId, ObservedEnvelope> &records,
		ConversationId conversationId,
		std::uint64_t telegramPeerIdBinding,
		AccountId localAccountId,
		ClientId localClientId,
		const AccountCredentialPublic &localCredential,
		std::uint64_t currentTime,
		const EnvelopeCodec &envelopeCodec,
		const Sha256Provider &sha256,
		const PersistentGroupLedger &groupLedger,
		const PersistentKeyPackagePool &keyPackages) {
	const auto &envelope = transitionRecord.envelope;
	const auto transition = SignedGroupTransitionCodecV1().decode(
		envelope.payload);
	if (!transition
		|| envelope.objectKind != ObjectKind::SignedGroupTransition
		|| !ValidPayload(envelope, sha256)
		|| envelope.objectId != transition->transition.transitionId
		|| envelope.epochOrGeneration != transition->transition.generation
		|| envelope.conversationId != conversationId
		|| envelope.telegramPeerIdBinding != telegramPeerIdBinding
		|| envelope.authenticationData != QByteArray(
			reinterpret_cast<const char*>(
				transition->actorSignature.data()),
			int(transition->actorSignature.size()))
		|| transition->transition.previousGeneration
			!= groupLedger.checkpoint().generation
		|| transition->transition.generation
			!= groupLedger.checkpoint().generation + 1
		|| transition->previousStateHash
			!= groupLedger.checkpoint().stateHash) {
		return std::nullopt;
	}
	const auto actor = groupLedger.state()->memberByClient(
		transition->actorClientId);
	const auto actorCredential = groupLedger.credential(
		transition->actorAccountId);
	if (!actor
		|| actor->accountId != transition->actorAccountId
		|| !actorCredential
		|| !SameActor(
			transitionRecord,
			*transition,
			actor->telegramUserIdBinding)) {
		return std::nullopt;
	}
	const auto commit = Find(records, transition->mlsCommitObjectId);
	const auto distribution = Find(
		records,
		transition->archiveDistributionObjectId);
	if (!commit
		|| !distribution
		|| commit->envelope.objectKind != ObjectKind::MlsCommit
		|| distribution->envelope.objectKind != ObjectKind::ArchiveEpoch
		|| !ValidPayload(commit->envelope, sha256)
		|| !ValidPayload(distribution->envelope, sha256)
		|| commit->envelope.payloadHash != transition->mlsCommitHash
		|| distribution->envelope.payloadHash
			!= transition->archiveDistributionHash
		|| !SameActor(*commit, *transition, actor->telegramUserIdBinding)
		|| !SameActor(
			*distribution,
			*transition,
			actor->telegramUserIdBinding)) {
		return std::nullopt;
	}
	const auto localTarget = transition->transition.targetAccountId
			== localAccountId
		&& transition->transition.targetClientId == localClientId;
	const auto material = AdmissionKind(transition->transition.kind)
		? (localTarget
			? LocalAdmissionMaterial(
				*transition,
				localCredential,
				telegramPeerIdBinding,
				currentTime,
				envelopeCodec,
				sha256,
				keyPackages)
			: RemoteAdmissionMaterial(
				records,
				*transition,
				telegramPeerIdBinding,
				currentTime,
				sha256))
		: std::optional<AdmissionMaterial>();
	if (AdmissionKind(transition->transition.kind) && !material) {
		return std::nullopt;
	}
	auto applied = VerifyAndApplySignedGroupTransition({
		.currentState = groupLedger.state(),
		.currentCheckpoint = groupLedger.checkpoint(),
		.signedTransition = &*transition,
		.actorCredential = actorCredential,
		.targetCredential = material ? &material->credential : nullptr,
		.mlsCommitObjectId = commit->envelope.objectId,
		.mlsCommit = commit->envelope.payload,
		.nextArchiveKey = nullptr,
		.archiveDistributionObjectId = distribution->envelope.objectId,
		.archiveDistribution = distribution->envelope.payload,
		.targetKeyPackage = material ? material->keyPackage : QByteArray(),
		.allowMissingArchiveKey = true,
	}, sha256);
	if (applied.result != SignedGroupTransitionResult::Applied
		|| !applied.applied) {
		return std::nullopt;
	}
	return Candidate{
		.transition = *transition,
		.applied = std::move(*applied.applied),
		.transitionEnvelope = envelope,
		.commitEnvelope = commit->envelope,
		.distributionEnvelope = distribution->envelope,
		.admittedCredential = (transition->transition.kind
				== GroupTransitionKind::AddMember)
			? std::optional<AccountCredentialPublic>(material->credential)
			: std::nullopt,
		.targetKeyPackage = material ? material->keyPackage : QByteArray(),
	};
}

} // namespace

bool IsPublicJoinRelevantObject(
		const TelegramTransport::UntrustedObject &object,
		ConversationId conversationId,
		std::uint64_t telegramPeerIdBinding,
		const EnvelopeCodec &envelopeCodec) {
	const auto envelope = envelopeCodec.decodeUntrusted(object.bytes);
	return conversationId
		&& telegramPeerIdBinding
		&& envelope
		&& JoinRelevantKind(envelope->objectKind)
		&& envelope->conversationId == conversationId
		&& envelope->telegramPeerIdBinding == telegramPeerIdBinding
		&& object.observedTelegramPeerIdBinding == telegramPeerIdBinding
		&& object.observedMessageId > 0;
}

PublicJoinCatchupOutcome CatchUpPublicJoin(
		const std::vector<TelegramTransport::UntrustedObject> &objects,
		ConversationId conversationId,
		std::uint64_t telegramPeerIdBinding,
		AccountId localAccountId,
		ClientId localClientId,
		const AccountCredentialPublic &localCredential,
		std::uint64_t currentTime,
		const EnvelopeCodec &envelopeCodec,
		const Sha256Provider &sha256,
		PersistentGroupLedger &groupLedger,
		const PersistentKeyPackagePool &keyPackages) {
	if (!conversationId
		|| !telegramPeerIdBinding
		|| !localAccountId
		|| !localClientId
		|| !currentTime
		|| !groupLedger.loaded()
		|| !groupLedger.state()
		|| !keyPackages.loaded()
		|| groupLedger.state()->conversationId() != conversationId) {
		return {};
	}
	auto records = std::map<ObjectId, ObservedEnvelope>();
	for (const auto &object : objects) {
		const auto envelope = envelopeCodec.decodeUntrusted(object.bytes);
		if (!envelope
			|| envelope->conversationId != conversationId
			|| envelope->telegramPeerIdBinding != telegramPeerIdBinding
			|| object.observedTelegramPeerIdBinding
				!= telegramPeerIdBinding
			|| !object.observedSenderTelegramUserIdBinding
			|| object.observedMessageId <= 0) {
			continue;
		}
		const auto i = records.find(envelope->objectId);
		if (i != end(records)) {
			if (i->second.envelope != *envelope
				|| i->second.senderTelegramUserIdBinding
					!= object.observedSenderTelegramUserIdBinding) {
				return {
					.status = PublicJoinCatchupStatus::ForkDetected,
					.bundle = std::nullopt,
					.appliedTransitions = 0,
				};
			}
			continue;
		}
		records.emplace(envelope->objectId, ObservedEnvelope{
			.envelope = *envelope,
			.senderTelegramUserIdBinding =
				object.observedSenderTelegramUserIdBinding,
		});
	}
	auto appliedTransitions = std::uint64_t();
	while (true) {
		auto candidates = std::vector<Candidate>();
		for (const auto &entry : records) {
			const auto &record = entry.second;
			if (record.envelope.objectKind
					!= ObjectKind::SignedGroupTransition
				|| record.envelope.epochOrGeneration
					!= groupLedger.checkpoint().generation + 1) {
				continue;
			}
			auto candidate = VerifyCandidate(
				record,
				records,
				conversationId,
				telegramPeerIdBinding,
				localAccountId,
				localClientId,
				localCredential,
				currentTime,
				envelopeCodec,
				sha256,
				groupLedger,
				keyPackages);
			if (candidate) {
				candidates.push_back(std::move(*candidate));
			}
		}
		if (candidates.empty()) {
			return {
				.status = appliedTransitions
					? PublicJoinCatchupStatus::UpdatedWaiting
					: PublicJoinCatchupStatus::Waiting,
				.bundle = std::nullopt,
				.appliedTransitions = appliedTransitions,
			};
		} else if (candidates.size() != 1) {
			return {
				.status = PublicJoinCatchupStatus::ForkDetected,
				.bundle = std::nullopt,
				.appliedTransitions = appliedTransitions,
			};
		}
		auto &candidate = candidates.front();
		const auto localTarget = candidate.transition.transition.targetAccountId
				== localAccountId
			&& candidate.transition.transition.targetClientId == localClientId;
		if (localTarget && AdmissionKind(candidate.transition.transition.kind)) {
			auto welcomes = std::vector<TransportEnvelope>();
			const auto actor = groupLedger.state()->memberByClient(
				candidate.transition.actorClientId);
			for (const auto &entry : records) {
				const auto &record = entry.second;
				if (record.envelope.objectKind == ObjectKind::MlsWelcome
					&& record.envelope.authenticationData
						== candidate.transitionEnvelope.payload
					&& actor
					&& SameActor(
						record,
						candidate.transition,
						actor->telegramUserIdBinding)
					&& ValidPayload(record.envelope, sha256)) {
					welcomes.push_back(record.envelope);
				}
			}
			if (welcomes.empty()) {
				return {
					.status = appliedTransitions
						? PublicJoinCatchupStatus::UpdatedWaiting
						: PublicJoinCatchupStatus::Waiting,
					.bundle = std::nullopt,
					.appliedTransitions = appliedTransitions,
				};
			} else if (welcomes.size() != 1) {
				return {
					.status = PublicJoinCatchupStatus::ForkDetected,
					.bundle = std::nullopt,
					.appliedTransitions = appliedTransitions,
				};
			}
			return {
				.status = PublicJoinCatchupStatus::Ready,
				.bundle = VerifiedPublicJoinBundle{
					.transitionEnvelope = candidate.transitionEnvelope,
					.commitEnvelope = candidate.commitEnvelope,
					.welcomeEnvelope = std::move(welcomes.front()),
					.archiveDistributionEnvelope =
						candidate.distributionEnvelope,
					.targetCredential = localCredential,
					.targetKeyPackage = candidate.targetKeyPackage,
				},
				.appliedTransitions = appliedTransitions,
			};
		}
		const auto committed = groupLedger.commitTransition(
			groupLedger.revision(),
			candidate.transition,
			candidate.applied,
			candidate.admittedCredential
				? &*candidate.admittedCredential
				: nullptr);
		if (committed != GroupLedgerCommitResult::Committed) {
			return {
				.status = PublicJoinCatchupStatus::PersistenceFailure,
				.bundle = std::nullopt,
				.appliedTransitions = appliedTransitions,
			};
		}
		++appliedTransitions;
	}
}

} // namespace E2ECloud

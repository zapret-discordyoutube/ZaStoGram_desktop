/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "e2e_cloud/archive/history_grant_service.h"

#include "e2e_cloud/mls/openmls_bridge.h"

#include <utility>

namespace E2ECloud {
namespace {

[[nodiscard]] bool HasPermission(
		const GroupMember &member,
		AdminPermission permission) {
	return member.role == GroupRole::Owner
		|| (member.role == GroupRole::Administrator
			&& (member.adminPermissions & PermissionMask(permission)) != 0);
}

[[nodiscard]] bool MayGrant(
		const GroupMember &member,
		const HistoryAccess &access) {
	return HasPermission(member, AdminPermission::GrantHistory)
		&& (access.mode != HistoryAccessMode::Full
			|| HasPermission(member, AdminPermission::GrantFullHistory));
}

[[nodiscard]] bool PayloadMatchesPolicy(
		const HistoryGrantPayload &payload,
		const GroupMember &recipient,
		std::uint64_t groupGeneration,
		const PersistentGroupLedger &groupLedger) {
	if (payload.historyAccess.mode == HistoryAccessMode::None) {
		return payload.epochs.empty();
	} else if (payload.epochs.empty()) {
		return false;
	}
	for (auto index = std::size_t(); index != payload.epochs.size(); ++index) {
		const auto &epoch = payload.epochs[index];
		if (epoch.activationGroupGeneration > groupGeneration
			|| !groupLedger.verifiesArchiveEpoch(epoch)
			|| (index
				&& epoch.generation
					!= payload.epochs[index - 1].generation + 1)) {
			return false;
		}
	}
	const auto &first = payload.epochs.front();
	switch (payload.historyAccess.mode) {
	case HistoryAccessMode::None:
		return false;
	case HistoryAccessMode::Full:
		return first.generation == 1;
	case HistoryAccessMode::FromJoin:
		return first.activationGroupGeneration == recipient.joinedGeneration;
	case HistoryAccessMode::Since:
		return first.activationEventId
			== payload.historyAccess.boundaryEventId;
	}
	return false;
}

[[nodiscard]] HistoryGrantServiceStatus CommitPayload(
		HistoryGrantPayload payload,
		PersistentArchiveState &archiveState) {
	if (payload.historyAccess.mode == HistoryAccessMode::None) {
		return HistoryGrantServiceStatus::Accepted;
	}
	const auto committed = archiveState.mergeHistoryGrant(
		archiveState.revision(),
		std::move(payload));
	switch (committed) {
	case ArchiveStateCommitResult::Committed:
		return HistoryGrantServiceStatus::Accepted;
	case ArchiveStateCommitResult::AlreadyCommitted:
		return HistoryGrantServiceStatus::AlreadyAccepted;
	case ArchiveStateCommitResult::EpochConflict:
		return HistoryGrantServiceStatus::ArchiveConflict;
	case ArchiveStateCommitResult::PersistenceFailed:
		return HistoryGrantServiceStatus::PersistenceFailure;
	case ArchiveStateCommitResult::NotLoaded:
		return HistoryGrantServiceStatus::StateUnavailable;
	case ArchiveStateCommitResult::InvalidMutation:
	case ArchiveStateCommitResult::RevisionConflict:
		return HistoryGrantServiceStatus::InvalidGrant;
	}
	return HistoryGrantServiceStatus::InvalidGrant;
}

} // namespace

CreateAuthorizedHistoryGrantOutcome CreateAuthorizedHistoryGrant(
		CreateAuthorizedHistoryGrantArgs args,
		const PersistentGroupLedger &groupLedger,
		const PersistentArchiveState &archiveState,
		const OpenMlsBridge &bridge) {
	const auto failure = [](HistoryGrantServiceStatus status) {
		return CreateAuthorizedHistoryGrantOutcome{
			.status = status,
			.grant = std::nullopt,
		};
	};
	if (!groupLedger.loaded() || !archiveState.loaded()) {
		return failure(HistoryGrantServiceStatus::StateUnavailable);
	} else if (!args.conversationId
		|| groupLedger.state()->conversationId() != args.conversationId
		|| archiveState.conversationId() != args.conversationId) {
		return failure(HistoryGrantServiceStatus::WrongConversation);
	} else if (!args.telegramPeerIdBinding
		|| !args.groupGeneration
		|| !args.grantId
		|| !args.issuerAccountId
		|| !args.issuerClientId
		|| !args.recipientAccountId
		|| !args.issuerSigningPrivateKey
		|| !args.issuerSigningPrivateKey->valid()
		|| !IsValidHistoryAccess(args.historyAccess)) {
		return failure(HistoryGrantServiceStatus::InvalidGrant);
	}
	const auto state = groupLedger.stateAt(args.groupGeneration);
	if (!state) {
		return failure(HistoryGrantServiceStatus::StateUnavailable);
	}
	const auto issuer = state->member(args.issuerAccountId);
	if (!issuer
		|| !groupLedger.wasClientActiveAt(
			args.issuerAccountId,
			args.issuerClientId,
			args.groupGeneration)
		|| !MayGrant(*issuer, args.historyAccess)) {
		return failure(HistoryGrantServiceStatus::IssuerNotAuthorized);
	}
	const auto recipient = state->member(args.recipientAccountId);
	const auto recipientCredential = groupLedger.credential(
		args.recipientAccountId);
	if (!recipient || !recipientCredential) {
		return failure(HistoryGrantServiceStatus::RecipientNotAuthorized);
	} else if (recipient->historyAccess != args.historyAccess) {
		return failure(HistoryGrantServiceStatus::PolicyMismatch);
	}
	auto epochs = archiveState.exportForGrant(
		args.historyAccess,
		recipient->joinedGeneration);
	if (!epochs) {
		return failure(HistoryGrantServiceStatus::ArchiveBoundaryUnavailable);
	}
	for (const auto &epoch : *epochs) {
		if (!groupLedger.verifiesArchiveEpoch(epoch)) {
			return failure(HistoryGrantServiceStatus::ArchiveConflict);
		}
	}
	auto grant = CreateHistoryGrant({
		.conversationId = args.conversationId,
		.grantId = args.grantId,
		.issuerAccountId = args.issuerAccountId,
		.issuerClientId = args.issuerClientId,
		.recipientAccountId = args.recipientAccountId,
		.telegramPeerIdBinding = args.telegramPeerIdBinding,
		.groupGeneration = args.groupGeneration,
		.historyAccess = args.historyAccess,
		.recipientArchivePublicKey =
			recipientCredential->archiveHpkePublicKey,
		.issuerSigningPrivateKey = args.issuerSigningPrivateKey,
		.epochs = &*epochs,
	}, bridge);
	return grant
		? CreateAuthorizedHistoryGrantOutcome{
			.status = HistoryGrantServiceStatus::Created,
			.grant = std::move(grant),
		}
		: failure(HistoryGrantServiceStatus::CryptoFailure);
}

CreateAuthorizedHistoryGrantOutcome CreateAdmissionHistoryGrant(
		CreateAdmissionHistoryGrantArgs args,
		const PersistentGroupLedger &groupLedger,
		const PersistentArchiveState &archiveState,
		const Sha256Provider &sha256,
		const OpenMlsBridge &bridge) {
	const auto failure = [](HistoryGrantServiceStatus status) {
		return CreateAuthorizedHistoryGrantOutcome{
			.status = status,
			.grant = std::nullopt,
		};
	};
	const auto &grant = args.grant;
	if (!groupLedger.loaded()
		|| !groupLedger.state()
		|| !archiveState.loaded()
		|| !args.signedTransition
		|| !args.applied
		|| !args.archiveEpoch) {
		return failure(HistoryGrantServiceStatus::StateUnavailable);
	}
	const auto &signedTransition = *args.signedTransition;
	const auto &transition = signedTransition.transition;
	const auto &applied = *args.applied;
	const auto &archiveEpoch = *args.archiveEpoch;
	if (grant.conversationId != groupLedger.state()->conversationId()
		|| grant.conversationId != archiveState.conversationId()
		|| transition.conversationId != grant.conversationId
		|| transition.transitionId
			!= archiveEpoch.activationEventId
		|| transition.generation != grant.groupGeneration
		|| transition.generation != archiveEpoch.generation
		|| archiveEpoch.activationGroupGeneration != transition.generation
		|| applied.state.conversationId() != grant.conversationId
		|| applied.state.generation() != transition.generation
		|| applied.checkpoint.generation != transition.generation
		|| applied.checkpoint.stateHash != signedTransition.resultingStateHash
		|| transition.targetAccountId != grant.recipientAccountId
		|| DeriveArchiveKeyCommitment(
			grant.conversationId,
			archiveEpoch.generation,
			archiveEpoch.activationGroupGeneration,
			archiveEpoch.activationEventId,
			archiveEpoch.key,
			sha256) != signedTransition.archiveKeyCommitment) {
		return failure(HistoryGrantServiceStatus::InvalidGrant);
	}
	const auto issuer = groupLedger.state()->member(grant.issuerAccountId);
	const auto issuerClient = groupLedger.state()->memberByClient(
		grant.issuerClientId);
	const auto recipient = applied.state.member(grant.recipientAccountId);
	const auto recipientCredential = args.admittedCredential
		? args.admittedCredential
		: groupLedger.credential(grant.recipientAccountId);
	const auto recipientAccountId = recipientCredential
		? DeriveAccountId(*recipientCredential, sha256)
		: std::nullopt;
	if (!issuer
		|| !issuerClient
		|| issuerClient->accountId != grant.issuerAccountId
		|| !MayGrant(*issuer, grant.historyAccess)) {
		return failure(HistoryGrantServiceStatus::IssuerNotAuthorized);
	} else if (!recipient
		|| recipient->historyAccess != grant.historyAccess
		|| !recipientCredential
		|| !recipientAccountId
		|| *recipientAccountId != grant.recipientAccountId) {
		return failure(HistoryGrantServiceStatus::RecipientNotAuthorized);
	}
	auto epochs = std::optional<std::vector<ArchiveEpochSecret>>();
	switch (grant.historyAccess.mode) {
	case HistoryAccessMode::None:
		epochs.emplace();
		break;
	case HistoryAccessMode::FromJoin:
		if (recipient->joinedGeneration != transition.generation) {
			return failure(HistoryGrantServiceStatus::PolicyMismatch);
		}
		epochs.emplace();
		break;
	case HistoryAccessMode::Full:
	case HistoryAccessMode::Since:
		epochs = archiveState.exportForGrant(
			grant.historyAccess,
			recipient->joinedGeneration);
		break;
	}
	if (!epochs) {
		return failure(HistoryGrantServiceStatus::ArchiveBoundaryUnavailable);
	}
	if (grant.historyAccess.mode != HistoryAccessMode::None) {
		epochs->push_back({
			.generation = archiveEpoch.generation,
			.activationGroupGeneration =
				archiveEpoch.activationGroupGeneration,
			.activationEventId = archiveEpoch.activationEventId,
			.key = archiveEpoch.key.clone(),
		});
	}
	auto encrypted = CreateHistoryGrant({
		.conversationId = grant.conversationId,
		.grantId = grant.grantId,
		.issuerAccountId = grant.issuerAccountId,
		.issuerClientId = grant.issuerClientId,
		.recipientAccountId = grant.recipientAccountId,
		.telegramPeerIdBinding = grant.telegramPeerIdBinding,
		.groupGeneration = grant.groupGeneration,
		.historyAccess = grant.historyAccess,
		.recipientArchivePublicKey =
			recipientCredential->archiveHpkePublicKey,
		.issuerSigningPrivateKey = grant.issuerSigningPrivateKey,
		.epochs = &*epochs,
	}, bridge);
	return encrypted
		? CreateAuthorizedHistoryGrantOutcome{
			.status = HistoryGrantServiceStatus::Created,
			.grant = std::move(encrypted),
		}
		: failure(HistoryGrantServiceStatus::CryptoFailure);
}

HistoryGrantServiceStatus AcceptAuthorizedHistoryGrant(
		AcceptAuthorizedHistoryGrantArgs args,
		const PersistentGroupLedger &groupLedger,
		PersistentArchiveState &archiveState,
		const Sha256Provider &sha256,
		const OpenMlsBridge &bridge) {
	if (!groupLedger.loaded() || !archiveState.loaded()) {
		return HistoryGrantServiceStatus::StateUnavailable;
	} else if (!args.grant
		|| !args.recipientArchivePrivateKey
		|| !args.recipientArchivePrivateKey->valid()
		|| !args.recipientAccountId) {
		return HistoryGrantServiceStatus::InvalidGrant;
	}
	const auto &grant = *args.grant;
	if (grant.conversationId != args.conversationId
		|| groupLedger.state()->conversationId() != args.conversationId
		|| archiveState.conversationId() != args.conversationId) {
		return HistoryGrantServiceStatus::WrongConversation;
	} else if (!args.telegramPeerIdBinding
		|| grant.telegramPeerIdBinding != args.telegramPeerIdBinding) {
		return HistoryGrantServiceStatus::WrongCarrier;
	} else if (grant.recipientAccountId != args.recipientAccountId) {
		return HistoryGrantServiceStatus::RecipientNotAuthorized;
	}
	const auto state = groupLedger.stateAt(grant.groupGeneration);
	if (!state) {
		return HistoryGrantServiceStatus::StateUnavailable;
	}
	const auto issuer = state->member(grant.issuerAccountId);
	if (!issuer
		|| !groupLedger.wasClientActiveAt(
			grant.issuerAccountId,
			grant.issuerClientId,
			grant.groupGeneration)
		|| !MayGrant(*issuer, grant.historyAccess)) {
		return HistoryGrantServiceStatus::IssuerNotAuthorized;
	}
	const auto recipient = state->member(args.recipientAccountId);
	if (!recipient) {
		return HistoryGrantServiceStatus::RecipientNotAuthorized;
	} else if (recipient->historyAccess != grant.historyAccess) {
		return HistoryGrantServiceStatus::PolicyMismatch;
	}
	const auto issuerCredential = groupLedger.credential(
		grant.issuerAccountId);
	if (!issuerCredential) {
		return HistoryGrantServiceStatus::IssuerNotAuthorized;
	}
	auto payload = OpenHistoryGrant(
		grant,
		args.recipientAccountId,
		*args.recipientArchivePrivateKey,
		*issuerCredential,
		sha256,
		bridge);
	if (!payload) {
		return HistoryGrantServiceStatus::CryptoFailure;
	} else if (!PayloadMatchesPolicy(
			*payload,
			*recipient,
			grant.groupGeneration,
			groupLedger)) {
		return HistoryGrantServiceStatus::PolicyMismatch;
	}
	return CommitPayload(std::move(*payload), archiveState);
}

} // namespace E2ECloud

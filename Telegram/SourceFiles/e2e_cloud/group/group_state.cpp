/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "e2e_cloud/group/group_state.h"

#include "e2e_cloud/group/group_transition_codec.h"

#include <algorithm>
#include <limits>
#include <utility>

namespace E2ECloud {

std::optional<ProtectedGroupState> ProtectedGroupState::Create(
		CreateGroupStateArgs args) {
	if (!args.conversationId
		|| !args.ownerAccountId
		|| !args.ownerClientId
		|| !args.ownerTelegramUserIdBinding
		|| !IsValidHistoryAccess(args.policy.defaultHistoryAccess)) {
		return std::nullopt;
	}
	auto result = ProtectedGroupState();
	result._conversationId = args.conversationId;
	result._generation = 1;
	result._policy = args.policy;
	result._members.push_back({
		.accountId = args.ownerAccountId,
		.telegramUserIdBinding = args.ownerTelegramUserIdBinding,
		.role = GroupRole::Owner,
		.adminPermissions = 0,
		.historyAccess = {
			.mode = HistoryAccessMode::Full,
			.boundaryEventId = {},
		},
		.joinedGeneration = result._generation,
		.clients = { args.ownerClientId },
	});
	return result;
}

GroupTransitionResult ProtectedGroupState::validate(
		const GroupTransition &transition,
		const GroupTransitionAuthentication &authentication) const {
	if (!IsValidGroupTransitionStructure(transition)) {
		return GroupTransitionResult::InvalidStructure;
	} else if (transition.conversationId != _conversationId) {
		return GroupTransitionResult::WrongConversation;
	} else if (!transition.transitionId
		|| _appliedTransitionIds.contains(transition.transitionId)) {
		return GroupTransitionResult::InvalidTransitionId;
	} else if (_generation == std::numeric_limits<std::uint64_t>::max()
		|| transition.previousGeneration != _generation
		|| transition.generation != _generation + 1) {
		return GroupTransitionResult::InvalidGeneration;
	}
	const auto actor = member(authentication.actor.accountId);
	if (!actor) {
		return GroupTransitionResult::UnknownActor;
	} else if (std::find(
			begin(actor->clients),
			end(actor->clients),
			authentication.actor.clientId) == end(actor->clients)) {
		return GroupTransitionResult::InvalidActorClient;
	}
	const auto target = member(transition.targetAccountId);
	const auto credential = authentication.targetClientAuthorization;
	switch (transition.kind) {
	case GroupTransitionKind::AddMember:
		if (!actorHasPermission(*actor, AdminPermission::ManageAdmissions)) {
			return GroupTransitionResult::PermissionDenied;
		} else if (!transition.targetAccountId
			|| !transition.targetClientId
			|| !transition.targetTelegramUserIdBinding) {
			return GroupTransitionResult::InvalidTarget;
		} else if (!credential
			|| credential->accountId != transition.targetAccountId
			|| credential->clientId != transition.targetClientId) {
			return GroupTransitionResult::InvalidTargetCredential;
		} else if (target) {
			return GroupTransitionResult::TargetAlreadyMember;
		} else if (memberByTelegramUserId(
				transition.targetTelegramUserIdBinding)) {
			return GroupTransitionResult::TelegramUserAlreadyBound;
		} else if (memberByClient(transition.targetClientId)) {
			return GroupTransitionResult::ClientAlreadyExists;
		} else if (!IsValidHistoryAccess(transition.historyAccess)) {
			return GroupTransitionResult::InvalidHistoryAccess;
		} else if (!actorMayGrant(*actor, transition.historyAccess)) {
			return GroupTransitionResult::PermissionDenied;
		}
		return GroupTransitionResult::Allowed;
	case GroupTransitionKind::RemoveMember:
		if (!actorHasPermission(*actor, AdminPermission::RemoveMembers)) {
			return GroupTransitionResult::PermissionDenied;
		} else if (!target) {
			return GroupTransitionResult::TargetNotMember;
		} else if (target->role == GroupRole::Owner) {
			return GroupTransitionResult::OwnerInvariant;
		} else if (target->role == GroupRole::Administrator
			&& actor->role != GroupRole::Owner) {
			return GroupTransitionResult::PermissionDenied;
		}
		return GroupTransitionResult::Allowed;
	case GroupTransitionKind::AddClient:
		if (!target) {
			return GroupTransitionResult::TargetNotMember;
		} else if (!transition.targetClientId) {
			return GroupTransitionResult::InvalidTarget;
		} else if (!credential
			|| credential->accountId != transition.targetAccountId
			|| credential->clientId != transition.targetClientId) {
			return GroupTransitionResult::InvalidTargetCredential;
		} else if (memberByClient(transition.targetClientId)) {
			return GroupTransitionResult::ClientAlreadyExists;
		}
		return GroupTransitionResult::Allowed;
	case GroupTransitionKind::RemoveClient:
		if (!target) {
			return GroupTransitionResult::TargetNotMember;
		} else if (!transition.targetClientId) {
			return GroupTransitionResult::InvalidTarget;
		} else if (!credential
			|| credential->accountId != transition.targetAccountId
			|| credential->clientId != transition.targetClientId) {
			return GroupTransitionResult::InvalidTargetCredential;
		} else if (std::find(
				begin(target->clients),
				end(target->clients),
				transition.targetClientId) == end(target->clients)) {
			return GroupTransitionResult::ClientNotFound;
		} else if (target->clients.size() == 1) {
			return GroupTransitionResult::InvalidTarget;
		}
		return GroupTransitionResult::Allowed;
	case GroupTransitionKind::SetRole:
		if (actor->role != GroupRole::Owner) {
			return GroupTransitionResult::PermissionDenied;
		} else if (!target) {
			return GroupTransitionResult::TargetNotMember;
		} else if (target->role == GroupRole::Owner) {
			return GroupTransitionResult::OwnerInvariant;
		} else if (transition.targetRole != GroupRole::Member
			&& transition.targetRole != GroupRole::Administrator) {
			return GroupTransitionResult::InvalidRole;
		} else if (!validPermissions(transition.targetAdminPermissions)
			|| (transition.targetRole == GroupRole::Member
				&& transition.targetAdminPermissions)) {
			return GroupTransitionResult::InvalidPermissions;
		}
		return GroupTransitionResult::Allowed;
	case GroupTransitionKind::TransferOwnership:
		if (actor->role != GroupRole::Owner) {
			return GroupTransitionResult::PermissionDenied;
		} else if (!target) {
			return GroupTransitionResult::TargetNotMember;
		} else if (target->role == GroupRole::Owner) {
			return GroupTransitionResult::OwnerInvariant;
		}
		return GroupTransitionResult::Allowed;
	case GroupTransitionKind::SetDefaultHistory:
		if (!actorHasPermission(
				*actor,
				AdminPermission::ChangeDefaultHistory)) {
			return GroupTransitionResult::PermissionDenied;
		} else if (!IsValidHistoryAccess(transition.historyAccess)) {
			return GroupTransitionResult::InvalidHistoryAccess;
		} else if (!actorMayGrant(*actor, transition.historyAccess)) {
			return GroupTransitionResult::PermissionDenied;
		}
		return GroupTransitionResult::Allowed;
	case GroupTransitionKind::SetMemberHistory:
		if (!target) {
			return GroupTransitionResult::TargetNotMember;
		} else if (!IsValidHistoryAccess(transition.historyAccess)) {
			return GroupTransitionResult::InvalidHistoryAccess;
		} else if (!actorMayGrant(*actor, transition.historyAccess)) {
			return GroupTransitionResult::PermissionDenied;
		}
		return GroupTransitionResult::Allowed;
	}
	return GroupTransitionResult::InvalidTarget;
}

GroupTransitionResult ProtectedGroupState::applyVerified(
		const GroupTransition &transition,
		const GroupTransitionAuthentication &authentication) {
	const auto validation = validate(transition, authentication);
	if (validation != GroupTransitionResult::Allowed) {
		return validation;
	}
	const auto actorAccountId = authentication.actor.accountId;
	switch (transition.kind) {
	case GroupTransitionKind::AddMember:
		_members.push_back({
			.accountId = transition.targetAccountId,
			.telegramUserIdBinding = transition.targetTelegramUserIdBinding,
			.role = GroupRole::Member,
			.adminPermissions = 0,
			.historyAccess = transition.historyAccess,
			.joinedGeneration = transition.generation,
			.clients = { transition.targetClientId },
		});
		break;
	case GroupTransitionKind::RemoveMember:
		_members.erase(std::remove_if(
			begin(_members),
			end(_members),
			[&](const GroupMember &member) {
				return member.accountId == transition.targetAccountId;
			}), end(_members));
		break;
	case GroupTransitionKind::AddClient:
		memberMutable(transition.targetAccountId)->clients.push_back(
			transition.targetClientId);
		break;
	case GroupTransitionKind::RemoveClient: {
		auto &clients = memberMutable(transition.targetAccountId)->clients;
		clients.erase(std::remove(
			begin(clients),
			end(clients),
			transition.targetClientId), end(clients));
		break;
	}
	case GroupTransitionKind::SetRole: {
		auto target = memberMutable(transition.targetAccountId);
		target->role = transition.targetRole;
		target->adminPermissions = transition.targetAdminPermissions;
		break;
	}
	case GroupTransitionKind::TransferOwnership: {
		auto previous = memberMutable(actorAccountId);
		auto target = memberMutable(transition.targetAccountId);
		previous->role = GroupRole::Administrator;
		previous->adminPermissions = kDefaultAdminPermissions;
		target->role = GroupRole::Owner;
		target->adminPermissions = 0;
		break;
	}
	case GroupTransitionKind::SetDefaultHistory:
		_policy.defaultHistoryAccess = transition.historyAccess;
		break;
	case GroupTransitionKind::SetMemberHistory:
		memberMutable(transition.targetAccountId)->historyAccess =
			transition.historyAccess;
		break;
	}
	_generation = transition.generation;
	_lastTransitionId = transition.transitionId;
	_appliedTransitionIds.emplace(transition.transitionId);
	return GroupTransitionResult::Allowed;
}

ConversationId ProtectedGroupState::conversationId() const {
	return _conversationId;
}

std::uint64_t ProtectedGroupState::generation() const {
	return _generation;
}

ObjectId ProtectedGroupState::lastTransitionId() const {
	return _lastTransitionId;
}

const GroupPolicy &ProtectedGroupState::policy() const {
	return _policy;
}

const std::vector<GroupMember> &ProtectedGroupState::members() const {
	return _members;
}

const GroupMember *ProtectedGroupState::member(AccountId accountId) const {
	const auto i = std::find_if(
		begin(_members),
		end(_members),
		[&](const GroupMember &member) {
			return member.accountId == accountId;
		});
	return (i != end(_members)) ? &*i : nullptr;
}

const GroupMember *ProtectedGroupState::memberByTelegramUserId(
		std::uint64_t telegramUserId) const {
	const auto i = std::find_if(
		begin(_members),
		end(_members),
		[&](const GroupMember &member) {
			return member.telegramUserIdBinding == telegramUserId;
		});
	return (i != end(_members)) ? &*i : nullptr;
}

const GroupMember *ProtectedGroupState::memberByClient(ClientId clientId) const {
	const auto i = std::find_if(
		begin(_members),
		end(_members),
		[&](const GroupMember &member) {
			return std::find(
				begin(member.clients),
				end(member.clients),
				clientId) != end(member.clients);
		});
	return (i != end(_members)) ? &*i : nullptr;
}

GroupMember *ProtectedGroupState::memberMutable(AccountId accountId) {
	const auto i = std::find_if(
		begin(_members),
		end(_members),
		[&](const GroupMember &member) {
			return member.accountId == accountId;
		});
	return (i != end(_members)) ? &*i : nullptr;
}

bool ProtectedGroupState::actorHasPermission(
		const GroupMember &actor,
		AdminPermission permission) const {
	return actor.role == GroupRole::Owner
		|| (actor.role == GroupRole::Administrator
			&& (actor.adminPermissions & PermissionMask(permission)));
}

bool ProtectedGroupState::actorMayGrant(
		const GroupMember &actor,
		const HistoryAccess &access) const {
	if (!actorHasPermission(actor, AdminPermission::GrantHistory)) {
		return false;
	}
	return access.mode != HistoryAccessMode::Full
		|| actorHasPermission(actor, AdminPermission::GrantFullHistory);
}

bool ProtectedGroupState::validPermissions(
		AdminPermissions permissions) const {
	return (permissions & ~kAllAdminPermissions) == 0;
}

LocalGroupTransitionAuthorizer::LocalGroupTransitionAuthorizer(
		const ProtectedGroupState &state,
		const FreshnessGate &freshness)
: _state(state)
, _freshness(freshness) {
}

GroupTransitionResult LocalGroupTransitionAuthorizer::validate(
		const GroupTransition &transition,
		const GroupTransitionAuthentication &authentication) const {
	if (!_freshness.administrationAllowed()
		|| _freshness.knownCheckpoint().conversationId
			!= _state.conversationId()) {
		return GroupTransitionResult::FreshnessRequired;
	}
	return _state.validate(transition, authentication);
}

} // namespace E2ECloud

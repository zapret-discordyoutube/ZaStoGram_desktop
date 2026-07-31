/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "e2e_cloud/core/freshness_gate.h"
#include "e2e_cloud/core/types.h"

#include <cstdint>
#include <optional>
#include <set>
#include <vector>

namespace E2ECloud {

enum class GroupRole : std::uint8_t {
	Member,
	Administrator,
	Owner,
};

enum class AdminPermission : std::uint32_t {
	ManageAdmissions = (1U << 0),
	RemoveMembers = (1U << 1),
	GrantHistory = (1U << 2),
	GrantFullHistory = (1U << 3),
	ChangeDefaultHistory = (1U << 4),
};

using AdminPermissions = std::uint32_t;

[[nodiscard]] constexpr AdminPermissions PermissionMask(
		AdminPermission permission) {
	return static_cast<AdminPermissions>(permission);
}

inline constexpr auto kDefaultAdminPermissions =
	PermissionMask(AdminPermission::ManageAdmissions)
	| PermissionMask(AdminPermission::RemoveMembers)
	| PermissionMask(AdminPermission::GrantHistory)
	| PermissionMask(AdminPermission::ChangeDefaultHistory);

inline constexpr auto kAllAdminPermissions = kDefaultAdminPermissions
	| PermissionMask(AdminPermission::GrantFullHistory);

struct GroupMember {
	AccountId accountId;
	std::uint64_t telegramUserIdBinding = 0;
	GroupRole role = GroupRole::Member;
	AdminPermissions adminPermissions = 0;
	HistoryAccess historyAccess;
	std::uint64_t joinedGeneration = 0;
	std::vector<ClientId> clients;

	friend inline bool operator==(
		const GroupMember &,
		const GroupMember &) = default;
};

struct GroupPolicy {
	HistoryAccess defaultHistoryAccess;

	friend inline bool operator==(
		const GroupPolicy &,
		const GroupPolicy &) = default;
};

enum class GroupTransitionKind : std::uint8_t {
	AddMember,
	RemoveMember,
	AddClient,
	RemoveClient,
	SetRole,
	TransferOwnership,
	SetDefaultHistory,
	SetMemberHistory,
};

struct GroupTransition {
	ConversationId conversationId;
	ObjectId transitionId;
	std::uint64_t previousGeneration = 0;
	std::uint64_t generation = 0;
	GroupTransitionKind kind = GroupTransitionKind::AddMember;
	AccountId targetAccountId;
	ClientId targetClientId;
	std::uint64_t targetTelegramUserIdBinding = 0;
	GroupRole targetRole = GroupRole::Member;
	AdminPermissions targetAdminPermissions = 0;
	HistoryAccess historyAccess;

	friend inline bool operator==(
		const GroupTransition &,
		const GroupTransition &) = default;
};

struct AuthenticatedActor {
	AccountId accountId;
	ClientId clientId;
};

struct VerifiedClientAuthorization {
	AccountId accountId;
	ClientId clientId;
};

struct GroupTransitionAuthentication {
	AuthenticatedActor actor;
	std::optional<VerifiedClientAuthorization> targetClientAuthorization;
};

enum class GroupTransitionResult {
	Allowed,
	FreshnessRequired,
	WrongConversation,
	InvalidStructure,
	InvalidTransitionId,
	InvalidGeneration,
	UnknownActor,
	InvalidActorClient,
	PermissionDenied,
	InvalidTarget,
	InvalidTargetCredential,
	TargetAlreadyMember,
	TargetNotMember,
	TelegramUserAlreadyBound,
	ClientAlreadyExists,
	ClientNotFound,
	InvalidRole,
	InvalidPermissions,
	InvalidHistoryAccess,
	OwnerInvariant,
};

struct CreateGroupStateArgs {
	ConversationId conversationId;
	AccountId ownerAccountId;
	ClientId ownerClientId;
	std::uint64_t ownerTelegramUserIdBinding = 0;
	GroupPolicy policy;
};

class ProtectedGroupState final {
public:
	[[nodiscard]] static std::optional<ProtectedGroupState> Create(
		CreateGroupStateArgs args);

	[[nodiscard]] GroupTransitionResult validate(
		const GroupTransition &transition,
		const GroupTransitionAuthentication &authentication) const;
	[[nodiscard]] GroupTransitionResult applyVerified(
		const GroupTransition &transition,
		const GroupTransitionAuthentication &authentication);

	[[nodiscard]] ConversationId conversationId() const;
	[[nodiscard]] std::uint64_t generation() const;
	[[nodiscard]] ObjectId lastTransitionId() const;
	[[nodiscard]] const GroupPolicy &policy() const;
	[[nodiscard]] const std::vector<GroupMember> &members() const;
	[[nodiscard]] const GroupMember *member(AccountId accountId) const;
	[[nodiscard]] const GroupMember *memberByTelegramUserId(
		std::uint64_t telegramUserId) const;
	[[nodiscard]] const GroupMember *memberByClient(ClientId clientId) const;

private:
	[[nodiscard]] GroupMember *memberMutable(AccountId accountId);
	[[nodiscard]] bool actorHasPermission(
		const GroupMember &actor,
		AdminPermission permission) const;
	[[nodiscard]] bool actorMayGrant(
		const GroupMember &actor,
		const HistoryAccess &access) const;
	[[nodiscard]] bool validPermissions(AdminPermissions permissions) const;

	ConversationId _conversationId;
	std::uint64_t _generation = 0;
	ObjectId _lastTransitionId;
	GroupPolicy _policy;
	std::vector<GroupMember> _members;
	std::set<ObjectId> _appliedTransitionIds;

};

class LocalGroupTransitionAuthorizer final {
public:
	LocalGroupTransitionAuthorizer(
		const ProtectedGroupState &state,
		const FreshnessGate &freshness);

	[[nodiscard]] GroupTransitionResult validate(
		const GroupTransition &transition,
		const GroupTransitionAuthentication &authentication) const;

private:
	const ProtectedGroupState &_state;
	const FreshnessGate &_freshness;

};

} // namespace E2ECloud

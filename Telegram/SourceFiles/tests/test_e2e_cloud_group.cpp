/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "e2e_cloud/group/group_state.h"
#include "e2e_cloud/group/group_transition_codec.h"

#include <cstdio>
#include <optional>

namespace {

using namespace E2ECloud;

template <typename Id>
[[nodiscard]] Id FilledId(std::uint8_t value) {
	auto result = Id();
	result.bytes.fill(value);
	return result;
}

[[nodiscard]] int Fail(const char *message) {
	std::fprintf(stderr, "%s\n", message);
	return 1;
}

[[nodiscard]] HistoryAccess History(HistoryAccessMode mode) {
	return {
		.mode = mode,
		.boundaryEventId = {},
	};
}

[[nodiscard]] std::optional<ProtectedGroupState> CreateGroup() {
	return ProtectedGroupState::Create({
		.conversationId = FilledId<ConversationId>(1),
		.ownerAccountId = FilledId<AccountId>(10),
		.ownerClientId = FilledId<ClientId>(11),
		.ownerTelegramUserIdBinding = 100,
		.policy = { .defaultHistoryAccess = History(
			HistoryAccessMode::FromJoin) },
	});
}

[[nodiscard]] GroupTransition Transition(
		const ProtectedGroupState &state,
		GroupTransitionKind kind,
		std::uint8_t idValue) {
	return {
		.conversationId = state.conversationId(),
		.transitionId = FilledId<ObjectId>(idValue),
		.previousGeneration = state.generation(),
		.generation = state.generation() + 1,
		.kind = kind,
		.targetAccountId = {},
		.targetClientId = {},
		.targetTelegramUserIdBinding = 0,
		.targetRole = GroupRole::Member,
		.targetAdminPermissions = 0,
		.historyAccess = History(HistoryAccessMode::FromJoin),
	};
}

[[nodiscard]] GroupTransition AddMemberTransition(
		const ProtectedGroupState &state,
		AccountId accountId,
		ClientId clientId,
		std::uint64_t telegramUserId,
		HistoryAccess historyAccess,
		std::uint8_t idValue) {
	auto result = Transition(
		state,
		GroupTransitionKind::AddMember,
		idValue);
	result.targetAccountId = accountId;
	result.targetClientId = clientId;
	result.targetTelegramUserIdBinding = telegramUserId;
	result.historyAccess = historyAccess;
	return result;
}

[[nodiscard]] GroupTransitionAuthentication Authentication(
		AccountId actorAccountId,
		ClientId actorClientId,
		std::optional<VerifiedClientAuthorization> target = std::nullopt) {
	return {
		.actor = {
			.accountId = actorAccountId,
			.clientId = actorClientId,
		},
		.targetClientAuthorization = target,
	};
}

[[nodiscard]] GroupTransitionAuthentication OwnerAuthentication(
		std::optional<VerifiedClientAuthorization> target = std::nullopt) {
	return Authentication(
		FilledId<AccountId>(10),
		FilledId<ClientId>(11),
		target);
}

[[nodiscard]] int AddFirstMember(ProtectedGroupState &state) {
	const auto accountId = FilledId<AccountId>(20);
	const auto clientId = FilledId<ClientId>(21);
	const auto transition = AddMemberTransition(
		state,
		accountId,
		clientId,
		200,
		History(HistoryAccessMode::FromJoin),
		31);
	const auto authentication = OwnerAuthentication(
		VerifiedClientAuthorization{
			.accountId = accountId,
			.clientId = clientId,
		});
	return (state.applyVerified(transition, authentication)
		== GroupTransitionResult::Allowed) ? 0 : 1;
}

class TestVerifier final : public FreshnessResponseVerifier {
public:
	[[nodiscard]] bool verify(
			const FreshnessResponse&) const override {
		return true;
	}

};

[[nodiscard]] int ScenarioGroupCreation() {
	const auto group = CreateGroup();
	if (!group
		|| group->generation() != 1
		|| group->members().size() != 1
		|| group->members().front().role != GroupRole::Owner
		|| group->members().front().historyAccess.mode
			!= HistoryAccessMode::Full
		|| !group->memberByTelegramUserId(100)
		|| !group->memberByClient(FilledId<ClientId>(11))) {
		return Fail("protected group genesis violated owner invariants");
	}
	const auto invalid = ProtectedGroupState::Create({
		.conversationId = FilledId<ConversationId>(1),
		.ownerAccountId = FilledId<AccountId>(10),
		.ownerClientId = {},
		.ownerTelegramUserIdBinding = 100,
		.policy = { .defaultHistoryAccess = History(
			HistoryAccessMode::FromJoin) },
	});
	if (invalid) {
		return Fail("protected group accepted an owner without a client");
	}
	return 0;
}

[[nodiscard]] int ScenarioGroupTransitionCodec() {
	const auto group = CreateGroup();
	if (!group) {
		return Fail("protected group setup failed");
	}
	const auto transition = AddMemberTransition(
		*group,
		FilledId<AccountId>(20),
		FilledId<ClientId>(21),
		200,
		History(HistoryAccessMode::FromJoin),
		31);
	const auto codec = GroupTransitionCodecV1();
	const auto encoded = codec.encode(transition);
	if (!encoded
		|| encoded->size() != kGroupTransitionEncodedSize
		|| codec.decode(*encoded) != transition
		|| std::uint8_t((*encoded)[9]) != 1
		|| std::uint8_t((*encoded)[90])
			!= std::uint8_t(GroupTransitionKind::AddMember)) {
		return Fail("protected group transition codec was not deterministic");
	}
	auto unknownKind = *encoded;
	unknownKind[90] = char(99);
	if (codec.decode(unknownKind)) {
		return Fail("protected group codec accepted an unknown operation");
	}
	auto trailing = *encoded;
	trailing.append('x');
	if (codec.decode(trailing)) {
		return Fail("protected group codec accepted trailing bytes");
	}
	auto nonCanonical = Transition(
		*group,
		GroupTransitionKind::RemoveMember,
		32);
	nonCanonical.targetAccountId = FilledId<AccountId>(20);
	nonCanonical.targetClientId = FilledId<ClientId>(21);
	if (codec.encode(nonCanonical)) {
		return Fail("protected group codec accepted ambiguous unused fields");
	}
	return 0;
}

[[nodiscard]] int ScenarioAdmissionRequiresAuthorityAndCredential() {
	auto group = CreateGroup();
	if (!group) {
		return Fail("protected group setup failed");
	}
	const auto accountId = FilledId<AccountId>(20);
	const auto clientId = FilledId<ClientId>(21);
	const auto transition = AddMemberTransition(
		*group,
		accountId,
		clientId,
		200,
		History(HistoryAccessMode::FromJoin),
		31);
	if (group->validate(transition, OwnerAuthentication())
			!= GroupTransitionResult::InvalidTargetCredential) {
		return Fail("group admission accepted a Telegram-only participant");
	}
	const auto authentication = OwnerAuthentication(
		VerifiedClientAuthorization{
			.accountId = accountId,
			.clientId = clientId,
		});
	if (group->applyVerified(transition, authentication)
			!= GroupTransitionResult::Allowed
		|| group->members().size() != 2
		|| !group->member(accountId)
		|| group->member(accountId)->telegramUserIdBinding != 200) {
		return Fail("authorized group admission was not applied");
	}
	const auto secondAccountId = FilledId<AccountId>(30);
	const auto secondClientId = FilledId<ClientId>(31);
	const auto second = AddMemberTransition(
		*group,
		secondAccountId,
		secondClientId,
		300,
		History(HistoryAccessMode::FromJoin),
		32);
	const auto memberAuthentication = Authentication(
		accountId,
		clientId,
		VerifiedClientAuthorization{
			.accountId = secondAccountId,
			.clientId = secondClientId,
		});
	if (group->validate(second, memberAuthentication)
			!= GroupTransitionResult::PermissionDenied) {
		return Fail("ordinary member gained admission authority");
	}
	return 0;
}

[[nodiscard]] int ScenarioClientEnrollmentUsesAccountProof() {
	auto group = CreateGroup();
	if (!group || AddFirstMember(*group)) {
		return Fail("protected group member setup failed");
	}
	const auto accountId = FilledId<AccountId>(20);
	const auto clientId = FilledId<ClientId>(22);
	auto add = Transition(*group, GroupTransitionKind::AddClient, 32);
	add.targetAccountId = accountId;
	add.targetClientId = clientId;
	const auto authentication = OwnerAuthentication(
		VerifiedClientAuthorization{
			.accountId = accountId,
			.clientId = clientId,
		});
	if (group->applyVerified(add, authentication)
			!= GroupTransitionResult::Allowed
		|| !group->memberByClient(clientId)) {
		return Fail("new installation did not enroll from account proof");
	}
	auto duplicate = Transition(*group, GroupTransitionKind::AddClient, 33);
	duplicate.targetAccountId = accountId;
	duplicate.targetClientId = clientId;
	if (group->validate(duplicate, authentication)
			!= GroupTransitionResult::ClientAlreadyExists) {
		return Fail("duplicate client credential was accepted");
	}
	auto remove = Transition(*group, GroupTransitionKind::RemoveClient, 34);
	remove.targetAccountId = accountId;
	remove.targetClientId = clientId;
	if (group->applyVerified(remove, authentication)
			!= GroupTransitionResult::Allowed
		|| group->memberByClient(clientId)) {
		return Fail("account-authorized client removal failed");
	}
	auto last = Transition(*group, GroupTransitionKind::RemoveClient, 35);
	last.targetAccountId = accountId;
	last.targetClientId = FilledId<ClientId>(21);
	const auto lastAuthentication = OwnerAuthentication(
		VerifiedClientAuthorization{
			.accountId = accountId,
			.clientId = FilledId<ClientId>(21),
		});
	if (group->validate(last, lastAuthentication)
			!= GroupTransitionResult::InvalidTarget) {
		return Fail("member lost its final recoverable client state");
	}
	return 0;
}

[[nodiscard]] int ScenarioAdminCapabilitiesLimitHistory() {
	auto group = CreateGroup();
	if (!group || AddFirstMember(*group)) {
		return Fail("protected group member setup failed");
	}
	const auto accountId = FilledId<AccountId>(20);
	auto promote = Transition(*group, GroupTransitionKind::SetRole, 32);
	promote.targetAccountId = accountId;
	promote.targetRole = GroupRole::Administrator;
	promote.targetAdminPermissions = kDefaultAdminPermissions;
	if (group->applyVerified(promote, OwnerAuthentication())
			!= GroupTransitionResult::Allowed) {
		return Fail("owner could not appoint an E2E administrator");
	}
	auto full = Transition(*group, GroupTransitionKind::SetMemberHistory, 33);
	full.targetAccountId = FilledId<AccountId>(10);
	full.historyAccess = History(HistoryAccessMode::Full);
	const auto adminAuthentication = Authentication(
		accountId,
		FilledId<ClientId>(21));
	if (group->validate(full, adminAuthentication)
			!= GroupTransitionResult::PermissionDenied) {
		return Fail("restricted administrator granted full history");
	}
	auto limited = full;
	limited.transitionId = FilledId<ObjectId>(34);
	limited.historyAccess = {
		.mode = HistoryAccessMode::Since,
		.boundaryEventId = FilledId<ObjectId>(80),
	};
	if (group->applyVerified(limited, adminAuthentication)
			!= GroupTransitionResult::Allowed) {
		return Fail("administrator could not grant bounded history");
	}
	auto escalate = Transition(*group, GroupTransitionKind::SetRole, 35);
	escalate.targetAccountId = FilledId<AccountId>(10);
	escalate.targetRole = GroupRole::Member;
	if (group->validate(escalate, adminAuthentication)
			!= GroupTransitionResult::PermissionDenied) {
		return Fail("administrator changed protected roles without owner");
	}
	return 0;
}

[[nodiscard]] int ScenarioOwnershipTransferIsAtomic() {
	auto group = CreateGroup();
	if (!group || AddFirstMember(*group)) {
		return Fail("protected group member setup failed");
	}
	auto transfer = Transition(
		*group,
		GroupTransitionKind::TransferOwnership,
		32);
	transfer.targetAccountId = FilledId<AccountId>(20);
	if (group->applyVerified(transfer, OwnerAuthentication())
			!= GroupTransitionResult::Allowed
		|| group->member(FilledId<AccountId>(10))->role
			!= GroupRole::Administrator
		|| group->member(FilledId<AccountId>(20))->role
			!= GroupRole::Owner) {
		return Fail("ownership transfer did not preserve exactly one owner");
	}
	auto removeOwner = Transition(
		*group,
		GroupTransitionKind::RemoveMember,
		33);
	removeOwner.targetAccountId = FilledId<AccountId>(20);
	const auto formerOwnerAuthentication = Authentication(
		FilledId<AccountId>(10),
		FilledId<ClientId>(11));
	if (group->validate(removeOwner, formerOwnerAuthentication)
			!= GroupTransitionResult::OwnerInvariant) {
		return Fail("administrator could remove the protected owner");
	}
	return 0;
}

[[nodiscard]] int ScenarioFreshnessBlocksLocalAdministration() {
	auto group = CreateGroup();
	if (!group) {
		return Fail("protected group setup failed");
	}
	const auto checkpoint = Checkpoint{
		.conversationId = group->conversationId(),
		.generation = group->generation(),
		.stateHash = FilledId<Digest>(40),
	};
	auto freshness = FreshnessGate(checkpoint);
	const auto accountId = FilledId<AccountId>(20);
	const auto clientId = FilledId<ClientId>(21);
	const auto transition = AddMemberTransition(
		*group,
		accountId,
		clientId,
		200,
		History(HistoryAccessMode::FromJoin),
		31);
	const auto authentication = OwnerAuthentication(
		VerifiedClientAuthorization{
			.accountId = accountId,
			.clientId = clientId,
		});
	auto authorizer = LocalGroupTransitionAuthorizer(*group, freshness);
	if (authorizer.validate(transition, authentication)
			!= GroupTransitionResult::FreshnessRequired) {
		return Fail("local administration bypassed freshness gate");
	}
	const auto nonce = FilledId<ChallengeNonce>(41);
	const auto response = FreshnessResponse{
		.conversationId = checkpoint.conversationId,
		.nonce = nonce,
		.checkpoint = checkpoint,
		.witnessAccountId = FilledId<AccountId>(10),
		.witnessClientId = FilledId<ClientId>(11),
		.authenticatedProof = QByteArray("proof"),
	};
	const auto verifier = TestVerifier();
	if (!freshness.beginChallenge(nonce)
		|| freshness.acceptResponse(response, verifier)
			!= FreshnessResponseResult::Accepted
		|| authorizer.validate(transition, authentication)
			!= GroupTransitionResult::Allowed) {
		return Fail("freshness confirmation did not enable administration");
	}
	return 0;
}

[[nodiscard]] int ScenarioTransitionReplayIsRejected() {
	auto group = CreateGroup();
	if (!group) {
		return Fail("protected group setup failed");
	}
	const auto accountId = FilledId<AccountId>(20);
	const auto clientId = FilledId<ClientId>(21);
	const auto transition = AddMemberTransition(
		*group,
		accountId,
		clientId,
		200,
		History(HistoryAccessMode::FromJoin),
		31);
	const auto authentication = OwnerAuthentication(
		VerifiedClientAuthorization{
			.accountId = accountId,
			.clientId = clientId,
		});
	if (group->applyVerified(transition, authentication)
			!= GroupTransitionResult::Allowed) {
		return Fail("protected transition setup failed");
	}
	auto replay = Transition(*group, GroupTransitionKind::SetMemberHistory, 31);
	replay.targetAccountId = accountId;
	if (group->validate(replay, OwnerAuthentication())
			!= GroupTransitionResult::InvalidTransitionId) {
		return Fail("duplicate protected transition identifier was accepted");
	}
	return 0;
}

} // namespace

int main(int, char *[]) {
	for (const auto scenario : {
		ScenarioGroupCreation,
		ScenarioGroupTransitionCodec,
		ScenarioAdmissionRequiresAuthorityAndCredential,
		ScenarioClientEnrollmentUsesAccountProof,
		ScenarioAdminCapabilitiesLimitHistory,
		ScenarioOwnershipTransferIsAtomic,
		ScenarioFreshnessBlocksLocalAdministration,
		ScenarioTransitionReplayIsRejected,
	}) {
		if (const auto result = scenario()) {
			return result;
		}
	}
	return 0;
}

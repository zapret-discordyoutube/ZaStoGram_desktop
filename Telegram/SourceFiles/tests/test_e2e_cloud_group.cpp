/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "e2e_cloud/group/group_state.h"
#include "e2e_cloud/archive/archived_content_reader.h"
#include "e2e_cloud/archive/history_grant_service.h"
#include "e2e_cloud/archive/persistent_archive_state.h"
#include "e2e_cloud/core/envelope_codec.h"
#include "e2e_cloud/core/freshness_crypto.h"
#include "e2e_cloud/group/group_state_codec.h"
#include "e2e_cloud/group/persistent_group_ledger.h"
#include "e2e_cloud/group/signed_group_genesis.h"
#include "e2e_cloud/group/group_transition_codec.h"
#include "e2e_cloud/group/signed_group_transition.h"
#include "e2e_cloud/identity/openssl_account_crypto.h"
#include "e2e_cloud/identity/safety_gossip.h"
#include "e2e_cloud/protocol/freshness_protocol.h"
#include "e2e_cloud/mls/client_key_package.h"
#include "e2e_cloud/mls/mls_context_codec.h"
#include "e2e_cloud/mls/openmls_bridge.h"
#include "e2e_cloud/protocol/group_change_transaction.h"
#include "e2e_cloud/storage/aes_gcm_local_record_protector.h"

#include <cstdio>
#include <optional>
#include <utility>

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

[[nodiscard]] ArchiveKey32 CloneArchiveKey(const ArchiveKey32 &key) {
	return key.clone();
}

class MemoryBlobStore final : public AtomicBlobStore {
public:
	[[nodiscard]] BlobReadResult read() const override {
		return bytes
			? BlobReadResult{
				.status = BlobReadStatus::Found,
				.bytes = *bytes,
			}
			: BlobReadResult{
				.status = BlobReadStatus::Missing,
				.bytes = {},
			};
	}

	bool writeAtomic(const QByteArray &value) override {
		if (failWrites) {
			return false;
		}
		bytes = value;
		return true;
	}

	std::optional<QByteArray> bytes;
	bool failWrites = false;
};

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

[[nodiscard]] int ScenarioGroupSnapshotRestoresInvariants() {
	auto group = CreateGroup();
	if (!group || AddFirstMember(*group)) {
		return Fail("protected group snapshot setup failed");
	}
	const auto snapshot = group->snapshot();
	const auto restored = ProtectedGroupState::Restore(snapshot);
	const auto codec = ProtectedGroupStateCodecV1();
	const auto encoded = codec.encode(*group);
	const auto decoded = encoded ? codec.decode(*encoded) : std::nullopt;
	if (!restored
		|| restored->conversationId() != group->conversationId()
		|| restored->generation() != group->generation()
		|| restored->lastTransitionId() != group->lastTransitionId()
		|| restored->policy() != group->policy()
		|| restored->members() != group->members()
		|| !encoded
		|| !decoded
		|| decoded->members() != group->members()
		|| decoded->generation() != group->generation()) {
		return Fail("protected group snapshot did not round-trip");
	}
	auto duplicateClient = snapshot;
	duplicateClient.members[1].clients.push_back(
		duplicateClient.members[0].clients.front());
	if (ProtectedGroupState::Restore(std::move(duplicateClient))) {
		return Fail("protected group restored a duplicate client identity");
	}
	auto secondOwner = snapshot;
	secondOwner.members[1].role = GroupRole::Owner;
	if (ProtectedGroupState::Restore(std::move(secondOwner))) {
		return Fail("protected group restored more than one owner");
	}
	auto trailing = *encoded;
	trailing.append(char(0));
	if (codec.decode(trailing)) {
		return Fail("protected group state codec accepted trailing bytes");
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

[[nodiscard]] int ScenarioClientKeyPackageEnvelopeIsSelfAuthenticating() {
	auto identity = GenerateAccountPrivateIdentity();
	const auto sha256 = OpenSslSha256Provider();
	const auto accountId = identity
		? DeriveAccountId(identity->credential, sha256)
		: std::nullopt;
	const auto conversationId = FilledId<ConversationId>(36);
	const auto authorizationId = FilledId<ObjectId>(37);
	const auto clientId = FilledId<ClientId>(38);
	const auto keyPackage = QByteArray("opaque OpenMLS KeyPackage");
	const auto generation = std::uint64_t(9);
	const auto peerBinding = std::uint64_t(400);
	const auto authorization = accountId
		? CreateClientAuthorizationProof({
			.conversationId = conversationId,
			.authorizationId = authorizationId,
			.accountId = *accountId,
			.clientId = clientId,
			.requestedAfterGeneration = generation,
			.createdAt = 1'000'000,
			.accountCredential = &identity->credential,
			.accountSigningPrivateKey = &identity->signingPrivateKey,
			.keyPackage = keyPackage,
		}, sha256)
		: std::nullopt;
	const auto publication = authorization
		? std::optional<ClientKeyPackagePublication>({
			.accountCredential = identity->credential,
			.authorization = *authorization,
			.keyPackage = keyPackage,
		})
		: std::nullopt;
	const auto payload = publication
		? ClientKeyPackagePublicationCodecV1().encode(*publication)
		: std::nullopt;
	if (!identity || !accountId || !authorization || !payload) {
		return Fail("client KeyPackage publication setup failed");
	}
	const auto signature = QByteArray(
		reinterpret_cast<const char*>(authorization->signature.data()),
		int(authorization->signature.size()));
	auto envelope = TransportEnvelope{
		.conversationId = conversationId,
		.objectKind = ObjectKind::ClientKeyPackage,
		.senderAccountId = *accountId,
		.senderClientId = clientId,
		.telegramPeerIdBinding = peerBinding,
		.epochOrGeneration = generation,
		.objectId = authorizationId,
		.payloadHash = sha256.digest(*payload),
		.payload = *payload,
		.authenticationData = signature,
	};
	const auto verified = VerifyClientKeyPackageEnvelope(
		envelope,
		conversationId,
		peerBinding,
		generation,
		sha256);
	if (verified.result != ClientKeyPackageEnvelopeResult::Verified
		|| !verified.publication
		|| *verified.publication != *publication
		|| !ClientAuthorizationUsableAt(*authorization, 1'000'000)
		|| ClientAuthorizationUsableAt(
			*authorization,
			authorization->expiresAt
				+ kClientAuthorizationClockSkewSeconds + 1)) {
		return Fail("client KeyPackage envelope did not verify");
	}
	auto changedLifetime = *publication;
	++changedLifetime.authorization.createdAt;
	++changedLifetime.authorization.expiresAt;
	const auto changedLifetimePayload
		= ClientKeyPackagePublicationCodecV1().encode(changedLifetime);
	if (!changedLifetimePayload) {
		return Fail("client KeyPackage lifetime mutation setup failed");
	}
	auto changedLifetimeEnvelope = envelope;
	changedLifetimeEnvelope.payload = *changedLifetimePayload;
	changedLifetimeEnvelope.payloadHash = sha256.digest(
		*changedLifetimePayload);
	if (VerifyClientKeyPackageEnvelope(
		changedLifetimeEnvelope,
		conversationId,
		peerBinding,
		generation,
		sha256).result
			!= ClientKeyPackageEnvelopeResult::InvalidAuthorization) {
		return Fail("modified KeyPackage lifetime was accepted");
	}
	auto moved = envelope;
	moved.telegramPeerIdBinding++;
	if (VerifyClientKeyPackageEnvelope(
		moved,
		conversationId,
		peerBinding,
		generation,
		sha256).result != ClientKeyPackageEnvelopeResult::WrongCarrier) {
		return Fail("client KeyPackage crossed its Telegram carrier binding");
	}
	auto modified = envelope;
	modified.payload[modified.payload.size() - 1] ^= 1;
	if (VerifyClientKeyPackageEnvelope(
		modified,
		conversationId,
		peerBinding,
		generation,
		sha256).result != ClientKeyPackageEnvelopeResult::InvalidEnvelope) {
		return Fail("modified client KeyPackage envelope was accepted");
	}
	if (VerifyClientKeyPackageEnvelope(
		envelope,
		conversationId,
		peerBinding,
		generation + 1,
		sha256).result != ClientKeyPackageEnvelopeResult::WrongGeneration) {
		return Fail("stale client KeyPackage authorization was accepted");
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
		.challengedCheckpoint = checkpoint,
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
	auto advanced = checkpoint;
	++advanced.generation;
	advanced.stateHash = FilledId<Digest>(42);
	auto conflicting = advanced;
	conflicting.stateHash = FilledId<Digest>(43);
	if (!freshness.advanceTrustedCheckpoint(advanced)
		|| freshness.knownCheckpoint() != advanced
		|| freshness.advanceTrustedCheckpoint(conflicting)) {
		return Fail("trusted freshness checkpoint did not advance safely");
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

[[nodiscard]] int ScenarioSignedTransitionBindsAdmissionAndMlsCommit() {
	auto ownerIdentity = GenerateAccountPrivateIdentity();
	auto targetIdentity = GenerateAccountPrivateIdentity();
	const auto sha256 = OpenSslSha256Provider();
	const auto ownerAccountId = ownerIdentity
		? DeriveAccountId(ownerIdentity->credential, sha256)
		: std::nullopt;
	const auto targetAccountId = targetIdentity
		? DeriveAccountId(targetIdentity->credential, sha256)
		: std::nullopt;
	if (!ownerIdentity
		|| !targetIdentity
		|| !ownerAccountId
		|| !targetAccountId) {
		return Fail("signed group transition identity setup failed");
	}
	const auto ownerClientId = FilledId<ClientId>(51);
	auto group = ProtectedGroupState::Create({
		.conversationId = FilledId<ConversationId>(50),
		.ownerAccountId = *ownerAccountId,
		.ownerClientId = ownerClientId,
		.ownerTelegramUserIdBinding = 500,
		.policy = { .defaultHistoryAccess = History(
			HistoryAccessMode::FromJoin) },
	});
	if (!group) {
		return Fail("signed group transition group setup failed");
	}
	const auto targetClientId = FilledId<ClientId>(52);
	const auto keyPackage = QByteArray("canonical target MLS KeyPackage");
	const auto targetAuthorization = CreateClientAuthorizationProof({
		.conversationId = group->conversationId(),
		.authorizationId = FilledId<ObjectId>(53),
		.accountId = *targetAccountId,
		.clientId = targetClientId,
		.requestedAfterGeneration = group->generation(),
		.createdAt = 1'000'000,
		.accountCredential = &targetIdentity->credential,
		.accountSigningPrivateKey = &targetIdentity->signingPrivateKey,
		.keyPackage = keyPackage,
	}, sha256);
	auto transition = AddMemberTransition(
		*group,
		*targetAccountId,
		targetClientId,
		600,
		History(HistoryAccessMode::FromJoin),
		54);
	const auto checkpoint = Checkpoint{
		.conversationId = group->conversationId(),
		.generation = group->generation(),
		.stateHash = FilledId<Digest>(55),
	};
	const auto mlsCommit = QByteArray("exact MLS add commit");
	const auto mlsCommitObjectId = FilledId<ObjectId>(56);
	const auto archiveCrypto = ArchiveEpochCrypto();
	auto nextArchiveKey = archiveCrypto.generateKey();
	const auto signedTransition = targetAuthorization && nextArchiveKey
		? CreateSignedGroupTransition({
			.transition = transition,
			.actorAccountId = *ownerAccountId,
			.actorClientId = ownerClientId,
			.previousStateHash = checkpoint.stateHash,
			.mlsCommitObjectId = mlsCommitObjectId,
			.actorCredential = &ownerIdentity->credential,
			.actorSigningPrivateKey = &ownerIdentity->signingPrivateKey,
			.nextArchiveKey = &*nextArchiveKey,
			.archiveDistributionObjectId = mlsCommitObjectId,
			.archiveDistribution = mlsCommit,
			.targetClientAuthorization = &*targetAuthorization,
			.mlsCommit = mlsCommit,
		}, sha256)
		: std::nullopt;
	const auto codec = SignedGroupTransitionCodecV1();
	const auto targetEncoded = targetAuthorization
		? ClientAuthorizationProofCodecV1().encode(*targetAuthorization)
		: std::nullopt;
	const auto encoded = signedTransition
		? codec.encode(*signedTransition)
		: std::nullopt;
	const auto decoded = encoded ? codec.decode(*encoded) : std::nullopt;
	const auto applied = decoded
		? VerifyAndApplySignedGroupTransition({
			.currentState = &*group,
			.currentCheckpoint = checkpoint,
			.signedTransition = &*decoded,
			.actorCredential = &ownerIdentity->credential,
			.targetCredential = &targetIdentity->credential,
			.mlsCommitObjectId = mlsCommitObjectId,
			.mlsCommit = mlsCommit,
			.nextArchiveKey = &*nextArchiveKey,
			.archiveDistributionObjectId = mlsCommitObjectId,
			.archiveDistribution = mlsCommit,
			.targetKeyPackage = keyPackage,
		}, sha256)
		: VerifySignedGroupTransitionOutcome();
	if (!targetAuthorization
		|| !targetEncoded
		|| targetEncoded->size() != kClientAuthorizationProofEncodedSize
		|| !signedTransition
		|| !encoded
		|| encoded->size() != kSignedGroupTransitionEncodedSize
		|| !decoded
		|| *decoded != *signedTransition
		|| applied.result != SignedGroupTransitionResult::Applied
		|| !applied.applied
		|| !applied.applied->state.member(*targetAccountId)
		|| applied.applied->checkpoint.generation != transition.generation
		|| applied.applied->checkpoint.stateHash
			!= signedTransition->resultingStateHash) {
		return Fail("signed admission transition did not verify and apply");
	}
	const auto wrongCommit = VerifyAndApplySignedGroupTransition({
		.currentState = &*group,
		.currentCheckpoint = checkpoint,
		.signedTransition = &*decoded,
		.actorCredential = &ownerIdentity->credential,
		.targetCredential = &targetIdentity->credential,
		.mlsCommitObjectId = mlsCommitObjectId,
		.mlsCommit = QByteArray("substituted MLS commit"),
		.nextArchiveKey = &*nextArchiveKey,
		.archiveDistributionObjectId = mlsCommitObjectId,
		.archiveDistribution = mlsCommit,
		.targetKeyPackage = keyPackage,
	}, sha256);
	const auto wrongKeyPackage = VerifyAndApplySignedGroupTransition({
		.currentState = &*group,
		.currentCheckpoint = checkpoint,
		.signedTransition = &*decoded,
		.actorCredential = &ownerIdentity->credential,
		.targetCredential = &targetIdentity->credential,
		.mlsCommitObjectId = mlsCommitObjectId,
		.mlsCommit = mlsCommit,
		.nextArchiveKey = &*nextArchiveKey,
		.archiveDistributionObjectId = mlsCommitObjectId,
		.archiveDistribution = mlsCommit,
		.targetKeyPackage = QByteArray("substituted KeyPackage"),
	}, sha256);
	auto wrongArchiveKey = archiveCrypto.generateKey();
	const auto wrongArchive = wrongArchiveKey
		? VerifyAndApplySignedGroupTransition({
			.currentState = &*group,
			.currentCheckpoint = checkpoint,
			.signedTransition = &*decoded,
			.actorCredential = &ownerIdentity->credential,
			.targetCredential = &targetIdentity->credential,
			.mlsCommitObjectId = mlsCommitObjectId,
			.mlsCommit = mlsCommit,
			.nextArchiveKey = &*wrongArchiveKey,
			.archiveDistributionObjectId = mlsCommitObjectId,
			.archiveDistribution = mlsCommit,
			.targetKeyPackage = keyPackage,
		}, sha256)
		: VerifySignedGroupTransitionOutcome();
	if (wrongCommit.result != SignedGroupTransitionResult::InvalidMlsCommit
		|| wrongKeyPackage.result
			!= SignedGroupTransitionResult::InvalidTargetAuthorization
		|| wrongArchive.result
			!= SignedGroupTransitionResult::InvalidArchiveKey) {
		return Fail("signed transition did not bind MLS admission bytes");
	}
	auto modified = *decoded;
	modified.actorSignature[0] ^= 1;
	if (VerifyAndApplySignedGroupTransition({
		.currentState = &*group,
		.currentCheckpoint = checkpoint,
		.signedTransition = &modified,
		.actorCredential = &ownerIdentity->credential,
		.targetCredential = &targetIdentity->credential,
		.mlsCommitObjectId = mlsCommitObjectId,
		.mlsCommit = mlsCommit,
		.nextArchiveKey = &*nextArchiveKey,
		.archiveDistributionObjectId = mlsCommitObjectId,
		.archiveDistribution = mlsCommit,
		.targetKeyPackage = keyPackage,
	}, sha256).result != SignedGroupTransitionResult::InvalidActorSignature) {
		return Fail("signed transition accepted a modified actor signature");
	}
	return 0;
}

[[nodiscard]] int ScenarioSignedGenesisPinsTheChainRoot() {
	auto owner = GenerateAccountPrivateIdentity();
	const auto sha256 = OpenSslSha256Provider();
	const auto ownerAccountId = owner
		? DeriveAccountId(owner->credential, sha256)
		: std::nullopt;
	const auto archiveCrypto = ArchiveEpochCrypto();
	auto archiveKey = archiveCrypto.generateKey();
	if (!owner || !ownerAccountId || !archiveKey) {
		return Fail("signed genesis identity setup failed");
	}
	const auto conversationId = FilledId<ConversationId>(70);
	const auto ownerClientId = FilledId<ClientId>(72);
	const auto groupId = QByteArray(
		reinterpret_cast<const char*>(conversationId.bytes.data()),
		int(conversationId.bytes.size()));
	const auto ownerMlsCredential = MlsContextCodecV1().encodeCredential({
		.conversationId = conversationId,
		.accountId = *ownerAccountId,
		.clientId = ownerClientId,
	});
	const auto initialMls = ownerMlsCredential
		? OpenMlsBridge().createGroup(*ownerMlsCredential, groupId)
		: OpenMlsStateOutput();
	if (initialMls.status != OpenMlsBridgeStatus::Ok
		|| initialMls.roster.isEmpty()) {
		return Fail("signed genesis OpenMLS state setup failed");
	}
	const auto initialMlsPublicObjectId = FilledId<ObjectId>(71);
	const auto genesisObjectId = FilledId<ObjectId>(75);
	const auto initialMlsPublicObject = initialMls.roster;
	const auto genesis = CreateSignedGroupGenesis({
		.conversationId = conversationId,
		.genesisObjectId = genesisObjectId,
		.telegramPeerIdBinding = 700,
		.ownerAccountId = *ownerAccountId,
		.ownerClientId = ownerClientId,
		.ownerTelegramUserIdBinding = 701,
		.policy = { .defaultHistoryAccess = History(
			HistoryAccessMode::FromJoin) },
		.mlsGroupId = sha256.digest(groupId),
		.initialMlsPublicObjectId = initialMlsPublicObjectId,
		.archiveActivationEventId = FilledId<ObjectId>(74),
		.initialArchiveKey = &*archiveKey,
		.ownerCredential = &owner->credential,
		.ownerSigningPrivateKey = &owner->signingPrivateKey,
		.initialMlsPublicObject = initialMlsPublicObject,
	}, sha256);
	const auto codec = SignedGroupGenesisCodecV1();
	const auto encoded = genesis ? codec.encode(*genesis) : std::nullopt;
	const auto decoded = encoded ? codec.decode(*encoded) : std::nullopt;
	const auto verified = decoded
		? VerifySignedGroupGenesis({
			.genesis = &*decoded,
			.ownerCredential = &owner->credential,
			.genesisObjectId = genesisObjectId,
			.initialMlsPublicObjectId = initialMlsPublicObjectId,
			.initialMlsPublicObject = initialMlsPublicObject,
			.initialArchiveKey = &*archiveKey,
		}, sha256)
		: VerifySignedGroupGenesisOutcome();
	if (!genesis
		|| !encoded
		|| encoded->size() != kSignedGroupGenesisEncodedSize
		|| !decoded
		|| *decoded != *genesis
		|| verified.result != SignedGroupGenesisResult::Verified
		|| !verified.verified
		|| verified.verified->state.generation() != 1
		|| verified.verified->state.member(*ownerAccountId) == nullptr
		|| verified.verified->checkpoint.stateHash != sha256.digest(*encoded)
		|| verified.verified->initialArchiveEpoch.generation != 1
		|| verified.verified->initialArchiveEpoch.key.bytes()
			!= archiveKey->bytes()) {
		return Fail("signed group genesis did not establish its chain root");
	}
	if (VerifySignedGroupGenesis({
		.genesis = &*decoded,
		.ownerCredential = &owner->credential,
		.genesisObjectId = genesisObjectId,
		.initialMlsPublicObjectId = initialMlsPublicObjectId,
		.initialMlsPublicObject = QByteArray(
			"substituted public MLS roster"),
		.initialArchiveKey = &*archiveKey,
	}, sha256).result != SignedGroupGenesisResult::InvalidMlsObject) {
		return Fail("signed genesis accepted substituted MLS state");
	}
	auto wrongArchiveKey = archiveCrypto.generateKey();
	if (!wrongArchiveKey
		|| VerifySignedGroupGenesis({
			.genesis = &*decoded,
			.ownerCredential = &owner->credential,
			.genesisObjectId = genesisObjectId,
			.initialMlsPublicObjectId = initialMlsPublicObjectId,
			.initialMlsPublicObject = initialMlsPublicObject,
			.initialArchiveKey = &*wrongArchiveKey,
		}, sha256).result != SignedGroupGenesisResult::InvalidArchiveKey) {
		return Fail("signed genesis accepted a substituted archive key");
	}
	auto modified = *decoded;
	modified.ownerSignature[0] ^= 1;
	if (VerifySignedGroupGenesis({
		.genesis = &modified,
		.ownerCredential = &owner->credential,
		.genesisObjectId = genesisObjectId,
		.initialMlsPublicObjectId = initialMlsPublicObjectId,
		.initialMlsPublicObject = initialMlsPublicObject,
		.initialArchiveKey = &*archiveKey,
	}, sha256).result != SignedGroupGenesisResult::InvalidOwnerSignature) {
		return Fail("signed genesis accepted a modified owner signature");
	}
	return 0;
}

[[nodiscard]] int ScenarioPersistentGroupLedgerTracksHistoricalMembership() {
	auto owner = GenerateAccountPrivateIdentity();
	auto target = GenerateAccountPrivateIdentity();
	const auto sha256 = OpenSslSha256Provider();
	const auto ownerAccountId = owner
		? DeriveAccountId(owner->credential, sha256)
		: std::nullopt;
	const auto targetAccountId = target
		? DeriveAccountId(target->credential, sha256)
		: std::nullopt;
	const auto archiveCrypto = ArchiveEpochCrypto();
	auto archiveKey = archiveCrypto.generateKey();
	if (!owner
		|| !target
		|| !ownerAccountId
		|| !targetAccountId
		|| !archiveKey) {
		return Fail("group ledger setup failed");
	}
	const auto conversationId = FilledId<ConversationId>(90);
	const auto ownerClientId = FilledId<ClientId>(91);
	const auto genesisObjectId = FilledId<ObjectId>(92);
	const auto initialMlsPublicObjectId = FilledId<ObjectId>(93);
	const auto groupId = QByteArray(
		reinterpret_cast<const char*>(conversationId.bytes.data()),
		int(conversationId.bytes.size()));
	const auto ownerMlsCredential = MlsContextCodecV1().encodeCredential({
		.conversationId = conversationId,
		.accountId = *ownerAccountId,
		.clientId = ownerClientId,
	});
	const auto initialMls = ownerMlsCredential
		? OpenMlsBridge().createGroup(*ownerMlsCredential, groupId)
		: OpenMlsStateOutput();
	const auto initialMlsPublicObject = initialMls.roster;
	const auto genesis = CreateSignedGroupGenesis({
		.conversationId = conversationId,
		.genesisObjectId = genesisObjectId,
		.telegramPeerIdBinding = 900,
		.ownerAccountId = *ownerAccountId,
		.ownerClientId = ownerClientId,
		.ownerTelegramUserIdBinding = 901,
		.policy = { .defaultHistoryAccess = History(
			HistoryAccessMode::FromJoin) },
		.mlsGroupId = sha256.digest(groupId),
		.initialMlsPublicObjectId = initialMlsPublicObjectId,
		.archiveActivationEventId = FilledId<ObjectId>(95),
		.initialArchiveKey = &*archiveKey,
		.ownerCredential = &owner->credential,
		.ownerSigningPrivateKey = &owner->signingPrivateKey,
		.initialMlsPublicObject = initialMlsPublicObject,
	}, sha256);
	const auto verifiedGenesis = genesis
		? VerifySignedGroupGenesis({
			.genesis = &*genesis,
			.ownerCredential = &owner->credential,
			.genesisObjectId = genesisObjectId,
			.initialMlsPublicObjectId = initialMlsPublicObjectId,
			.initialMlsPublicObject = initialMlsPublicObject,
			.initialArchiveKey = &*archiveKey,
		}, sha256)
		: VerifySignedGroupGenesisOutcome();
	auto localKey = LocalRecordKey();
	localKey.fill(96);
	const auto protector = AesGcmLocalRecordProtector(std::move(localKey));
	auto blob = MemoryBlobStore();
	auto ledger = PersistentGroupLedger(blob, protector, sha256);
	if (initialMls.status != OpenMlsBridgeStatus::Ok
		|| !genesis
		|| !verifiedGenesis.verified
		|| ledger.load(conversationId) != GroupLedgerLoadResult::Missing
		|| ledger.initialize(
			*genesis,
			verifiedGenesis.verified->state,
			verifiedGenesis.verified->checkpoint,
			owner->credential) != GroupLedgerCommitResult::Committed) {
		return Fail("group ledger genesis was not persisted");
	}
	const auto freshnessChallenge = FreshnessChallenge{
		.conversationId = conversationId,
		.knownCheckpoint = ledger.checkpoint(),
		.nonce = FilledId<ChallengeNonce>(96),
	};
	const auto signedFreshness = CreateFreshnessResponse({
		.challenge = freshnessChallenge,
		.witnessCheckpoint = ledger.checkpoint(),
		.witnessAccountId = *ownerAccountId,
		.witnessClientId = ownerClientId,
		.witnessSigningPrivateKey = &owner->signingPrivateKey,
	});
	const auto encodedChallenge = FreshnessChallengeCodecV1().encode(
		freshnessChallenge);
	const auto decodedChallenge = encodedChallenge
		? FreshnessChallengeCodecV1().decode(*encodedChallenge)
		: std::nullopt;
	const auto encodedFreshness = signedFreshness
		? FreshnessResponseCodecV1().encode(*signedFreshness)
		: std::nullopt;
	const auto decodedFreshness = encodedFreshness
		? FreshnessResponseCodecV1().decode(*encodedFreshness)
		: std::nullopt;
	const auto freshnessVerifier = AccountFreshnessResponseVerifier(ledger);
	auto freshnessGate = FreshnessGate(ledger.checkpoint());
	if (!decodedChallenge
		|| *decodedChallenge != freshnessChallenge
		|| !decodedFreshness
		|| !freshnessVerifier.verify(*decodedFreshness)
		|| !freshnessGate.beginChallenge(freshnessChallenge.nonce)
		|| freshnessGate.acceptResponse(
			*decodedFreshness,
			freshnessVerifier) != FreshnessResponseResult::Accepted
		|| !freshnessGate.sendingAllowed()) {
		return Fail("signed freshness witness did not open the gate");
	}
	auto modifiedFreshness = *decodedFreshness;
	modifiedFreshness.checkpoint.stateHash.bytes[0] ^= 1;
	if (freshnessVerifier.verify(modifiedFreshness)) {
		return Fail("freshness verifier accepted a modified checkpoint");
	}
	const auto freshnessEnvelopeCodec = EnvelopeCodecV1();
	const auto challengeEnvelope = PrepareFreshnessChallengeEnvelope({
		.challenge = freshnessChallenge,
		.requesterAccountId = *ownerAccountId,
		.requesterClientId = ownerClientId,
		.telegramPeerIdBinding = 900,
		.objectId = FilledId<ObjectId>(86),
		.requesterSigningPrivateKey = &owner->signingPrivateKey,
	}, freshnessEnvelopeCodec, sha256);
	const auto observedChallenge = challengeEnvelope
		? VerifyObservedFreshnessChallenge({
			.bytes = challengeEnvelope->bytes,
			.observedTelegramPeerIdBinding = 900,
			.observedSenderTelegramUserIdBinding = 901,
			.observedMessageId = 87,
		},
		conversationId,
		900,
		freshnessEnvelopeCodec,
		ledger,
		sha256)
		: std::nullopt;
	const auto responseEnvelope = observedChallenge
		? PrepareFreshnessResponseEnvelope({
			.challenge = observedChallenge->challenge,
			.witnessCheckpoint = ledger.checkpoint(),
			.witnessAccountId = *ownerAccountId,
			.witnessClientId = ownerClientId,
			.telegramPeerIdBinding = 900,
			.objectId = FilledId<ObjectId>(88),
			.witnessSigningPrivateKey = &owner->signingPrivateKey,
		}, freshnessEnvelopeCodec, sha256)
		: std::nullopt;
	const auto observedResponse = responseEnvelope
		? VerifyObservedFreshnessResponse({
			.bytes = responseEnvelope->bytes,
			.observedTelegramPeerIdBinding = 900,
			.observedSenderTelegramUserIdBinding = 901,
			.observedMessageId = 89,
		},
		conversationId,
		900,
		freshnessEnvelopeCodec,
		ledger,
		sha256)
		: std::nullopt;
	if (!observedChallenge
		|| !observedResponse
		|| observedResponse->response.nonce != freshnessChallenge.nonce) {
		return Fail("freshness envelopes lost observed Telegram authorship");
	}
	const auto safetyGossip = CreateSafetyGossip({
		.gossipId = FilledId<ObjectId>(89),
		.reporterAccountId = *ownerAccountId,
		.reporterClientId = ownerClientId,
		.reporterSigningPrivateKey = &owner->signingPrivateKey,
	}, ledger, sha256);
	const auto encodedGossip = safetyGossip
		? SafetyGossipCodecV1().encode(*safetyGossip)
		: std::nullopt;
	const auto decodedGossip = encodedGossip
		? SafetyGossipCodecV1().decode(*encodedGossip)
		: std::nullopt;
	if (!decodedGossip
		|| *decodedGossip != *safetyGossip
		|| VerifySafetyGossip(*decodedGossip, ledger, sha256)
			!= SafetyGossipVerifyResult::Verified) {
		return Fail("signed identity gossip did not match the pinned ledger");
	}
	const auto safetyObjectId = DeriveSafetyGossipObjectId(
		ledger.checkpoint(),
		*ownerAccountId,
		ownerClientId,
		sha256);
	const auto safetyEnvelope = PrepareSafetyGossipEnvelope({
		.gossipId = safetyObjectId,
		.reporterAccountId = *ownerAccountId,
		.reporterClientId = ownerClientId,
		.telegramPeerIdBinding = 900,
		.reporterSigningPrivateKey = &owner->signingPrivateKey,
	}, ledger, freshnessEnvelopeCodec, sha256);
	const auto observedSafety = safetyEnvelope
		? VerifyObservedSafetyGossip({
			.bytes = safetyEnvelope->bytes,
			.observedTelegramPeerIdBinding = 900,
			.observedSenderTelegramUserIdBinding = 901,
			.observedMessageId = 90,
		},
		conversationId,
		900,
		freshnessEnvelopeCodec,
		ledger,
		sha256)
		: VerifyObservedSafetyGossipOutcome();
	if (!safetyObjectId
		|| !observedSafety.verified
		|| observedSafety.result != SafetyGossipVerifyResult::Verified
		|| observedSafety.verified->gossip.gossipId != safetyObjectId) {
		return Fail("observed identity gossip did not verify");
	}
	auto modifiedGossip = *decodedGossip;
	modifiedGossip.entries.front().credentialHash.bytes[0] ^= 1;
	if (VerifySafetyGossip(modifiedGossip, ledger, sha256)
			!= SafetyGossipVerifyResult::InvalidSignature) {
		return Fail("identity gossip accepted a modified observation");
	}
	const auto targetClientId = FilledId<ClientId>(97);
	const auto keyPackage = QByteArray("ledger target KeyPackage");
	const auto authorization = CreateClientAuthorizationProof({
		.conversationId = conversationId,
		.authorizationId = FilledId<ObjectId>(98),
		.accountId = *targetAccountId,
		.clientId = targetClientId,
		.requestedAfterGeneration = 1,
		.createdAt = 1'000'000,
		.accountCredential = &target->credential,
		.accountSigningPrivateKey = &target->signingPrivateKey,
		.keyPackage = keyPackage,
	}, sha256);
	const auto transition = AddMemberTransition(
		*ledger.state(),
		*targetAccountId,
		targetClientId,
		902,
		History(HistoryAccessMode::Full),
		99);
	const auto commitObjectId = FilledId<ObjectId>(100);
	const auto commitBytes = QByteArray("ledger exact add commit");
	auto secondArchiveKey = archiveCrypto.generateKey();
	const auto signedTransition = authorization && secondArchiveKey
		? CreateSignedGroupTransition({
			.transition = transition,
			.actorAccountId = *ownerAccountId,
			.actorClientId = ownerClientId,
			.previousStateHash = ledger.checkpoint().stateHash,
			.mlsCommitObjectId = commitObjectId,
			.actorCredential = &owner->credential,
			.actorSigningPrivateKey = &owner->signingPrivateKey,
			.nextArchiveKey = &*secondArchiveKey,
			.archiveDistributionObjectId = commitObjectId,
			.archiveDistribution = commitBytes,
			.targetClientAuthorization = &*authorization,
			.mlsCommit = commitBytes,
		}, sha256)
		: std::nullopt;
	const auto applied = signedTransition
		? VerifyAndApplySignedGroupTransition({
			.currentState = ledger.state(),
			.currentCheckpoint = ledger.checkpoint(),
			.signedTransition = &*signedTransition,
			.actorCredential = &owner->credential,
			.targetCredential = &target->credential,
			.mlsCommitObjectId = commitObjectId,
			.mlsCommit = commitBytes,
			.nextArchiveKey = &*secondArchiveKey,
			.archiveDistributionObjectId = commitObjectId,
			.archiveDistribution = commitBytes,
			.targetKeyPackage = keyPackage,
		}, sha256)
		: VerifySignedGroupTransitionOutcome();
	if (!signedTransition
		|| !applied.applied
		|| ledger.commitTransition(
			ledger.revision(),
			*signedTransition,
			*applied.applied,
			&target->credential) != GroupLedgerCommitResult::Committed
		|| ledger.wasMemberAt(*targetAccountId, 1)
		|| !ledger.wasMemberAt(*targetAccountId, 2)
		|| !ledger.wasClientActiveAt(
			*targetAccountId,
			targetClientId,
			2)
		|| !ledger.stateAt(1)
		|| ledger.stateAt(1)->member(*targetAccountId)
		|| !ledger.stateAt(2)
		|| !ledger.stateAt(2)->member(*targetAccountId)
		|| !ledger.credential(*targetAccountId)) {
		return Fail("group ledger lost historical membership evidence");
	}
	auto transactionGroupBlob = MemoryBlobStore();
	auto transactionArchiveBlob = MemoryBlobStore();
	auto transactionMlsBlob = MemoryBlobStore();
	auto transactionOutboxBlob = MemoryBlobStore();
	auto transactionJournalBlob = MemoryBlobStore();
	auto transactionGroup = PersistentGroupLedger(
		transactionGroupBlob,
		protector,
		sha256);
	auto transactionArchive = PersistentArchiveState(
		transactionArchiveBlob,
		protector);
	auto transactionMls = PersistentMlsStateStore(
		transactionMlsBlob,
		protector);
	auto transactionOutbox = PersistentOutboxStore(
		transactionOutboxBlob,
		protector);
	auto transactionJournal = PersistentGroupChangeJournal(
		transactionJournalBlob,
		protector);
	const auto commitEnvelope = EncodedEnvelope{
		.conversationId = conversationId,
		.objectId = commitObjectId,
		.bytes = QByteArray("encoded exact MLS commit envelope"),
	};
	auto transactionInitialArchiveKey = archiveKey->bytes();
	if (transactionGroup.load(conversationId)
			!= GroupLedgerLoadResult::Missing
		|| transactionGroup.initialize(
			*genesis,
			verifiedGenesis.verified->state,
			verifiedGenesis.verified->checkpoint,
			owner->credential) != GroupLedgerCommitResult::Committed
		|| transactionArchive.load(conversationId)
			!= ArchiveStateLoadResult::Missing
		|| transactionArchive.initialize({
			.generation = 1,
			.activationGroupGeneration = 1,
			.activationEventId = FilledId<ObjectId>(95),
			.key = ArchiveKey32(std::move(transactionInitialArchiveKey)),
		}) != ArchiveStateCommitResult::Committed
		|| transactionMls.load(conversationId)
			!= MlsStateLoadResult::Missing
		|| transactionMls.initialize(
			QByteArray("test-openmls-engine"),
			QByteArray("before-add-state"))
			!= MlsStateCommitResult::Committed
		|| transactionOutbox.load() != PersistentOutboxLoadResult::Empty
		|| transactionJournal.load(conversationId)
			!= GroupChangeJournalLoadResult::Empty) {
		return Fail("group change transaction setup failed");
	}
	transactionOutboxBlob.failWrites = true;
	auto transactionCoordinator = GroupChangeTransactionCoordinator(
		transactionJournal,
		transactionMls,
		transactionArchive,
		transactionGroup,
		transactionOutbox,
		sha256);
	if (transactionCoordinator.apply({
		.conversationId = conversationId,
		.transactionId = transition.transitionId,
		.groupBaseRevision = 1,
		.archiveBaseRevision = 1,
		.mlsBaseRevision = 1,
		.signedTransition = *signedTransition,
		.targetCredential = target->credential,
		.targetKeyPackage = keyPackage,
		.mlsCommit = commitBytes,
		.archiveDistribution = commitBytes,
		.nextMlsEngineState = QByteArray("after-add-state"),
		.mlsReceipt = MlsOperationReceipt{
			.objectId = commitObjectId,
			.requestHash = FilledId<Digest>(108),
			.envelope = commitEnvelope,
		},
		.removalTombstone = std::nullopt,
		.archiveEpoch = ArchiveEpochSecret{
			.generation = 2,
			.activationGroupGeneration = 2,
			.activationEventId = transition.transitionId,
			.key = secondArchiveKey->clone(),
		},
		.outboxEnvelopes = { commitEnvelope },
	}) != GroupChangeApplyStatus::OutboxPersistenceFailure
		|| !transactionJournal.pending()
		|| transactionMls.revision() != 2
		|| transactionArchive.revision() != 2
		|| transactionGroup.revision() != 2
		|| transactionOutbox.size()) {
		return Fail("group change transaction did not fail closed at outbox");
	}
	transactionOutboxBlob.failWrites = false;
	auto recoveredGroup = PersistentGroupLedger(
		transactionGroupBlob,
		protector,
		sha256);
	auto recoveredArchive = PersistentArchiveState(
		transactionArchiveBlob,
		protector);
	auto recoveredMls = PersistentMlsStateStore(
		transactionMlsBlob,
		protector);
	auto recoveredOutbox = PersistentOutboxStore(
		transactionOutboxBlob,
		protector);
	auto recoveredJournal = PersistentGroupChangeJournal(
		transactionJournalBlob,
		protector);
	if (recoveredGroup.load(conversationId) != GroupLedgerLoadResult::Loaded
		|| recoveredArchive.load(conversationId)
			!= ArchiveStateLoadResult::Loaded
		|| recoveredMls.load(conversationId) != MlsStateLoadResult::Loaded
		|| recoveredOutbox.load() != PersistentOutboxLoadResult::Empty
		|| recoveredJournal.load(conversationId)
			!= GroupChangeJournalLoadResult::Pending) {
		return Fail("group change transaction restart setup failed");
	}
	auto recoveredCoordinator = GroupChangeTransactionCoordinator(
		recoveredJournal,
		recoveredMls,
		recoveredArchive,
		recoveredGroup,
		recoveredOutbox,
		sha256);
	if (recoveredCoordinator.recover() != GroupChangeApplyStatus::Recovered
		|| recoveredJournal.pending()
		|| recoveredOutbox.size() != 1
		|| !recoveredOutbox.contains(commitObjectId)
		|| recoveredGroup.revision() != 2
		|| recoveredArchive.revision() != 2
		|| recoveredMls.revision() != 2) {
		return Fail("group change transaction did not recover exactly once");
	}
	auto archiveBlob = MemoryBlobStore();
	auto archiveState = PersistentArchiveState(archiveBlob, protector);
	auto archiveStateKey = archiveKey->bytes();
	if (archiveState.load(conversationId) != ArchiveStateLoadResult::Missing
		|| archiveState.initialize({
			.generation = 1,
			.activationGroupGeneration = 1,
			.activationEventId = FilledId<ObjectId>(95),
			.key = ArchiveKey32(std::move(archiveStateKey)),
		}) != ArchiveStateCommitResult::Committed
		|| !secondArchiveKey
		|| archiveState.appendEpoch(archiveState.revision(), {
			.generation = 2,
			.activationGroupGeneration = 2,
			.activationEventId = FilledId<ObjectId>(99),
			.key = CloneArchiveKey(*secondArchiveKey),
		}) != ArchiveStateCommitResult::Committed) {
		return Fail("archive reader state setup failed");
	}
	const auto contentPlaintext = QByteArray("authorized historical body");
	const auto eventObjectId = FilledId<ObjectId>(103);
	const auto contentObjectId = FilledId<ObjectId>(104);
	auto prepared = PrepareArchivedContent({
		.conversationId = conversationId,
		.eventObjectId = eventObjectId,
		.contentObjectId = contentObjectId,
		.objectKind = ObjectKind::EncryptedMessageBody,
		.groupGeneration = 2,
		.senderAccountId = *targetAccountId,
		.senderClientId = targetClientId,
		.archiveEpochGeneration = 2,
		.archiveEpochKey = &*secondArchiveKey,
		.senderSigningPrivateKey = &target->signingPrivateKey,
		.plaintext = contentPlaintext,
	}, archiveCrypto);
	const auto contentCodec = EncryptedArchivedContentCodecV1();
	const auto contentBytes = prepared
		? contentCodec.encode(prepared->encrypted)
		: std::nullopt;
	auto contentEnvelope = TransportEnvelope();
	if (prepared && contentBytes) {
		contentEnvelope = {
			.conversationId = conversationId,
			.objectKind = ObjectKind::EncryptedMessageBody,
			.senderAccountId = *targetAccountId,
			.senderClientId = targetClientId,
			.telegramPeerIdBinding = 900,
			.epochOrGeneration = 2,
			.objectId = contentObjectId,
			.payloadHash = sha256.digest(*contentBytes),
			.payload = *contentBytes,
			.authenticationData = QByteArray(
				reinterpret_cast<const char*>(
					prepared->encrypted.signature.data()),
				prepared->encrypted.signature.size()),
		};
	}
	auto descriptorBytes = std::optional<QByteArray>();
	if (prepared && contentBytes) {
		auto descriptorKey = prepared->contentKey.bytes();
		descriptorBytes = ArchivedContentDescriptorCodecV1().encodePlaintext({
			.conversationId = conversationId,
			.eventObjectId = eventObjectId,
			.contentObjectId = contentObjectId,
			.objectKind = ObjectKind::EncryptedMessageBody,
			.groupGeneration = 2,
			.archiveEpochGeneration = 2,
			.encodedContentHash = sha256.digest(*contentBytes),
			.contentKey = ArchiveKey32(std::move(descriptorKey)),
		});
	}
	const auto liveOpened = descriptorBytes
		? OpenLiveArchivedContent(
			conversationId,
			900,
			{
				.conversationId = conversationId,
				.eventObjectId = eventObjectId,
				.senderAccountId = *targetAccountId,
				.senderClientId = targetClientId,
				.plaintext = *descriptorBytes,
			},
			contentEnvelope,
			ledger,
			contentCodec,
			ArchivedContentDescriptorCodecV1(),
			sha256)
		: ArchivedContentOpenOutcome();
	const auto storedOpened = OpenStoredArchivedContent(
		conversationId,
		900,
		contentEnvelope,
		ledger,
		archiveState,
		contentCodec,
		sha256,
		archiveCrypto);
	if (!prepared
		|| !contentBytes
		|| !descriptorBytes
		|| liveOpened.status != ArchivedContentOpenStatus::Opened
		|| !liveOpened.content
		|| liveOpened.content->plaintext != contentPlaintext
		|| storedOpened.status != ArchivedContentOpenStatus::Opened
		|| !storedOpened.content
		|| storedOpened.content->plaintext != contentPlaintext) {
		return Fail("archive reader rejected historically authorized content");
	}
	const auto bridge = OpenMlsBridge();
	const auto authorizedGrant = CreateAuthorizedHistoryGrant({
		.conversationId = conversationId,
		.grantId = FilledId<ObjectId>(107),
		.issuerAccountId = *ownerAccountId,
		.issuerClientId = ownerClientId,
		.recipientAccountId = *targetAccountId,
		.telegramPeerIdBinding = 900,
		.groupGeneration = 2,
		.historyAccess = History(HistoryAccessMode::Full),
		.issuerSigningPrivateKey = &owner->signingPrivateKey,
	}, ledger, archiveState, bridge);
	auto recipientArchiveBlob = MemoryBlobStore();
	auto recipientArchiveState = PersistentArchiveState(
		recipientArchiveBlob,
		protector);
	if (authorizedGrant.status != HistoryGrantServiceStatus::Created
		|| !authorizedGrant.grant
		|| recipientArchiveState.load(conversationId)
			!= ArchiveStateLoadResult::Missing
		|| recipientArchiveState.initialize({
			.generation = 2,
			.activationGroupGeneration = 2,
			.activationEventId = FilledId<ObjectId>(99),
			.key = CloneArchiveKey(*secondArchiveKey),
		}) != ArchiveStateCommitResult::Committed
		|| AcceptAuthorizedHistoryGrant({
			.conversationId = conversationId,
			.telegramPeerIdBinding = 900,
			.recipientAccountId = *targetAccountId,
			.recipientArchivePrivateKey =
				&target->archiveHpkePrivateKey,
			.grant = &*authorizedGrant.grant,
		}, ledger, recipientArchiveState, sha256, bridge)
			!= HistoryGrantServiceStatus::Accepted
		|| recipientArchiveState.epochCount() != 2
		|| !recipientArchiveState.epoch(1)) {
		return Fail("authorized full-history grant was not imported");
	}
	auto unauthorizedGrant = *authorizedGrant.grant;
	unauthorizedGrant.issuerClientId = targetClientId;
	if (AcceptAuthorizedHistoryGrant({
		.conversationId = conversationId,
		.telegramPeerIdBinding = 900,
		.recipientAccountId = *targetAccountId,
		.recipientArchivePrivateKey = &target->archiveHpkePrivateKey,
		.grant = &unauthorizedGrant,
	}, ledger, recipientArchiveState, sha256, bridge)
			!= HistoryGrantServiceStatus::IssuerNotAuthorized) {
		return Fail("history grant accepted an unauthorized issuer client");
	}
	auto unauthorizedPrepared = PrepareArchivedContent({
		.conversationId = conversationId,
		.eventObjectId = FilledId<ObjectId>(105),
		.contentObjectId = FilledId<ObjectId>(106),
		.objectKind = ObjectKind::EncryptedMessageBody,
		.groupGeneration = 1,
		.senderAccountId = *targetAccountId,
		.senderClientId = targetClientId,
		.archiveEpochGeneration = 1,
		.archiveEpochKey = &*archiveKey,
		.senderSigningPrivateKey = &target->signingPrivateKey,
		.plaintext = QByteArray("backdated body"),
	}, archiveCrypto);
	const auto unauthorizedBytes = unauthorizedPrepared
		? contentCodec.encode(unauthorizedPrepared->encrypted)
		: std::nullopt;
	auto unauthorizedEnvelope = TransportEnvelope();
	if (unauthorizedPrepared && unauthorizedBytes) {
		unauthorizedEnvelope = {
			.conversationId = conversationId,
			.objectKind = ObjectKind::EncryptedMessageBody,
			.senderAccountId = *targetAccountId,
			.senderClientId = targetClientId,
			.telegramPeerIdBinding = 900,
			.epochOrGeneration = 1,
			.objectId = unauthorizedPrepared->encrypted.contentObjectId,
			.payloadHash = sha256.digest(*unauthorizedBytes),
			.payload = *unauthorizedBytes,
			.authenticationData = QByteArray(
				reinterpret_cast<const char*>(
					unauthorizedPrepared->encrypted.signature.data()),
				unauthorizedPrepared->encrypted.signature.size()),
		};
	}
	if (!unauthorizedPrepared
		|| !unauthorizedBytes
		|| OpenStoredArchivedContent(
			conversationId,
			900,
			unauthorizedEnvelope,
			ledger,
			archiveState,
			contentCodec,
			sha256,
			archiveCrypto).status
				!= ArchivedContentOpenStatus::SenderNotAuthorized) {
		return Fail("archive reader accepted a backdated non-member sender");
	}
	auto restored = PersistentGroupLedger(blob, protector, sha256);
	if (restored.load(conversationId) != GroupLedgerLoadResult::Loaded
		|| restored.revision() != 2
		|| restored.events().size() != 2
		|| !restored.wasMemberAt(*targetAccountId, 2)) {
		return Fail("group ledger did not survive authenticated restart");
	}
	auto remove = Transition(
		*restored.state(),
		GroupTransitionKind::RemoveMember,
		101);
	remove.targetAccountId = *targetAccountId;
	const auto removeCommitObjectId = FilledId<ObjectId>(102);
	const auto removeCommit = QByteArray("ledger exact remove commit");
	auto removalArchiveKey = archiveCrypto.generateKey();
	const auto signedRemove = removalArchiveKey
		? CreateSignedGroupTransition({
		.transition = remove,
		.actorAccountId = *ownerAccountId,
		.actorClientId = ownerClientId,
		.previousStateHash = restored.checkpoint().stateHash,
		.mlsCommitObjectId = removeCommitObjectId,
		.actorCredential = &owner->credential,
		.actorSigningPrivateKey = &owner->signingPrivateKey,
		.nextArchiveKey = &*removalArchiveKey,
		.archiveDistributionObjectId = removeCommitObjectId,
		.archiveDistribution = removeCommit,
		.targetClientAuthorization = nullptr,
		.mlsCommit = removeCommit,
	}, sha256)
		: std::nullopt;
	const auto appliedRemove = signedRemove
		? VerifyAndApplySignedGroupTransition({
			.currentState = restored.state(),
			.currentCheckpoint = restored.checkpoint(),
			.signedTransition = &*signedRemove,
			.actorCredential = &owner->credential,
			.targetCredential = nullptr,
			.mlsCommitObjectId = removeCommitObjectId,
			.mlsCommit = removeCommit,
			.nextArchiveKey = &*removalArchiveKey,
			.archiveDistributionObjectId = removeCommitObjectId,
			.archiveDistribution = removeCommit,
			.targetKeyPackage = {},
		}, sha256)
		: VerifySignedGroupTransitionOutcome();
	blob.failWrites = true;
	if (!signedRemove
		|| !appliedRemove.applied
		|| restored.commitTransition(
			restored.revision(),
			*signedRemove,
			*appliedRemove.applied,
			nullptr) != GroupLedgerCommitResult::PersistenceFailed
		|| restored.checkpoint().generation != 2
		|| !restored.wasMemberAt(*targetAccountId, 2)) {
		return Fail("failed group ledger write changed live authority");
	}
	return 0;
}

} // namespace

int main(int, char *[]) {
	for (const auto scenario : {
		ScenarioGroupCreation,
		ScenarioGroupSnapshotRestoresInvariants,
		ScenarioGroupTransitionCodec,
		ScenarioAdmissionRequiresAuthorityAndCredential,
		ScenarioClientEnrollmentUsesAccountProof,
		ScenarioClientKeyPackageEnvelopeIsSelfAuthenticating,
		ScenarioAdminCapabilitiesLimitHistory,
		ScenarioOwnershipTransferIsAtomic,
		ScenarioFreshnessBlocksLocalAdministration,
		ScenarioTransitionReplayIsRejected,
		ScenarioSignedTransitionBindsAdmissionAndMlsCommit,
		ScenarioSignedGenesisPinsTheChainRoot,
		ScenarioPersistentGroupLedgerTracksHistoricalMembership,
	}) {
		if (const auto result = scenario()) {
			return result;
		}
	}
	return 0;
}

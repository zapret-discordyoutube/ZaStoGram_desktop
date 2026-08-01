/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "e2e_cloud/archive/history_grant_crypto.h"
#include "e2e_cloud/group/group_transition_codec.h"
#include "e2e_cloud/identity/openssl_account_crypto.h"

#include <QtCore/QByteArray>

#include <cstdint>
#include <optional>

namespace E2ECloud {

inline constexpr auto kClientAuthorizationProofEncodedSize = 274;
inline constexpr auto kSignedGroupTransitionEncodedSize = 806;
inline constexpr auto kClientAuthorizationLifetimeSeconds
	= std::uint64_t(60 * 60 * 24 * 28 * 3);
inline constexpr auto kClientAuthorizationClockSkewSeconds
	= std::uint64_t(60 * 10);

struct ClientAuthorizationProof {
	ConversationId conversationId;
	ObjectId authorizationId;
	AccountId accountId;
	ClientId clientId;
	std::uint64_t requestedAfterGeneration = 0;
	std::uint64_t createdAt = 0;
	std::uint64_t expiresAt = 0;
	Digest accountCredentialHash;
	Digest keyPackageHash;
	AccountSignature signature = {};

	friend inline bool operator==(
		const ClientAuthorizationProof &,
		const ClientAuthorizationProof &) = default;
};

struct SignedGroupTransition {
	GroupTransition transition;
	AccountId actorAccountId;
	ClientId actorClientId;
	Digest previousStateHash;
	Digest resultingStateHash;
	ObjectId mlsCommitObjectId;
	Digest mlsCommitHash;
	Digest archiveKeyCommitment;
	ObjectId archiveDistributionObjectId;
	Digest archiveDistributionHash;
	std::optional<ClientAuthorizationProof> targetClientAuthorization;
	AccountSignature actorSignature = {};

	friend inline bool operator==(
		const SignedGroupTransition &,
		const SignedGroupTransition &) = default;
};

struct CreateClientAuthorizationArgs {
	ConversationId conversationId;
	ObjectId authorizationId;
	AccountId accountId;
	ClientId clientId;
	std::uint64_t requestedAfterGeneration = 0;
	std::uint64_t createdAt = 0;
	const AccountCredentialPublic *accountCredential = nullptr;
	const SecureKey32 *accountSigningPrivateKey = nullptr;
	QByteArray keyPackage;
};

struct CreateSignedGroupTransitionArgs {
	GroupTransition transition;
	AccountId actorAccountId;
	ClientId actorClientId;
	Digest previousStateHash;
	ObjectId mlsCommitObjectId;
	const AccountCredentialPublic *actorCredential = nullptr;
	const SecureKey32 *actorSigningPrivateKey = nullptr;
	const ArchiveKey32 *nextArchiveKey = nullptr;
	ObjectId archiveDistributionObjectId;
	QByteArray archiveDistribution;
	const ClientAuthorizationProof *targetClientAuthorization = nullptr;
	QByteArray mlsCommit;
};

class ClientAuthorizationProofCodecV1 final {
public:
	[[nodiscard]] std::optional<QByteArray> encode(
		const ClientAuthorizationProof &proof) const;
	[[nodiscard]] std::optional<ClientAuthorizationProof> decode(
		const QByteArray &bytes) const;
};

class SignedGroupTransitionCodecV1 final {
public:
	[[nodiscard]] std::optional<QByteArray> encode(
		const SignedGroupTransition &transition) const;
	[[nodiscard]] std::optional<SignedGroupTransition> decode(
		const QByteArray &bytes) const;
};

enum class SignedGroupTransitionResult {
	Applied,
	InvalidStructure,
	WrongConversation,
	InvalidCheckpoint,
	InvalidActorCredential,
	InvalidActorSignature,
	InvalidMlsCommit,
	InvalidArchiveKey,
	InvalidArchiveDistribution,
	MissingTargetAuthorization,
	UnexpectedTargetAuthorization,
	InvalidTargetCredential,
	InvalidTargetAuthorization,
	TransitionRejected,
};

struct AppliedSignedGroupTransition {
	ProtectedGroupState state;
	Checkpoint checkpoint;
	std::optional<ArchiveEpochSecret> archiveEpoch;
};

struct VerifySignedGroupTransitionArgs {
	const ProtectedGroupState *currentState = nullptr;
	Checkpoint currentCheckpoint;
	const SignedGroupTransition *signedTransition = nullptr;
	const AccountCredentialPublic *actorCredential = nullptr;
	const AccountCredentialPublic *targetCredential = nullptr;
	ObjectId mlsCommitObjectId;
	QByteArray mlsCommit;
	const ArchiveKey32 *nextArchiveKey = nullptr;
	ObjectId archiveDistributionObjectId;
	QByteArray archiveDistribution;
	QByteArray targetKeyPackage;
	bool allowMissingArchiveKey = false;
};

struct VerifySignedGroupTransitionOutcome {
	SignedGroupTransitionResult result
		= SignedGroupTransitionResult::InvalidStructure;
	std::optional<AppliedSignedGroupTransition> applied;
};

[[nodiscard]] std::optional<ClientAuthorizationProof>
	CreateClientAuthorizationProof(
		CreateClientAuthorizationArgs args,
		const Sha256Provider &sha256);
[[nodiscard]] bool VerifyClientAuthorizationProof(
	const ClientAuthorizationProof &proof,
	ConversationId conversationId,
	AccountId accountId,
	ClientId clientId,
	std::uint64_t requestedAfterGeneration,
	const AccountCredentialPublic &accountCredential,
	const QByteArray &keyPackage,
	const Sha256Provider &sha256);
[[nodiscard]] bool ClientAuthorizationUsableAt(
	const ClientAuthorizationProof &proof,
	std::uint64_t currentTime);
[[nodiscard]] std::optional<SignedGroupTransition>
	CreateSignedGroupTransition(
		CreateSignedGroupTransitionArgs args,
		const Sha256Provider &sha256);
[[nodiscard]] std::optional<Checkpoint> DeriveSignedGroupTransitionCheckpoint(
	const SignedGroupTransition &transition,
	const Sha256Provider &sha256);
[[nodiscard]] bool VerifySignedGroupTransitionActor(
	const SignedGroupTransition &transition,
	const AccountCredentialPublic &actorCredential,
	const Sha256Provider &sha256);
[[nodiscard]] VerifySignedGroupTransitionOutcome
	VerifyAndApplySignedGroupTransition(
		VerifySignedGroupTransitionArgs args,
		const Sha256Provider &sha256);

} // namespace E2ECloud

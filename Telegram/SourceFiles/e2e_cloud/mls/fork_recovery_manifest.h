/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "e2e_cloud/mls/client_key_package.h"

#include <QtCore/QByteArray>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

namespace E2ECloud {

inline constexpr auto kMaximumForkRecoveryCandidates = std::size_t(64);
inline constexpr auto kMaximumForkRecoveryClients = std::size_t(4096);
inline constexpr auto kMaximumForkRecoveryManifestSize = 1024 * 1024;

struct ForkRecoveryCandidate {
	ObjectId transitionId;
	Digest transitionPayloadHash;

	friend inline bool operator==(
		const ForkRecoveryCandidate &,
		const ForkRecoveryCandidate &) = default;
};

struct ForkRecoveryPartitionClient {
	AccountId accountId;
	ClientId clientId;

	friend inline bool operator==(
		const ForkRecoveryPartitionClient &,
		const ForkRecoveryPartitionClient &) = default;
};

struct ForkRecoveryReplacement {
	AccountId accountId;
	ClientId clientId;
	ObjectId publicationObjectId;
	Digest publicationPayloadHash;
	Digest keyPackageHash;

	friend inline bool operator==(
		const ForkRecoveryReplacement &,
		const ForkRecoveryReplacement &) = default;
};

struct SignedForkRecoveryManifest {
	ConversationId conversationId;
	ObjectId recoveryId;
	std::uint64_t telegramPeerIdBinding = 0;
	std::uint64_t commonGeneration = 0;
	Digest commonStateHash;
	std::uint64_t resolvedGeneration = 0;
	std::uint64_t recoveryGeneration = 0;
	AccountId ownerAccountId;
	ClientId ownerClientId;
	std::vector<ForkRecoveryCandidate> candidates;
	ObjectId canonicalTransitionId;
	Digest canonicalTransitionPayloadHash;
	Digest canonicalStateHash;
	std::vector<ForkRecoveryPartitionClient> canonicalPartition;
	std::vector<ForkRecoveryReplacement> replacements;
	ObjectId recoveryCommitObjectId;
	Digest recoveryCommitHash;
	ObjectId recoveryWelcomeObjectId;
	Digest recoveryWelcomeHash;
	ObjectId archiveDistributionObjectId;
	Digest archiveKeyCommitment;
	Digest archiveDistributionHash;
	AccountSignature ownerSignature = {};

	friend inline bool operator==(
		const SignedForkRecoveryManifest &,
		const SignedForkRecoveryManifest &) = default;
};

class SignedForkRecoveryManifestCodecV1 final {
public:
	[[nodiscard]] std::optional<QByteArray> encode(
		const SignedForkRecoveryManifest &manifest) const;
	[[nodiscard]] std::optional<SignedForkRecoveryManifest> decode(
		const QByteArray &bytes) const;
};

struct CreateSignedForkRecoveryManifestArgs {
	ConversationId conversationId;
	ObjectId recoveryId;
	std::uint64_t telegramPeerIdBinding = 0;
	std::uint64_t currentTime = 0;
	Checkpoint commonCheckpoint;
	Checkpoint canonicalCheckpoint;
	const ProtectedGroupState *commonState = nullptr;
	const ProtectedGroupState *canonicalState = nullptr;
	std::vector<ForkRecoveryCandidate> candidates;
	ForkRecoveryCandidate canonicalCandidate;
	std::vector<ForkRecoveryPartitionClient> canonicalPartition;
	std::vector<TransportEnvelope> replacementKeyPackageEnvelopes;
	ObjectId recoveryCommitObjectId;
	QByteArray recoveryCommit;
	ObjectId recoveryWelcomeObjectId;
	QByteArray recoveryWelcome;
	ObjectId archiveDistributionObjectId;
	QByteArray archiveDistribution;
	const ArchiveKey32 *nextArchiveKey = nullptr;
	AccountId ownerAccountId;
	ClientId ownerClientId;
	const AccountCredentialPublic *ownerCredential = nullptr;
	const SecureKey32 *ownerSigningPrivateKey = nullptr;
};

struct VerifySignedForkRecoveryManifestArgs {
	const SignedForkRecoveryManifest *manifest = nullptr;
	const ProtectedGroupState *commonState = nullptr;
	const ProtectedGroupState *canonicalState = nullptr;
	Checkpoint commonCheckpoint;
	Checkpoint canonicalCheckpoint;
	std::vector<ForkRecoveryCandidate> observedCandidates;
	std::vector<TransportEnvelope> replacementKeyPackageEnvelopes;
	ObjectId recoveryCommitObjectId;
	QByteArray recoveryCommit;
	ObjectId recoveryWelcomeObjectId;
	QByteArray recoveryWelcome;
	ObjectId archiveDistributionObjectId;
	QByteArray archiveDistribution;
	const ArchiveKey32 *nextArchiveKey = nullptr;
	const AccountCredentialPublic *ownerCredential = nullptr;
	std::uint64_t currentTime = 0;
};

enum class ForkRecoveryManifestResult {
	Verified,
	InvalidStructure,
	WrongConversation,
	InvalidCheckpoint,
	InvalidOwner,
	InvalidSignature,
	CandidateSetMismatch,
	InvalidCanonicalCandidate,
	InvalidPartition,
	InvalidReplacement,
	InvalidArchiveKey,
	ArtifactMismatch,
};

[[nodiscard]] std::optional<SignedForkRecoveryManifest>
	CreateSignedForkRecoveryManifest(
		CreateSignedForkRecoveryManifestArgs args,
		const Sha256Provider &sha256);
[[nodiscard]] ForkRecoveryManifestResult VerifySignedForkRecoveryManifest(
	VerifySignedForkRecoveryManifestArgs args,
	const Sha256Provider &sha256);
[[nodiscard]] bool VerifySignedForkRecoveryManifestSignature(
	const SignedForkRecoveryManifest &manifest,
	const AccountCredentialPublic &ownerCredential,
	const Sha256Provider &sha256);

} // namespace E2ECloud

/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "e2e_cloud/archive/history_grant_crypto.h"
#include "e2e_cloud/group/group_state.h"
#include "e2e_cloud/identity/openssl_account_crypto.h"

#include <QtCore/QByteArray>

#include <cstdint>
#include <optional>

namespace E2ECloud {

inline constexpr auto kSignedGroupGenesisEncodedSize = 435;

struct SignedGroupGenesis {
	ConversationId conversationId;
	ObjectId genesisObjectId;
	std::uint64_t telegramPeerIdBinding = 0;
	AccountId ownerAccountId;
	ClientId ownerClientId;
	std::uint64_t ownerTelegramUserIdBinding = 0;
	GroupPolicy policy;
	Digest mlsGroupId;
	ObjectId initialMlsPublicObjectId;
	Digest initialMlsPublicHash;
	std::uint64_t archiveEpochGeneration = 0;
	ObjectId archiveActivationEventId;
	Digest archiveKeyCommitment;
	Digest ownerCredentialHash;
	AccountSignature ownerSignature = {};

	friend inline bool operator==(
		const SignedGroupGenesis &,
		const SignedGroupGenesis &) = default;
};

struct CreateSignedGroupGenesisArgs {
	ConversationId conversationId;
	ObjectId genesisObjectId;
	std::uint64_t telegramPeerIdBinding = 0;
	AccountId ownerAccountId;
	ClientId ownerClientId;
	std::uint64_t ownerTelegramUserIdBinding = 0;
	GroupPolicy policy;
	Digest mlsGroupId;
	ObjectId initialMlsPublicObjectId;
	ObjectId archiveActivationEventId;
	const ArchiveKey32 *initialArchiveKey = nullptr;
	const AccountCredentialPublic *ownerCredential = nullptr;
	const SecureKey32 *ownerSigningPrivateKey = nullptr;
	QByteArray initialMlsPublicObject;
};

class SignedGroupGenesisCodecV1 final {
public:
	[[nodiscard]] std::optional<QByteArray> encode(
		const SignedGroupGenesis &genesis) const;
	[[nodiscard]] std::optional<SignedGroupGenesis> decode(
		const QByteArray &bytes) const;
};

enum class SignedGroupGenesisResult {
	Verified,
	InvalidStructure,
	InvalidOwnerCredential,
	InvalidOwnerSignature,
	InvalidMlsObject,
	InvalidArchiveKey,
};

struct VerifiedSignedGroupGenesis {
	ProtectedGroupState state;
	Checkpoint checkpoint;
	ArchiveEpochSecret initialArchiveEpoch;
};

struct VerifySignedGroupGenesisOutcome {
	SignedGroupGenesisResult result
		= SignedGroupGenesisResult::InvalidStructure;
	std::optional<VerifiedSignedGroupGenesis> verified;
};

struct VerifiedSignedGroupGenesisPublic {
	ProtectedGroupState state;
	Checkpoint checkpoint;
};

struct VerifySignedGroupGenesisPublicOutcome {
	SignedGroupGenesisResult result
		= SignedGroupGenesisResult::InvalidStructure;
	std::optional<VerifiedSignedGroupGenesisPublic> verified;
};

struct VerifySignedGroupGenesisArgs {
	const SignedGroupGenesis *genesis = nullptr;
	const AccountCredentialPublic *ownerCredential = nullptr;
	ObjectId genesisObjectId;
	ObjectId initialMlsPublicObjectId;
	QByteArray initialMlsPublicObject;
	const ArchiveKey32 *initialArchiveKey = nullptr;
};

[[nodiscard]] std::optional<SignedGroupGenesis> CreateSignedGroupGenesis(
	CreateSignedGroupGenesisArgs args,
	const Sha256Provider &sha256);
[[nodiscard]] VerifySignedGroupGenesisPublicOutcome
VerifySignedGroupGenesisPublic(
	VerifySignedGroupGenesisArgs args,
	const Sha256Provider &sha256);
[[nodiscard]] VerifySignedGroupGenesisOutcome VerifySignedGroupGenesis(
	VerifySignedGroupGenesisArgs args,
	const Sha256Provider &sha256);

} // namespace E2ECloud

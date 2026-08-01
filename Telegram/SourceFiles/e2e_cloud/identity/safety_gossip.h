/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "e2e_cloud/core/interfaces.h"
#include "e2e_cloud/group/persistent_group_ledger.h"

namespace E2ECloud {

inline constexpr auto kMaximumSafetyGossipEntries = 4096;

struct SafetyGossipEntry {
	std::uint64_t telegramUserIdBinding = 0;
	AccountId accountId;
	Digest credentialHash;

	friend inline bool operator==(
		const SafetyGossipEntry &,
		const SafetyGossipEntry &) = default;
};

struct SafetyGossip {
	ConversationId conversationId;
	ObjectId gossipId;
	Checkpoint checkpoint;
	AccountId reporterAccountId;
	ClientId reporterClientId;
	std::vector<SafetyGossipEntry> entries;
	AccountSignature signature = {};

	friend inline bool operator==(
		const SafetyGossip &,
		const SafetyGossip &) = default;
};

class SafetyGossipCodecV1 final {
public:
	[[nodiscard]] std::optional<QByteArray> encode(
		const SafetyGossip &gossip) const;
	[[nodiscard]] std::optional<SafetyGossip> decode(
		const QByteArray &bytes) const;
};

struct CreateSafetyGossipArgs {
	ObjectId gossipId;
	AccountId reporterAccountId;
	ClientId reporterClientId;
	const SecureKey32 *reporterSigningPrivateKey = nullptr;
};

struct PrepareSafetyGossipEnvelopeArgs {
	ObjectId gossipId;
	AccountId reporterAccountId;
	ClientId reporterClientId;
	std::uint64_t telegramPeerIdBinding = 0;
	const SecureKey32 *reporterSigningPrivateKey = nullptr;
};

struct ObservedSafetyGossip {
	TransportEnvelope envelope;
	SafetyGossip gossip;
	std::int64_t telegramMessageId = 0;
};

enum class SafetyGossipVerifyResult {
	Verified,
	FutureCheckpoint,
	InvalidStructure,
	WrongConversation,
	InvalidReporter,
	InvalidSignature,
	ForkDetected,
	IdentityConflict,
};

struct VerifyObservedSafetyGossipOutcome {
	SafetyGossipVerifyResult result
		= SafetyGossipVerifyResult::InvalidStructure;
	std::optional<ObservedSafetyGossip> verified;
};

[[nodiscard]] std::optional<SafetyGossip> CreateSafetyGossip(
	CreateSafetyGossipArgs args,
	const PersistentGroupLedger &groupLedger,
	const Sha256Provider &sha256);
[[nodiscard]] ObjectId DeriveSafetyGossipObjectId(
	Checkpoint checkpoint,
	AccountId reporterAccountId,
	ClientId reporterClientId,
	const Sha256Provider &sha256);
[[nodiscard]] std::optional<EncodedEnvelope> PrepareSafetyGossipEnvelope(
	PrepareSafetyGossipEnvelopeArgs args,
	const PersistentGroupLedger &groupLedger,
	const EnvelopeCodec &envelopeCodec,
	const Sha256Provider &sha256);
[[nodiscard]] SafetyGossipVerifyResult VerifySafetyGossip(
	const SafetyGossip &gossip,
	const PersistentGroupLedger &groupLedger,
	const Sha256Provider &sha256);
[[nodiscard]] VerifyObservedSafetyGossipOutcome VerifyObservedSafetyGossip(
	const TelegramTransport::UntrustedObject &object,
	ConversationId expectedConversationId,
	std::uint64_t expectedTelegramPeerIdBinding,
	const EnvelopeCodec &envelopeCodec,
	const PersistentGroupLedger &groupLedger,
	const Sha256Provider &sha256);

} // namespace E2ECloud

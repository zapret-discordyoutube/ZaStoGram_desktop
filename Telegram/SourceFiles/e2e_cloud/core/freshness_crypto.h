/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "e2e_cloud/core/freshness_gate.h"
#include "e2e_cloud/group/persistent_group_ledger.h"

namespace E2ECloud {

inline constexpr auto kFreshnessChallengeEncodedSize = 114;
inline constexpr auto kFreshnessResponseEncodedSize = 266;

class FreshnessChallengeCodecV1 final {
public:
	[[nodiscard]] std::optional<QByteArray> encode(
		const FreshnessChallenge &challenge) const;
	[[nodiscard]] std::optional<FreshnessChallenge> decode(
		const QByteArray &bytes) const;
};

class FreshnessResponseCodecV1 final {
public:
	[[nodiscard]] std::optional<QByteArray> encode(
		const FreshnessResponse &response) const;
	[[nodiscard]] std::optional<FreshnessResponse> decode(
		const QByteArray &bytes) const;
};

struct CreateFreshnessResponseArgs {
	FreshnessChallenge challenge;
	Checkpoint witnessCheckpoint;
	AccountId witnessAccountId;
	ClientId witnessClientId;
	const SecureKey32 *witnessSigningPrivateKey = nullptr;
};

[[nodiscard]] std::optional<FreshnessResponse> CreateFreshnessResponse(
	CreateFreshnessResponseArgs args);

class AccountFreshnessResponseVerifier final
	: public FreshnessResponseVerifier {
public:
	explicit AccountFreshnessResponseVerifier(
		const PersistentGroupLedger &groupLedger);

	[[nodiscard]] bool verify(
		const FreshnessResponse &response) const override;

private:
	const PersistentGroupLedger &_groupLedger;
};

} // namespace E2ECloud

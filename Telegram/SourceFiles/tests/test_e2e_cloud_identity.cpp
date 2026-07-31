/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "e2e_cloud/identity/account_identity.h"
#include "e2e_cloud/identity/openssl_account_crypto.h"

#include <cstdio>
#include <vector>

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

[[nodiscard]] AccountCredentialPublic Credential() {
	auto result = AccountCredentialPublic();
	result.signingPublicKey.fill(1);
	result.archiveHpkePublicKey.fill(2);
	return result;
}

class TestSha256 final : public Sha256Provider {
public:
	[[nodiscard]] Digest digest(const QByteArray &bytes) const override {
		inputs.push_back(bytes);
		return result;
	}

	Digest result = FilledId<Digest>(9);
	mutable std::vector<QByteArray> inputs;

};

[[nodiscard]] int ScenarioCredentialCodec() {
	const auto credential = Credential();
	const auto codec = AccountCredentialCodecV1();
	const auto encoded = codec.encode(credential);
	if (!encoded
		|| encoded->size() != kAccountCredentialEncodedSize
		|| codec.decode(*encoded) != credential
		|| std::uint8_t((*encoded)[9]) != 1
		|| std::uint8_t((*encoded)[11]) != 1) {
		return Fail("account credential codec was not deterministic");
	}
	auto unsupported = *encoded;
	unsupported[9] = char(2);
	if (codec.decode(unsupported)) {
		return Fail("account credential codec accepted an unknown version");
	}
	auto emptyKey = credential;
	emptyKey.signingPublicKey.fill(0);
	if (codec.encode(emptyKey)) {
		return Fail("account credential accepted an empty signing key");
	}
	return 0;
}

[[nodiscard]] int ScenarioAccountIdDerivation() {
	const auto credential = Credential();
	auto sha256 = TestSha256();
	const auto accountId = DeriveAccountId(credential, sha256);
	if (!accountId
		|| accountId->bytes != sha256.result.bytes
		|| sha256.inputs.size() != 1
		|| sha256.inputs.front().size()
			<= kAccountCredentialEncodedSize) {
		return Fail("account identifier did not bind the full credential");
	}
	return 0;
}

[[nodiscard]] int ScenarioPairwiseSafetyIsSymmetric() {
	const auto first = FilledId<AccountId>(1);
	const auto second = FilledId<AccountId>(2);
	auto sha256 = TestSha256();
	if (!DerivePairwiseSafetyDigest(first, second, sha256)
		|| !DerivePairwiseSafetyDigest(second, first, sha256)
		|| sha256.inputs.size() != 2
		|| sha256.inputs[0] != sha256.inputs[1]
		|| DerivePairwiseSafetyDigest(first, first, sha256)) {
		return Fail("pairwise safety digest depended on participant order");
	}
	return 0;
}

[[nodiscard]] int ScenarioGroupSafetySortsAndValidatesRoster() {
	const auto conversationId = FilledId<ConversationId>(4);
	const auto owner = FilledId<AccountId>(1);
	const auto member = FilledId<AccountId>(2);
	auto sha256 = TestSha256();
	if (!DeriveGroupSafetyDigest(
			conversationId,
			owner,
			{ owner, member },
			sha256)
		|| !DeriveGroupSafetyDigest(
			conversationId,
			owner,
			{ member, owner },
			sha256)
		|| sha256.inputs.size() != 2
		|| sha256.inputs[0] != sha256.inputs[1]
		|| DeriveGroupSafetyDigest(
			conversationId,
			owner,
			{ member },
			sha256)
		|| DeriveGroupSafetyDigest(
			conversationId,
			owner,
			{ owner, owner },
			sha256)) {
		return Fail("group safety digest accepted an ambiguous roster");
	}
	return 0;
}

[[nodiscard]] int ScenarioSafetyCodeFormatting() {
	auto digest = Digest();
	digest.bytes.fill(0xFF);
	const auto formatted = FormatSafetyCode(digest);
	const auto expected = QString::fromLatin1(QByteArray(
		"ZZZZ ZZZZ ZZZZ ZZZZ ZZZZ ZZZZ "
		"ZZZZ ZZZZ ZZZZ ZZZZ ZZZZ ZZZZ"));
	if (!formatted
		|| *formatted != expected
		|| FormatSafetyCode(Digest())) {
		return Fail("safety code formatting was ambiguous or incomplete");
	}
	return 0;
}

[[nodiscard]] int ScenarioOpenSslIdentityAndSignatures() {
	auto identity = GenerateAccountPrivateIdentity();
	auto other = GenerateAccountPrivateIdentity();
	if (!identity
		|| !other
		|| !identity->signingPrivateKey.valid()
		|| !identity->archiveHpkePrivateKey.valid()
		|| !AccountCredentialCodecV1().encode(identity->credential)) {
		return Fail("OpenSSL did not generate a complete account identity");
	}
	const auto data = QByteArray("authorized transition");
	const auto signature = SignAccountData(
		identity->signingPrivateKey,
		AccountSignatureDomain::GroupTransition,
		data);
	if (!signature
		|| !VerifyAccountSignature(
			identity->credential,
			AccountSignatureDomain::GroupTransition,
			data,
			*signature)
		|| VerifyAccountSignature(
			identity->credential,
			AccountSignatureDomain::HistoryGrant,
			data,
			*signature)
		|| VerifyAccountSignature(
			identity->credential,
			AccountSignatureDomain::GroupTransition,
			QByteArray("tampered transition"),
			*signature)
		|| VerifyAccountSignature(
			other->credential,
			AccountSignatureDomain::GroupTransition,
			data,
			*signature)) {
		return Fail("account signature was not bound to identity and domain");
	}
	return 0;
}

[[nodiscard]] int ScenarioOpenSslAccountId() {
	auto identity = GenerateAccountPrivateIdentity();
	const auto sha256 = OpenSslSha256Provider();
	const auto first = identity
		? DeriveAccountId(identity->credential, sha256)
		: std::nullopt;
	const auto second = identity
		? DeriveAccountId(identity->credential, sha256)
		: std::nullopt;
	if (!first || first != second) {
		return Fail("OpenSSL account identifier was not deterministic");
	}
	return 0;
}

} // namespace

int main(int, char *[]) {
	for (const auto scenario : {
		ScenarioCredentialCodec,
		ScenarioAccountIdDerivation,
		ScenarioPairwiseSafetyIsSymmetric,
		ScenarioGroupSafetySortsAndValidatesRoster,
		ScenarioSafetyCodeFormatting,
		ScenarioOpenSslIdentityAndSignatures,
		ScenarioOpenSslAccountId,
	}) {
		if (const auto result = scenario()) {
			return result;
		}
	}
	return 0;
}

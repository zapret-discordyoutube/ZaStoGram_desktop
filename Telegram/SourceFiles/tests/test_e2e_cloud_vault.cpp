/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "e2e_cloud/vault/argon2id_password_kdf.h"
#include "e2e_cloud/vault/cloud_vault.h"
#include "e2e_cloud/vault/cloud_vault_selection.h"
#include "e2e_cloud/vault/password_kdf.h"
#include "e2e_cloud/vault/password_vault.h"
#include "e2e_cloud/vault/persistent_cloud_vault_anchor.h"

#include <algorithm>
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

[[nodiscard]] Argon2idConfig MakeConfig() {
	return {
		.parameterVersion = 1,
		.memoryKibibytes = 64 * 1024,
		.iterations = 3,
		.parallelism = 1,
	};
}

[[nodiscard]] VaultMasterKey MakeMasterKey() {
	auto result = VaultMasterKey();
	for (auto i = std::size_t(0); i != result.size(); ++i) {
		result[i] = std::uint8_t(i + 1);
	}
	return result;
}

class TestPasswordKdf final : public PasswordKdf {
public:
	[[nodiscard]] std::optional<PasswordDerivedKey> deriveArgon2id(
			const QByteArray &password,
			const Argon2idParameters &parameters) const override {
		++calls;
		lastParameters = parameters;
		if (fail || password.isEmpty()) {
			return std::nullopt;
		}
		auto result = PasswordDerivedKey();
		for (auto i = std::size_t(0); i != result.size(); ++i) {
			result[i] = std::uint8_t(parameters.salt[i % 16]
				+ std::uint8_t(password.constData()[i % password.size()])
				+ i);
		}
		return result;
	}

	mutable int calls = 0;
	mutable Argon2idParameters lastParameters;
	bool fail = false;

};

class MemoryBlobStore final : public AtomicBlobStore {
public:
	[[nodiscard]] BlobReadResult read() const override {
		return error
			? BlobReadResult{
				.status = BlobReadStatus::Error,
				.bytes = {},
			}
			: bytes
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
	bool error = false;
	bool failWrites = false;

};

[[nodiscard]] int ScenarioVaultRoundTrip() {
	auto kdf = TestPasswordKdf();
	const auto vault = PasswordVault(kdf);
	const auto expected = MakeMasterKey();
	auto input = expected;
	const auto wrapped = vault.wrap(
		std::move(input),
		QByteArray("correct horse battery staple"),
		MakeConfig(),
		9);
	if (!wrapped
		|| wrapped->size() != 114
		|| input != VaultMasterKey()
		|| kdf.calls != 1) {
		return Fail("vault key was not wrapped with a consumed master key");
	}
	const auto opened = vault.unwrap(
		*wrapped,
		QByteArray("correct horse battery staple"));
	if (!opened
		|| opened->masterKey != expected
		|| opened->generation != 9
		|| opened->parameters != kdf.lastParameters
		|| opened->parameters.memoryKibibytes
			!= MakeConfig().memoryKibibytes
		|| opened->parameters.iterations != MakeConfig().iterations
		|| opened->parameters.parallelism != MakeConfig().parallelism) {
		return Fail("vault key did not survive an authenticated round trip");
	}
	return 0;
}

[[nodiscard]] int ScenarioVaultRejectsWrongPasswordAndTampering() {
	auto kdf = TestPasswordKdf();
	const auto vault = PasswordVault(kdf);
	auto key = MakeMasterKey();
	const auto wrapped = vault.wrap(
		std::move(key),
		QByteArray("password one"),
		MakeConfig(),
		4);
	if (!wrapped
		|| vault.unwrap(*wrapped, QByteArray("password two"))) {
		return Fail("vault accepted the wrong password");
	}
	for (const auto offset : { 0, 14, 42, 54, 66, 113 }) {
		auto tampered = *wrapped;
		tampered[offset] = char(std::uint8_t(tampered[offset]) ^ 1);
		if (vault.unwrap(tampered, QByteArray("password one"))) {
			return Fail("vault accepted tampered parameters or ciphertext");
		}
	}
	return 0;
}

[[nodiscard]] int ScenarioVaultUsesFreshNonce() {
	auto kdf = TestPasswordKdf();
	const auto vault = PasswordVault(kdf);
	auto firstKey = MakeMasterKey();
	auto secondKey = MakeMasterKey();
	const auto first = vault.wrap(
		std::move(firstKey),
		QByteArray("same password"),
		MakeConfig(),
		1);
	const auto second = vault.wrap(
		std::move(secondKey),
		QByteArray("same password"),
		MakeConfig(),
		1);
	const auto firstOpened = first
		? vault.unwrap(*first, QByteArray("same password"))
		: std::nullopt;
	const auto secondOpened = second
		? vault.unwrap(*second, QByteArray("same password"))
		: std::nullopt;
	if (!first
		|| !second
		|| first == second
		|| !firstOpened
		|| !secondOpened
		|| firstOpened->parameters.salt == secondOpened->parameters.salt) {
		return Fail("vault wrapping reused deterministic ciphertext");
	}
	return 0;
}

[[nodiscard]] int ScenarioVaultBoundsKdfBeforeDerivation() {
	auto kdf = TestPasswordKdf();
	const auto vault = PasswordVault(kdf);
	auto key = MakeMasterKey();
	auto config = MakeConfig();
	config.memoryKibibytes = 32 * 1024;
	if (vault.wrap(
			std::move(key),
			QByteArray("password"),
			config,
			1)
		|| kdf.calls) {
		return Fail("vault created a record with weak password work factors");
	}
	return 0;
}

[[nodiscard]] int ScenarioArgon2idReferenceVector() {
	auto parameters = Argon2idParameters{
		.parameterVersion = 1,
		.memoryKibibytes = 256,
		.iterations = 2,
		.parallelism = 1,
		.salt = {},
	};
	const auto salt = QByteArray("somesalt12345678");
	std::copy_n(
		reinterpret_cast<const std::uint8_t*>(salt.constData()),
		parameters.salt.size(),
		parameters.salt.begin());
	const auto result = Argon2idPasswordKdf().deriveArgon2id(
		QByteArray("password"),
		parameters);
	const auto expected = PasswordDerivedKey{
		0x81, 0x10, 0xe1, 0x16, 0x5e, 0xb0, 0xe1, 0x11,
		0x4e, 0xe3, 0x7d, 0x5f, 0xf0, 0x17, 0x57, 0x3b,
		0xa0, 0x08, 0x4b, 0x83, 0x66, 0xb4, 0x10, 0x8d,
		0xb4, 0x47, 0x49, 0x95, 0x4b, 0x8d, 0x98, 0x71,
	};
	if (!result || *result != expected) {
		return Fail("Argon2id provider did not match the reference vector");
	}
	return 0;
}

[[nodiscard]] int ScenarioCloudVaultRoundTripAndUpdate() {
	auto kdf = TestPasswordKdf();
	auto sha256 = OpenSslSha256Provider();
	auto codec = CloudVaultCodecV1(kdf, sha256);
	auto identity = GenerateAccountPrivateIdentity();
	if (!identity) {
		return Fail("account identity generation failed for cloud vault");
	}
	const auto expectedAccountId = DeriveAccountId(
		identity->credential,
		sha256);
	auto created = codec.create(
		777,
		std::move(*identity),
		QByteArray("correct horse battery staple"),
		MakeConfig());
	if (!created
		|| created->unlocked.generation != 1
		|| created->unlocked.previousBlobDigest
		|| !created->unlocked.blobDigest
		|| !created->unlocked.conversations.empty()) {
		return Fail("initial cloud vault was not created");
	}
	auto unlocked = codec.unlock(
		created->encoded,
		QByteArray("correct horse battery staple"),
		777);
	const auto accountId = unlocked
		? DeriveAccountId(unlocked->identity.credential, sha256)
		: std::nullopt;
	if (!unlocked
		|| accountId != expectedAccountId
		|| unlocked->blobDigest != created->unlocked.blobDigest
		|| codec.unlock(
			created->encoded,
			QByteArray("wrong password"),
			777)
		|| codec.unlock(
			created->encoded,
			QByteArray("correct horse battery staple"),
			778)) {
		return Fail("cloud vault unlock did not enforce password and account");
	}
	const auto conversation = CloudVaultConversation{
		.conversationId = FilledId<ConversationId>(3),
		.telegramPeerIdBinding = 9001,
		.checkpoint = {
			.conversationId = FilledId<ConversationId>(3),
			.generation = 8,
			.stateHash = FilledId<Digest>(4),
		},
		.ownerAccountId = FilledId<AccountId>(5),
	};
	auto update = codec.prepareUpdate(*unlocked, { conversation });
	if (!update
		|| update->generation != 2
		|| update->previousBlobDigest != unlocked->blobDigest
		|| update->blobDigest == unlocked->blobDigest) {
		return Fail("cloud vault update did not extend its digest chain");
	}
	const auto updateBytes = update->encoded;
	if (!codec.applyPublished(*unlocked, std::move(*update))
		|| unlocked->generation != 2
		|| unlocked->conversations != std::vector{ conversation }) {
		return Fail("published cloud vault update was not adopted");
	}
	auto reopened = codec.unlock(
		updateBytes,
		QByteArray("correct horse battery staple"),
		777);
	if (!reopened
		|| reopened->generation != 2
		|| reopened->previousBlobDigest != created->unlocked.blobDigest
		|| reopened->conversations != std::vector{ conversation }) {
		return Fail("updated cloud vault did not survive another installation");
	}
	return 0;
}

[[nodiscard]] int ScenarioCloudVaultRejectsTamperingAndKeyMismatch() {
	auto kdf = TestPasswordKdf();
	auto sha256 = OpenSslSha256Provider();
	auto codec = CloudVaultCodecV1(kdf, sha256);
	auto identity = GenerateAccountPrivateIdentity();
	if (!identity) {
		return Fail("account identity generation failed for tamper test");
	}
	identity->credential.signingPublicKey[0] ^= 1;
	if (codec.create(
		777,
		std::move(*identity),
		QByteArray("correct horse battery staple"),
		MakeConfig())) {
		return Fail("cloud vault accepted mismatched private identity keys");
	}
	auto validIdentity = GenerateAccountPrivateIdentity();
	auto created = validIdentity
		? codec.create(
			777,
			std::move(*validIdentity),
			QByteArray("correct horse battery staple"),
			MakeConfig())
		: std::nullopt;
	if (!created) {
		return Fail("cloud vault tamper fixture could not be created");
	}
	for (const auto offset : {
		0,
		20,
		created->encoded.size() / 2,
		created->encoded.size() - 1,
	}) {
		auto tampered = created->encoded;
		tampered[offset] = char(std::uint8_t(tampered[offset]) ^ 1);
		if (codec.unlock(
			tampered,
			QByteArray("correct horse battery staple"),
			777)) {
			return Fail("cloud vault accepted modified header or ciphertext");
		}
	}
	return 0;
}

[[nodiscard]] int ScenarioCloudVaultSelectionDetectsForksAndGaps() {
	auto kdf = TestPasswordKdf();
	auto sha256 = OpenSslSha256Provider();
	auto codec = CloudVaultCodecV1(kdf, sha256);
	auto selector = CloudVaultSelector(codec, sha256);
	auto identity = GenerateAccountPrivateIdentity();
	auto created = identity
		? codec.create(
			777,
			std::move(*identity),
			QByteArray("selection password"),
			MakeConfig())
		: std::nullopt;
	if (!created) {
		return Fail("cloud vault selection fixture could not be created");
	}
	const auto accountId = DeriveAccountId(
		created->unlocked.identity.credential,
		sha256);
	if (!accountId) {
		return Fail("cloud vault selection account id was invalid");
	}
	const auto firstConversation = CloudVaultConversation{
		.conversationId = FilledId<ConversationId>(3),
		.telegramPeerIdBinding = 9001,
		.checkpoint = {
			.conversationId = FilledId<ConversationId>(3),
			.generation = 1,
			.stateHash = FilledId<Digest>(4),
		},
		.ownerAccountId = *accountId,
	};
	const auto secondConversation = CloudVaultConversation{
		.conversationId = FilledId<ConversationId>(5),
		.telegramPeerIdBinding = 9002,
		.checkpoint = {
			.conversationId = FilledId<ConversationId>(5),
			.generation = 1,
			.stateHash = FilledId<Digest>(6),
		},
		.ownerAccountId = *accountId,
	};
	const auto versionOne = created->encoded;
	const auto versionOneAnchor = CloudVaultAnchor{
		.generation = created->unlocked.generation,
		.blobDigest = created->unlocked.blobDigest,
		.accountId = *accountId,
	};
	auto firstUpdate = codec.prepareUpdate(
		created->unlocked,
		{ firstConversation });
	auto competingUpdate = codec.prepareUpdate(
		created->unlocked,
		{ secondConversation });
	if (!firstUpdate
		|| !competingUpdate
		|| firstUpdate->blobDigest == competingUpdate->blobDigest) {
		return Fail("cloud vault fork fixtures were not distinct");
	}
	const auto versionTwo = firstUpdate->encoded;
	const auto versionTwoAnchor = CloudVaultAnchor{
		.generation = firstUpdate->generation,
		.blobDigest = firstUpdate->blobDigest,
		.accountId = *accountId,
	};
	if (!codec.applyPublished(
		created->unlocked,
		std::move(*firstUpdate))) {
		return Fail("cloud vault selection fixture update was not adopted");
	}
	auto secondUpdate = codec.prepareUpdate(
		created->unlocked,
		{ firstConversation, secondConversation });
	if (!secondUpdate) {
		return Fail("cloud vault third selection version was not created");
	}
	const auto versionThree = secondUpdate->encoded;
	auto selected = selector.select(
		{ versionOne, versionTwo, versionThree },
		QByteArray("selection password"),
		777,
		versionOneAnchor);
	if (selected.status != CloudVaultSelectionStatus::Selected
		|| !selected.vault
		|| selected.vault->generation != 3) {
		return Fail("cloud vault selector did not follow the signed chain");
	}
	auto forked = selector.select(
		{ versionTwo, competingUpdate->encoded },
		QByteArray("selection password"),
		777,
		versionOneAnchor);
	if (forked.status != CloudVaultSelectionStatus::ForkDetected) {
		return Fail("cloud vault selector silently chose a concurrent update");
	}
	auto gap = selector.select(
		{ versionThree },
		QByteArray("selection password"),
		777,
		versionOneAnchor);
	if (gap.status != CloudVaultSelectionStatus::ChainGap) {
		return Fail("cloud vault selector accepted a missing anchored version");
	}
	auto rollback = selector.select(
		{ versionOne },
		QByteArray("selection password"),
		777,
		versionTwoAnchor);
	if (rollback.status != CloudVaultSelectionStatus::RollbackDetected) {
		return Fail("cloud vault selector accepted an anchored rollback");
	}
	auto missing = selector.select(
		{},
		QByteArray("selection password"),
		777,
		versionTwoAnchor);
	if (missing.status != CloudVaultSelectionStatus::RollbackDetected) {
		return Fail("cloud vault selector accepted deletion after an anchor");
	}
	return 0;
}

[[nodiscard]] int ScenarioPersistentCloudVaultAnchor() {
	auto blob = MemoryBlobStore();
	auto persistent = PersistentCloudVaultAnchor(blob, 777);
	const auto accountId = FilledId<AccountId>(3);
	const auto first = CloudVaultAnchor{
		.generation = 4,
		.blobDigest = FilledId<Digest>(5),
		.accountId = accountId,
	};
	const auto second = CloudVaultAnchor{
		.generation = 5,
		.blobDigest = FilledId<Digest>(6),
		.accountId = accountId,
	};
	if (persistent.load() != CloudVaultAnchorLoadResult::Missing
		|| !persistent.loaded()
		|| persistent.anchor()
		|| persistent.commit(first)
			!= CloudVaultAnchorCommitResult::Committed
		|| persistent.commit(first)
			!= CloudVaultAnchorCommitResult::AlreadyCommitted
		|| persistent.anchor() != first) {
		return Fail("cloud vault anchor did not commit idempotently");
	}
	auto reopened = PersistentCloudVaultAnchor(blob, 777);
	if (reopened.load() != CloudVaultAnchorLoadResult::Loaded
		|| reopened.anchor() != first
		|| reopened.commit(CloudVaultAnchor{
			.generation = 3,
			.blobDigest = FilledId<Digest>(7),
			.accountId = accountId,
		}) != CloudVaultAnchorCommitResult::Conflict
		|| reopened.commit(CloudVaultAnchor{
			.generation = 4,
			.blobDigest = FilledId<Digest>(8),
			.accountId = accountId,
		}) != CloudVaultAnchorCommitResult::Conflict
		|| reopened.commit(CloudVaultAnchor{
			.generation = 5,
			.blobDigest = second.blobDigest,
			.accountId = FilledId<AccountId>(9),
		}) != CloudVaultAnchorCommitResult::Conflict) {
		return Fail("cloud vault anchor accepted an invalid chain change");
	}
	blob.failWrites = true;
	if (reopened.commit(second)
			!= CloudVaultAnchorCommitResult::PersistenceFailed
		|| reopened.anchor() != first) {
		return Fail("failed cloud vault anchor write changed live state");
	}
	blob.failWrites = false;
	if (reopened.commit(second) != CloudVaultAnchorCommitResult::Committed) {
		return Fail("cloud vault anchor did not advance monotonically");
	}
	auto wrongUser = PersistentCloudVaultAnchor(blob, 778);
	if (wrongUser.load() != CloudVaultAnchorLoadResult::InvalidSnapshot) {
		return Fail("cloud vault anchor crossed Telegram accounts");
	}
	blob.bytes = QByteArray("invalid");
	auto corrupted = PersistentCloudVaultAnchor(blob, 777);
	if (corrupted.load() != CloudVaultAnchorLoadResult::InvalidSnapshot
		|| corrupted.loaded()) {
		return Fail("corrupt cloud vault anchor did not fail closed");
	}
	return 0;
}

} // namespace

int main(int, char *[]) {
	for (const auto scenario : {
		ScenarioVaultRoundTrip,
		ScenarioVaultRejectsWrongPasswordAndTampering,
		ScenarioVaultUsesFreshNonce,
		ScenarioVaultBoundsKdfBeforeDerivation,
		ScenarioArgon2idReferenceVector,
		ScenarioCloudVaultRoundTripAndUpdate,
		ScenarioCloudVaultRejectsTamperingAndKeyMismatch,
		ScenarioCloudVaultSelectionDetectsForksAndGaps,
		ScenarioPersistentCloudVaultAnchor,
	}) {
		if (const auto result = scenario()) {
			return result;
		}
	}
	return 0;
}

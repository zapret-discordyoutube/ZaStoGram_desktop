/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "e2e_cloud/group/signed_group_genesis.h"

#include "e2e_cloud/mls/mls_roster_codec.h"

#include <algorithm>
#include <array>
#include <utility>

namespace E2ECloud {
namespace {

inline constexpr auto kGenesisMagic = std::array<std::uint8_t, 8>{
	'T', 'D', 'E', '2', 'E', 'G', 'E', 'N',
};
inline constexpr auto kGenesisBodySize = kSignedGroupGenesisEncodedSize - 64;

struct Reader {
	const QByteArray &bytes;
	int offset = 0;
};

void AppendUint8(QByteArray &result, std::uint8_t value) {
	result.append(char(value));
}

void AppendUint16(QByteArray &result, std::uint16_t value) {
	result.append(char(value >> 8));
	result.append(char(value));
}

void AppendUint64(QByteArray &result, std::uint64_t value) {
	for (auto shift = 56; shift >= 0; shift -= 8) {
		result.append(char(value >> shift));
	}
}

template <typename Array>
void AppendArray(QByteArray &result, const Array &value) {
	result.append(
		reinterpret_cast<const char*>(value.data()),
		int(value.size()));
}

[[nodiscard]] bool ReadUint8(Reader &reader, std::uint8_t &value) {
	if (reader.offset == reader.bytes.size()) {
		return false;
	}
	value = std::uint8_t(reader.bytes[reader.offset++]);
	return true;
}

[[nodiscard]] bool ReadUint16(Reader &reader, std::uint16_t &value) {
	if (reader.bytes.size() - reader.offset < 2) {
		return false;
	}
	const auto data = reinterpret_cast<const std::uint8_t*>(
		reader.bytes.constData() + reader.offset);
	value = (std::uint16_t(data[0]) << 8) | std::uint16_t(data[1]);
	reader.offset += 2;
	return true;
}

[[nodiscard]] bool ReadUint64(Reader &reader, std::uint64_t &value) {
	if (reader.bytes.size() - reader.offset < 8) {
		return false;
	}
	const auto data = reinterpret_cast<const std::uint8_t*>(
		reader.bytes.constData() + reader.offset);
	value = 0;
	for (auto i = 0; i != 8; ++i) {
		value = (value << 8) | std::uint64_t(data[i]);
	}
	reader.offset += 8;
	return true;
}

template <typename Array>
[[nodiscard]] bool ReadArray(Reader &reader, Array &value) {
	const auto size = int(value.size());
	if (reader.bytes.size() - reader.offset < size) {
		return false;
	}
	std::copy_n(
		reinterpret_cast<const std::uint8_t*>(
			reader.bytes.constData() + reader.offset),
		size,
		value.data());
	reader.offset += size;
	return true;
}

[[nodiscard]] bool Nonzero(const auto &value) {
	return std::any_of(begin(value), end(value), [](std::uint8_t byte) {
		return byte != 0;
	});
}

[[nodiscard]] bool ValidGenesis(const SignedGroupGenesis &genesis) {
	return genesis.conversationId
		&& genesis.genesisObjectId
		&& genesis.telegramPeerIdBinding
		&& genesis.ownerAccountId
		&& genesis.ownerClientId
		&& genesis.ownerTelegramUserIdBinding
		&& IsValidHistoryAccess(genesis.policy.defaultHistoryAccess)
		&& genesis.mlsGroupId
		&& genesis.initialMlsPublicObjectId
		&& genesis.initialMlsPublicHash
		&& genesis.archiveEpochGeneration == 1
		&& genesis.archiveActivationEventId
		&& genesis.archiveKeyCommitment
		&& genesis.ownerCredentialHash
		&& Nonzero(genesis.ownerSignature);
}

[[nodiscard]] QByteArray EncodeBody(const SignedGroupGenesis &genesis) {
	auto result = QByteArray();
	result.reserve(kGenesisBodySize);
	AppendArray(result, kGenesisMagic);
	AppendUint16(result, 1);
	AppendArray(result, genesis.conversationId.bytes);
	AppendArray(result, genesis.genesisObjectId.bytes);
	AppendUint64(result, genesis.telegramPeerIdBinding);
	AppendArray(result, genesis.ownerAccountId.bytes);
	AppendArray(result, genesis.ownerClientId.bytes);
	AppendUint64(result, genesis.ownerTelegramUserIdBinding);
	AppendUint8(
		result,
		std::uint8_t(genesis.policy.defaultHistoryAccess.mode));
	AppendArray(
		result,
		genesis.policy.defaultHistoryAccess.boundaryEventId.bytes);
	AppendArray(result, genesis.mlsGroupId.bytes);
	AppendArray(result, genesis.initialMlsPublicObjectId.bytes);
	AppendArray(result, genesis.initialMlsPublicHash.bytes);
	AppendUint64(result, genesis.archiveEpochGeneration);
	AppendArray(result, genesis.archiveActivationEventId.bytes);
	AppendArray(result, genesis.archiveKeyCommitment.bytes);
	AppendArray(result, genesis.ownerCredentialHash.bytes);
	return result;
}

} // namespace

std::optional<QByteArray> SignedGroupGenesisCodecV1::encode(
		const SignedGroupGenesis &genesis) const {
	if (!ValidGenesis(genesis)) {
		return std::nullopt;
	}
	auto result = EncodeBody(genesis);
	AppendArray(result, genesis.ownerSignature);
	return (result.size() == kSignedGroupGenesisEncodedSize)
		? std::optional<QByteArray>(std::move(result))
		: std::nullopt;
}

std::optional<SignedGroupGenesis> SignedGroupGenesisCodecV1::decode(
		const QByteArray &bytes) const {
	if (bytes.size() != kSignedGroupGenesisEncodedSize) {
		return std::nullopt;
	}
	auto reader = Reader{ bytes };
	auto magic = std::array<std::uint8_t, 8>();
	auto version = std::uint16_t();
	auto mode = std::uint8_t();
	auto result = SignedGroupGenesis();
	if (!ReadArray(reader, magic)
		|| !ReadUint16(reader, version)
		|| !ReadArray(reader, result.conversationId.bytes)
		|| !ReadArray(reader, result.genesisObjectId.bytes)
		|| !ReadUint64(reader, result.telegramPeerIdBinding)
		|| !ReadArray(reader, result.ownerAccountId.bytes)
		|| !ReadArray(reader, result.ownerClientId.bytes)
		|| !ReadUint64(reader, result.ownerTelegramUserIdBinding)
		|| !ReadUint8(reader, mode)
		|| !ReadArray(
			reader,
			result.policy.defaultHistoryAccess.boundaryEventId.bytes)
		|| !ReadArray(reader, result.mlsGroupId.bytes)
		|| !ReadArray(reader, result.initialMlsPublicObjectId.bytes)
		|| !ReadArray(reader, result.initialMlsPublicHash.bytes)
		|| !ReadUint64(reader, result.archiveEpochGeneration)
		|| !ReadArray(reader, result.archiveActivationEventId.bytes)
		|| !ReadArray(reader, result.archiveKeyCommitment.bytes)
		|| !ReadArray(reader, result.ownerCredentialHash.bytes)
		|| !ReadArray(reader, result.ownerSignature)
		|| reader.offset != bytes.size()
		|| magic != kGenesisMagic
		|| version != 1) {
		return std::nullopt;
	}
	result.policy.defaultHistoryAccess.mode = HistoryAccessMode(mode);
	return ValidGenesis(result)
		? std::optional<SignedGroupGenesis>(result)
		: std::nullopt;
}

std::optional<SignedGroupGenesis> CreateSignedGroupGenesis(
		CreateSignedGroupGenesisArgs args,
		const Sha256Provider &sha256) {
	if (!args.conversationId
		|| !args.genesisObjectId
		|| !args.telegramPeerIdBinding
		|| !args.ownerAccountId
		|| !args.ownerClientId
		|| !args.ownerTelegramUserIdBinding
		|| !IsValidHistoryAccess(args.policy.defaultHistoryAccess)
		|| !args.mlsGroupId
		|| !args.initialMlsPublicObjectId
		|| !args.archiveActivationEventId
		|| !args.initialArchiveKey
		|| !args.initialArchiveKey->valid()
		|| !args.ownerCredential
		|| !args.ownerSigningPrivateKey
		|| !args.ownerSigningPrivateKey->valid()
		|| args.initialMlsPublicObject.isEmpty()) {
		return std::nullopt;
	}
	const auto ownerAccountId = DeriveAccountId(*args.ownerCredential, sha256);
	const auto credential = AccountCredentialCodecV1().encode(
		*args.ownerCredential);
	if (!ownerAccountId
		|| *ownerAccountId != args.ownerAccountId
		|| !credential) {
		return std::nullopt;
	}
	auto result = SignedGroupGenesis{
		.conversationId = args.conversationId,
		.genesisObjectId = args.genesisObjectId,
		.telegramPeerIdBinding = args.telegramPeerIdBinding,
		.ownerAccountId = args.ownerAccountId,
		.ownerClientId = args.ownerClientId,
		.ownerTelegramUserIdBinding = args.ownerTelegramUserIdBinding,
		.policy = args.policy,
		.mlsGroupId = args.mlsGroupId,
		.initialMlsPublicObjectId = args.initialMlsPublicObjectId,
		.initialMlsPublicHash = sha256.digest(args.initialMlsPublicObject),
		.archiveEpochGeneration = 1,
		.archiveActivationEventId = args.archiveActivationEventId,
		.archiveKeyCommitment = *DeriveArchiveKeyCommitment(
			args.conversationId,
			1,
			1,
			args.archiveActivationEventId,
			*args.initialArchiveKey,
			sha256),
		.ownerCredentialHash = sha256.digest(*credential),
		.ownerSignature = {},
	};
	const auto signature = SignAccountData(
		*args.ownerSigningPrivateKey,
		AccountSignatureDomain::GroupGenesis,
		EncodeBody(result));
	if (!signature) {
		return std::nullopt;
	}
	result.ownerSignature = *signature;
	return SignedGroupGenesisCodecV1().encode(result)
		? std::optional<SignedGroupGenesis>(result)
		: std::nullopt;
}

VerifySignedGroupGenesisOutcome VerifySignedGroupGenesis(
		VerifySignedGroupGenesisArgs args,
		const Sha256Provider &sha256) {
	const auto failure = [](SignedGroupGenesisResult result) {
		return VerifySignedGroupGenesisOutcome{
			.result = result,
			.verified = std::nullopt,
		};
	};
	auto publicResult = VerifySignedGroupGenesisPublic(args, sha256);
	if (!publicResult.verified) {
		return failure(publicResult.result);
	}
	const auto &genesis = *args.genesis;
	if (!args.initialArchiveKey
		|| !args.initialArchiveKey->valid()
		|| DeriveArchiveKeyCommitment(
			genesis.conversationId,
			genesis.archiveEpochGeneration,
			1,
			genesis.archiveActivationEventId,
			*args.initialArchiveKey,
			sha256) != genesis.archiveKeyCommitment) {
		return failure(SignedGroupGenesisResult::InvalidArchiveKey);
	}
	auto key = args.initialArchiveKey->bytes();
	return {
		.result = SignedGroupGenesisResult::Verified,
		.verified = VerifiedSignedGroupGenesis{
			.state = std::move(publicResult.verified->state),
			.checkpoint = publicResult.verified->checkpoint,
			.initialArchiveEpoch = {
				.generation = 1,
				.activationGroupGeneration = 1,
				.activationEventId = genesis.archiveActivationEventId,
				.key = ArchiveKey32(std::move(key)),
			},
		},
	};
}

VerifySignedGroupGenesisPublicOutcome VerifySignedGroupGenesisPublic(
		VerifySignedGroupGenesisArgs args,
		const Sha256Provider &sha256) {
	const auto failure = [](SignedGroupGenesisResult result) {
		return VerifySignedGroupGenesisPublicOutcome{
			.result = result,
			.verified = std::nullopt,
		};
	};
	if (!args.genesis
		|| !args.ownerCredential
		|| !SignedGroupGenesisCodecV1().encode(*args.genesis)) {
		return failure(SignedGroupGenesisResult::InvalidStructure);
	}
	const auto &genesis = *args.genesis;
	const auto ownerAccountId = DeriveAccountId(*args.ownerCredential, sha256);
	const auto credential = AccountCredentialCodecV1().encode(
		*args.ownerCredential);
	if (!ownerAccountId
		|| *ownerAccountId != genesis.ownerAccountId
		|| !credential
		|| sha256.digest(*credential) != genesis.ownerCredentialHash) {
		return failure(SignedGroupGenesisResult::InvalidOwnerCredential);
	} else if (!VerifyAccountSignature(
			*args.ownerCredential,
			AccountSignatureDomain::GroupGenesis,
			EncodeBody(genesis),
			genesis.ownerSignature)) {
		return failure(SignedGroupGenesisResult::InvalidOwnerSignature);
	} else if (!args.genesisObjectId
		|| args.genesisObjectId != genesis.genesisObjectId) {
		return failure(SignedGroupGenesisResult::InvalidStructure);
	} else if (!args.initialMlsPublicObjectId
		|| args.initialMlsPublicObjectId
			!= genesis.initialMlsPublicObjectId
		|| args.initialMlsPublicObject.isEmpty()
		|| sha256.digest(args.initialMlsPublicObject)
			!= genesis.initialMlsPublicHash) {
		return failure(SignedGroupGenesisResult::InvalidMlsObject);
	}
	auto state = ProtectedGroupState::Create({
		.conversationId = genesis.conversationId,
		.ownerAccountId = genesis.ownerAccountId,
		.ownerClientId = genesis.ownerClientId,
		.ownerTelegramUserIdBinding = genesis.ownerTelegramUserIdBinding,
		.policy = genesis.policy,
	});
	const auto groupId = QByteArray(
		reinterpret_cast<const char*>(genesis.conversationId.bytes.data()),
		int(genesis.conversationId.bytes.size()));
	const auto roster = MlsRosterCodecV1().decode(
		args.initialMlsPublicObject,
		MlsContextCodecV1());
	const auto encoded = SignedGroupGenesisCodecV1().encode(genesis);
	if (!state
		|| !encoded
		|| sha256.digest(groupId) != genesis.mlsGroupId
		|| !roster
		|| roster->epoch != 0
		|| !MlsRosterMatchesGroupState(*roster, *state)) {
		return failure(SignedGroupGenesisResult::InvalidMlsObject);
	}
	return {
		.result = SignedGroupGenesisResult::Verified,
		.verified = VerifiedSignedGroupGenesisPublic{
			.state = std::move(*state),
			.checkpoint = {
				.conversationId = genesis.conversationId,
				.generation = 1,
				.stateHash = sha256.digest(*encoded),
			},
		},
	};
}

} // namespace E2ECloud

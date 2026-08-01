/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "e2e_cloud/group/signed_group_transition.h"

#include <algorithm>
#include <array>
#include <limits>
#include <utility>

namespace E2ECloud {
namespace {

inline constexpr auto kAuthorizationMagic = std::array<std::uint8_t, 8>{
	'T', 'D', 'E', '2', 'E', 'C', 'A', 'U',
};
inline constexpr auto kTransitionMagic = std::array<std::uint8_t, 8>{
	'T', 'D', 'E', '2', 'E', 'S', 'G', 'T',
};
inline constexpr auto kCheckpointMagic = std::array<std::uint8_t, 8>{
	'T', 'D', 'E', '2', 'E', 'G', 'C', 'H',
};
inline constexpr auto kAuthorizationBodySize =
	kClientAuthorizationProofEncodedSize - 64;
inline constexpr auto kTransitionBodySize =
	kSignedGroupTransitionEncodedSize - 64;

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

[[nodiscard]] bool RequiresTargetAuthorization(GroupTransitionKind kind) {
	return kind == GroupTransitionKind::AddMember
		|| kind == GroupTransitionKind::AddClient;
}

[[nodiscard]] QByteArray ZeroBytes(int size) {
	auto result = QByteArray();
	result.resize(size);
	std::fill_n(result.data(), result.size(), char(0));
	return result;
}

[[nodiscard]] bool ValidAuthorization(
		const ClientAuthorizationProof &proof) {
	return proof.conversationId
		&& proof.authorizationId
		&& proof.accountId
		&& proof.clientId
		&& proof.requestedAfterGeneration
		&& proof.createdAt
		&& proof.expiresAt > proof.createdAt
		&& proof.expiresAt - proof.createdAt
			== kClientAuthorizationLifetimeSeconds
		&& proof.accountCredentialHash
		&& proof.keyPackageHash
		&& Nonzero(proof.signature);
}

[[nodiscard]] QByteArray EncodeAuthorizationBody(
		const ClientAuthorizationProof &proof) {
	auto result = QByteArray();
	result.reserve(kAuthorizationBodySize);
	AppendArray(result, kAuthorizationMagic);
	AppendUint16(result, 1);
	AppendArray(result, proof.conversationId.bytes);
	AppendArray(result, proof.authorizationId.bytes);
	AppendArray(result, proof.accountId.bytes);
	AppendArray(result, proof.clientId.bytes);
	AppendUint64(result, proof.requestedAfterGeneration);
	AppendUint64(result, proof.createdAt);
	AppendUint64(result, proof.expiresAt);
	AppendArray(result, proof.accountCredentialHash.bytes);
	AppendArray(result, proof.keyPackageHash.bytes);
	return result;
}

[[nodiscard]] QByteArray EncodeTransitionBody(
		const SignedGroupTransition &signedTransition) {
	const auto encodedTransition = GroupTransitionCodecV1().encode(
		signedTransition.transition);
	if (!encodedTransition) {
		return {};
	}
	auto target = ZeroBytes(kClientAuthorizationProofEncodedSize);
	if (signedTransition.targetClientAuthorization) {
		const auto encoded = ClientAuthorizationProofCodecV1().encode(
			*signedTransition.targetClientAuthorization);
		if (!encoded) {
			return {};
		}
		target = *encoded;
	}
	auto result = QByteArray();
	result.reserve(kTransitionBodySize);
	AppendArray(result, kTransitionMagic);
	AppendUint16(result, 1);
	result.append(*encodedTransition);
	AppendArray(result, signedTransition.actorAccountId.bytes);
	AppendArray(result, signedTransition.actorClientId.bytes);
	AppendArray(result, signedTransition.previousStateHash.bytes);
	AppendArray(result, signedTransition.resultingStateHash.bytes);
	AppendArray(result, signedTransition.mlsCommitObjectId.bytes);
	AppendArray(result, signedTransition.mlsCommitHash.bytes);
	AppendArray(result, signedTransition.archiveKeyCommitment.bytes);
	AppendArray(result, signedTransition.archiveDistributionObjectId.bytes);
	AppendArray(result, signedTransition.archiveDistributionHash.bytes);
	AppendUint8(
		result,
		signedTransition.targetClientAuthorization ? 1 : 0);
	result.append(target);
	return result;
}

[[nodiscard]] std::optional<Digest> DeriveResultingHash(
		const SignedGroupTransition &signedTransition,
		const Sha256Provider &sha256) {
	const auto transition = GroupTransitionCodecV1().encode(
		signedTransition.transition);
	if (!transition) {
		return std::nullopt;
	}
	auto result = QByteArray();
	result.reserve(
		8 + 2 + 32 + transition->size() + 32 + 16 + 32 + 32 + 32
		+ 32 + 32
		+ 1 + kClientAuthorizationProofEncodedSize);
	AppendArray(result, kCheckpointMagic);
	AppendUint16(result, 1);
	AppendArray(result, signedTransition.previousStateHash.bytes);
	result.append(*transition);
	AppendArray(result, signedTransition.actorAccountId.bytes);
	AppendArray(result, signedTransition.actorClientId.bytes);
	AppendArray(result, signedTransition.mlsCommitObjectId.bytes);
	AppendArray(result, signedTransition.mlsCommitHash.bytes);
	AppendArray(result, signedTransition.archiveKeyCommitment.bytes);
	AppendArray(result, signedTransition.archiveDistributionObjectId.bytes);
	AppendArray(result, signedTransition.archiveDistributionHash.bytes);
	AppendUint8(
		result,
		signedTransition.targetClientAuthorization ? 1 : 0);
	if (signedTransition.targetClientAuthorization) {
		const auto target = ClientAuthorizationProofCodecV1().encode(
			*signedTransition.targetClientAuthorization);
		if (!target) {
			return std::nullopt;
		}
		result.append(*target);
	} else {
		result.append(ZeroBytes(kClientAuthorizationProofEncodedSize));
	}
	const auto hash = sha256.digest(result);
	return hash ? std::optional<Digest>(hash) : std::nullopt;
}

[[nodiscard]] bool TargetAuthorizationMatches(
		const ClientAuthorizationProof &proof,
		const GroupTransition &transition) {
	return proof.conversationId == transition.conversationId
		&& proof.accountId == transition.targetAccountId
		&& proof.clientId == transition.targetClientId
		&& proof.requestedAfterGeneration
		&& proof.requestedAfterGeneration <= transition.previousGeneration;
}

} // namespace

std::optional<QByteArray> ClientAuthorizationProofCodecV1::encode(
		const ClientAuthorizationProof &proof) const {
	if (!ValidAuthorization(proof)) {
		return std::nullopt;
	}
	auto result = EncodeAuthorizationBody(proof);
	AppendArray(result, proof.signature);
	return result;
}

std::optional<ClientAuthorizationProof>
ClientAuthorizationProofCodecV1::decode(const QByteArray &bytes) const {
	if (bytes.size() != kClientAuthorizationProofEncodedSize) {
		return std::nullopt;
	}
	auto reader = Reader{ bytes };
	auto magic = std::array<std::uint8_t, 8>();
	auto version = std::uint16_t();
	auto result = ClientAuthorizationProof();
	if (!ReadArray(reader, magic)
		|| !ReadUint16(reader, version)
		|| !ReadArray(reader, result.conversationId.bytes)
		|| !ReadArray(reader, result.authorizationId.bytes)
		|| !ReadArray(reader, result.accountId.bytes)
		|| !ReadArray(reader, result.clientId.bytes)
		|| !ReadUint64(reader, result.requestedAfterGeneration)
		|| !ReadUint64(reader, result.createdAt)
		|| !ReadUint64(reader, result.expiresAt)
		|| !ReadArray(reader, result.accountCredentialHash.bytes)
		|| !ReadArray(reader, result.keyPackageHash.bytes)
		|| !ReadArray(reader, result.signature)
		|| reader.offset != bytes.size()
		|| magic != kAuthorizationMagic
		|| version != 1
		|| !ValidAuthorization(result)) {
		return std::nullopt;
	}
	return result;
}

std::optional<QByteArray> SignedGroupTransitionCodecV1::encode(
		const SignedGroupTransition &signedTransition) const {
	if (!signedTransition.actorAccountId
		|| !signedTransition.actorClientId
		|| !signedTransition.previousStateHash
		|| !signedTransition.resultingStateHash
		|| !signedTransition.mlsCommitObjectId
		|| !signedTransition.mlsCommitHash
		|| !signedTransition.archiveKeyCommitment
		|| !signedTransition.archiveDistributionObjectId
		|| !signedTransition.archiveDistributionHash
		|| RequiresTargetAuthorization(signedTransition.transition.kind)
			!= signedTransition.targetClientAuthorization.has_value()
		|| !Nonzero(signedTransition.actorSignature)) {
		return std::nullopt;
	}
	auto result = EncodeTransitionBody(signedTransition);
	if (result.size() != kTransitionBodySize) {
		return std::nullopt;
	}
	AppendArray(result, signedTransition.actorSignature);
	return result;
}

std::optional<SignedGroupTransition> SignedGroupTransitionCodecV1::decode(
		const QByteArray &bytes) const {
	if (bytes.size() != kSignedGroupTransitionEncodedSize) {
		return std::nullopt;
	}
	auto reader = Reader{ bytes };
	auto magic = std::array<std::uint8_t, 8>();
	auto version = std::uint16_t();
	auto transitionBytes = QByteArray();
	auto targetPresent = std::uint8_t();
	auto targetBytes = QByteArray();
	auto result = SignedGroupTransition();
	if (!ReadArray(reader, magic)
		|| !ReadUint16(reader, version)
		|| reader.bytes.size() - reader.offset < kGroupTransitionEncodedSize) {
		return std::nullopt;
	}
	transitionBytes = QByteArray(
		reader.bytes.constData() + reader.offset,
		kGroupTransitionEncodedSize);
	reader.offset += kGroupTransitionEncodedSize;
	const auto transition = GroupTransitionCodecV1().decode(transitionBytes);
	if (!transition
		|| !ReadArray(reader, result.actorAccountId.bytes)
		|| !ReadArray(reader, result.actorClientId.bytes)
		|| !ReadArray(reader, result.previousStateHash.bytes)
		|| !ReadArray(reader, result.resultingStateHash.bytes)
		|| !ReadArray(reader, result.mlsCommitObjectId.bytes)
		|| !ReadArray(reader, result.mlsCommitHash.bytes)
		|| !ReadArray(reader, result.archiveKeyCommitment.bytes)
		|| !ReadArray(reader, result.archiveDistributionObjectId.bytes)
		|| !ReadArray(reader, result.archiveDistributionHash.bytes)
		|| !ReadUint8(reader, targetPresent)
		|| targetPresent > 1
		|| reader.bytes.size() - reader.offset
			< kClientAuthorizationProofEncodedSize) {
		return std::nullopt;
	}
	targetBytes = QByteArray(
		reader.bytes.constData() + reader.offset,
		kClientAuthorizationProofEncodedSize);
	reader.offset += kClientAuthorizationProofEncodedSize;
	result.transition = *transition;
	if (targetPresent) {
		result.targetClientAuthorization =
			ClientAuthorizationProofCodecV1().decode(targetBytes);
		if (!result.targetClientAuthorization) {
			return std::nullopt;
		}
	} else if (std::any_of(
			targetBytes.constData(),
			targetBytes.constData() + targetBytes.size(),
			[](char value) { return value != 0; })) {
		return std::nullopt;
	}
	if (!ReadArray(reader, result.actorSignature)
		|| reader.offset != bytes.size()
		|| magic != kTransitionMagic
		|| version != 1) {
		return std::nullopt;
	}
	return encode(result)
		? std::optional<SignedGroupTransition>(std::move(result))
		: std::nullopt;
}

std::optional<ClientAuthorizationProof> CreateClientAuthorizationProof(
		CreateClientAuthorizationArgs args,
		const Sha256Provider &sha256) {
	if (!args.conversationId
		|| !args.authorizationId
		|| !args.accountId
		|| !args.clientId
		|| !args.requestedAfterGeneration
		|| !args.createdAt
		|| args.createdAt > std::numeric_limits<std::uint64_t>::max()
			- kClientAuthorizationLifetimeSeconds
		|| !args.accountCredential
		|| !args.accountSigningPrivateKey
		|| !args.accountSigningPrivateKey->valid()
		|| args.keyPackage.isEmpty()) {
		return std::nullopt;
	}
	const auto derivedAccountId = DeriveAccountId(*args.accountCredential, sha256);
	const auto credentialBytes = AccountCredentialCodecV1().encode(
		*args.accountCredential);
	if (!derivedAccountId
		|| *derivedAccountId != args.accountId
		|| !credentialBytes) {
		return std::nullopt;
	}
	auto result = ClientAuthorizationProof{
		.conversationId = args.conversationId,
		.authorizationId = args.authorizationId,
		.accountId = args.accountId,
		.clientId = args.clientId,
		.requestedAfterGeneration = args.requestedAfterGeneration,
		.createdAt = args.createdAt,
		.expiresAt = args.createdAt + kClientAuthorizationLifetimeSeconds,
		.accountCredentialHash = sha256.digest(*credentialBytes),
		.keyPackageHash = sha256.digest(args.keyPackage),
		.signature = {},
	};
	const auto signature = SignAccountData(
		*args.accountSigningPrivateKey,
		AccountSignatureDomain::ClientAuthorization,
		EncodeAuthorizationBody(result));
	if (!signature) {
		return std::nullopt;
	}
	result.signature = *signature;
	return ValidAuthorization(result)
		? std::optional<ClientAuthorizationProof>(result)
		: std::nullopt;
}

bool ClientAuthorizationUsableAt(
		const ClientAuthorizationProof &proof,
		std::uint64_t currentTime) {
	return ValidAuthorization(proof)
		&& currentTime
		&& (proof.createdAt <= currentTime
			|| proof.createdAt - currentTime
				<= kClientAuthorizationClockSkewSeconds)
		&& (currentTime < proof.expiresAt
			|| currentTime - proof.expiresAt
				<= kClientAuthorizationClockSkewSeconds);
}

bool VerifyClientAuthorizationProof(
		const ClientAuthorizationProof &proof,
		ConversationId conversationId,
		AccountId accountId,
		ClientId clientId,
		std::uint64_t requestedAfterGeneration,
		const AccountCredentialPublic &accountCredential,
		const QByteArray &keyPackage,
		const Sha256Provider &sha256) {
	const auto derivedAccountId = DeriveAccountId(
		accountCredential,
		sha256);
	const auto credentialBytes = AccountCredentialCodecV1().encode(
		accountCredential);
	return ValidAuthorization(proof)
		&& conversationId
		&& accountId
		&& clientId
		&& requestedAfterGeneration
		&& !keyPackage.isEmpty()
		&& proof.conversationId == conversationId
		&& proof.accountId == accountId
		&& proof.clientId == clientId
		&& proof.requestedAfterGeneration == requestedAfterGeneration
		&& derivedAccountId
		&& *derivedAccountId == accountId
		&& credentialBytes
		&& sha256.digest(*credentialBytes) == proof.accountCredentialHash
		&& sha256.digest(keyPackage) == proof.keyPackageHash
		&& VerifyAccountSignature(
			accountCredential,
			AccountSignatureDomain::ClientAuthorization,
			EncodeAuthorizationBody(proof),
			proof.signature);
}

std::optional<SignedGroupTransition> CreateSignedGroupTransition(
		CreateSignedGroupTransitionArgs args,
		const Sha256Provider &sha256) {
	const auto needsTarget = RequiresTargetAuthorization(args.transition.kind);
	if (!IsValidGroupTransitionStructure(args.transition)
		|| !args.actorAccountId
		|| !args.actorClientId
		|| !args.previousStateHash
		|| !args.mlsCommitObjectId
		|| !args.actorCredential
		|| !args.actorSigningPrivateKey
		|| !args.actorSigningPrivateKey->valid()
		|| !args.nextArchiveKey
		|| !args.nextArchiveKey->valid()
		|| !args.archiveDistributionObjectId
		|| args.archiveDistribution.isEmpty()
		|| args.mlsCommit.isEmpty()
		|| needsTarget != bool(args.targetClientAuthorization)) {
		return std::nullopt;
	}
	const auto derivedActorId = DeriveAccountId(*args.actorCredential, sha256);
	const auto archiveKeyCommitment = DeriveArchiveKeyCommitment(
		args.transition.conversationId,
		args.transition.generation,
		args.transition.generation,
		args.transition.transitionId,
		*args.nextArchiveKey,
		sha256);
	if (!derivedActorId
		|| *derivedActorId != args.actorAccountId
		|| !archiveKeyCommitment) {
		return std::nullopt;
	}
	auto result = SignedGroupTransition{
		.transition = args.transition,
		.actorAccountId = args.actorAccountId,
		.actorClientId = args.actorClientId,
		.previousStateHash = args.previousStateHash,
		.resultingStateHash = {},
		.mlsCommitObjectId = args.mlsCommitObjectId,
		.mlsCommitHash = sha256.digest(args.mlsCommit),
		.archiveKeyCommitment = *archiveKeyCommitment,
		.archiveDistributionObjectId = args.archiveDistributionObjectId,
		.archiveDistributionHash = sha256.digest(args.archiveDistribution),
		.targetClientAuthorization = needsTarget
			? std::optional<ClientAuthorizationProof>(
				*args.targetClientAuthorization)
			: std::nullopt,
		.actorSignature = {},
	};
	const auto resultingHash = DeriveResultingHash(result, sha256);
	if (!resultingHash) {
		return std::nullopt;
	}
	result.resultingStateHash = *resultingHash;
	const auto signature = SignAccountData(
		*args.actorSigningPrivateKey,
		AccountSignatureDomain::GroupTransition,
		EncodeTransitionBody(result));
	if (!signature) {
		return std::nullopt;
	}
	result.actorSignature = *signature;
	return SignedGroupTransitionCodecV1().encode(result)
		? std::optional<SignedGroupTransition>(std::move(result))
		: std::nullopt;
}

std::optional<Checkpoint> DeriveSignedGroupTransitionCheckpoint(
		const SignedGroupTransition &transition,
		const Sha256Provider &sha256) {
	const auto hash = DeriveResultingHash(transition, sha256);
	return (hash && *hash == transition.resultingStateHash)
		? std::optional<Checkpoint>({
			.conversationId = transition.transition.conversationId,
			.generation = transition.transition.generation,
			.stateHash = *hash,
		})
		: std::nullopt;
}

bool VerifySignedGroupTransitionActor(
		const SignedGroupTransition &transition,
		const AccountCredentialPublic &actorCredential,
		const Sha256Provider &sha256) {
	const auto actorAccountId = DeriveAccountId(actorCredential, sha256);
	return SignedGroupTransitionCodecV1().encode(transition).has_value()
		&& actorAccountId
		&& *actorAccountId == transition.actorAccountId
		&& VerifyAccountSignature(
			actorCredential,
			AccountSignatureDomain::GroupTransition,
			EncodeTransitionBody(transition),
			transition.actorSignature);
}

VerifySignedGroupTransitionOutcome VerifyAndApplySignedGroupTransition(
		VerifySignedGroupTransitionArgs args,
		const Sha256Provider &sha256) {
	const auto failure = [](SignedGroupTransitionResult result) {
		return VerifySignedGroupTransitionOutcome{
			.result = result,
			.applied = std::nullopt,
		};
	};
	if (!args.currentState || !args.signedTransition || !args.actorCredential) {
		return failure(SignedGroupTransitionResult::InvalidStructure);
	}
	const auto &current = *args.currentState;
	const auto &signedTransition = *args.signedTransition;
	const auto &transition = signedTransition.transition;
	if (!SignedGroupTransitionCodecV1().encode(signedTransition)) {
		return failure(SignedGroupTransitionResult::InvalidStructure);
	} else if (transition.conversationId != current.conversationId()
		|| args.currentCheckpoint.conversationId != current.conversationId()) {
		return failure(SignedGroupTransitionResult::WrongConversation);
	} else if (args.currentCheckpoint.generation != current.generation()
		|| !args.currentCheckpoint.stateHash
		|| signedTransition.previousStateHash
			!= args.currentCheckpoint.stateHash) {
		return failure(SignedGroupTransitionResult::InvalidCheckpoint);
	}
	const auto actorAccountId = DeriveAccountId(*args.actorCredential, sha256);
	if (!actorAccountId || *actorAccountId != signedTransition.actorAccountId) {
		return failure(SignedGroupTransitionResult::InvalidActorCredential);
	} else if (!VerifySignedGroupTransitionActor(
			signedTransition,
			*args.actorCredential,
			sha256)) {
		return failure(SignedGroupTransitionResult::InvalidActorSignature);
	} else if (!args.mlsCommitObjectId
		|| args.mlsCommitObjectId != signedTransition.mlsCommitObjectId
		|| args.mlsCommit.isEmpty()
		|| sha256.digest(args.mlsCommit) != signedTransition.mlsCommitHash) {
		return failure(SignedGroupTransitionResult::InvalidMlsCommit);
	}
	const auto archiveKeyCommitment = args.nextArchiveKey
		? DeriveArchiveKeyCommitment(
			transition.conversationId,
			transition.generation,
			transition.generation,
			transition.transitionId,
			*args.nextArchiveKey,
			sha256)
		: std::nullopt;
	if ((!archiveKeyCommitment && !args.allowMissingArchiveKey)
		|| (archiveKeyCommitment
			&& *archiveKeyCommitment
				!= signedTransition.archiveKeyCommitment)) {
		return failure(SignedGroupTransitionResult::InvalidArchiveKey);
	}
	if (!args.archiveDistributionObjectId
		|| args.archiveDistributionObjectId
			!= signedTransition.archiveDistributionObjectId
		|| args.archiveDistribution.isEmpty()
		|| sha256.digest(args.archiveDistribution)
			!= signedTransition.archiveDistributionHash) {
		return failure(
			SignedGroupTransitionResult::InvalidArchiveDistribution);
	}
	const auto resultingHash = DeriveResultingHash(signedTransition, sha256);
	if (!resultingHash
		|| *resultingHash != signedTransition.resultingStateHash) {
		return failure(SignedGroupTransitionResult::InvalidCheckpoint);
	}
	const auto needsTarget = RequiresTargetAuthorization(transition.kind);
	if (needsTarget && !signedTransition.targetClientAuthorization) {
		return failure(SignedGroupTransitionResult::MissingTargetAuthorization);
	} else if (!needsTarget && signedTransition.targetClientAuthorization) {
		return failure(SignedGroupTransitionResult::UnexpectedTargetAuthorization);
	}
	auto authentication = GroupTransitionAuthentication{
		.actor = {
			.accountId = signedTransition.actorAccountId,
			.clientId = signedTransition.actorClientId,
		},
		.targetClientAuthorization = std::nullopt,
	};
	if (needsTarget) {
		const auto &proof = *signedTransition.targetClientAuthorization;
		if (!args.targetCredential
			|| !TargetAuthorizationMatches(proof, transition)) {
			return failure(SignedGroupTransitionResult::InvalidTargetCredential);
		}
		const auto targetAccountId = DeriveAccountId(
			*args.targetCredential,
			sha256);
		if (!targetAccountId || *targetAccountId != proof.accountId) {
			return failure(SignedGroupTransitionResult::InvalidTargetCredential);
		} else if (!VerifyClientAuthorizationProof(
			proof,
			transition.conversationId,
			transition.targetAccountId,
			transition.targetClientId,
			proof.requestedAfterGeneration,
			*args.targetCredential,
			args.targetKeyPackage,
			sha256)) {
			return failure(SignedGroupTransitionResult::InvalidTargetAuthorization);
		}
		authentication.targetClientAuthorization = VerifiedClientAuthorization{
			.accountId = proof.accountId,
			.clientId = proof.clientId,
		};
	}
	auto candidate = current;
	if (candidate.applyVerified(transition, authentication)
		!= GroupTransitionResult::Allowed) {
		return failure(SignedGroupTransitionResult::TransitionRejected);
	}
	return {
		.result = SignedGroupTransitionResult::Applied,
		.applied = AppliedSignedGroupTransition{
			.state = std::move(candidate),
			.checkpoint = {
				.conversationId = transition.conversationId,
				.generation = transition.generation,
				.stateHash = signedTransition.resultingStateHash,
			},
			.archiveEpoch = args.nextArchiveKey
			? std::optional<ArchiveEpochSecret>({
				.generation = transition.generation,
				.activationGroupGeneration = transition.generation,
				.activationEventId = transition.transitionId,
				.key = args.nextArchiveKey->clone(),
			})
			: std::nullopt,
		},
	};
}

} // namespace E2ECloud

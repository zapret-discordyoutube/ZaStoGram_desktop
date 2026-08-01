/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "e2e_cloud/mls/fork_recovery_manifest.h"

#include <algorithm>
#include <array>
#include <limits>
#include <set>
#include <utility>

namespace E2ECloud {
namespace {

inline constexpr auto kMagic = std::array<std::uint8_t, 8>{
	'T', 'D', 'E', '2', 'E', 'F', 'R', 'M',
};

struct Reader {
	const QByteArray &bytes;
	int offset = 0;
};

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

[[nodiscard]] bool CandidateLess(
		const ForkRecoveryCandidate &a,
		const ForkRecoveryCandidate &b) {
	return (a.transitionId != b.transitionId)
		? a.transitionId < b.transitionId
		: a.transitionPayloadHash < b.transitionPayloadHash;
}

[[nodiscard]] bool ClientLess(
		const ForkRecoveryPartitionClient &a,
		const ForkRecoveryPartitionClient &b) {
	return (a.accountId != b.accountId)
		? a.accountId < b.accountId
		: a.clientId < b.clientId;
}

[[nodiscard]] bool ReplacementLess(
		const ForkRecoveryReplacement &a,
		const ForkRecoveryReplacement &b) {
	return (a.accountId != b.accountId)
		? a.accountId < b.accountId
		: a.clientId < b.clientId;
}

[[nodiscard]] bool ValidCandidate(const ForkRecoveryCandidate &candidate) {
	return candidate.transitionId && candidate.transitionPayloadHash;
}

[[nodiscard]] bool ValidClient(
		const ForkRecoveryPartitionClient &client) {
	return client.accountId && client.clientId;
}

[[nodiscard]] bool ValidReplacement(
		const ForkRecoveryReplacement &replacement) {
	return replacement.accountId
		&& replacement.clientId
		&& replacement.publicationObjectId
		&& replacement.publicationPayloadHash
		&& replacement.keyPackageHash;
}

[[nodiscard]] bool ValidManifest(
		const SignedForkRecoveryManifest &manifest,
		bool requireSignature) {
	if (!manifest.conversationId
		|| !manifest.recoveryId
		|| !manifest.telegramPeerIdBinding
		|| !manifest.commonGeneration
		|| !manifest.commonStateHash
		|| manifest.commonGeneration
			> std::numeric_limits<std::uint64_t>::max() - 2
		|| manifest.resolvedGeneration != manifest.commonGeneration + 1
		|| manifest.recoveryGeneration != manifest.commonGeneration + 2
		|| !manifest.ownerAccountId
		|| !manifest.ownerClientId
		|| manifest.candidates.size() < 2
		|| manifest.candidates.size() > kMaximumForkRecoveryCandidates
		|| !manifest.canonicalTransitionId
		|| !manifest.canonicalTransitionPayloadHash
		|| !manifest.canonicalStateHash
		|| manifest.canonicalPartition.empty()
		|| manifest.canonicalPartition.size()
			> kMaximumForkRecoveryClients
		|| manifest.replacements.size() > kMaximumForkRecoveryClients
		|| manifest.canonicalPartition.size() + manifest.replacements.size()
			> kMaximumForkRecoveryClients
		|| !manifest.recoveryCommitObjectId
		|| !manifest.recoveryCommitHash
		|| !manifest.recoveryWelcomeObjectId
		|| !manifest.recoveryWelcomeHash
		|| !manifest.archiveDistributionObjectId
		|| !manifest.archiveKeyCommitment
		|| !manifest.archiveDistributionHash
		|| (requireSignature && !Nonzero(manifest.ownerSignature))) {
		return false;
	}
	if (!std::is_sorted(
			begin(manifest.candidates),
			end(manifest.candidates),
			CandidateLess)
		|| std::adjacent_find(
			begin(manifest.candidates),
			end(manifest.candidates),
			[](const auto &a, const auto &b) {
				return a.transitionId == b.transitionId;
			}) != end(manifest.candidates)
		|| std::any_of(
			begin(manifest.candidates),
			end(manifest.candidates),
			[](const auto &candidate) {
				return !ValidCandidate(candidate);
			})) {
		return false;
	}
	const auto canonical = ForkRecoveryCandidate{
		.transitionId = manifest.canonicalTransitionId,
		.transitionPayloadHash = manifest.canonicalTransitionPayloadHash,
	};
	if (std::find(
			begin(manifest.candidates),
			end(manifest.candidates),
			canonical) == end(manifest.candidates)
		|| !std::is_sorted(
			begin(manifest.canonicalPartition),
			end(manifest.canonicalPartition),
			ClientLess)
		|| std::adjacent_find(
			begin(manifest.canonicalPartition),
			end(manifest.canonicalPartition))
			!= end(manifest.canonicalPartition)
		|| std::any_of(
			begin(manifest.canonicalPartition),
			end(manifest.canonicalPartition),
			[](const auto &client) { return !ValidClient(client); })
		|| !std::is_sorted(
			begin(manifest.replacements),
			end(manifest.replacements),
			ReplacementLess)
		|| std::adjacent_find(
			begin(manifest.replacements),
			end(manifest.replacements),
			[](const auto &a, const auto &b) {
				return a.accountId == b.accountId
					&& a.clientId == b.clientId;
			}) != end(manifest.replacements)
		|| std::any_of(
			begin(manifest.replacements),
			end(manifest.replacements),
			[](const auto &replacement) {
				return !ValidReplacement(replacement);
			})) {
		return false;
	}
	auto objectIds = std::set<ObjectId>{
		manifest.recoveryId,
		manifest.recoveryCommitObjectId,
		manifest.recoveryWelcomeObjectId,
		manifest.archiveDistributionObjectId,
	};
	if (objectIds.size() != 4) {
		return false;
	}
	for (const auto &candidate : manifest.candidates) {
		if (!objectIds.emplace(candidate.transitionId).second) {
			return false;
		}
	}
	for (const auto &replacement : manifest.replacements) {
		if (!objectIds.emplace(replacement.publicationObjectId).second
			|| std::binary_search(
				begin(manifest.canonicalPartition),
				end(manifest.canonicalPartition),
				ForkRecoveryPartitionClient{
					.accountId = replacement.accountId,
					.clientId = replacement.clientId,
				},
				ClientLess)) {
			return false;
		}
	}
	return true;
}

[[nodiscard]] QByteArray EncodeBody(
		const SignedForkRecoveryManifest &manifest) {
	auto result = QByteArray();
	result.reserve(
		512
		+ int(manifest.candidates.size()) * 64
		+ int(manifest.canonicalPartition.size()) * 64
		+ int(manifest.replacements.size()) * 160);
	AppendArray(result, kMagic);
	AppendUint16(result, 1);
	AppendArray(result, manifest.conversationId.bytes);
	AppendArray(result, manifest.recoveryId.bytes);
	AppendUint64(result, manifest.telegramPeerIdBinding);
	AppendUint64(result, manifest.commonGeneration);
	AppendArray(result, manifest.commonStateHash.bytes);
	AppendUint64(result, manifest.resolvedGeneration);
	AppendUint64(result, manifest.recoveryGeneration);
	AppendArray(result, manifest.ownerAccountId.bytes);
	AppendArray(result, manifest.ownerClientId.bytes);
	AppendUint16(result, std::uint16_t(manifest.candidates.size()));
	for (const auto &candidate : manifest.candidates) {
		AppendArray(result, candidate.transitionId.bytes);
		AppendArray(result, candidate.transitionPayloadHash.bytes);
	}
	AppendArray(result, manifest.canonicalTransitionId.bytes);
	AppendArray(result, manifest.canonicalTransitionPayloadHash.bytes);
	AppendArray(result, manifest.canonicalStateHash.bytes);
	AppendUint16(
		result,
		std::uint16_t(manifest.canonicalPartition.size()));
	for (const auto &client : manifest.canonicalPartition) {
		AppendArray(result, client.accountId.bytes);
		AppendArray(result, client.clientId.bytes);
	}
	AppendUint16(result, std::uint16_t(manifest.replacements.size()));
	for (const auto &replacement : manifest.replacements) {
		AppendArray(result, replacement.accountId.bytes);
		AppendArray(result, replacement.clientId.bytes);
		AppendArray(result, replacement.publicationObjectId.bytes);
		AppendArray(result, replacement.publicationPayloadHash.bytes);
		AppendArray(result, replacement.keyPackageHash.bytes);
	}
	AppendArray(result, manifest.recoveryCommitObjectId.bytes);
	AppendArray(result, manifest.recoveryCommitHash.bytes);
	AppendArray(result, manifest.recoveryWelcomeObjectId.bytes);
	AppendArray(result, manifest.recoveryWelcomeHash.bytes);
	AppendArray(result, manifest.archiveDistributionObjectId.bytes);
	AppendArray(result, manifest.archiveKeyCommitment.bytes);
	AppendArray(result, manifest.archiveDistributionHash.bytes);
	return result;
}

[[nodiscard]] std::optional<std::vector<ForkRecoveryReplacement>>
BuildReplacements(
		const std::vector<TransportEnvelope> &envelopes,
		ConversationId conversationId,
		std::uint64_t telegramPeerIdBinding,
		std::uint64_t commonGeneration,
		std::uint64_t currentTime,
		const Sha256Provider &sha256) {
	if (envelopes.size() > kMaximumForkRecoveryClients) {
		return std::nullopt;
	}
	auto result = std::vector<ForkRecoveryReplacement>();
	result.reserve(envelopes.size());
	for (const auto &envelope : envelopes) {
		const auto verified = VerifyClientKeyPackageEnvelope(
			envelope,
			conversationId,
			telegramPeerIdBinding,
			commonGeneration,
			sha256);
		if (verified.result != ClientKeyPackageEnvelopeResult::Verified
			|| !verified.publication
			|| !ClientAuthorizationUsableAt(
				verified.publication->authorization,
				currentTime)) {
			return std::nullopt;
		}
		result.push_back({
			.accountId = envelope.senderAccountId,
			.clientId = envelope.senderClientId,
			.publicationObjectId = envelope.objectId,
			.publicationPayloadHash = envelope.payloadHash,
			.keyPackageHash = sha256.digest(
				verified.publication->keyPackage),
		});
	}
	std::sort(begin(result), end(result), ReplacementLess);
	return std::adjacent_find(
		begin(result),
		end(result),
		[](const auto &a, const auto &b) {
			return a.accountId == b.accountId && a.clientId == b.clientId;
		}) == end(result)
		? std::optional<std::vector<ForkRecoveryReplacement>>(
			std::move(result))
		: std::nullopt;
}

[[nodiscard]] bool PartitionMatchesState(
		const SignedForkRecoveryManifest &manifest,
		const ProtectedGroupState &state) {
	auto expected = std::set<ForkRecoveryPartitionClient, decltype(&ClientLess)>(
		&ClientLess);
	for (const auto &member : state.members()) {
		for (const auto clientId : member.clients) {
			expected.emplace(ForkRecoveryPartitionClient{
				.accountId = member.accountId,
				.clientId = clientId,
			});
		}
	}
	auto actual = std::set<ForkRecoveryPartitionClient, decltype(&ClientLess)>(
		&ClientLess);
	actual.insert(
		begin(manifest.canonicalPartition),
		end(manifest.canonicalPartition));
	for (const auto &replacement : manifest.replacements) {
		actual.emplace(ForkRecoveryPartitionClient{
			.accountId = replacement.accountId,
			.clientId = replacement.clientId,
		});
	}
	return actual == expected;
}

[[nodiscard]] bool OwnerMatches(
		const SignedForkRecoveryManifest &manifest,
		const ProtectedGroupState &commonState,
		const AccountCredentialPublic &credential,
		const Sha256Provider &sha256) {
	const auto owner = commonState.member(manifest.ownerAccountId);
	const auto accountId = DeriveAccountId(credential, sha256);
	return owner
		&& owner->role == GroupRole::Owner
		&& std::find(
			begin(owner->clients),
			end(owner->clients),
			manifest.ownerClientId) != end(owner->clients)
		&& accountId
		&& *accountId == manifest.ownerAccountId;
}

} // namespace

std::optional<QByteArray> SignedForkRecoveryManifestCodecV1::encode(
		const SignedForkRecoveryManifest &manifest) const {
	if (!ValidManifest(manifest, true)) {
		return std::nullopt;
	}
	auto result = EncodeBody(manifest);
	AppendArray(result, manifest.ownerSignature);
	return result.size() <= kMaximumForkRecoveryManifestSize
		? std::optional<QByteArray>(std::move(result))
		: std::nullopt;
}

std::optional<SignedForkRecoveryManifest>
SignedForkRecoveryManifestCodecV1::decode(const QByteArray &bytes) const {
	if (bytes.isEmpty() || bytes.size() > kMaximumForkRecoveryManifestSize) {
		return std::nullopt;
	}
	auto reader = Reader{ bytes };
	auto magic = std::array<std::uint8_t, 8>();
	auto version = std::uint16_t();
	auto candidateCount = std::uint16_t();
	auto partitionCount = std::uint16_t();
	auto replacementCount = std::uint16_t();
	auto result = SignedForkRecoveryManifest();
	if (!ReadArray(reader, magic)
		|| !ReadUint16(reader, version)
		|| magic != kMagic
		|| version != 1
		|| !ReadArray(reader, result.conversationId.bytes)
		|| !ReadArray(reader, result.recoveryId.bytes)
		|| !ReadUint64(reader, result.telegramPeerIdBinding)
		|| !ReadUint64(reader, result.commonGeneration)
		|| !ReadArray(reader, result.commonStateHash.bytes)
		|| !ReadUint64(reader, result.resolvedGeneration)
		|| !ReadUint64(reader, result.recoveryGeneration)
		|| !ReadArray(reader, result.ownerAccountId.bytes)
		|| !ReadArray(reader, result.ownerClientId.bytes)
		|| !ReadUint16(reader, candidateCount)
		|| candidateCount < 2
		|| candidateCount > kMaximumForkRecoveryCandidates) {
		return std::nullopt;
	}
	result.candidates.reserve(candidateCount);
	for (auto index = std::uint16_t(); index != candidateCount; ++index) {
		auto candidate = ForkRecoveryCandidate();
		if (!ReadArray(reader, candidate.transitionId.bytes)
			|| !ReadArray(reader, candidate.transitionPayloadHash.bytes)) {
			return std::nullopt;
		}
		result.candidates.push_back(candidate);
	}
	if (!ReadArray(reader, result.canonicalTransitionId.bytes)
		|| !ReadArray(reader, result.canonicalTransitionPayloadHash.bytes)
		|| !ReadArray(reader, result.canonicalStateHash.bytes)
		|| !ReadUint16(reader, partitionCount)
		|| !partitionCount
		|| partitionCount > kMaximumForkRecoveryClients) {
		return std::nullopt;
	}
	result.canonicalPartition.reserve(partitionCount);
	for (auto index = std::uint16_t(); index != partitionCount; ++index) {
		auto client = ForkRecoveryPartitionClient();
		if (!ReadArray(reader, client.accountId.bytes)
			|| !ReadArray(reader, client.clientId.bytes)) {
			return std::nullopt;
		}
		result.canonicalPartition.push_back(client);
	}
	if (!ReadUint16(reader, replacementCount)
		|| replacementCount > kMaximumForkRecoveryClients
		|| std::size_t(partitionCount) + std::size_t(replacementCount)
			> kMaximumForkRecoveryClients) {
		return std::nullopt;
	}
	result.replacements.reserve(replacementCount);
	for (auto index = std::uint16_t(); index != replacementCount; ++index) {
		auto replacement = ForkRecoveryReplacement();
		if (!ReadArray(reader, replacement.accountId.bytes)
			|| !ReadArray(reader, replacement.clientId.bytes)
			|| !ReadArray(reader, replacement.publicationObjectId.bytes)
			|| !ReadArray(reader, replacement.publicationPayloadHash.bytes)
			|| !ReadArray(reader, replacement.keyPackageHash.bytes)) {
			return std::nullopt;
		}
		result.replacements.push_back(replacement);
	}
	if (!ReadArray(reader, result.recoveryCommitObjectId.bytes)
		|| !ReadArray(reader, result.recoveryCommitHash.bytes)
		|| !ReadArray(reader, result.recoveryWelcomeObjectId.bytes)
		|| !ReadArray(reader, result.recoveryWelcomeHash.bytes)
		|| !ReadArray(reader, result.archiveDistributionObjectId.bytes)
		|| !ReadArray(reader, result.archiveKeyCommitment.bytes)
		|| !ReadArray(reader, result.archiveDistributionHash.bytes)
		|| !ReadArray(reader, result.ownerSignature)
		|| reader.offset != bytes.size()
		|| !ValidManifest(result, true)) {
		return std::nullopt;
	}
	return result;
}

std::optional<SignedForkRecoveryManifest> CreateSignedForkRecoveryManifest(
		CreateSignedForkRecoveryManifestArgs args,
		const Sha256Provider &sha256) {
	if (!args.commonState
		|| !args.canonicalState
		|| !args.currentTime
		|| !args.ownerCredential
		|| !args.ownerSigningPrivateKey
		|| !args.ownerSigningPrivateKey->valid()
		|| !args.nextArchiveKey
		|| !args.nextArchiveKey->valid()
		|| args.recoveryCommit.isEmpty()
		|| args.recoveryWelcome.isEmpty()
		|| args.archiveDistribution.isEmpty()) {
		return std::nullopt;
	}
	std::sort(begin(args.candidates), end(args.candidates), CandidateLess);
	std::sort(
		begin(args.canonicalPartition),
		end(args.canonicalPartition),
		ClientLess);
	const auto replacements = BuildReplacements(
		args.replacementKeyPackageEnvelopes,
		args.conversationId,
		args.telegramPeerIdBinding,
		args.commonCheckpoint.generation,
		args.currentTime,
		sha256);
	if (!replacements) {
		return std::nullopt;
	}
	const auto archiveKeyCommitment = DeriveArchiveKeyCommitment(
		args.conversationId,
		args.commonCheckpoint.generation + 2,
		args.commonCheckpoint.generation + 2,
		args.recoveryId,
		*args.nextArchiveKey,
		sha256);
	if (!archiveKeyCommitment) {
		return std::nullopt;
	}
	auto result = SignedForkRecoveryManifest{
		.conversationId = args.conversationId,
		.recoveryId = args.recoveryId,
		.telegramPeerIdBinding = args.telegramPeerIdBinding,
		.commonGeneration = args.commonCheckpoint.generation,
		.commonStateHash = args.commonCheckpoint.stateHash,
		.resolvedGeneration = args.commonCheckpoint.generation + 1,
		.recoveryGeneration = args.commonCheckpoint.generation + 2,
		.ownerAccountId = args.ownerAccountId,
		.ownerClientId = args.ownerClientId,
		.candidates = std::move(args.candidates),
		.canonicalTransitionId = args.canonicalCandidate.transitionId,
		.canonicalTransitionPayloadHash =
			args.canonicalCandidate.transitionPayloadHash,
		.canonicalStateHash = args.canonicalCheckpoint.stateHash,
		.canonicalPartition = std::move(args.canonicalPartition),
		.replacements = *replacements,
		.recoveryCommitObjectId = args.recoveryCommitObjectId,
		.recoveryCommitHash = sha256.digest(args.recoveryCommit),
		.recoveryWelcomeObjectId = args.recoveryWelcomeObjectId,
		.recoveryWelcomeHash = sha256.digest(args.recoveryWelcome),
		.archiveDistributionObjectId = args.archiveDistributionObjectId,
		.archiveKeyCommitment = *archiveKeyCommitment,
		.archiveDistributionHash = sha256.digest(args.archiveDistribution),
		.ownerSignature = {},
	};
	if (!ValidManifest(result, false)
		|| !OwnerMatches(
			result,
			*args.commonState,
			*args.ownerCredential,
			sha256)
		|| !PartitionMatchesState(result, *args.canonicalState)) {
		return std::nullopt;
	}
	const auto signature = SignAccountData(
		*args.ownerSigningPrivateKey,
		AccountSignatureDomain::ForkRecovery,
		EncodeBody(result));
	if (!signature) {
		return std::nullopt;
	}
	result.ownerSignature = *signature;
	const auto verified = VerifySignedForkRecoveryManifest({
		.manifest = &result,
		.commonState = args.commonState,
		.canonicalState = args.canonicalState,
		.commonCheckpoint = args.commonCheckpoint,
		.canonicalCheckpoint = args.canonicalCheckpoint,
		.observedCandidates = result.candidates,
		.replacementKeyPackageEnvelopes =
			std::move(args.replacementKeyPackageEnvelopes),
		.recoveryCommitObjectId = args.recoveryCommitObjectId,
		.recoveryCommit = std::move(args.recoveryCommit),
		.recoveryWelcomeObjectId = args.recoveryWelcomeObjectId,
		.recoveryWelcome = std::move(args.recoveryWelcome),
		.archiveDistributionObjectId = args.archiveDistributionObjectId,
		.archiveDistribution = std::move(args.archiveDistribution),
		.nextArchiveKey = args.nextArchiveKey,
		.ownerCredential = args.ownerCredential,
		.currentTime = args.currentTime,
	}, sha256);
	return verified == ForkRecoveryManifestResult::Verified
		? std::optional<SignedForkRecoveryManifest>(std::move(result))
		: std::nullopt;
}

ForkRecoveryManifestResult VerifySignedForkRecoveryManifest(
		VerifySignedForkRecoveryManifestArgs args,
		const Sha256Provider &sha256) {
	if (!args.manifest
		|| !args.commonState
		|| !args.canonicalState
		|| !args.ownerCredential
		|| !args.currentTime
		|| !ValidManifest(*args.manifest, true)) {
		return ForkRecoveryManifestResult::InvalidStructure;
	}
	const auto &manifest = *args.manifest;
	if (manifest.conversationId != args.commonCheckpoint.conversationId
		|| manifest.conversationId != args.commonState->conversationId()
		|| manifest.conversationId != args.canonicalState->conversationId()
		|| manifest.conversationId
			!= args.canonicalCheckpoint.conversationId) {
		return ForkRecoveryManifestResult::WrongConversation;
	}
	if (args.commonState->generation() != manifest.commonGeneration
		|| args.canonicalState->generation() != manifest.resolvedGeneration
		|| args.commonCheckpoint.generation != manifest.commonGeneration
		|| args.commonCheckpoint.stateHash != manifest.commonStateHash
		|| args.canonicalCheckpoint.generation
			!= manifest.resolvedGeneration
		|| args.canonicalCheckpoint.stateHash
			!= manifest.canonicalStateHash) {
		return ForkRecoveryManifestResult::InvalidCheckpoint;
	}
	if (!OwnerMatches(
			manifest,
			*args.commonState,
			*args.ownerCredential,
			sha256)) {
		return ForkRecoveryManifestResult::InvalidOwner;
	}
	if (!VerifyAccountSignature(
			*args.ownerCredential,
			AccountSignatureDomain::ForkRecovery,
			EncodeBody(manifest),
			manifest.ownerSignature)) {
		return ForkRecoveryManifestResult::InvalidSignature;
	}
	std::sort(
		begin(args.observedCandidates),
		end(args.observedCandidates),
		CandidateLess);
	if (args.observedCandidates != manifest.candidates) {
		return ForkRecoveryManifestResult::CandidateSetMismatch;
	}
	const auto canonical = ForkRecoveryCandidate{
		.transitionId = manifest.canonicalTransitionId,
		.transitionPayloadHash = manifest.canonicalTransitionPayloadHash,
	};
	if (std::find(
			begin(args.observedCandidates),
			end(args.observedCandidates),
			canonical) == end(args.observedCandidates)) {
		return ForkRecoveryManifestResult::InvalidCanonicalCandidate;
	}
	if (!PartitionMatchesState(manifest, *args.canonicalState)) {
		return ForkRecoveryManifestResult::InvalidPartition;
	}
	const auto replacements = BuildReplacements(
		args.replacementKeyPackageEnvelopes,
		manifest.conversationId,
		manifest.telegramPeerIdBinding,
		manifest.commonGeneration,
		args.currentTime,
		sha256);
	if (!replacements || *replacements != manifest.replacements) {
		return ForkRecoveryManifestResult::InvalidReplacement;
	}
	const auto archiveKeyCommitment = args.nextArchiveKey
		? DeriveArchiveKeyCommitment(
			manifest.conversationId,
			manifest.recoveryGeneration,
			manifest.recoveryGeneration,
			manifest.recoveryId,
			*args.nextArchiveKey,
			sha256)
		: std::nullopt;
	if (!archiveKeyCommitment
		|| *archiveKeyCommitment != manifest.archiveKeyCommitment) {
		return ForkRecoveryManifestResult::InvalidArchiveKey;
	}
	if (args.recoveryCommitObjectId != manifest.recoveryCommitObjectId
		|| args.recoveryCommit.isEmpty()
		|| sha256.digest(args.recoveryCommit) != manifest.recoveryCommitHash
		|| args.recoveryWelcomeObjectId
			!= manifest.recoveryWelcomeObjectId
		|| args.recoveryWelcome.isEmpty()
		|| sha256.digest(args.recoveryWelcome)
			!= manifest.recoveryWelcomeHash
		|| args.archiveDistributionObjectId
			!= manifest.archiveDistributionObjectId
		|| args.archiveDistribution.isEmpty()
		|| sha256.digest(args.archiveDistribution)
			!= manifest.archiveDistributionHash) {
		return ForkRecoveryManifestResult::ArtifactMismatch;
	}
	return ForkRecoveryManifestResult::Verified;
}

bool VerifySignedForkRecoveryManifestSignature(
		const SignedForkRecoveryManifest &manifest,
		const AccountCredentialPublic &ownerCredential,
		const Sha256Provider &sha256) {
	const auto accountId = DeriveAccountId(ownerCredential, sha256);
	return ValidManifest(manifest, true)
		&& accountId
		&& *accountId == manifest.ownerAccountId
		&& VerifyAccountSignature(
			ownerCredential,
			AccountSignatureDomain::ForkRecovery,
			EncodeBody(manifest),
			manifest.ownerSignature);
}

} // namespace E2ECloud

/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "e2e_cloud/protocol/group_control_codec.h"

#include <algorithm>
#include <array>

namespace E2ECloud {
namespace {

inline constexpr auto kPreludeMagic = std::array<std::uint8_t, 8>{
	'T', 'D', 'E', '2', 'E', 'G', 'P', 'R',
};
inline constexpr auto kDistributionMagic = std::array<std::uint8_t, 8>{
	'T', 'D', 'E', '2', 'E', 'A', 'D', 'S',
};

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

[[nodiscard]] QByteArray ZeroBytes(int size) {
	auto result = QByteArray();
	result.resize(size);
	std::fill_n(result.data(), result.size(), char(0));
	return result;
}

[[nodiscard]] bool RequiresTargetAuthorization(GroupTransitionKind kind) {
	return kind == GroupTransitionKind::AddMember
		|| kind == GroupTransitionKind::AddClient;
}

[[nodiscard]] bool ValidPrelude(const GroupChangePrelude &prelude) {
	return IsValidGroupTransitionStructure(prelude.transition)
		&& prelude.actorAccountId
		&& prelude.actorClientId
		&& prelude.previousStateHash
		&& prelude.mlsCommitObjectId
		&& prelude.archiveDistributionObjectId
		&& prelude.archiveKeyCommitment
		&& RequiresTargetAuthorization(prelude.transition.kind)
			== prelude.targetClientAuthorization.has_value();
}

} // namespace

std::optional<QByteArray> GroupControlCodecV1::encodePrelude(
		const GroupChangePrelude &prelude) const {
	if (!ValidPrelude(prelude)) {
		return std::nullopt;
	}
	const auto transition = GroupTransitionCodecV1().encode(
		prelude.transition);
	auto target = ZeroBytes(kClientAuthorizationProofEncodedSize);
	if (prelude.targetClientAuthorization) {
		const auto encoded = ClientAuthorizationProofCodecV1().encode(
			*prelude.targetClientAuthorization);
		if (!encoded) {
			return std::nullopt;
		}
		target = *encoded;
	}
	auto result = QByteArray();
	result.reserve(kGroupChangePreludeEncodedSize);
	AppendArray(result, kPreludeMagic);
	AppendUint16(result, 1);
	result.append(*transition);
	AppendArray(result, prelude.actorAccountId.bytes);
	AppendArray(result, prelude.actorClientId.bytes);
	AppendArray(result, prelude.previousStateHash.bytes);
	AppendArray(result, prelude.mlsCommitObjectId.bytes);
	AppendArray(result, prelude.archiveDistributionObjectId.bytes);
	AppendArray(result, prelude.archiveKeyCommitment.bytes);
	AppendUint8(result, prelude.targetClientAuthorization ? 1 : 0);
	result.append(target);
	return result.size() == kGroupChangePreludeEncodedSize
		? std::optional<QByteArray>(std::move(result))
		: std::nullopt;
}

std::optional<GroupChangePrelude> GroupControlCodecV1::decodePrelude(
		const QByteArray &bytes) const {
	if (bytes.size() != kGroupChangePreludeEncodedSize) {
		return std::nullopt;
	}
	auto reader = Reader{ bytes };
	auto magic = std::array<std::uint8_t, 8>();
	auto version = std::uint16_t();
	auto targetPresent = std::uint8_t();
	auto transitionBytes = QByteArray();
	auto targetBytes = QByteArray();
	auto result = GroupChangePrelude();
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
		|| !ReadArray(reader, result.mlsCommitObjectId.bytes)
		|| !ReadArray(reader, result.archiveDistributionObjectId.bytes)
		|| !ReadArray(reader, result.archiveKeyCommitment.bytes)
		|| !ReadUint8(reader, targetPresent)
		|| targetPresent > 1
		|| reader.bytes.size() - reader.offset
			< kClientAuthorizationProofEncodedSize) {
		return std::nullopt;
	}
	result.transition = *transition;
	targetBytes = QByteArray(
		reader.bytes.constData() + reader.offset,
		kClientAuthorizationProofEncodedSize);
	reader.offset += kClientAuthorizationProofEncodedSize;
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
	return reader.offset == bytes.size()
		&& magic == kPreludeMagic
		&& version == 1
		&& ValidPrelude(result)
		? std::optional<GroupChangePrelude>(std::move(result))
		: std::nullopt;
}

std::optional<QByteArray> GroupControlCodecV1::encodeArchiveDistribution(
		const ArchiveEpochDistribution &distribution) const {
	if (!distribution.conversationId
		|| !distribution.transitionId
		|| !distribution.groupGeneration
		|| !distribution.archiveEpochGeneration
		|| !distribution.activationEventId
		|| !distribution.key.valid()) {
		return std::nullopt;
	}
	auto result = QByteArray();
	result.reserve(kArchiveEpochDistributionEncodedSize);
	AppendArray(result, kDistributionMagic);
	AppendUint16(result, 1);
	AppendArray(result, distribution.conversationId.bytes);
	AppendArray(result, distribution.transitionId.bytes);
	AppendUint64(result, distribution.groupGeneration);
	AppendUint64(result, distribution.archiveEpochGeneration);
	AppendArray(result, distribution.activationEventId.bytes);
	AppendArray(result, distribution.key.bytes());
	return result.size() == kArchiveEpochDistributionEncodedSize
		? std::optional<QByteArray>(std::move(result))
		: std::nullopt;
}

std::optional<ArchiveEpochDistribution>
GroupControlCodecV1::decodeArchiveDistribution(
		const QByteArray &bytes) const {
	if (bytes.size() != kArchiveEpochDistributionEncodedSize) {
		return std::nullopt;
	}
	auto reader = Reader{ bytes };
	auto magic = std::array<std::uint8_t, 8>();
	auto version = std::uint16_t();
	auto key = std::array<std::uint8_t, kArchiveKeySize>();
	auto result = ArchiveEpochDistribution();
	if (!ReadArray(reader, magic)
		|| !ReadUint16(reader, version)
		|| !ReadArray(reader, result.conversationId.bytes)
		|| !ReadArray(reader, result.transitionId.bytes)
		|| !ReadUint64(reader, result.groupGeneration)
		|| !ReadUint64(reader, result.archiveEpochGeneration)
		|| !ReadArray(reader, result.activationEventId.bytes)
		|| !ReadArray(reader, key)
		|| reader.offset != bytes.size()
		|| magic != kDistributionMagic
		|| version != 1) {
		return std::nullopt;
	}
	result.key = ArchiveKey32(std::move(key));
	return result.conversationId
		&& result.transitionId
		&& result.groupGeneration
		&& result.archiveEpochGeneration
		&& result.activationEventId
		&& result.key.valid()
		? std::optional<ArchiveEpochDistribution>(std::move(result))
		: std::nullopt;
}

bool GroupChangePreludeMatchesSignedTransition(
		const GroupChangePrelude &prelude,
		const SignedGroupTransition &transition) {
	return prelude.transition == transition.transition
		&& prelude.actorAccountId == transition.actorAccountId
		&& prelude.actorClientId == transition.actorClientId
		&& prelude.previousStateHash == transition.previousStateHash
		&& prelude.mlsCommitObjectId == transition.mlsCommitObjectId
		&& prelude.archiveDistributionObjectId
			== transition.archiveDistributionObjectId
		&& prelude.archiveKeyCommitment == transition.archiveKeyCommitment
		&& prelude.targetClientAuthorization
			== transition.targetClientAuthorization;
}

} // namespace E2ECloud

/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "e2e_cloud/core/types.h"

#include <QtCore/QByteArray>

#include <array>
#include <cstdint>
#include <optional>

namespace E2ECloud {

class Sha256Provider;

inline constexpr auto kArchiveKeySize = 32;
inline constexpr auto kArchiveContentKeyEnvelopeEncodedSize = 174;

class ArchiveKey32 final {
public:
	ArchiveKey32();
	explicit ArchiveKey32(std::array<std::uint8_t, kArchiveKeySize> &&bytes);
	ArchiveKey32(const ArchiveKey32 &) = delete;
	ArchiveKey32 &operator=(const ArchiveKey32 &) = delete;
	ArchiveKey32(ArchiveKey32 &&other) noexcept;
	ArchiveKey32 &operator=(ArchiveKey32 &&other) noexcept;
	~ArchiveKey32();

	[[nodiscard]] bool valid() const;
	[[nodiscard]] const std::array<std::uint8_t, kArchiveKeySize> &bytes() const;
	[[nodiscard]] ArchiveKey32 clone() const;

private:
	std::array<std::uint8_t, kArchiveKeySize> _bytes = {};

};

struct ArchiveContentKeyEnvelope {
	ConversationId conversationId;
	std::uint64_t epochGeneration = 0;
	ObjectId eventObjectId;
	ObjectId contentObjectId;
	std::array<std::uint8_t, 12> nonce = {};
	std::array<std::uint8_t, kArchiveKeySize> ciphertext = {};
	std::array<std::uint8_t, 16> authenticationTag = {};

	friend inline bool operator==(
		const ArchiveContentKeyEnvelope &,
		const ArchiveContentKeyEnvelope &) = default;
};

class ArchiveContentKeyEnvelopeCodecV1 final {
public:
	[[nodiscard]] std::optional<QByteArray> encode(
		const ArchiveContentKeyEnvelope &envelope) const;
	[[nodiscard]] std::optional<ArchiveContentKeyEnvelope> decode(
		const QByteArray &bytes) const;

};

class ArchiveEpochCrypto final {
public:
	[[nodiscard]] std::optional<ArchiveKey32> generateKey() const;
	[[nodiscard]] std::optional<ArchiveContentKeyEnvelope> wrapContentKey(
		ConversationId conversationId,
		std::uint64_t epochGeneration,
		ObjectId eventObjectId,
		ObjectId contentObjectId,
		const ArchiveKey32 &epochKey,
		const ArchiveKey32 &contentKey) const;
	[[nodiscard]] std::optional<ArchiveKey32> unwrapContentKey(
		const ArchiveKey32 &epochKey,
		const ArchiveContentKeyEnvelope &envelope) const;

};

[[nodiscard]] std::optional<Digest> DeriveArchiveKeyCommitment(
	ConversationId conversationId,
	std::uint64_t archiveEpochGeneration,
	std::uint64_t activationGroupGeneration,
	ObjectId activationEventId,
	const ArchiveKey32 &key,
	const Sha256Provider &sha256);

} // namespace E2ECloud

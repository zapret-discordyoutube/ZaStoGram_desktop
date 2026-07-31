/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "e2e_cloud/core/envelope_codec.h"

#include <algorithm>
#include <limits>
#include <utility>

namespace E2ECloud {
namespace {

struct Reader {
	const QByteArray &bytes;
	int offset = 0;
};

void AppendUint16(QByteArray &result, std::uint16_t value) {
	result.append(char(value >> 8));
	result.append(char(value));
}

void AppendUint32(QByteArray &result, std::uint32_t value) {
	result.append(char(value >> 24));
	result.append(char(value >> 16));
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

[[nodiscard]] bool ReadUint32(Reader &reader, std::uint32_t &value) {
	if (reader.bytes.size() - reader.offset < 4) {
		return false;
	}
	const auto data = reinterpret_cast<const std::uint8_t*>(
		reader.bytes.constData() + reader.offset);
	value = (std::uint32_t(data[0]) << 24)
		| (std::uint32_t(data[1]) << 16)
		| (std::uint32_t(data[2]) << 8)
		| std::uint32_t(data[3]);
	reader.offset += 4;
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

[[nodiscard]] bool ReadBytes(
		Reader &reader,
		int maximumSize,
		QByteArray &value) {
	auto size = std::uint32_t();
	if (!ReadUint32(reader, size)
		|| size > std::uint32_t(maximumSize)
		|| size > std::uint32_t(std::numeric_limits<int>::max())
		|| reader.bytes.size() - reader.offset < int(size)) {
		return false;
	}
	value = QByteArray(reader.bytes.constData() + reader.offset, int(size));
	reader.offset += int(size);
	return true;
}

} // namespace

std::optional<EncodedEnvelope> EnvelopeCodecV1::encode(
		const TransportEnvelope &envelope) const {
	if (ValidateEnvelope(envelope) != EnvelopeValidationError::None
		|| envelope.payload.size() > kMaxEnvelopePayloadSize
		|| envelope.authenticationData.size()
			> kMaxEnvelopeAuthenticationDataSize) {
		return std::nullopt;
	}
	auto result = QByteArray();
	result.reserve(
		8 + 4 + 32 + 2 + 32 + 16 + 8 + 8 + 32 + 32 + 4
		+ envelope.payload.size() + 4 + envelope.authenticationData.size());
	AppendArray(result, envelope.magic);
	AppendUint32(result, envelope.applicationProtocolVersion);
	AppendArray(result, envelope.conversationId.bytes);
	AppendUint16(result, std::uint16_t(envelope.objectKind));
	AppendArray(result, envelope.senderAccountId.bytes);
	AppendArray(result, envelope.senderClientId.bytes);
	AppendUint64(result, envelope.telegramPeerIdBinding);
	AppendUint64(result, envelope.epochOrGeneration);
	AppendArray(result, envelope.objectId.bytes);
	AppendArray(result, envelope.payloadHash.bytes);
	AppendUint32(result, std::uint32_t(envelope.payload.size()));
	result.append(envelope.payload);
	AppendUint32(result, std::uint32_t(envelope.authenticationData.size()));
	result.append(envelope.authenticationData);
	return EncodedEnvelope{
		.conversationId = envelope.conversationId,
		.objectId = envelope.objectId,
		.bytes = std::move(result),
	};
}

std::optional<TransportEnvelope> EnvelopeCodecV1::decode(
		const EncodedEnvelope &encoded) const {
	if (!encoded.conversationId || !encoded.objectId) {
		return std::nullopt;
	}
	const auto result = decodeUntrusted(encoded.bytes);
	if (!result
		|| result->conversationId != encoded.conversationId
		|| result->objectId != encoded.objectId) {
		return std::nullopt;
	}
	return result;
}

std::optional<TransportEnvelope> EnvelopeCodecV1::decodeUntrusted(
		const QByteArray &bytes) const {
	auto reader = Reader{ bytes };
	auto result = TransportEnvelope();
	auto objectKind = std::uint16_t();
	auto peerBinding = std::uint64_t();
	if (!ReadArray(reader, result.magic)
		|| !ReadUint32(reader, result.applicationProtocolVersion)
		|| !ReadArray(reader, result.conversationId.bytes)
		|| !ReadUint16(reader, objectKind)
		|| !ReadArray(reader, result.senderAccountId.bytes)
		|| !ReadArray(reader, result.senderClientId.bytes)
		|| !ReadUint64(reader, peerBinding)
		|| !ReadUint64(reader, result.epochOrGeneration)
		|| !ReadArray(reader, result.objectId.bytes)
		|| !ReadArray(reader, result.payloadHash.bytes)
		|| !ReadBytes(reader, kMaxEnvelopePayloadSize, result.payload)
		|| !ReadBytes(
			reader,
			kMaxEnvelopeAuthenticationDataSize,
			result.authenticationData)
		|| reader.offset != bytes.size()) {
		return std::nullopt;
	}
	result.objectKind = ObjectKind(objectKind);
	result.telegramPeerIdBinding = peerBinding;
	if (ValidateEnvelope(result) != EnvelopeValidationError::None) {
		return std::nullopt;
	}
	return result;
}

} // namespace E2ECloud

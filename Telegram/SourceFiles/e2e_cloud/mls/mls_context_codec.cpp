/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "e2e_cloud/mls/mls_context_codec.h"

#include <algorithm>
#include <array>

namespace E2ECloud {
namespace {

inline constexpr auto kCredentialMagic = std::array<std::uint8_t, 8>{
	'T', 'D', 'E', '2', 'E', 'C', 'L', 'I',
};
inline constexpr auto kAadMagic = std::array<std::uint8_t, 8>{
	'T', 'D', 'E', '2', 'E', 'A', 'A', 'D',
};

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

[[nodiscard]] bool MlsObjectKind(ObjectKind kind) {
	switch (kind) {
	case ObjectKind::MlsProposal:
	case ObjectKind::MlsCommit:
	case ObjectKind::MlsApplication:
	case ObjectKind::ArchiveEpoch:
		return true;
	default:
		return false;
	}
}

[[nodiscard]] bool ValidCredential(
		const MlsClientCredential &credential) {
	return credential.conversationId
		&& credential.accountId
		&& credential.clientId;
}

[[nodiscard]] bool ValidAad(const MlsTransportAad &aad) {
	return aad.conversationId
		&& MlsObjectKind(aad.objectKind)
		&& aad.senderAccountId
		&& aad.senderClientId
		&& aad.telegramPeerIdBinding
		&& aad.objectId
		&& aad.context.size()
			<= kMlsTransportAadMaximumSize - kMlsTransportAadFixedSize;
}

} // namespace

std::optional<QByteArray> MlsContextCodecV1::encodeCredential(
		const MlsClientCredential &credential) const {
	if (!ValidCredential(credential)) {
		return std::nullopt;
	}
	auto result = QByteArray();
	result.reserve(kMlsClientCredentialEncodedSize);
	AppendArray(result, kCredentialMagic);
	AppendUint16(result, 1);
	AppendArray(result, credential.conversationId.bytes);
	AppendArray(result, credential.accountId.bytes);
	AppendArray(result, credential.clientId.bytes);
	return result;
}

std::optional<MlsClientCredential> MlsContextCodecV1::decodeCredential(
		const QByteArray &bytes) const {
	if (bytes.size() != kMlsClientCredentialEncodedSize) {
		return std::nullopt;
	}
	auto reader = Reader{ bytes };
	auto magic = std::array<std::uint8_t, 8>();
	auto version = std::uint16_t();
	auto result = MlsClientCredential();
	if (!ReadArray(reader, magic)
		|| !ReadUint16(reader, version)
		|| !ReadArray(reader, result.conversationId.bytes)
		|| !ReadArray(reader, result.accountId.bytes)
		|| !ReadArray(reader, result.clientId.bytes)
		|| reader.offset != bytes.size()
		|| magic != kCredentialMagic
		|| version != 1
		|| !ValidCredential(result)) {
		return std::nullopt;
	}
	return result;
}

std::optional<QByteArray> MlsContextCodecV1::encodeAad(
		const MlsTransportAad &aad) const {
	if (!ValidAad(aad)) {
		return std::nullopt;
	}
	auto result = QByteArray();
	result.reserve(kMlsTransportAadFixedSize + aad.context.size());
	AppendArray(result, kAadMagic);
	AppendUint16(result, 1);
	AppendArray(result, aad.conversationId.bytes);
	AppendUint16(result, std::uint16_t(aad.objectKind));
	AppendArray(result, aad.senderAccountId.bytes);
	AppendArray(result, aad.senderClientId.bytes);
	AppendUint64(result, aad.telegramPeerIdBinding);
	AppendArray(result, aad.objectId.bytes);
	AppendUint32(result, std::uint32_t(aad.context.size()));
	result.append(aad.context);
	return result;
}

std::optional<MlsTransportAad> MlsContextCodecV1::decodeAad(
		const QByteArray &bytes) const {
	if (bytes.size() < kMlsTransportAadFixedSize
		|| bytes.size() > kMlsTransportAadMaximumSize) {
		return std::nullopt;
	}
	auto reader = Reader{ bytes };
	auto magic = std::array<std::uint8_t, 8>();
	auto version = std::uint16_t();
	auto kind = std::uint16_t();
	auto contextSize = std::uint32_t();
	auto result = MlsTransportAad();
	if (!ReadArray(reader, magic)
		|| !ReadUint16(reader, version)
		|| !ReadArray(reader, result.conversationId.bytes)
		|| !ReadUint16(reader, kind)
		|| !ReadArray(reader, result.senderAccountId.bytes)
		|| !ReadArray(reader, result.senderClientId.bytes)
		|| !ReadUint64(reader, result.telegramPeerIdBinding)
		|| !ReadArray(reader, result.objectId.bytes)
		|| !ReadUint32(reader, contextSize)
		|| contextSize > std::uint32_t(
			kMlsTransportAadMaximumSize - kMlsTransportAadFixedSize)
		|| reader.bytes.size() - reader.offset != int(contextSize)
		|| magic != kAadMagic
		|| version != 1) {
		return std::nullopt;
	}
	result.objectKind = ObjectKind(kind);
	result.context = QByteArray(
		reader.bytes.constData() + reader.offset,
		int(contextSize));
	return ValidAad(result)
		? std::optional<MlsTransportAad>(std::move(result))
		: std::nullopt;
}

} // namespace E2ECloud

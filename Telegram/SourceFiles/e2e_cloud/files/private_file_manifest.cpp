/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "e2e_cloud/files/private_file_manifest.h"

#include <algorithm>
#include <array>

namespace E2ECloud {
namespace {

inline constexpr auto kMagic = std::array<std::uint8_t, 8>{
	'T', 'D', 'E', '2', 'E', 'F', 'M', 'F',
};
inline constexpr auto kFixedSize = 174;
inline constexpr auto kMaximumFilenameSize = 1024;
inline constexpr auto kMaximumMimeTypeSize = 255;

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
		value.size());
}

[[nodiscard]] std::uint16_t ReadUint16(const char *data) {
	const auto bytes = reinterpret_cast<const std::uint8_t*>(data);
	return (std::uint16_t(bytes[0]) << 8) | std::uint16_t(bytes[1]);
}

[[nodiscard]] std::uint32_t ReadUint32(const char *data) {
	const auto bytes = reinterpret_cast<const std::uint8_t*>(data);
	return (std::uint32_t(bytes[0]) << 24)
		| (std::uint32_t(bytes[1]) << 16)
		| (std::uint32_t(bytes[2]) << 8)
		| std::uint32_t(bytes[3]);
}

[[nodiscard]] std::uint64_t ReadUint64(const char *data) {
	auto result = std::uint64_t(0);
	for (auto i = 0; i != 8; ++i) {
		result = (result << 8) | std::uint8_t(data[i]);
	}
	return result;
}

template <typename Array>
void ReadArray(const char *data, Array &value) {
	std::copy_n(
		reinterpret_cast<const std::uint8_t*>(data),
		value.size(),
		value.begin());
}

[[nodiscard]] bool ValidFilename(const QByteArray &value) {
	if (value.isEmpty() || value.size() > kMaximumFilenameSize) {
		return false;
	}
	for (auto i = 0; i != value.size(); ++i) {
		if (!value[i] || value[i] == '/' || value[i] == '\\') {
			return false;
		}
	}
	return value != QByteArray(".") && value != QByteArray("..");
}

[[nodiscard]] bool ValidMimeType(const QByteArray &value) {
	if (value.size() > kMaximumMimeTypeSize) {
		return false;
	}
	for (auto i = 0; i != value.size(); ++i) {
		if (!value[i] || value[i] == '\r' || value[i] == '\n') {
			return false;
		}
	}
	return true;
}

} // namespace

std::optional<QByteArray> PrivateFileManifestCodecV1::encodePlaintext(
		const PrivateFileManifest &manifest) const {
	if (!IsValidFileChunkContext(manifest.context)
		|| !manifest.key.valid()
		|| !manifest.plaintextHash
		|| !manifest.unixTime
		|| !ValidFilename(manifest.filenameUtf8)
		|| !ValidMimeType(manifest.mimeTypeUtf8)) {
		return std::nullopt;
	}
	auto result = QByteArray();
	result.reserve(
		kFixedSize
		+ manifest.filenameUtf8.size()
		+ manifest.mimeTypeUtf8.size());
	AppendArray(result, kMagic);
	AppendUint16(result, 2);
	AppendArray(result, manifest.context.conversationId.bytes);
	AppendArray(result, manifest.context.fileId.bytes);
	AppendArray(result, manifest.key.bytes());
	AppendUint64(result, manifest.context.plaintextSize);
	AppendUint32(result, manifest.context.chunkSize);
	AppendUint32(result, manifest.context.chunkCount);
	AppendArray(result, manifest.context.noncePrefix);
	AppendArray(result, manifest.plaintextHash.bytes);
	AppendUint64(result, manifest.unixTime);
	AppendUint16(result, std::uint16_t(manifest.filenameUtf8.size()));
	result.append(manifest.filenameUtf8);
	AppendUint16(result, std::uint16_t(manifest.mimeTypeUtf8.size()));
	result.append(manifest.mimeTypeUtf8);
	return result;
}

std::optional<PrivateFileManifest> PrivateFileManifestCodecV1::decodePlaintext(
		const QByteArray &bytes) const {
	if (bytes.size() < kFixedSize
		|| !std::equal(
			begin(kMagic),
			end(kMagic),
			reinterpret_cast<const std::uint8_t*>(bytes.constData()))
		|| ReadUint16(bytes.constData() + 8) != 2) {
		return std::nullopt;
	}
	auto context = FileChunkContext();
	auto keyBytes = std::array<std::uint8_t, 32>();
	auto hash = Digest();
	ReadArray(bytes.constData() + 10, context.conversationId.bytes);
	ReadArray(bytes.constData() + 42, context.fileId.bytes);
	ReadArray(bytes.constData() + 74, keyBytes);
	context.plaintextSize = ReadUint64(bytes.constData() + 106);
	context.chunkSize = ReadUint32(bytes.constData() + 114);
	context.chunkCount = ReadUint32(bytes.constData() + 118);
	ReadArray(bytes.constData() + 122, context.noncePrefix);
	ReadArray(bytes.constData() + 130, hash.bytes);
	const auto unixTime = ReadUint64(bytes.constData() + 162);
	const auto filenameSize = ReadUint16(bytes.constData() + 170);
	if (filenameSize > kMaximumFilenameSize
		|| bytes.size() < 174 + filenameSize) {
		return std::nullopt;
	}
	const auto filename = QByteArray(bytes.constData() + 172, filenameSize);
	const auto mimeOffset = 172 + filenameSize;
	const auto mimeSize = ReadUint16(bytes.constData() + mimeOffset);
	if (mimeSize > kMaximumMimeTypeSize
		|| bytes.size() != mimeOffset + 2 + mimeSize) {
		return std::nullopt;
	}
	const auto mime = QByteArray(bytes.constData() + mimeOffset + 2, mimeSize);
	auto key = FileEncryptionKey(std::move(keyBytes));
	if (!IsValidFileChunkContext(context)
		|| !key.valid()
		|| !hash
		|| !unixTime
		|| !ValidFilename(filename)
		|| !ValidMimeType(mime)) {
		return std::nullopt;
	}
	return PrivateFileManifest{
		.context = context,
		.key = std::move(key),
		.plaintextHash = hash,
		.unixTime = unixTime,
		.filenameUtf8 = filename,
		.mimeTypeUtf8 = mime,
	};
}

} // namespace E2ECloud

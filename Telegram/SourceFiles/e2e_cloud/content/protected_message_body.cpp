/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "e2e_cloud/content/protected_message_body.h"

#include <algorithm>
#include <array>

namespace E2ECloud {
namespace {

inline constexpr auto kMagic = std::array<std::uint8_t, 8>{
	'T', 'D', 'E', '2', 'E', 'M', 'S', 'G',
};
inline constexpr auto kHeaderSize = 8 + 2 + 8 + 4;

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
	auto result = std::uint64_t();
	for (auto i = 0; i != 8; ++i) {
		result = (result << 8) | std::uint8_t(data[i]);
	}
	return result;
}

[[nodiscard]] bool ValidUtf8(const QByteArray &bytes) {
	if (bytes.isEmpty() || bytes.size() > kMaximumProtectedMessageTextSize) {
		return false;
	}
	const auto data = reinterpret_cast<const std::uint8_t*>(
		bytes.constData());
	auto offset = 0;
	while (offset != bytes.size()) {
		const auto first = data[offset++];
		if (!first) {
			return false;
		} else if (first < 0x80) {
			continue;
		}
		auto continuationCount = 0;
		auto minimum = std::uint32_t();
		auto codepoint = std::uint32_t();
		if ((first & 0xE0) == 0xC0) {
			continuationCount = 1;
			minimum = 0x80;
			codepoint = first & 0x1F;
		} else if ((first & 0xF0) == 0xE0) {
			continuationCount = 2;
			minimum = 0x800;
			codepoint = first & 0x0F;
		} else if ((first & 0xF8) == 0xF0) {
			continuationCount = 3;
			minimum = 0x10000;
			codepoint = first & 0x07;
		} else {
			return false;
		}
		if (bytes.size() - offset < continuationCount) {
			return false;
		}
		for (auto i = 0; i != continuationCount; ++i) {
			const auto next = data[offset++];
			if ((next & 0xC0) != 0x80) {
				return false;
			}
			codepoint = (codepoint << 6) | (next & 0x3F);
		}
		if (codepoint < minimum
			|| codepoint > 0x10FFFF
			|| (codepoint >= 0xD800 && codepoint <= 0xDFFF)) {
			return false;
		}
	}
	return true;
}

} // namespace

std::optional<QByteArray> ProtectedMessageBodyCodecV1::encodePlaintext(
		const ProtectedMessageBody &body) const {
	if (!body.unixTime || !ValidUtf8(body.textUtf8)) {
		return std::nullopt;
	}
	auto result = QByteArray();
	result.reserve(kHeaderSize + body.textUtf8.size());
	AppendArray(result, kMagic);
	AppendUint16(result, 1);
	AppendUint64(result, body.unixTime);
	AppendUint32(result, std::uint32_t(body.textUtf8.size()));
	result.append(body.textUtf8);
	return result;
}

std::optional<ProtectedMessageBody>
ProtectedMessageBodyCodecV1::decodePlaintext(const QByteArray &bytes) const {
	if (bytes.size() < kHeaderSize
		|| !std::equal(
			begin(kMagic),
			end(kMagic),
			reinterpret_cast<const std::uint8_t*>(bytes.constData()))
		|| ReadUint16(bytes.constData() + 8) != 1) {
		return std::nullopt;
	}
	const auto unixTime = ReadUint64(bytes.constData() + 10);
	const auto size = ReadUint32(bytes.constData() + 18);
	if (!unixTime
		|| size > kMaximumProtectedMessageTextSize
		|| bytes.size() != kHeaderSize + int(size)) {
		return std::nullopt;
	}
	auto body = ProtectedMessageBody{
		.unixTime = unixTime,
		.textUtf8 = QByteArray(bytes.constData() + kHeaderSize, int(size)),
	};
	return ValidUtf8(body.textUtf8)
		? std::optional<ProtectedMessageBody>(std::move(body))
		: std::nullopt;
}

} // namespace E2ECloud

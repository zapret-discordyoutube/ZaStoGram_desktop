/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/proxy/mtproxy/client_hello_builder.h"

#include "mtproto/proxy/mtproxy/client_hello_constants.h"
#include "base/random.h"

#include <algorithm>
#include <optional>

namespace MTP::details {
namespace {

struct ClientHelloRange {
	int offset = 0;
	int length = 0;

	[[nodiscard]] explicit operator bool() const {
		return length > 0;
	}
};

[[nodiscard]] std::optional<int> ClientHelloRead16(
		const QByteArray &data,
		int offset) {
	if (offset < 0 || offset + 2 > data.size()) {
		return std::nullopt;
	}
	return (int(uchar(data[offset])) << 8)
		| int(uchar(data[offset + 1]));
}

[[nodiscard]] std::optional<int> ClientHelloRead24(
		const QByteArray &data,
		int offset) {
	if (offset < 0 || offset + 3 > data.size()) {
		return std::nullopt;
	}
	return (int(uchar(data[offset])) << 16)
		| (int(uchar(data[offset + 1])) << 8)
		| int(uchar(data[offset + 2]));
}

[[nodiscard]] ClientHelloRange ClientHelloSniHostRange(
		const QByteArray &data) {
	if (data.size() < 9 || uchar(data[0]) != 0x16) {
		return {};
	}
	const auto recordLength = ClientHelloRead16(data, 3);
	if (!recordLength) {
		return {};
	}
	const auto recordEnd = 5 + *recordLength;
	if (*recordLength < 4 || recordEnd > data.size()) {
		return {};
	}
	auto position = 5;
	if (uchar(data[position]) != 0x01) {
		return {};
	}
	const auto handshakeLength = ClientHelloRead24(data, position + 1);
	if (!handshakeLength) {
		return {};
	}
	position += 4;
	const auto handshakeEnd = position + *handshakeLength;
	if (handshakeEnd > recordEnd) {
		return {};
	}
	if (position + 34 > handshakeEnd) {
		return {};
	}
	position += 34;
	if (position + 1 > handshakeEnd) {
		return {};
	}
	const auto sessionIdLength = int(uchar(data[position++]));
	if (position + sessionIdLength > handshakeEnd) {
		return {};
	}
	position += sessionIdLength;
	const auto cipherSuitesLength = ClientHelloRead16(data, position);
	if (!cipherSuitesLength) {
		return {};
	}
	position += 2;
	if (position + *cipherSuitesLength > handshakeEnd) {
		return {};
	}
	position += *cipherSuitesLength;
	if (position + 1 > handshakeEnd) {
		return {};
	}
	const auto compressionLength = int(uchar(data[position++]));
	if (position + compressionLength > handshakeEnd) {
		return {};
	}
	position += compressionLength;
	const auto extensionsLength = ClientHelloRead16(data, position);
	if (!extensionsLength) {
		return {};
	}
	position += 2;
	const auto extensionsEnd = position + *extensionsLength;
	if (extensionsEnd > handshakeEnd) {
		return {};
	}
	while (position + 4 <= extensionsEnd) {
		const auto type = ClientHelloRead16(data, position);
		const auto length = ClientHelloRead16(data, position + 2);
		if (!type || !length) {
			return {};
		}
		const auto value = position + 4;
		const auto next = value + *length;
		if (next > extensionsEnd) {
			return {};
		}
		if (*type != 0x0000) {
			position = next;
			continue;
		}
		const auto listLength = ClientHelloRead16(data, value);
		if (!listLength) {
			return {};
		}
		auto listPosition = value + 2;
		const auto listEnd = listPosition + *listLength;
		if (listEnd > next) {
			return {};
		}
		while (listPosition + 3 <= listEnd) {
			const auto nameType = uchar(data[listPosition]);
			const auto nameLength = ClientHelloRead16(data, listPosition + 1);
			if (!nameLength) {
				return {};
			}
			const auto nameOffset = listPosition + 3;
			if (nameOffset + *nameLength > listEnd) {
				return {};
			}
			if (nameType == 0 && *nameLength > 1) {
				return { nameOffset, *nameLength };
			}
			listPosition = nameOffset + *nameLength;
		}
		return {};
	}
	return {};
}

[[nodiscard]] int ClientHelloFragmentSplit(const QByteArray &data) {
	const auto range = ClientHelloSniHostRange(data);
	if (range) {
		return range.offset + 1 + base::RandomIndex(range.length - 1);
	}
	const auto size = int(data.size());
	const auto maxFirst = std::min(768, size - 96);
	const auto minFirst = std::min(224, maxFirst);
	const auto fallbackRange = (maxFirst > minFirst)
		? (maxFirst - minFirst + 1)
		: 1;
	return minFirst + base::RandomIndex(fallbackRange);
}


} // namespace

ClientHelloFragmentationPlan PrepareClientHelloFragmentation(
		const QByteArray &data,
		ProxyClientHelloFragmentation mode) {
	const auto size = int(data.size());
	if (mode != ProxyClientHelloFragmentation::Soft || size < 384) {
		return {};
	}
	const auto delayRange = int(
		kClientHelloFragmentDelayMax - kClientHelloFragmentDelayMin + 1);
	return {
		ClientHelloFragmentSplit(data),
		kClientHelloFragmentDelayMin + base::RandomIndex(delayRange),
	};
}


} // namespace MTP::details

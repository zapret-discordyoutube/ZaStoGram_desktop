/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "mtproto/protocol/mtproto_binary.h"
#include "base/bytes.h"

#include <QtCore/QLatin1String>
#include <QtCore/QtEndian>

namespace MTP::details {

[[nodiscard]] inline bool CheckPart(bytes::const_span data, QLatin1String check) {
	if (data.size() < check.size()) {
		return false;
	}
	return !bytes::compare(
		data.subspan(0, check.size()),
		bytes::make_span(check.data(), check.size()));
}

[[nodiscard]] inline bool IsTlsAlert(bytes::const_span data) {
	return data.size() >= 2
		&& data[0] == bytes::type(0x15)
		&& data[1] == bytes::type(0x03);
}

[[nodiscard]] inline int ReadPartLength(bytes::const_span data, int offset) {
	const auto storage = data.subspan(offset, sizeof(uint16));
	return qFromBigEndian(binary::Read<uint16>(storage));
}

} // namespace MTP::details

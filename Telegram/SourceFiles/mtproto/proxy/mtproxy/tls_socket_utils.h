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
#include <QtCore/QByteArrayView>
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

[[nodiscard]] inline QString FakeTlsResponseClass(
		QByteArrayView prefix,
		qint64 totalBytes) {
	if (!totalBytes) {
		return u"zero"_q;
	}
	if (prefix.startsWith("HTTP/")
		|| prefix.startsWith("GET ")
		|| prefix.startsWith("POST ")) {
		return u"http_like"_q;
	}
	if (prefix.size() < 5) {
		return u"partial_tls_header"_q;
	}
	const auto type = uchar(prefix[0]);
	if (type == 0x15) {
		return u"tls_alert"_q;
	}
	const auto recordLength = (int(uchar(prefix[3])) << 8)
		| int(uchar(prefix[4]));
	if (totalBytes < 5 + recordLength) {
		return u"partial_tls_record"_q;
	} else if (type == 0x16) {
		return u"tls_handshake"_q;
	} else if (type == 0x17) {
		return u"tls_appdata"_q;
	}
	return u"non_tls"_q;
}

} // namespace MTP::details

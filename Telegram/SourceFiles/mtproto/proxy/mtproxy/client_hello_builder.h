/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "base/basic_types.h"
#include "base/bytes.h"
#include "base/timer.h"
#include "mtproto/proxy/data.h"
#include "scheme.h"

#include <QtCore/QByteArray>

#include <optional>

namespace MTP::details {

struct SyntheticPskOffer {
	bytes::vector identity;
	uint32 obfuscatedTicketAge = 0;
	int binderLength = 0;
};

struct ClientHello {
	QByteArray data;
	QByteArray digest;
	// The time actually mixed into the digest. Relays check it and refuse
	// anything more than three seconds ahead of their own clock, so this is
	// the one value worth reporting - re-reading the clock anywhere else
	// gives a number that has already drifted from the one on the wire.
	TimeId timestamp = 0;
};

struct ClientHelloFragmentationPlan {
	int firstSize = 0;
	crl::time secondDelay = 0;

	[[nodiscard]] explicit operator bool() const {
		return firstSize > 0;
	}
};

struct ClientHelloGenerationOptions {
	bool deterministic = false;
};

[[nodiscard]] MTPTlsClientHello PrepareClientHelloRules(
	ProxyTlsProfile profile);

[[nodiscard]] ClientHello PrepareClientHello(
	const MTPTlsClientHello &rules,
	bytes::const_span domain,
	bytes::const_span key,
	ProxyTlsProfile profile,
	std::optional<SyntheticPskOffer> pskOffer,
	ClientHelloGenerationOptions options = {});

[[nodiscard]] ClientHelloFragmentationPlan PrepareClientHelloFragmentation(
	const QByteArray &data,
	ProxyClientHelloFragmentation mode);

} // namespace MTP::details

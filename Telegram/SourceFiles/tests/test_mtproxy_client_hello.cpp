/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/proxy/mtproxy/client_hello_builder.h"
#include "mtproto/proxy/mtproxy/client_hello_facts.h"
#include "mtproto/proxy/mtproxy/client_hello_profile.h"

#include "base/bytes.h"

#include <QtCore/QByteArray>
#include <QtCore/QString>

#include <cstdio>
#include <optional>

namespace {

[[nodiscard]] int Fail(const char *message) {
	std::fprintf(stderr, "%s\n", message);
	return 1;
}

[[nodiscard]] bytes::const_span AsBytes(const QByteArray &value) {
	return bytes::make_span(value.constData(), value.size());
}

} // namespace

int main(int, char *[]) {
	const auto domain = QByteArray("ja4-capture.test");
	const auto key = QByteArray::fromHex("00112233445566778899aabbccddeeff");
	const auto &profile = MTP::details::ClientHelloProfile(
		MTP::ProxyTlsProfile::ChromeModern);
	if (profile.validation != MTP::details::ClientHelloProfileValidation::Validated
		|| !profile.expectedJa4[0]) {
		return Fail("ChromeModern profile is not validated.");
	}

	auto options = MTP::details::ClientHelloGenerationOptions();
	options.deterministic = true;

	const auto rules = MTP::details::PrepareClientHelloRules(
		MTP::ProxyTlsProfile::ChromeModern);
	const auto hello = MTP::details::PrepareClientHello(
		rules,
		AsBytes(domain),
		AsBytes(key),
		MTP::ProxyTlsProfile::ChromeModern,
		std::nullopt,
		options);
	if (hello.data.isEmpty() || hello.digest.size() != 32) {
		return Fail("ChromeModern ClientHello was not generated.");
	}

	const auto facts = MTP::details::ComputeClientHelloFacts(hello.data);
	if (!facts) {
		return Fail("ChromeModern ClientHello facts were not parsed.");
	}
	if (!facts->hasSni || facts->firstAlpn != QByteArray("h2")) {
		return Fail("ChromeModern ClientHello core facts drifted.");
	}
	const auto ja4 = MTP::details::ComputeClientHelloJa4(*facts);
	if (ja4 != QString::fromLatin1(profile.expectedJa4)) {
		return Fail("ChromeModern ClientHello JA4 drifted.");
	}
	return 0;
}

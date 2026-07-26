/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/proxy/mtproxy/client_hello_profile.h"

#include <array>

namespace MTP::details {
namespace {

// Measured 26 July 2026 against one relay from two networks, twelve attempts
// per profile per network. On an unfiltered network every profile below is
// answered in under fifty milliseconds. On a filtered one, chrome_modern and
// android_chrome are answered three times out of twelve and otherwise get
// silence, while the other four are answered twelve times out of twelve - on
// the same relay, with the same secret, in the same minutes.
//
// What is being refused is not one field but an exact match. Three follow-up
// experiments each changed one thing in the refused hello and each made it
// pass: the trailing GREASE payload byte set to 0xff instead of 0x00, that
// byte moved to the first GREASE extension instead of the last, and the ECH
// payload length taken off the {144, 176, 208, 240} set the builder draws
// from. Extension order, packet size, the post-quantum key share and JA4
// were each measured and ruled out - JA4 is byte-identical between a profile
// that passes and one that does not.
//
// So the trait that decides a profile's fate is its tail: chrome_modern and
// android_chrome end with a GREASE extension carrying one zero byte, which
// is what Chromium really sends and what this network matches on. The
// profiles that pass end with an empty GREASE extension or with no GREASE
// extension at all. A byte-for-byte capture of a real browser is refused
// too, one time out of six, so an imperfect copy is not a defect here - it
// is the reason the client connects.
constexpr auto kWithheldReason
	= "measured refused: 3/12 answered on a filtered network, 12/12 for "
	"every profile whose last extension is not a GREASE one carrying a zero "
	"byte, on the same relay in the same minutes";

constexpr auto kProfiles = std::array{
	// First entry is also what an unknown value falls back to, so the
	// default stands at the front. Deliberately not aligned to the real
	// Yandex Browser capture: that capture is refused where this template is
	// answered, see kWithheldReason and client_hello_rules.cpp.
	ClientHelloProfileInfo{
		.profile = ProxyTlsProfile::Yandex,
		.id = "yandex",
		.validation = ClientHelloProfileValidation::Claimed,
	},
	ClientHelloProfileInfo{
		.profile = ProxyTlsProfile::ChromeModern,
		.id = "chrome_modern",
		.validation = ClientHelloProfileValidation::Validated,
		.captureSource = "local_chrome_headless_capture",
		.captureVersion = "Google Chrome 149.0.7827.155",
		.expectedJa4 = "t13d1516h2_8daaf6152771_d8a2da3f94cd",
		.withheld = true,
		.withheldReason = kWithheldReason,
	},
	ClientHelloProfileInfo{
		.profile = ProxyTlsProfile::AndroidChrome,
		.id = "android_chrome",
		.validation = ClientHelloProfileValidation::Claimed,
		.withheld = true,
		.withheldReason = kWithheldReason,
	},
	ClientHelloProfileInfo{
		.profile = ProxyTlsProfile::Firefox,
		.id = "firefox",
		.validation = ClientHelloProfileValidation::Claimed,
	},
	ClientHelloProfileInfo{
		.profile = ProxyTlsProfile::FirefoxAndroid,
		.id = "firefox_android",
		.validation = ClientHelloProfileValidation::Claimed,
	},
	ClientHelloProfileInfo{
		.profile = ProxyTlsProfile::AndroidOkHttp,
		.id = "android_okhttp",
		.validation = ClientHelloProfileValidation::Claimed,
	},
};

} // namespace

const ClientHelloProfileInfo &ClientHelloProfile(ProxyTlsProfile profile) {
	const auto normalized = (profile == ProxyTlsProfile::Auto
		|| profile == ProxyTlsProfile::AutoRotate)
		? DefaultClientHelloProfile()
		: profile;
	for (const auto &info : kProfiles) {
		if (info.profile == normalized) {
			return info;
		}
	}
	return kProfiles[0];
}

ProxyTlsProfile EffectiveClientHelloProfile(ProxyTlsProfile profile) {
	const auto &info = ClientHelloProfile(profile);
	return info.withheld ? DefaultClientHelloProfile() : info.profile;
}

ProxyTlsProfile DefaultClientHelloProfile() {
	// Yandex over the Chrome templates: both answer everywhere the client was
	// measured, and this one is not the shape a filtered network refuses.
	return ProxyTlsProfile::Yandex;
}

bool IsClientHelloProfileValidated(ProxyTlsProfile profile) {
	return ClientHelloProfile(profile).validation
		== ClientHelloProfileValidation::Validated;
}

} // namespace MTP::details

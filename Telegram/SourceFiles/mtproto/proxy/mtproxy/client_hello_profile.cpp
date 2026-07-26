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
// answered in under fifty milliseconds. On a filtered one the four without
// extension permutation are answered twelve times out of twelve, while the
// two that permute their extensions on every hello - chrome_modern and
// android_chrome - are answered three times out of twelve and otherwise get
// silence, on the same relay, with the same secret, in the same minutes. The
// post-quantum key share is not what is being refused: three of the four
// that pass carry it too. Permutation is the only structural trait the two
// refused ones share and the others lack.
constexpr auto kWithheldReason
	= "measured refused: 3/12 answered on a filtered network, 12/12 for "
	"every non-permuting profile on the same relay";

constexpr auto kProfiles = std::array{
	// First entry is also what an unknown value falls back to, so the
	// default stands at the front.
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

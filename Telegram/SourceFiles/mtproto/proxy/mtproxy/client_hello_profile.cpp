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

constexpr auto kProfiles = std::array{
	ClientHelloProfileInfo{
		.profile = ProxyTlsProfile::ChromeModern,
		.id = "chrome_modern",
		.validation = ClientHelloProfileValidation::Validated,
		.captureSource = "local_chrome_headless_capture",
		.captureVersion = "Google Chrome 149.0.7827.155",
		.expectedJa4 = "t13d1516h2_8daaf6152771_d8a2da3f94cd",
	},
	ClientHelloProfileInfo{
		.profile = ProxyTlsProfile::AndroidChrome,
		.id = "android_chrome",
		.validation = ClientHelloProfileValidation::Claimed,
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
		.profile = ProxyTlsProfile::Yandex,
		.id = "yandex",
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

ProxyTlsProfile DefaultClientHelloProfile() {
	return ProxyTlsProfile::ChromeModern;
}

bool IsClientHelloProfileValidated(ProxyTlsProfile profile) {
	return ClientHelloProfile(profile).validation
		== ClientHelloProfileValidation::Validated;
}

} // namespace MTP::details

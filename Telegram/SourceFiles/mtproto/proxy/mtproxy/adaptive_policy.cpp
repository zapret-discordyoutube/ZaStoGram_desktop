/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/proxy/mtproxy/adaptive_policy.h"

#include "mtproto/proxy/mtproxy/client_hello_profile.h"
#include "base/timer.h"

#include <QtCore/QMutex>

#include <iterator>
#include <map>

namespace MTP::details {
namespace {

constexpr ProxyTlsProfile kAutoRotateCandidatePool[] = {
	ProxyTlsProfile::FirefoxAndroid,
	ProxyTlsProfile::AndroidChrome,
	ProxyTlsProfile::Yandex,
	ProxyTlsProfile::ChromeModern,
};
constexpr auto kAutoRotateFailureThreshold = 2;
constexpr auto kAutoRotateMinDwell = crl::time(60 * 1000);

struct AutoProfileState {
	int profileIndex = -1;
	uint32 failures = 0;
	uint32 profileFailures = 0;
	crl::time profileChangedAt = 0;
};

QMutex AutoProfilesMutex;
std::map<QString, AutoProfileState> AutoProfiles; // Guarded by the mutex.

[[nodiscard]] int AutoRotatePoolSize() {
	return int(std::size(kAutoRotateCandidatePool));
}

[[nodiscard]] ProxyTlsProfile KnownClientHelloProfile(
		ProxyTlsProfile profile) {
	const auto &info = ClientHelloProfile(profile);
	return (info.profile == profile)
		? info.profile
		: DefaultClientHelloProfile();
}

[[nodiscard]] ProxyTlsProfile AutoRotatePoolProfile(int index) {
	const auto size = AutoRotatePoolSize();
	const auto normalized = (index % size + size) % size;
	return KnownClientHelloProfile(kAutoRotateCandidatePool[normalized]);
}

[[nodiscard]] int AutoRotateInitialIndex(const QString &key) {
	auto hash = quint64(0xcbf29ce484222325ULL);
	for (const auto byte : key.toUtf8()) {
		hash ^= quint8(byte);
		hash *= 0x100000001b3ULL;
	}
	return int(hash % AutoRotatePoolSize());
}

[[nodiscard]] bool IsLightConnectionPattern(ProxyConnectionPattern pattern) {
	return (pattern == ProxyConnectionPattern::Soft)
		|| (pattern == ProxyConnectionPattern::Browser);
}

} // namespace

bool FailureNeedsRecipe(const QString &diagnostic) {
	if (diagnostic == u"tcp_not_connected"_q) {
		return false;
	}
	return (diagnostic == u"client_hello_sent_no_server_hello"_q)
		|| (diagnostic == u"tls_alert_after_client_hello"_q)
		|| (diagnostic == u"short_tls_response_after_client_hello"_q)
		|| (diagnostic == u"unrecognized_tls_response_after_client_hello"_q)
		|| (diagnostic == u"server_hello_hmac_mismatch"_q)
		|| (diagnostic == u"post_handshake_no_appdata"_q);
}

ProxyTlsProfile CompatibilityTlsProfile(
		ProxyTlsProfile effective,
		int recipeLevel) {
	if (recipeLevel <= 1) {
		return effective;
	} else if (recipeLevel == 2) {
		const auto candidate = (effective == ProxyTlsProfile::FirefoxAndroid)
			? ProxyTlsProfile::AndroidChrome
			: ProxyTlsProfile::FirefoxAndroid;
		return KnownClientHelloProfile(candidate);
	} else if (recipeLevel == 3) {
		const auto candidate = (effective == ProxyTlsProfile::AndroidChrome)
			? ProxyTlsProfile::Yandex
			: ProxyTlsProfile::AndroidChrome;
		return KnownClientHelloProfile(candidate);
	}
	const auto candidate = (effective == ProxyTlsProfile::Yandex)
		? ProxyTlsProfile::Firefox
		: ProxyTlsProfile::Yandex;
	return KnownClientHelloProfile(candidate);
}

AdaptiveRecipeResult ApplyAdaptiveRecipe(const AdaptiveRecipeInput &input) {
	auto result = AdaptiveRecipeResult();
	result.stealth = input.stealth;
	if (input.endpointKey.isEmpty() || input.recipeLevel <= 0) {
		return result;
	}
	auto &stealth = result.stealth;
	const auto autoProfile = (input.configuredTlsProfile == ProxyTlsProfile::Auto)
		|| (input.configuredTlsProfile == ProxyTlsProfile::AutoRotate);

	if (input.lastDiagnostic == u"post_handshake_no_appdata"_q) {
		if (stealth.recordSizing == ProxyRecordSizing::Off) {
			stealth.recordSizing = ProxyRecordSizing::Conservative;
			result.changed = true;
		}
		if (stealth.startupCover == ProxyStartupCover::Off) {
			stealth.startupCover = ProxyStartupCover::Soft;
			result.changed = true;
		}
		if (input.recipeLevel >= 2
			&& stealth.connectionPattern != ProxyConnectionPattern::Strict
			&& IsLightConnectionPattern(stealth.connectionPattern)) {
			stealth.connectionPattern = ProxyConnectionPattern::Quiet;
			result.changed = true;
		}
		return result;
	}

	if (input.recipeLevel >= 1
		&& stealth.clientHelloFragmentation
			!= ProxyClientHelloFragmentation::Off) {
		stealth.clientHelloFragmentation = ProxyClientHelloFragmentation::Off;
		result.changed = true;
	}
	if (input.recipeLevel >= 2 && autoProfile) {
		const auto previous = stealth.tlsProfile;
		stealth.tlsProfile = CompatibilityTlsProfile(
			input.effectiveTlsProfile,
			input.recipeLevel);
		if (stealth.tlsProfile != previous) {
			result.changed = true;
		}
	}
	if (input.recipeLevel >= 4
		&& stealth.connectionPattern != ProxyConnectionPattern::Strict
		&& IsLightConnectionPattern(stealth.connectionPattern)) {
		stealth.connectionPattern = ProxyConnectionPattern::Quiet;
		result.changed = true;
	}
	return result;
}

ProxyTlsProfile ResolveEffectiveTlsProfile(
		ProxyTlsProfile profile,
		const QString &endpointKey) {
	if (profile != ProxyTlsProfile::AutoRotate) {
		// Auto is a valid profile here (Chrome-style permutation in
		// PrepareClientHelloRules); only AutoRotate needs resolving.
		return profile;
	}
	QMutexLocker lock(&AutoProfilesMutex);
	auto &state = AutoProfiles[endpointKey];
	if (state.profileIndex < 0) {
		state.profileIndex = AutoRotateInitialIndex(endpointKey);
		state.profileChangedAt = crl::now();
	}
	return AutoRotatePoolProfile(state.profileIndex);
}

ProxyTlsProfile RotateTlsProfileOnFailure(
		const QString &endpointKey,
		const QString &diagnostic,
		ProxyTlsProfile previous) {
	if (endpointKey.isEmpty() || !FailureNeedsRecipe(diagnostic)) {
		return previous;
	}
	QMutexLocker lock(&AutoProfilesMutex);
	auto &state = AutoProfiles[endpointKey];
	if (state.profileIndex < 0) {
		state.profileIndex = AutoRotateInitialIndex(endpointKey);
		state.profileChangedAt = crl::now();
	}
	++state.failures;
	++state.profileFailures;
	const auto now = crl::now();
	if (state.profileFailures < kAutoRotateFailureThreshold
		|| (state.profileChangedAt
			&& now - state.profileChangedAt < kAutoRotateMinDwell)) {
		return previous;
	}
	state.profileFailures = 0;
	state.profileChangedAt = now;
	state.profileIndex = (state.profileIndex + 1) % AutoRotatePoolSize();
	return AutoRotatePoolProfile(state.profileIndex);
}

} // namespace MTP::details

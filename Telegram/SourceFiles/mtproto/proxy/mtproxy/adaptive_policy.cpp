/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/proxy/mtproxy/adaptive_policy.h"

#include <QtCore/QMutex>

#include <map>

namespace MTP::details {
namespace {

// Pool used for AutoRotate and for compatibility rotation cursors. Mirrors
// the Android fork's autoRotatePoolProfile order.
constexpr ProxyTlsProfile kAutoRotatePool[] = {
	ProxyTlsProfile::FirefoxAndroid,
	ProxyTlsProfile::Yandex,
	ProxyTlsProfile::ChromeModern,
};
constexpr auto kAutoRotatePoolSize = int(std::size(kAutoRotatePool));

struct AutoProfileState {
	int profileIndex = -1;
	uint32 failures = 0;
	int recipeLevel = 0;
	QString lastDiagnostic;
};

QMutex AutoProfilesMutex;
std::map<QString, AutoProfileState> AutoProfiles; // Guarded by the mutex.

[[nodiscard]] int AutoRotateInitialIndex(const QString &key) {
	// FNV-1a over the endpoint key, deterministic per endpoint.
	auto hash = quint64(0xcbf29ce484222325ULL);
	for (const auto byte : key.toUtf8()) {
		hash ^= quint8(byte);
		hash *= 0x100000001b3ULL;
	}
	return int(hash % kAutoRotatePoolSize);
}

[[nodiscard]] bool IsLightConnectionPattern(ProxyConnectionPattern pattern) {
	return (pattern == ProxyConnectionPattern::Off)
		|| (pattern == ProxyConnectionPattern::Soft)
		|| (pattern == ProxyConnectionPattern::Browser);
}

} // namespace

bool FailureNeedsRecipe(const QString &diagnostic) {
	if (diagnostic == u"tcp_not_connected"_q) {
		// ClientHello was not sent, so JA4 did not cause this failure.
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
		return (effective == ProxyTlsProfile::FirefoxAndroid)
			? ProxyTlsProfile::AndroidChrome
			: ProxyTlsProfile::FirefoxAndroid;
	} else if (recipeLevel == 3) {
		return (effective == ProxyTlsProfile::AndroidChrome)
			? ProxyTlsProfile::Yandex
			: ProxyTlsProfile::AndroidChrome;
	}
	return (effective == ProxyTlsProfile::Yandex)
		? ProxyTlsProfile::Firefox
		: ProxyTlsProfile::Yandex;
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
		// Handshake completed but no application data arrived: cover the
		// post-handshake traffic shape rather than touching the JA4.
		if (stealth.recordSizing == ProxyRecordSizing::Off) {
			stealth.recordSizing = ProxyRecordSizing::Conservative;
			result.changed = true;
		}
		if (stealth.timing == ProxyTiming::Off) {
			stealth.timing = ProxyTiming::Gentle;
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

	// Failures before/at the ServerHello stage: the ClientHello shape itself
	// is suspect, so simplify it and rotate the profile.
	if (input.recipeLevel >= 1
		&& stealth.clientHelloFragmentation
			!= ProxyClientHelloFragmentation::Off) {
		stealth.clientHelloFragmentation = ProxyClientHelloFragmentation::Off;
		result.changed = true;
	}
	if (input.recipeLevel >= 2 && autoProfile) {
		const auto previous = stealth.tlsProfile;
		stealth.tlsProfile = CompatibilityTlsProfile(
			stealth.tlsProfile,
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
	}
	return kAutoRotatePool[state.profileIndex % kAutoRotatePoolSize];
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
	}
	state.profileIndex = (state.profileIndex + 1) % kAutoRotatePoolSize;
	++state.failures;
	return kAutoRotatePool[state.profileIndex];
}

int EndpointRecipeLevel(const QString &endpointKey) {
	if (endpointKey.isEmpty()) {
		return 0;
	}
	QMutexLocker lock(&AutoProfilesMutex);
	const auto i = AutoProfiles.find(endpointKey);
	return (i != AutoProfiles.end()) ? i->second.recipeLevel : 0;
}

QString EndpointLastDiagnostic(const QString &endpointKey) {
	if (endpointKey.isEmpty()) {
		return QString();
	}
	QMutexLocker lock(&AutoProfilesMutex);
	const auto i = AutoProfiles.find(endpointKey);
	return (i != AutoProfiles.end()) ? i->second.lastDiagnostic : QString();
}

void NoteEndpointFailure(
		const QString &endpointKey,
		const QString &diagnostic) {
	if (endpointKey.isEmpty() || !FailureNeedsRecipe(diagnostic)) {
		return;
	}
	QMutexLocker lock(&AutoProfilesMutex);
	auto &state = AutoProfiles[endpointKey];
	state.lastDiagnostic = diagnostic;
	if (state.recipeLevel < 4) {
		++state.recipeLevel;
	}
}

void NoteEndpointSuccess(const QString &endpointKey) {
	if (endpointKey.isEmpty()) {
		return;
	}
	QMutexLocker lock(&AutoProfilesMutex);
	const auto i = AutoProfiles.find(endpointKey);
	if (i != AutoProfiles.end()) {
		i->second.recipeLevel = 0;
		i->second.lastDiagnostic.clear();
	}
}

int CooldownMsForEndpoint(const QString &endpointKey) {
	const auto diagnostic = EndpointLastDiagnostic(endpointKey);
	if (diagnostic == u"post_handshake_no_appdata"_q) {
		return 20000;
	} else if (diagnostic == u"server_hello_hmac_mismatch"_q
		|| diagnostic == u"client_hello_sent_no_server_hello"_q
		|| diagnostic == u"tls_alert_after_client_hello"_q
		|| diagnostic == u"short_tls_response_after_client_hello"_q
		|| diagnostic == u"unrecognized_tls_response_after_client_hello"_q) {
		return 15000;
	}
	return 10000;
}

} // namespace MTP::details

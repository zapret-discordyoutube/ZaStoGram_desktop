/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "mtproto/mtproto_proxy_data.h"

namespace MTP::details {

// Adaptive MTProxy "recipe" engine, ported from the Android ZaStoGram fork
// (jni/tgnet/MtProxyAdaptivePolicy). Given a per-endpoint failure diagnostic
// and an escalation level, it nudges the FakeTLS stealth knobs (record
// sizing, timing, startup cover, ClientHello fragmentation, connection
// pattern and the TLS profile) toward a more DPI-compatible shape. Pure
// logic + a small per-endpoint rotation cursor; no I/O, host-testable.

struct AdaptiveRecipeInput {
	QString endpointKey;
	QString lastDiagnostic;
	int recipeLevel = 0;
	ProxyTlsProfile configuredTlsProfile = ProxyTlsProfile::Auto;
	ProxyStealthOptions stealth;
};

struct AdaptiveRecipeResult {
	bool changed = false;
	ProxyStealthOptions stealth;
};

// Escalates the stealth knobs in `input.stealth` according to the last
// diagnostic and recipe level. The tlsProfile is only rotated when the
// user's configured profile is Auto/AutoRotate (an explicit JA4 choice is
// never overridden).
[[nodiscard]] AdaptiveRecipeResult ApplyAdaptiveRecipe(
	const AdaptiveRecipeInput &input);

// Resolves AutoRotate -> a per-endpoint rotating pool member; passes any
// other profile (including Auto) through unchanged.
[[nodiscard]] ProxyTlsProfile ResolveEffectiveTlsProfile(
	ProxyTlsProfile profile,
	const QString &endpointKey);

// Advances the per-endpoint rotation cursor on a JA4-relevant failure and
// returns the next profile to try; returns `previous` unchanged otherwise.
[[nodiscard]] ProxyTlsProfile RotateTlsProfileOnFailure(
	const QString &endpointKey,
	const QString &diagnostic,
	ProxyTlsProfile previous);

// Whether a diagnostic indicates the ClientHello/JA4 shape may be the cause
// (and is therefore worth escalating the recipe / rotating the profile).
[[nodiscard]] bool FailureNeedsRecipe(const QString &diagnostic);

// Per-level compatibility rotation between known-good profiles.
[[nodiscard]] ProxyTlsProfile CompatibilityTlsProfile(
	ProxyTlsProfile effective,
	int recipeLevel);

} // namespace MTP::details

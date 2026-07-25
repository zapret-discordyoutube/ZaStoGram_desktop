/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "base/const_string.h"

#define TDESKTOP_REQUESTED_ALPHA_VERSION (0ULL)

#ifdef TDESKTOP_ALLOW_CLOSED_ALPHA
#define TDESKTOP_ALPHA_VERSION TDESKTOP_REQUESTED_ALPHA_VERSION
#else // TDESKTOP_ALLOW_CLOSED_ALPHA
#define TDESKTOP_ALPHA_VERSION (0ULL)
#endif // TDESKTOP_ALLOW_CLOSED_ALPHA

// used in Updater.cpp and Setup.iss for Windows
constexpr auto AppId = "{53F49750-6209-4FBF-9CA8-7A333C87D1ED}"_cs;
constexpr auto AppNameOld = "Telegram Win (Unofficial)"_cs;
constexpr auto AppName = "ZaStoGram"_cs;
constexpr auto AppFile = "Telegram"_cs;
constexpr auto AppVersion = 7000005;
constexpr auto AppVersionStr = "7.0.5";
// ZaStoGram ships stable-only releases: keep AppBetaVersion = false even when
// upstream version-bump commits ("Beta version X.Y.Z") flip it during merges.
constexpr auto AppBetaVersion = false;
constexpr auto AppAlphaVersion = TDESKTOP_ALPHA_VERSION;

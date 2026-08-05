/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "base/const_string.h"

// ZaStoGram build identity, baked in by CI right before the build.
//
// CI gives every binary a channel-qualified run number: "stable-<run number>"
// for a tagged release and "dev-<run number>" for a pre-release. The dev
// number also drives same-AppVersion in-app updates. The local release helper
// uses "dev-0-<commit>" so local packages are identifiable and follow dev.
//
// The "Bake ZaStoGram build id." step in .github/workflows/win.yml rewrites the
// line below, so keep it on one line and keep this header trivial to include:
// only boxes/about_box.cpp does, so a new build id costs one translation unit
// instead of a full rebuild.
constexpr auto ZsgBuildId = ""_cs;

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
// A tagged stable release is already fully described by AppVersionStr, so it
// keeps the id empty. A pre-release built from `dev` gets "dev-<run number>",
// which is exactly the name of the GitHub release the binary was downloaded
// from, so an installed build can be traced back to its commit. A local build
// keeps whatever is committed here.
//
// The "Bake ZaStoGram build id." step in .github/workflows/win.yml rewrites the
// line below, so keep it on one line and keep this header trivial to include:
// only boxes/about_box.cpp does, so a new build id costs one translation unit
// instead of a full rebuild.
constexpr auto ZsgBuildId = ""_cs;

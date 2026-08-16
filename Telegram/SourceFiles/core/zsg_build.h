/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information see the local LEGAL file.
*/
#pragma once

#include "base/const_string.h"

// ZaStoGram build identity, baked in by CI right before the build.
//
// CI gives every binary a channel-qualified run number: "stable-<run number>"
// for a tagged release and "dev-<run number>" for a pre-release. The dev
// number also drives same-AppVersion in-app updates. The local release helper
// allocates the next Forgejo dev number and publishes the matching manifest.
//
// The local Windows release publisher rewrites the line below, so keep it on
// one line and keep this header trivial to include:
// only boxes/about_box.cpp does, so a new build id costs one translation unit
// instead of a full rebuild.
constexpr auto ZsgBuildId = ""_cs;

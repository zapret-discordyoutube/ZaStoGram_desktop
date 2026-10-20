/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information see the local LEGAL file.
*/
#pragma once

#include "base/basic_types.h"

class QUrl;

namespace Core::ZsgMirrors {

// git.zapret.moe is dropped by name inside Russia, so the updater has to be
// able to reach the same Forgejo through its numbered mirrors (git2, git3...).
// Names come from three places, in this order: the host that worked last
// time, the list the mirror controller publishes at /_sites/mirrors.json
// (cached in tdata after every successful check) and the built-in names.

// Is this host one of the git mirrors that may stand in for another one?
[[nodiscard]] bool IsGitHost(const QString &host);

// Candidates in the order they should be tried, at most a few of them.
[[nodiscard]] QStringList Hosts();

// The same URL on another host; URLs of other sites stay as they are.
[[nodiscard]] QString WithHost(const QString &url, const QString &host);
[[nodiscard]] QUrl WithHost(const QUrl &url, const QString &host);

// Remembers the host that answered and refreshes the mirror list from it.
void RememberGood(const QString &host);

// Parses /_sites/mirrors.json: usable names, the preferred one first.
[[nodiscard]] QStringList ParseNames(const QByteArray &json);

} // namespace Core::ZsgMirrors

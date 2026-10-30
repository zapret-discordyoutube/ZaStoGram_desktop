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
// able to reach the same Forgejo through its mirrors: numbered (git2, git3...)
// and, since 2026-10-30, random labels, which are the names handed out.
// Names come from three places, in this order: the host that worked last
// time, the list the mirror controller publishes at /_sites/mirrors.json
// (cached in tdata after every successful check) and the built-in names.
// When all of them are silent, the names come from the project's entry
// pages on big platforms (Apps Script, gist; schema 1, families.git.hosts),
// the same lists ZapretGUI and Zapret KVN read.

// Is this host one of the git mirrors that may stand in for another one?
// Any *.zapret.moe name except another site's numbered names (wiki2...):
// names are accepted only from the lists above, never from elsewhere.
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

// Parses an entry page: the git names, in its order.
[[nodiscard]] QStringList ParseEntry(const QByteArray &json);

// Asks the entry pages one after another; the first one that gives names
// not in `tried` is remembered and passed to `done` (empty if none did).
void FetchEntryNames(QStringList tried, Fn<void(QStringList)> done);

} // namespace Core::ZsgMirrors

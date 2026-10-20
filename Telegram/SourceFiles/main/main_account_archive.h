/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "base/basic_types.h"

namespace Main {

class Session;

// Local copy of an account that Telegram is about to take away (deleted,
// banned, frozen or terminated). Desktop keeps no message database on disk,
// so the copy is written from what the session holds in memory right now:
// the chat list, the loaded history, links and the downloaded files.
// A "live" mirror of the same data is refreshed in the background, so the
// copy exists even when the account is lost while the app is closed.
namespace AccountArchive {

enum class Reason {
	ForcedLogout,
	Frozen,
	Manual,
	Live,
};

[[nodiscard]] QString RootPath();

// Writes the copy synchronously (only right before a logout wipes the
// session), returns the folder or an empty string.
QString Save(not_null<Session*> session, Reason reason);

// Collects in short slices and writes in the background, so the window never
// stalls; `done` gets the folder (empty when nothing was saved or it is busy).
void SaveAsync(
	not_null<Session*> session,
	Reason reason,
	Fn<void(QString)> done);

// Starts the periodic "live" mirror of the session.
void Watch(not_null<Session*> session);

// Saves a copy once per freeze (called when the app config says "frozen").
void SaveFrozenOnce(not_null<Session*> session, TimeId since);

// Remembers where the copy went; it is shown once the logout has finished.
void SetPending(const QString &folder, Reason reason);
void NotifyPending();

[[nodiscard]] bool HasUnseen();
void MarkSeen();

} // namespace AccountArchive
} // namespace Main

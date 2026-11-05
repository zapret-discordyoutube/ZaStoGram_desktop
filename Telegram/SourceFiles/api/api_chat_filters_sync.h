/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "base/timer.h"
#include "base/weak_ptr.h"

namespace Data {
class LocalFolders;
} // namespace Data

namespace Main {
class Session;
} // namespace Main

namespace MTP {
class Error;
} // namespace MTP

namespace Api {

// Synchronizes ZaStoGram's own folders between devices through Saved
// Messages. The data is the canonical JSON of Data::LocalFolders
// (serializeForSync), compressed with qCompress (a 4 byte big-endian length
// and a zlib stream), base64 encoded and split into text messages of at most
// kChunkChars characters. Each message is
//
//   ZSG-FOLDERS v1 <rev> <index>/<count>\n<base64 part>
//
// where <rev> is the same for all parts of one version and <index> starts
// from 1. A reader takes the newest complete version. The parts are edited in
// place when the data changes, so the chat does not fill with messages.
class LocalFoldersSync final : public base::has_weak_ptr {
public:
	LocalFoldersSync(
		not_null<Main::Session*> session,
		not_null<Data::LocalFolders*> folders);

private:
	void schedule(crl::time delay);
	void sync();
	void finish();
	void fail(const MTP::Error &error);
	void gotMessages(const std::vector<std::pair<int32, QString>> &messages);
	void notify(const QString &text);

	const not_null<Main::Session*> _session;
	const not_null<Data::LocalFolders*> _folders;
	base::Timer _timer;
	base::Timer _poll;
	rpl::lifetime _lifetime;
	bool _syncing = false;
	bool _dirty = false;
	bool _muted = false;
	int _incompleteRetries = 0;
	int _notifiedTooLargeKb = 0;

};

} // namespace Api

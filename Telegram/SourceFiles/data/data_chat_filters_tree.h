/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "base/flat_set.h"
#include "data/data_chat_filters.h"
#include "data/data_peer_id.h"
#include "data/data_types.h"

#include <rpl/event_stream.h>

#include <QtCore/QByteArray>
#include <QtCore/QString>
#include <QtCore/QStringList>

namespace Data {

class Session;

// ZaStoGram's own folders. They are kept on this device (and optionally
// synchronized through Saved Messages), so they have no count limit and can
// be nested without a depth limit. Each one is shown through the ordinary
// ChatFilter machinery under a device-local id above kLocalFilterIdBase.

struct LocalFolder {
	QString uid; // Global, the same on every device.
	FilterId id = 0; // Local to this device.
	QString parentUid; // Empty for a top-level folder.
	QString title;
	QString iconEmoji;
	int order = 0; // Among siblings.
	bool sync = true;
	bool deleted = false; // A tombstone, so that sync can delete elsewhere.
	int64 rev = 0; // Milliseconds since epoch of the last change.
	base::flat_set<PeerId> own; // Chats added directly to this folder.
	std::vector<PeerId> pinned; // Pinned in this folder, in order.
};

class LocalFolders final {
public:
	explicit LocalFolders(not_null<Session*> owner);

	void load();

	[[nodiscard]] const LocalFolder *find(FilterId id) const;
	[[nodiscard]] const LocalFolder *findByUid(const QString &uid) const;

	// Alive folders: top-level ones in order, each followed by descendants.
	[[nodiscard]] std::vector<FilterId> ids() const;
	// Alive children in order, parent == 0 means the top level.
	[[nodiscard]] std::vector<FilterId> childrenOf(FilterId parent) const;
	[[nodiscard]] FilterId parentOf(FilterId id) const;
	[[nodiscard]] bool isNested(FilterId id) const;
	[[nodiscard]] int depth(FilterId id) const;
	// "Work / Clients / VIP".
	[[nodiscard]] QString pathTitle(FilterId id) const;
	// Own chats and the chats of all descendants.
	[[nodiscard]] base::flat_set<PeerId> peersOf(FilterId id) const;
	[[nodiscard]] bool contains(FilterId id, PeerId peerId) const;

	FilterId create(const QString &title, FilterId parent = 0);
	bool rename(FilterId id, const QString &title);
	bool setIcon(FilterId id, const QString &iconEmoji);
	// False when the new parent is the folder itself or its descendant.
	bool move(FilterId id, FilterId newParent);
	bool remove(FilterId id); // With all subfolders.
	bool setSync(FilterId id, bool sync);
	bool addChat(FilterId id, PeerId peerId);
	bool removeChat(FilterId id, PeerId peerId);
	// From the folder and all its subfolders (a parent shows their chats).
	bool removeChatDeep(FilterId id, PeerId peerId);
	// From every folder, for example when the chat is left.
	bool removeChatEverywhere(PeerId peerId);
	// Replaces the chats added directly to the folder.
	bool setChats(FilterId id, const base::flat_set<PeerId> &peers);
	bool setPinned(FilterId id, std::vector<PeerId> pinned);
	[[nodiscard]] std::vector<PeerId> pinnedOf(FilterId id) const;
	// Among siblings: -1 is up, +1 is down.
	bool moveBy(FilterId id, int delta);
	// Orders the top-level folders as in the list (others keep their place
	// after them).
	void reorderTop(const std::vector<FilterId> &ids);

	// The JSON format is shared with Android and with Saved Messages sync.
	[[nodiscard]] QByteArray serialize(bool syncedOnly) const;
	bool deserialize(const QByteArray &json);

	// Saved Messages sync: the canonical form has no device-local ids and a
	// fixed order, so equal states give equal bytes on every device.
	[[nodiscard]] QByteArray serializeForSync() const;
	// Per-folder newest-wins merge, local-only folders are never touched.
	// Returns true if anything changed.
	bool mergeRemote(const QByteArray &json);

	[[nodiscard]] rpl::producer<> changed() const;

private:
	[[nodiscard]] LocalFolder *findMutable(FilterId id);
	[[nodiscard]] LocalFolder *findAnyByUid(const QString &uid);
	void applySiblingOrder(const std::vector<FilterId> &ids);
	[[nodiscard]] std::vector<const LocalFolder*> childrenOfUid(
		const QString &uid) const;
	void collectSubtree(
		const QString &uid,
		std::vector<LocalFolder*> &result);
	void changedFolder(LocalFolder &folder);
	void save();

	const not_null<Session*> _owner;
	std::vector<LocalFolder> _folders;
	int _nextNumber = 0;
	bool _loaded = false;
	rpl::event_stream<> _changed;

};

} // namespace Data

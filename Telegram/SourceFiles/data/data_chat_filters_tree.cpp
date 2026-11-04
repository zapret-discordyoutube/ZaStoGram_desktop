/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "data/data_chat_filters_tree.h"

#include "data/data_session.h"
#include "main/main_session.h"
#include "storage/storage_account.h"

#include <QtCore/QDateTime>
#include <QtCore/QJsonArray>
#include <QtCore/QJsonDocument>
#include <QtCore/QJsonObject>
#include <QtCore/QUuid>

namespace Data {
namespace {

constexpr auto kFormatVersion = 1;

[[nodiscard]] int64 NowMs() {
	return int64(QDateTime::currentMSecsSinceEpoch());
}

// The same canonical form is used by the other ZaStoGram clients:
// u<id> for users, c<id> for basic groups, ch<id> for channels.
[[nodiscard]] QString PeerToString(PeerId id) {
	if (peerIsUser(id)) {
		return u"u"_q + QString::number(peerToUser(id).bare);
	} else if (peerIsChat(id)) {
		return u"c"_q + QString::number(peerToChat(id).bare);
	} else if (peerIsChannel(id)) {
		return u"ch"_q + QString::number(peerToChannel(id).bare);
	}
	return QString();
}

[[nodiscard]] PeerId PeerFromString(const QString &text) {
	const auto parse = [&](int prefix) -> BareId {
		auto ok = false;
		const auto value = text.mid(prefix).toULongLong(&ok);
		return ok ? value : 0;
	};
	if (text.startsWith(u"ch"_q)) {
		const auto bare = parse(2);
		return bare ? peerFromChannel(ChannelId(bare)) : PeerId();
	} else if (text.startsWith(u'c')) {
		const auto bare = parse(1);
		return bare ? peerFromChat(ChatId(bare)) : PeerId();
	} else if (text.startsWith(u'u')) {
		const auto bare = parse(1);
		return bare ? peerFromUser(UserId(bare)) : PeerId();
	}
	return PeerId();
}

[[nodiscard]] QJsonObject FolderToJson(const LocalFolder &folder, bool withId) {
	auto peers = QStringList();
	for (const auto peerId : folder.own) {
		const auto text = PeerToString(peerId);
		if (!text.isEmpty()) {
			peers.push_back(text);
		}
	}
	peers.sort(); // Stable bytes for sync.
	auto peersJson = QJsonArray();
	for (const auto &text : peers) {
		peersJson.push_back(text);
	}
	auto pinnedJson = QJsonArray();
	for (const auto peerId : folder.pinned) {
		const auto text = PeerToString(peerId);
		if (!text.isEmpty()) {
			pinnedJson.push_back(text);
		}
	}
	auto object = QJsonObject();
	object.insert(u"uid"_q, folder.uid);
	if (withId) {
		object.insert(u"id"_q, int(folder.id));
	}
	object.insert(u"parent"_q, folder.parentUid);
	object.insert(u"title"_q, folder.title);
	object.insert(u"icon"_q, folder.iconEmoji);
	object.insert(u"order"_q, folder.order);
	object.insert(u"sync"_q, folder.sync);
	object.insert(u"deleted"_q, folder.deleted);
	object.insert(u"rev"_q, double(folder.rev));
	object.insert(u"peers"_q, peersJson);
	object.insert(u"pinned"_q, pinnedJson);
	return object;
}

[[nodiscard]] LocalFolder FolderFromJson(const QJsonObject &object) {
	auto folder = LocalFolder();
	folder.uid = object.value(u"uid"_q).toString();
	folder.id = FilterId(object.value(u"id"_q).toInt());
	folder.parentUid = object.value(u"parent"_q).toString();
	folder.title = object.value(u"title"_q).toString();
	folder.iconEmoji = object.value(u"icon"_q).toString();
	folder.order = object.value(u"order"_q).toInt();
	folder.sync = object.value(u"sync"_q).toBool(true);
	folder.deleted = object.value(u"deleted"_q).toBool();
	folder.rev = int64(object.value(u"rev"_q).toDouble());
	for (const auto &peer : object.value(u"peers"_q).toArray()) {
		if (const auto peerId = PeerFromString(peer.toString())) {
			folder.own.emplace(peerId);
		}
	}
	for (const auto &peer : object.value(u"pinned"_q).toArray()) {
		if (const auto peerId = PeerFromString(peer.toString())) {
			folder.pinned.push_back(peerId);
		}
	}
	return folder;
}

[[nodiscard]] bool ParseRoot(
		const QByteArray &json,
		std::vector<LocalFolder> &folders,
		int &next) {
	auto error = QJsonParseError();
	const auto document = QJsonDocument::fromJson(json, &error);
	if (error.error != QJsonParseError::NoError || !document.isObject()) {
		return false;
	}
	const auto root = document.object();
	if (root.value(u"v"_q).toInt() != kFormatVersion) {
		return false;
	}
	next = root.value(u"next"_q).toInt();
	for (const auto &value : root.value(u"folders"_q).toArray()) {
		auto folder = FolderFromJson(value.toObject());
		if (!folder.uid.isEmpty()) {
			folders.push_back(std::move(folder));
		}
	}
	return true;
}

} // namespace

LocalFolders::LocalFolders(not_null<Session*> owner)
: _owner(owner) {
}

void LocalFolders::load() {
	if (_loaded) {
		return;
	}
	_loaded = true;
	const auto json = _owner->session().local().readZsgFolders();
	if (json.isEmpty()) {
		return;
	}
	if (deserialize(json)) {
		_changed.fire({});
	}
}

const LocalFolder *LocalFolders::find(FilterId id) const {
	for (const auto &folder : _folders) {
		if (folder.id == id && !folder.deleted) {
			return &folder;
		}
	}
	return nullptr;
}

LocalFolder *LocalFolders::findMutable(FilterId id) {
	return const_cast<LocalFolder*>(std::as_const(*this).find(id));
}

const LocalFolder *LocalFolders::findByUid(const QString &uid) const {
	for (const auto &folder : _folders) {
		if (folder.uid == uid && !folder.deleted) {
			return &folder;
		}
	}
	return nullptr;
}

std::vector<const LocalFolder*> LocalFolders::childrenOfUid(
		const QString &uid) const {
	auto result = std::vector<const LocalFolder*>();
	for (const auto &folder : _folders) {
		if (folder.deleted) {
			continue;
		}
		const auto orphan = !folder.parentUid.isEmpty()
			&& !findByUid(folder.parentUid);
		if (folder.parentUid == uid || (uid.isEmpty() && orphan)) {
			result.push_back(&folder);
		}
	}
	ranges::sort(result, [](const LocalFolder *a, const LocalFolder *b) {
		return (a->order != b->order)
			? (a->order < b->order)
			: (a->uid < b->uid);
	});
	return result;
}

std::vector<FilterId> LocalFolders::childrenOf(FilterId parent) const {
	auto uid = QString();
	if (parent) {
		const auto folder = find(parent);
		if (!folder) {
			return {};
		}
		uid = folder->uid;
	}
	auto result = std::vector<FilterId>();
	for (const auto child : childrenOfUid(uid)) {
		result.push_back(child->id);
	}
	return result;
}

std::vector<FilterId> LocalFolders::ids() const {
	auto result = std::vector<FilterId>();
	const auto walk = [&](const auto &self, const QString &uid) -> void {
		for (const auto child : childrenOfUid(uid)) {
			result.push_back(child->id);
			self(self, child->uid);
		}
	};
	walk(walk, QString());
	return result;
}

FilterId LocalFolders::parentOf(FilterId id) const {
	const auto folder = find(id);
	if (!folder || folder->parentUid.isEmpty()) {
		return 0;
	}
	const auto parent = findByUid(folder->parentUid);
	return parent ? parent->id : 0;
}

bool LocalFolders::isNested(FilterId id) const {
	return parentOf(id) != 0;
}

int LocalFolders::depth(FilterId id) const {
	auto result = 0;
	// A guard against a corrupted cycle: a tree is never deeper than this.
	for (auto parent = parentOf(id); parent; parent = parentOf(parent)) {
		if (++result > int(_folders.size())) {
			break;
		}
	}
	return result;
}

QString LocalFolders::pathTitle(FilterId id) const {
	auto parts = QStringList();
	auto current = id;
	for (auto guard = 0; current && guard <= int(_folders.size()); ++guard) {
		const auto folder = find(current);
		if (!folder) {
			break;
		}
		parts.push_front(folder->title);
		current = parentOf(current);
	}
	return parts.join(u" / "_q);
}

base::flat_set<PeerId> LocalFolders::peersOf(FilterId id) const {
	auto result = base::flat_set<PeerId>();
	const auto folder = find(id);
	if (!folder) {
		return result;
	}
	const auto walk = [&](const auto &self, const LocalFolder &f) -> void {
		for (const auto peerId : f.own) {
			result.emplace(peerId);
		}
		for (const auto child : childrenOfUid(f.uid)) {
			self(self, *child);
		}
	};
	walk(walk, *folder);
	return result;
}

bool LocalFolders::contains(FilterId id, PeerId peerId) const {
	const auto folder = find(id);
	return folder && folder->own.contains(peerId);
}

void LocalFolders::collectSubtree(
		const QString &uid,
		std::vector<LocalFolder*> &result) {
	for (auto &folder : _folders) {
		if (!folder.deleted && folder.parentUid == uid) {
			result.push_back(&folder);
			collectSubtree(folder.uid, result);
		}
	}
}

FilterId LocalFolders::create(const QString &title, FilterId parent) {
	const auto trimmed = title.trimmed();
	if (trimmed.isEmpty()) {
		return 0;
	}
	auto parentUid = QString();
	if (parent) {
		const auto folder = find(parent);
		if (!folder) {
			return 0;
		}
		parentUid = folder->uid;
	}
	auto order = 0;
	for (const auto sibling : childrenOfUid(parentUid)) {
		order = std::max(order, sibling->order + 1);
	}
	auto folder = LocalFolder();
	folder.uid = QUuid::createUuid().toString(QUuid::WithoutBraces);
	folder.id = kLocalFilterIdBase + (++_nextNumber);
	folder.parentUid = parentUid;
	folder.title = trimmed;
	folder.order = order;
	folder.rev = NowMs();
	const auto id = folder.id;
	_folders.push_back(std::move(folder));
	save();
	_changed.fire({});
	return id;
}

void LocalFolders::changedFolder(LocalFolder &folder) {
	folder.rev = NowMs();
	save();
	_changed.fire({});
}

bool LocalFolders::rename(FilterId id, const QString &title) {
	const auto folder = findMutable(id);
	const auto trimmed = title.trimmed();
	if (!folder || trimmed.isEmpty() || folder->title == trimmed) {
		return false;
	}
	folder->title = trimmed;
	changedFolder(*folder);
	return true;
}

bool LocalFolders::setIcon(FilterId id, const QString &iconEmoji) {
	const auto folder = findMutable(id);
	if (!folder || folder->iconEmoji == iconEmoji) {
		return false;
	}
	folder->iconEmoji = iconEmoji;
	changedFolder(*folder);
	return true;
}

bool LocalFolders::move(FilterId id, FilterId newParent) {
	const auto folder = findMutable(id);
	if (!folder) {
		return false;
	}
	auto parentUid = QString();
	if (newParent) {
		if (newParent == id) {
			return false;
		}
		const auto parent = find(newParent);
		if (!parent) {
			return false;
		}
		// The new parent must not be inside the moved subtree.
		for (auto up = newParent, guard = 0;
			up && guard <= int(_folders.size());
			up = parentOf(up), ++guard) {
			if (up == id) {
				return false;
			}
		}
		parentUid = parent->uid;
	}
	if (folder->parentUid == parentUid) {
		return false;
	}
	auto order = 0;
	for (const auto sibling : childrenOfUid(parentUid)) {
		order = std::max(order, sibling->order + 1);
	}
	folder->parentUid = parentUid;
	folder->order = order;
	changedFolder(*folder);
	return true;
}

bool LocalFolders::remove(FilterId id) {
	const auto folder = findMutable(id);
	if (!folder) {
		return false;
	}
	auto subtree = std::vector<LocalFolder*>{ folder };
	collectSubtree(folder->uid, subtree);
	const auto now = NowMs();
	for (const auto entry : subtree) {
		entry->deleted = true;
		entry->own.clear();
		entry->rev = now;
	}
	save();
	_changed.fire({});
	return true;
}

bool LocalFolders::setSync(FilterId id, bool sync) {
	const auto folder = findMutable(id);
	if (!folder || folder->sync == sync) {
		return false;
	}
	folder->sync = sync;
	changedFolder(*folder);
	return true;
}

bool LocalFolders::addChat(FilterId id, PeerId peerId) {
	const auto folder = findMutable(id);
	if (!folder || !peerId || !folder->own.emplace(peerId).second) {
		return false;
	}
	changedFolder(*folder);
	return true;
}

bool LocalFolders::removeChat(FilterId id, PeerId peerId) {
	const auto folder = findMutable(id);
	if (!folder || !folder->own.remove(peerId)) {
		return false;
	}
	changedFolder(*folder);
	return true;
}

bool LocalFolders::removeChatDeep(FilterId id, PeerId peerId) {
	const auto folder = findMutable(id);
	if (!folder) {
		return false;
	}
	auto subtree = std::vector<LocalFolder*>{ folder };
	collectSubtree(folder->uid, subtree);
	auto changed = false;
	const auto now = NowMs();
	for (const auto entry : subtree) {
		if (entry->own.remove(peerId)) {
			entry->rev = now;
			changed = true;
		}
	}
	if (changed) {
		save();
		_changed.fire({});
	}
	return changed;
}

bool LocalFolders::removeChatEverywhere(PeerId peerId) {
	auto changed = false;
	const auto now = NowMs();
	for (auto &folder : _folders) {
		if (!folder.deleted && folder.own.remove(peerId)) {
			folder.rev = now;
			changed = true;
		}
	}
	if (changed) {
		save();
		_changed.fire({});
	}
	return changed;
}

QByteArray LocalFolders::serialize(bool syncedOnly) const {
	auto folders = QJsonArray();
	for (const auto &folder : _folders) {
		if (!syncedOnly || folder.sync) {
			folders.push_back(FolderToJson(folder, true));
		}
	}
	auto root = QJsonObject();
	root.insert(u"v"_q, kFormatVersion);
	root.insert(u"next"_q, _nextNumber);
	root.insert(u"folders"_q, folders);
	return QJsonDocument(root).toJson(QJsonDocument::Compact);
}

QByteArray LocalFolders::serializeForSync() const {
	auto synced = std::vector<const LocalFolder*>();
	for (const auto &folder : _folders) {
		if (folder.sync) {
			synced.push_back(&folder);
		}
	}
	ranges::sort(synced, [](const LocalFolder *a, const LocalFolder *b) {
		return a->uid < b->uid;
	});
	auto folders = QJsonArray();
	for (const auto folder : synced) {
		folders.push_back(FolderToJson(*folder, false));
	}
	auto root = QJsonObject();
	root.insert(u"v"_q, kFormatVersion);
	root.insert(u"folders"_q, folders);
	return QJsonDocument(root).toJson(QJsonDocument::Compact);
}

bool LocalFolders::deserialize(const QByteArray &json) {
	auto folders = std::vector<LocalFolder>();
	auto next = 0;
	if (!ParseRoot(json, folders, next)) {
		return false;
	}
	auto seenIds = base::flat_set<FilterId>();
	auto valid = std::vector<LocalFolder>();
	for (auto &folder : folders) {
		if (!IsLocalFilterId(folder.id) || !seenIds.emplace(folder.id).second) {
			continue;
		}
		next = std::max(next, int(folder.id - kLocalFilterIdBase));
		valid.push_back(std::move(folder));
	}
	_folders = std::move(valid);
	_nextNumber = next;
	return true;
}

LocalFolder *LocalFolders::findAnyByUid(const QString &uid) {
	for (auto &folder : _folders) {
		if (folder.uid == uid) {
			return &folder;
		}
	}
	return nullptr;
}

bool LocalFolders::mergeRemote(const QByteArray &json) {
	auto remote = std::vector<LocalFolder>();
	auto next = 0;
	if (!ParseRoot(json, remote, next)) {
		return false;
	}
	auto changed = false;
	for (auto &incoming : remote) {
		const auto folder = findAnyByUid(incoming.uid);
		if (!folder) {
			if (incoming.deleted) {
				continue; // Nothing to delete here.
			}
			incoming.id = kLocalFilterIdBase + (++_nextNumber);
			incoming.sync = true;
			_folders.push_back(std::move(incoming));
			changed = true;
		} else if (!folder->sync) {
			continue; // Local-only folders are never touched.
		} else if (incoming.rev > folder->rev) {
			folder->parentUid = incoming.parentUid;
			folder->title = incoming.title;
			folder->iconEmoji = incoming.iconEmoji;
			folder->order = incoming.order;
			folder->own = std::move(incoming.own);
			folder->pinned = std::move(incoming.pinned);
			folder->deleted = incoming.deleted;
			folder->rev = incoming.rev;
			changed = true;
		}
	}
	// Old tombstones have long been delivered everywhere.
	constexpr auto kTombstoneLifetime = int64(30) * 24 * 60 * 60 * 1000;
	const auto limit = NowMs() - kTombstoneLifetime;
	const auto before = _folders.size();
	_folders.erase(
		std::remove_if(_folders.begin(), _folders.end(), [&](
				const LocalFolder &folder) {
			return folder.deleted && folder.rev < limit;
		}),
		_folders.end());
	if (_folders.size() != before) {
		changed = true;
	}
	if (changed) {
		save();
		_changed.fire({});
	}
	return changed;
}

bool LocalFolders::setChats(
		FilterId id,
		const base::flat_set<PeerId> &peers) {
	const auto folder = findMutable(id);
	if (!folder || folder->own == peers) {
		return false;
	}
	folder->own = peers;
	changedFolder(*folder);
	return true;
}

bool LocalFolders::setPinned(FilterId id, std::vector<PeerId> pinned) {
	const auto folder = findMutable(id);
	if (!folder || folder->pinned == pinned) {
		return false;
	}
	folder->pinned = std::move(pinned);
	changedFolder(*folder);
	return true;
}

std::vector<PeerId> LocalFolders::pinnedOf(FilterId id) const {
	const auto folder = find(id);
	return folder ? folder->pinned : std::vector<PeerId>();
}

void LocalFolders::applySiblingOrder(const std::vector<FilterId> &ids) {
	auto changed = false;
	const auto now = NowMs();
	for (auto i = 0, count = int(ids.size()); i != count; ++i) {
		if (const auto folder = findMutable(ids[i])) {
			if (folder->order != i) {
				folder->order = i;
				folder->rev = now;
				changed = true;
			}
		}
	}
	if (changed) {
		save();
		_changed.fire({});
	}
}

bool LocalFolders::moveBy(FilterId id, int delta) {
	const auto folder = findMutable(id);
	if (!folder || !delta) {
		return false;
	}
	const auto parentUid = parentOf(id) ? folder->parentUid : QString();
	auto ordered = std::vector<FilterId>();
	for (const auto sibling : childrenOfUid(parentUid)) {
		ordered.push_back(sibling->id);
	}
	const auto i = ranges::find(ordered, id);
	if (i == ordered.end()) {
		return false;
	}
	const auto index = int(i - ordered.begin());
	const auto target = index + delta;
	if (target < 0 || target >= int(ordered.size())) {
		return false;
	}
	std::swap(ordered[index], ordered[target]);
	applySiblingOrder(ordered);
	return true;
}

void LocalFolders::reorderTop(const std::vector<FilterId> &ids) {
	auto ordered = std::vector<FilterId>();
	for (const auto id : ids) {
		if (find(id) && !parentOf(id) && !ranges::contains(ordered, id)) {
			ordered.push_back(id);
		}
	}
	for (const auto sibling : childrenOfUid(QString())) {
		if (!ranges::contains(ordered, sibling->id)) {
			ordered.push_back(sibling->id);
		}
	}
	applySiblingOrder(ordered);
}

void LocalFolders::save() {
	if (!_loaded) {
		return;
	}
	_owner->session().local().writeZsgFolders(serialize(false));
}

rpl::producer<> LocalFolders::changed() const {
	return _changed.events();
}

} // namespace Data

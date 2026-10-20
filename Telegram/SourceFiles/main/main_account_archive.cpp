/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "main/main_account_archive.h"

#include "base/call_delayed.h"
#include "base/timer.h"
#include "base/unixtime.h"
#include "boxes/abstract_box.h"
#include "core/application.h"
#include "core/file_utilities.h"
#include "data/data_channel.h"
#include "data/data_chat.h"
#include "data/data_document.h"
#include "data/data_folder.h"
#include "data/data_media_types.h"
#include "data/data_peer.h"
#include "data/data_photo.h"
#include "data/data_photo_media.h"
#include "data/data_session.h"
#include "data/data_user.h"
#include "dialogs/dialogs_main_list.h"
#include "dialogs/dialogs_indexed_list.h"
#include "dialogs/dialogs_row.h"
#include "history/history.h"
#include "history/history_item.h"
#include "history/view/history_view_element.h"
#include "main/main_account.h"
#include "main/main_session.h"
#include "ui/boxes/confirm_box.h"
#include "ui/image/image.h"

#include <QtCore/QDateTime>
#include <QtCore/QDir>
#include <QtCore/QFile>
#include <QtCore/QFileInfo>
#include <QtCore/QJsonArray>
#include <QtCore/QJsonDocument>
#include <QtCore/QJsonObject>
#include <QtCore/QRegularExpression>
#include <QtCore/QTextStream>
#include <QtCore/QUrl>
#include <QtGui/QDesktopServices>
#include <QtGui/QImage>

namespace Main::AccountArchive {
namespace {

constexpr auto kLiveFirstDelay = 2 * 60 * crl::time(1000);
constexpr auto kLiveInterval = 30 * 60 * crl::time(1000);
constexpr auto kBusyRetry = 20 * crl::time(1000);
// The chat list is walked in short slices so the window never stalls:
// at most kSliceBudget ms of work, then the event loop gets kSliceGap ms.
constexpr auto kSliceBudget = crl::time(6);
constexpr auto kSliceGap = crl::time(20);
constexpr auto kLiveMessages = 300;
constexpr auto kMediaBudget = int64(2) << 30;

struct PendingNotice {
	QString folder;
	Reason reason = Reason::ForcedLogout;
};
PendingNotice Pending;

struct ChatInfo {
	uint64 id = 0;
	QString title;
	QString kind;
	QString username;
	QString link;
	QString inviteLink;
	QString about;
	QString fileName;
	int messages = 0;
	int own = 0;
	int files = 0;
};

[[nodiscard]] QString Esc(const QString &text) {
	return text.toHtmlEscaped();
}

[[nodiscard]] QString Linkify(QString escaped) {
	static const auto expression = QRegularExpression(
		u"(https?://[^\\s<]+)"_q);
	return escaped.replace(expression, u"<a href=\"\\1\">\\1</a>"_q);
}

[[nodiscard]] QString ReasonText(Reason reason) {
	switch (reason) {
	case Reason::ForcedLogout:
		return u"Telegram завершил сессию (аккаунт удалён или заблокирован)"_q;
	case Reason::Frozen:
		return u"Аккаунт заморожен"_q;
	case Reason::Manual:
		return u"Сохранено вручную"_q;
	case Reason::Live:
		return u"Автоматическая копия"_q;
	}
	return QString();
}

[[nodiscard]] QString ReasonSlug(Reason reason) {
	switch (reason) {
	case Reason::ForcedLogout: return u"logout"_q;
	case Reason::Frozen: return u"frozen"_q;
	case Reason::Manual: return u"manual"_q;
	case Reason::Live: return u"live"_q;
	}
	return u"unknown"_q;
}

[[nodiscard]] bool WriteText(const QString &path, const QString &text) {
	auto file = QFile(path);
	if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
		return false;
	}
	file.write(text.toUtf8());
	return true;
}

[[nodiscard]] bool WriteJson(const QString &path, const QJsonValue &value) {
	auto file = QFile(path);
	if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
		return false;
	}
	const auto document = value.isArray()
		? QJsonDocument(value.toArray())
		: QJsonDocument(value.toObject());
	file.write(document.toJson(QJsonDocument::Indented));
	return true;
}

[[nodiscard]] QString UnseenPath() {
	return RootPath() + u"/unseen"_q;
}

[[nodiscard]] QString SafeName(QString name) {
	static const auto bad = QRegularExpression(u"[\\\\/:*?\"<>|]"_q);
	return name.replace(bad, u"_"_q);
}

[[nodiscard]] QString KindOf(not_null<PeerData*> peer) {
	if (peer->isUser()) {
		return peer->isBot() ? u"bot"_q : u"user"_q;
	} else if (peer->isChat()) {
		return u"group"_q;
	} else if (peer->isMegagroup()) {
		return u"supergroup"_q;
	} else if (peer->isChannel()) {
		return u"channel"_q;
	}
	return u"chat"_q;
}

[[nodiscard]] QString ChatLink(const ChatInfo &info, not_null<PeerData*> peer) {
	if (!info.username.isEmpty()) {
		return u"https://t.me/"_q + info.username;
	} else if (peer->isChannel()) {
		return u"https://t.me/c/"_q
			+ QString::number(peerToChannel(peer->id).bare);
	}
	return QString();
}

[[nodiscard]] QString MessageLink(
		const ChatInfo &info,
		not_null<PeerData*> peer,
		MsgId id) {
	if (peer->isUser()) {
		return QString();
	} else if (!info.username.isEmpty()) {
		return u"https://t.me/"_q + info.username
			+ '/' + QString::number(id.bare);
	} else if (peer->isChannel()) {
		return u"https://t.me/c/"_q
			+ QString::number(peerToChannel(peer->id).bare)
			+ '/' + QString::number(id.bare);
	}
	return QString();
}

constexpr auto kStyle = R"(<style>body{font:15px/1.4 sans-serif;max-width:860px;margin:0 auto;padding:16px;background:#f4f4f5;color:#111}
a{color:#2a7ae4}.m{background:#fff;border-radius:10px;padding:8px 12px;margin:8px 0;max-width:85%}.m.out{margin-left:auto;background:#e3f2fd}
.h span{color:#888;font-size:12px}.f,.d{color:#555;font-size:13px;margin-top:2px}.t{margin-top:4px;word-wrap:break-word}
table{border-collapse:collapse;width:100%;background:#fff}td,th{padding:6px 8px;border-bottom:1px solid #eee;text-align:left;vertical-align:top}
.about{white-space:pre-wrap;color:#444}</style>)";


struct Meta {
	QString userId;
	QString name;
	QString phone;
	QString username;
};

// A plain copy of what the writer needs: collecting touches the session
// on the main thread, writing the files happens on a background thread.
struct MessageRec {
	int64 id = 0;
	TimeId date = 0;
	bool out = false;
	bool deletedBySender = false;
	QString fromId;
	QString from;
	QString text;
	QString description;
	QString link;
	QString sourcePath;
	QImage photo;
};

struct ChatData {
	ChatInfo info;
	std::vector<MessageRec> messages;
};

struct Writer {
	QString folder;
	int64 budget = kMediaBudget;
};

bool Busy = false;

void CollectHistories(
		not_null<const Dialogs::MainList*> list,
		std::vector<not_null<History*>> &result,
		base::flat_set<not_null<History*>> &seen) {
	for (const auto &row : list->indexed()->all()) {
		const auto history = row->history();
		if (history && seen.emplace(history).second) {
			result.push_back(history);
		}
	}
}

[[nodiscard]] ChatInfo Describe(not_null<History*> history) {
	const auto peer = history->peer;
	auto info = ChatInfo();
	info.id = peer->id.value;
	info.title = peer->name();
	if (info.title.isEmpty()) {
		info.title = u"Чат "_q + QString::number(info.id);
	}
	info.kind = KindOf(peer);
	info.username = peer->username();
	info.about = peer->about();
	info.link = ChatLink(info, peer);
	if (const auto chat = peer->asChat()) {
		info.inviteLink = chat->inviteLink();
	} else if (const auto channel = peer->asChannel()) {
		info.inviteLink = channel->inviteLink();
	}
	info.fileName = u"chat_"_q + QString::number(info.id);
	return info;
}

void DescribeMedia(
		not_null<HistoryItem*> item,
		bool full,
		not_null<MessageRec*> rec) {
	const auto media = item->media();
	if (!media) {
		return;
	}
	if (const auto document = media->document()) {
		const auto name = document->filename();
		rec->description = u"Файл"_q
			+ (name.isEmpty() ? QString() : (u": "_q + name))
			+ (document->mimeString().isEmpty()
				? QString()
				: (u" ("_q + document->mimeString() + ')'));
		if (full) {
			// Looking at the disk for every message is what a live copy
			// must never do: only the one-off copies check the files.
			const auto source = document->filepath(true);
			if (!source.isEmpty() && QFileInfo::exists(source)) {
				rec->sourcePath = source;
			}
		}
	} else if (const auto photo = media->photo()) {
		rec->description = u"Фото"_q;
		if (full) {
			const auto view = photo->createMediaView();
			if (const auto image = view->image(Data::PhotoSize::Large)) {
				rec->photo = image->original();
			}
		}
	} else if (media->webpage()) {
		rec->description = u"Ссылка"_q;
	} else {
		rec->description = u"Вложение"_q;
	}
}

[[nodiscard]] ChatData CollectChat(not_null<History*> history, bool full) {
	auto result = ChatData{ .info = Describe(history) };
	const auto peer = history->peer;
	auto items = std::vector<not_null<HistoryItem*>>();
	for (const auto &block : history->blocks) {
		for (const auto &view : block->messages) {
			items.push_back(view->data());
		}
	}
	if (items.empty()) {
		if (const auto last = history->lastMessage()) {
			items.push_back(last);
		}
	}
	auto first = size_t(0);
	if (!full && items.size() > size_t(kLiveMessages)) {
		first = items.size() - size_t(kLiveMessages);
	}
	result.messages.reserve(items.size() - first);
	for (auto i = first; i != items.size(); ++i) {
		const auto item = items[i];
		auto rec = MessageRec();
		rec.id = item->id.bare;
		rec.date = item->date();
		rec.out = item->out();
		rec.deletedBySender = item->isDeletedBySender();
		rec.fromId = QString::number(item->from()->id.value);
		rec.from = item->from()->name();
		rec.text = item->originalText().text;
		if (rec.text.isEmpty() && item->isService()) {
			rec.text = item->notificationText().text;
		}
		rec.link = MessageLink(result.info, peer, item->id);
		DescribeMedia(item, full, &rec);
		result.messages.push_back(std::move(rec));
	}
	return result;
}

// Puts the downloaded file or loaded photo of a message into media/,
// returns the path relative to the report folder (empty when not available).
[[nodiscard]] QString SaveFiles(
		not_null<Writer*> writer,
		const ChatInfo &info,
		const MessageRec &rec) {
	if (rec.sourcePath.isEmpty() && rec.photo.isNull()) {
		return QString();
	}
	const auto folder = writer->folder + u"/media/"_q + info.fileName;
	if (!rec.sourcePath.isEmpty()) {
		const auto size = QFileInfo(rec.sourcePath).size();
		if (size > writer->budget) {
			return QString();
		}
		QDir().mkpath(folder);
		const auto base = QString::number(rec.id)
			+ '_'
			+ SafeName(QFileInfo(rec.sourcePath).fileName());
		const auto target = folder + '/' + base;
		if (QFileInfo::exists(target) || QFile::copy(rec.sourcePath, target)) {
			writer->budget -= size;
			return u"media/"_q + info.fileName + '/' + base;
		}
		return QString();
	}
	QDir().mkpath(folder);
	const auto base = QString::number(rec.id) + u".jpg"_q;
	if (rec.photo.save(folder + '/' + base, "JPG", 90)) {
		return u"media/"_q + info.fileName + '/' + base;
	}
	return QString();
}

void WriteChat(not_null<Writer*> writer, ChatData &chat) {
	auto &info = chat.info;
	auto messages = QJsonArray();
	auto html = QString();
	html += u"<!doctype html><html><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>"_q
		+ Esc(info.title) + u"</title>"_q + QString::fromUtf8(kStyle)
		+ u"</head><body><p><a href=\"index.html\">← Все чаты</a></p><h1>"_q
		+ Esc(info.title) + u"</h1>"_q;
	if (!info.link.isEmpty()) {
		html += u"<p><a href=\""_q + Esc(info.link) + u"\">"_q
			+ Esc(info.link) + u"</a></p>"_q;
	}
	if (!info.inviteLink.isEmpty()) {
		html += u"<p>Ссылка-приглашение: <a href=\""_q
			+ Esc(info.inviteLink) + u"\">"_q
			+ Esc(info.inviteLink) + u"</a></p>"_q;
	}
	if (!info.about.isEmpty()) {
		html += u"<p class=\"about\">"_q + Esc(info.about) + u"</p>"_q;
	}

	for (const auto &rec : chat.messages) {
		++info.messages;
		if (rec.out) {
			++info.own;
		}
		const auto saved = SaveFiles(writer, info, rec);
		if (!saved.isEmpty()) {
			++info.files;
		}
		const auto time = base::unixtime::parse(rec.date).toString(
			u"yyyy-MM-dd HH:mm:ss"_q);

		auto entry = QJsonObject();
		entry.insert(u"id"_q, double(rec.id));
		entry.insert(u"date"_q, double(rec.date));
		entry.insert(u"time"_q, time);
		entry.insert(u"out"_q, rec.out);
		entry.insert(u"from_id"_q, rec.fromId);
		entry.insert(u"from"_q, rec.from);
		entry.insert(u"text"_q, rec.text);
		if (!rec.description.isEmpty()) {
			entry.insert(u"media"_q, rec.description);
		}
		if (!saved.isEmpty()) {
			entry.insert(u"file"_q, saved);
		}
		if (rec.deletedBySender) {
			entry.insert(u"deleted_by_sender"_q, true);
		}
		if (!rec.link.isEmpty()) {
			entry.insert(u"link"_q, rec.link);
		}
		messages.push_back(entry);

		html += u"<div class=\"m"_q + (rec.out ? u" out"_q : QString())
			+ u"\"><div class=\"h\"><b>"_q + Esc(rec.from) + u"</b> <span>"_q
			+ time + u"</span>"_q;
		if (!rec.link.isEmpty()) {
			html += u" <a href=\""_q + Esc(rec.link) + u"\">#"_q
				+ QString::number(rec.id) + u"</a>"_q;
		}
		if (rec.deletedBySender) {
			html += u" <span>удалено отправителем</span>"_q;
		}
		html += u"</div>"_q;
		if (!rec.text.isEmpty()) {
			html += u"<div class=\"t\">"_q
				+ Linkify(Esc(rec.text)).replace('\n', u"<br>"_q)
				+ u"</div>"_q;
		}
		if (!rec.description.isEmpty()) {
			html += u"<div class=\"d\">"_q + Esc(rec.description)
				+ u"</div>"_q;
		}
		if (!saved.isEmpty()) {
			html += u"<div class=\"d\"><a href=\""_q + Esc(saved) + u"\">"_q
				+ Esc(saved.mid(saved.lastIndexOf('/') + 1)) + u"</a></div>"_q;
		}
		html += u"</div>"_q;
	}
	html += u"</body></html>"_q;

	auto json = QJsonObject();
	json.insert(u"id"_q, QString::number(info.id));
	json.insert(u"title"_q, info.title);
	json.insert(u"type"_q, info.kind);
	json.insert(u"username"_q, info.username);
	json.insert(u"link"_q, info.link);
	json.insert(u"invite_link"_q, info.inviteLink);
	json.insert(u"about"_q, info.about);
	json.insert(u"messages"_q, messages);
	[[maybe_unused]] const auto okJson = WriteJson(
		writer->folder + '/' + info.fileName + u".json"_q,
		json);
	[[maybe_unused]] const auto okHtml = WriteText(
		writer->folder + '/' + info.fileName + u".html"_q,
		html);
}

void WriteIndex(
		const QString &folder,
		const Meta &meta,
		Reason reason,
		const std::vector<ChatData> &chats) {
	auto html = QString();
	html += u"<!doctype html><html><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Архив аккаунта</title>"_q
		+ QString::fromUtf8(kStyle) + u"</head><body><h1>Архив аккаунта "_q
		+ Esc(meta.name) + u"</h1><p>ID: "_q + meta.userId;
	if (!meta.phone.isEmpty()) {
		html += u", телефон +"_q + Esc(meta.phone);
	}
	if (!meta.username.isEmpty()) {
		html += u", <a href=\"https://t.me/"_q + Esc(meta.username)
			+ u"\">@"_q + Esc(meta.username) + u"</a>"_q;
	}
	html += u"<br>Сохранено: "_q
		+ QDateTime::currentDateTime().toString(u"yyyy-MM-dd HH:mm"_q)
		+ u"<br>Причина: "_q + Esc(ReasonText(reason)) + u"</p>"_q;
	if (reason == Reason::Live) {
		html += u"<p>Это автоматическая копия: для каждого чата в ней последние сообщения без файлов. Полная копия со скачанными файлами создаётся при удалении, блокировке или заморозке аккаунта.</p>"_q;
	}
	html += u"<p>Приложение для ПК не хранит историю переписки на диске, поэтому сохранено то, что к этому моменту было загружено в память: список чатов, открывавшиеся переписки и скачанные файлы. Чего не было загружено, на устройстве нет.</p>"_q;
	html += u"<table><tr><th>Чат</th><th>Тип</th><th>Ссылка</th><th>Сообщений</th><th>Ваших</th><th>Файлов</th></tr>"_q;
	for (const auto &chat : chats) {
		const auto &info = chat.info;
		html += u"<tr><td><a href=\""_q + info.fileName + u".html\">"_q
			+ Esc(info.title) + u"</a></td><td>"_q + Esc(info.kind)
			+ u"</td><td>"_q;
		if (!info.link.isEmpty()) {
			html += u"<a href=\""_q + Esc(info.link) + u"\">"_q
				+ Esc(info.link) + u"</a>"_q;
		}
		if (!info.inviteLink.isEmpty()) {
			html += u"<br><a href=\""_q + Esc(info.inviteLink) + u"\">"_q
				+ Esc(info.inviteLink) + u"</a>"_q;
		}
		html += u"</td><td>"_q + QString::number(info.messages)
			+ u"</td><td>"_q + QString::number(info.own)
			+ u"</td><td>"_q + QString::number(info.files)
			+ u"</td></tr>"_q;
	}
	html += u"</table></body></html>"_q;
	[[maybe_unused]] const auto okIndex = WriteText(
		folder + u"/index.html"_q,
		html);

	auto links = QString();
	auto array = QJsonArray();
	for (const auto &chat : chats) {
		const auto &info = chat.info;
		if (!info.link.isEmpty() || !info.inviteLink.isEmpty()) {
			links += info.title + u" ["_q + info.kind + u"]\n"_q;
			if (!info.link.isEmpty()) {
				links += u"  "_q + info.link + '\n';
			}
			if (!info.inviteLink.isEmpty()) {
				links += u"  "_q + info.inviteLink + '\n';
			}
		}
		auto entry = QJsonObject();
		entry.insert(u"id"_q, QString::number(info.id));
		entry.insert(u"title"_q, info.title);
		entry.insert(u"type"_q, info.kind);
		entry.insert(u"username"_q, info.username);
		entry.insert(u"link"_q, info.link);
		entry.insert(u"invite_link"_q, info.inviteLink);
		entry.insert(u"about"_q, info.about);
		entry.insert(u"messages"_q, info.messages);
		entry.insert(u"own_messages"_q, info.own);
		entry.insert(u"files"_q, info.files);
		entry.insert(u"file"_q, info.fileName + u".json"_q);
		array.push_back(entry);
	}
	[[maybe_unused]] const auto okLinks = WriteText(
		folder + u"/links.txt"_q,
		links);
	[[maybe_unused]] const auto okChats = WriteJson(
		folder + u"/chats.json"_q,
		array);
}

// Thread-safe: works only on the plain copies made by CollectChat.
[[nodiscard]] QString WriteAll(
		Reason reason,
		const Meta &meta,
		std::vector<ChatData> chats) {
	const auto live = (reason == Reason::Live);
	const auto root = RootPath();
	QDir().mkpath(root);
	const auto stamp = QDateTime::currentDateTime().toString(
		u"yyyyMMdd-HHmmss"_q);
	const auto final = live
		? (root + u"/live_"_q + meta.userId)
		: (root + '/' + meta.userId + '_' + stamp + '_' + ReasonSlug(reason));
	const auto folder = live ? (final + u".tmp"_q) : final;
	QDir(folder).removeRecursively();
	if (!QDir().mkpath(folder)) {
		return QString();
	}

	auto writer = Writer{ .folder = folder };
	auto totalMessages = 0;
	auto totalFiles = 0;
	for (auto &chat : chats) {
		WriteChat(&writer, chat);
		totalMessages += chat.info.messages;
		totalFiles += chat.info.files;
	}
	WriteIndex(folder, meta, reason, chats);

	auto json = QJsonObject();
	json.insert(u"format"_q, 1);
	json.insert(u"user_id"_q, meta.userId);
	json.insert(u"name"_q, meta.name);
	json.insert(u"phone"_q, meta.phone);
	json.insert(u"username"_q, meta.username);
	json.insert(u"reason"_q, ReasonSlug(reason));
	json.insert(u"created"_q, double(QDateTime::currentSecsSinceEpoch()));
	json.insert(u"chats"_q, int(chats.size()));
	json.insert(u"messages"_q, totalMessages);
	json.insert(u"files"_q, totalFiles);
	[[maybe_unused]] const auto okMeta = WriteJson(
		folder + u"/meta.json"_q,
		json);

	if (live) {
		QDir(final).removeRecursively();
		if (!QDir().rename(folder, final)) {
			return QString();
		}
		return final;
	}
	[[maybe_unused]] const auto okUnseen = WriteText(
		UnseenPath(),
		meta.userId);
	return final;
}

[[nodiscard]] Meta MetaOf(not_null<Session*> session) {
	const auto user = session->user();
	return {
		.userId = QString::number(peerToUser(user->id).bare),
		.name = user->name(),
		.phone = user->phone(),
		.username = user->username(),
	};
}

[[nodiscard]] std::vector<PeerId> CollectIds(not_null<Session*> session) {
	auto histories = std::vector<not_null<History*>>();
	auto seen = base::flat_set<not_null<History*>>();
	const auto &owner = session->data();
	CollectHistories(owner.chatsList(), histories, seen);
	if (const auto folder = owner.folderLoaded(Data::Folder::kId)) {
		CollectHistories(folder->chatsList(), histories, seen);
	}
	auto result = std::vector<PeerId>();
	result.reserve(histories.size());
	for (const auto &history : histories) {
		result.push_back(history->peer->id);
	}
	return result;
}

// Nothing is loaded (the app was just started): keep the live copy that
// exists instead of replacing it with an empty one, and hand that one over.
[[nodiscard]] QString ExistingLive(const Meta &meta, Reason reason) {
	const auto existing = RootPath() + u"/live_"_q + meta.userId;
	if (reason == Reason::Live
		|| !QFileInfo::exists(existing + u"/index.html"_q)) {
		return QString();
	}
	[[maybe_unused]] const auto ok = WriteText(UnseenPath(), meta.userId);
	return existing;
}

struct Job {
	Reason reason = Reason::Live;
	Meta meta;
	std::vector<PeerId> ids;
	size_t index = 0;
	std::vector<ChatData> chats;
	Fn<void(QString)> done;
};

void Step(not_null<Session*> session, const std::shared_ptr<Job> &job) {
	const auto full = (job->reason != Reason::Live);
	const auto deadline = crl::now() + kSliceBudget;
	const auto &owner = session->data();
	while (job->index != job->ids.size()) {
		if (const auto history = owner.historyLoaded(job->ids[job->index])) {
			job->chats.push_back(CollectChat(history, full));
		}
		++job->index;
		if (crl::now() >= deadline) {
			break;
		}
	}
	if (job->index != job->ids.size()) {
		base::call_delayed(kSliceGap, session, [=] {
			Step(session, job);
		});
		return;
	}
	crl::async([job] {
		const auto folder = WriteAll(
			job->reason,
			job->meta,
			std::move(job->chats));
		crl::on_main([=] {
			Busy = false;
			if (job->done) {
				job->done(folder);
			}
		});
	});
}

void Begin(
		not_null<Session*> session,
		Reason reason,
		Fn<void(QString)> done) {
	auto job = std::make_shared<Job>();
	job->reason = reason;
	job->meta = MetaOf(session);
	job->done = std::move(done);
	if (Busy) {
		if (job->done) {
			job->done(QString());
		}
		return;
	}
	job->ids = CollectIds(session);
	if (job->ids.empty()) {
		const auto existing = ExistingLive(job->meta, reason);
		if (job->done) {
			job->done(existing);
		}
		return;
	}
	Busy = true;
	Step(session, job);
}

void LiveTick(not_null<Session*> session) {
	if (session->account().loggingOut()) {
		return;
	} else if (Busy) {
		base::call_delayed(kBusyRetry, session, [=] {
			LiveTick(session);
		});
		return;
	}
	Begin(session, Reason::Live, nullptr);
}

} // namespace

QString RootPath() {
	return cWorkingDir() + u"ZaStoArchive"_q;
}

QString Save(not_null<Session*> session, Reason reason) {
	// Used right before the logout wipes the session: it has to finish here.
	const auto meta = MetaOf(session);
	const auto ids = CollectIds(session);
	if (ids.empty()) {
		return ExistingLive(meta, reason);
	}
	auto chats = std::vector<ChatData>();
	chats.reserve(ids.size());
	const auto &owner = session->data();
	for (const auto id : ids) {
		if (const auto history = owner.historyLoaded(id)) {
			chats.push_back(CollectChat(history, true));
		}
	}
	return WriteAll(reason, meta, std::move(chats));
}

void SaveAsync(
		not_null<Session*> session,
		Reason reason,
		Fn<void(QString)> done) {
	Begin(session, reason, std::move(done));
}

void Watch(not_null<Session*> session) {
	const auto timer = session->lifetime().make_state<base::Timer>([=] {
		LiveTick(session);
	});
	timer->callEach(kLiveInterval);
	base::call_delayed(kLiveFirstDelay, session, [=] {
		LiveTick(session);
	});
}

void SaveFrozenOnce(not_null<Session*> session, TimeId since) {
	if (!since) {
		return;
	}
	const auto userId = peerToUser(session->user()->id).bare;
	const auto marker = RootPath()
		+ u"/frozen_"_q + QString::number(userId)
		+ '_' + QString::number(since);
	if (QFileInfo::exists(marker)) {
		return;
	}
	// Give the chat list time to load after the app starts.
	base::call_delayed(kLiveFirstDelay, session, [=] {
		if (QFileInfo::exists(marker)) {
			return;
		}
		Begin(session, Reason::Frozen, [=](QString folder) {
			if (!folder.isEmpty()) {
				QDir().mkpath(RootPath());
				[[maybe_unused]] const auto ok = WriteText(marker, folder);
			}
		});
	});
}

void SetPending(const QString &folder, Reason reason) {
	Pending.folder = folder;
	Pending.reason = reason;
}

void NotifyPending() {
	const auto folder = base::take(Pending.folder);
	const auto reason = Pending.reason;
	if (folder.isEmpty()) {
		return;
	}
	const auto text = ReasonText(reason)
		+ u".\n\nЛокальная копия аккаунта (чаты, каналы, группы, ссылки, сообщения и файлы, которые были загружены в приложение) сохранена в папке:\n"_q
		+ QDir::toNativeSeparators(folder)
		+ u"\n\nОткрыть: index.html в этой папке."_q;
	Ui::show(Ui::MakeConfirmBox({
		.text = text,
		.confirmed = [=](Fn<void()> close) {
			File::ShowInFolder(folder + u"/index.html"_q);
			close();
		},
		.confirmText = u"Открыть папку"_q,
		.cancelText = u"Закрыть"_q,
	}));
	MarkSeen();
}

bool HasUnseen() {
	return QFileInfo::exists(UnseenPath());
}

void MarkSeen() {
	QFile::remove(UnseenPath());
}

} // namespace Main::AccountArchive

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

namespace Main::AccountArchive {
namespace {

constexpr auto kLiveFirstDelay = 2 * 60 * crl::time(1000);
constexpr auto kLiveInterval = 15 * 60 * crl::time(1000);
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

struct Writer {
	QString folder;
	bool copyFiles = false;
	int64 budget = kMediaBudget;
};

// Puts the downloaded file or loaded photo of a message into media/,
// returns the path relative to the report folder (empty when not available).
[[nodiscard]] QString SaveMedia(
		not_null<Writer*> writer,
		not_null<HistoryItem*> item,
		const ChatInfo &info,
		QString *description) {
	const auto media = item->media();
	if (!media) {
		return QString();
	}
	if (const auto document = media->document()) {
		auto name = document->filename();
		*description = u"Файл"_q
			+ (name.isEmpty() ? QString() : (u": "_q + name))
			+ (document->mimeString().isEmpty()
				? QString()
				: (u" ("_q + document->mimeString() + ')'));
		const auto source = document->filepath(true);
		if (source.isEmpty() || !QFileInfo::exists(source)) {
			return QString();
		}
		if (!writer->copyFiles) {
			return QUrl::fromLocalFile(source).toString();
		}
		const auto size = QFileInfo(source).size();
		if (size > writer->budget) {
			return QString();
		}
		const auto folder = writer->folder + u"/media/"_q + info.fileName;
		QDir().mkpath(folder);
		const auto base = QString::number(item->id.bare)
			+ '_'
			+ SafeName(QFileInfo(source).fileName());
		const auto target = folder + '/' + base;
		if (QFileInfo::exists(target) || QFile::copy(source, target)) {
			writer->budget -= size;
			return u"media/"_q + info.fileName + '/' + base;
		}
		return QString();
	} else if (const auto photo = media->photo()) {
		*description = u"Фото"_q;
		if (!writer->copyFiles) {
			return QString();
		}
		const auto view = photo->createMediaView();
		const auto image = view->image(Data::PhotoSize::Large);
		if (!image) {
			return QString();
		}
		const auto original = image->original();
		if (original.isNull()) {
			return QString();
		}
		const auto folder = writer->folder + u"/media/"_q + info.fileName;
		QDir().mkpath(folder);
		const auto base = QString::number(item->id.bare) + u".jpg"_q;
		if (original.save(folder + '/' + base, "JPG", 90)) {
			return u"media/"_q + info.fileName + '/' + base;
		}
		return QString();
	} else if (media->webpage()) {
		*description = u"Ссылка"_q;
	} else {
		*description = u"Вложение"_q;
	}
	return QString();
}

void WriteChat(
		not_null<Writer*> writer,
		not_null<History*> history,
		ChatInfo &info) {
	const auto peer = history->peer;
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

	for (const auto item : items) {
		const auto when = base::unixtime::parse(item->date());
		const auto time = when.toString(u"yyyy-MM-dd HH:mm:ss"_q);
		const auto from = item->from()->name();
		auto text = item->originalText().text;
		if (text.isEmpty() && item->isService()) {
			text = item->notificationText().text;
		}
		auto description = QString();
		const auto saved = SaveMedia(writer, item, info, &description);
		const auto link = MessageLink(info, peer, item->id);
		++info.messages;
		if (item->out()) {
			++info.own;
		}
		if (!saved.isEmpty() && saved.startsWith(u"media/"_q)) {
			++info.files;
		}

		auto entry = QJsonObject();
		entry.insert(u"id"_q, double(item->id.bare));
		entry.insert(u"date"_q, double(item->date()));
		entry.insert(u"time"_q, time);
		entry.insert(u"out"_q, item->out());
		entry.insert(u"from_id"_q, QString::number(item->from()->id.value));
		entry.insert(u"from"_q, from);
		entry.insert(u"text"_q, text);
		if (!description.isEmpty()) {
			entry.insert(u"media"_q, description);
		}
		if (!saved.isEmpty()) {
			entry.insert(u"file"_q, saved);
		}
		if (item->isDeletedBySender()) {
			entry.insert(u"deleted_by_sender"_q, true);
		}
		if (!link.isEmpty()) {
			entry.insert(u"link"_q, link);
		}
		messages.push_back(entry);

		html += u"<div class=\"m"_q + (item->out() ? u" out"_q : QString())
			+ u"\"><div class=\"h\"><b>"_q + Esc(from) + u"</b> <span>"_q
			+ time + u"</span>"_q;
		if (!link.isEmpty()) {
			html += u" <a href=\""_q + Esc(link) + u"\">#"_q
				+ QString::number(item->id.bare) + u"</a>"_q;
		}
		if (item->isDeletedBySender()) {
			html += u" <span>удалено отправителем</span>"_q;
		}
		html += u"</div>"_q;
		if (!text.isEmpty()) {
			html += u"<div class=\"t\">"_q
				+ Linkify(Esc(text)).replace('\n', u"<br>"_q)
				+ u"</div>"_q;
		}
		if (!description.isEmpty()) {
			html += u"<div class=\"d\">"_q + Esc(description) + u"</div>"_q;
		}
		if (!saved.isEmpty()) {
			const auto name = saved.mid(saved.lastIndexOf('/') + 1);
			const auto href = saved.startsWith(u"media/"_q)
				? saved
				: saved;
			html += u"<div class=\"d\"><a href=\""_q + Esc(href) + u"\">"_q
				+ Esc(name) + u"</a></div>"_q;
		}
		html += u"</div>"_q;
	}
	html += u"</body></html>"_q;

	auto chat = QJsonObject();
	chat.insert(u"id"_q, QString::number(info.id));
	chat.insert(u"title"_q, info.title);
	chat.insert(u"type"_q, info.kind);
	chat.insert(u"username"_q, info.username);
	chat.insert(u"link"_q, info.link);
	chat.insert(u"invite_link"_q, info.inviteLink);
	chat.insert(u"about"_q, info.about);
	chat.insert(u"messages"_q, messages);
	[[maybe_unused]] const auto okJson = WriteJson(
		writer->folder + '/' + info.fileName + u".json"_q,
		chat);
	[[maybe_unused]] const auto okHtml = WriteText(
		writer->folder + '/' + info.fileName + u".html"_q,
		html);
}

void WriteIndex(
		const QString &folder,
		not_null<Session*> session,
		Reason reason,
		const std::vector<ChatInfo> &chats) {
	const auto user = session->user();
	auto html = QString();
	html += u"<!doctype html><html><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Архив аккаунта</title>"_q
		+ QString::fromUtf8(kStyle) + u"</head><body><h1>Архив аккаунта "_q
		+ Esc(user->name()) + u"</h1><p>ID: "_q
		+ QString::number(peerToUser(user->id).bare);
	if (!user->phone().isEmpty()) {
		html += u", телефон +"_q + Esc(user->phone());
	}
	if (!user->username().isEmpty()) {
		html += u", <a href=\"https://t.me/"_q + Esc(user->username())
			+ u"\">@"_q + Esc(user->username()) + u"</a>"_q;
	}
	html += u"<br>Сохранено: "_q
		+ QDateTime::currentDateTime().toString(u"yyyy-MM-dd HH:mm"_q)
		+ u"<br>Причина: "_q + Esc(ReasonText(reason)) + u"</p>"_q;
	html += u"<p>Приложение для ПК не хранит историю переписки на диске, поэтому сохранено то, что к этому моменту было загружено в память: список чатов, открывавшиеся переписки и скачанные файлы. Чего не было загружено, на устройстве нет.</p>"_q;
	html += u"<table><tr><th>Чат</th><th>Тип</th><th>Ссылка</th><th>Сообщений</th><th>Ваших</th><th>Файлов</th></tr>"_q;
	for (const auto &info : chats) {
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
	for (const auto &info : chats) {
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

void CollectHistories(
		not_null<Dialogs::MainList*> list,
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

} // namespace

QString RootPath() {
	return cWorkingDir() + u"ZaStoArchive"_q;
}

QString Save(not_null<Session*> session, Reason reason) {
	const auto user = session->user();
	const auto userId = peerToUser(user->id).bare;
	const auto live = (reason == Reason::Live);
	const auto root = RootPath();
	QDir().mkpath(root);

	auto histories = std::vector<not_null<History*>>();
	auto seen = base::flat_set<not_null<History*>>();
	const auto &owner = session->data();
	CollectHistories(owner.chatsList(), histories, seen);
	if (const auto folder = owner.folderLoaded(Data::Folder::kId)) {
		CollectHistories(folder->chatsList(), histories, seen);
	}
	if (histories.empty()) {
		// Nothing is loaded (the app was just started): keep what the
		// earlier live copy has instead of replacing it with an empty one.
		const auto existing = root
			+ u"/live_"_q + QString::number(userId);
		if (!live && QFileInfo::exists(existing + u"/index.html"_q)) {
			[[maybe_unused]] const auto ok = WriteText(
				UnseenPath(),
				QString::number(userId));
			return existing;
		}
		return QString();
	}

	const auto stamp = QDateTime::currentDateTime().toString(
		u"yyyyMMdd-HHmmss"_q);
	const auto final = live
		? (root + u"/live_"_q + QString::number(userId))
		: (root
			+ '/' + QString::number(userId)
			+ '_' + stamp
			+ '_' + ReasonSlug(reason));
	const auto folder = live ? (final + u".tmp"_q) : final;
	QDir(folder).removeRecursively();
	if (!QDir().mkpath(folder)) {
		return QString();
	}

	auto writer = Writer{ .folder = folder, .copyFiles = !live };
	auto chats = std::vector<ChatInfo>();
	chats.reserve(histories.size());
	auto totalMessages = 0;
	auto totalFiles = 0;
	for (const auto history : histories) {
		auto info = Describe(history);
		WriteChat(&writer, history, info);
		totalMessages += info.messages;
		totalFiles += info.files;
		chats.push_back(std::move(info));
	}
	WriteIndex(folder, session, reason, chats);

	auto meta = QJsonObject();
	meta.insert(u"format"_q, 1);
	meta.insert(u"user_id"_q, QString::number(userId));
	meta.insert(u"name"_q, user->name());
	meta.insert(u"phone"_q, user->phone());
	meta.insert(u"username"_q, user->username());
	meta.insert(u"reason"_q, ReasonSlug(reason));
	meta.insert(u"created"_q, double(QDateTime::currentSecsSinceEpoch()));
	meta.insert(u"chats"_q, int(chats.size()));
	meta.insert(u"messages"_q, totalMessages);
	meta.insert(u"files"_q, totalFiles);
	[[maybe_unused]] const auto okMeta = WriteJson(
		folder + u"/meta.json"_q,
		meta);

	if (live) {
		QDir(final).removeRecursively();
		if (!QDir().rename(folder, final)) {
			return QString();
		}
		return final;
	}
	[[maybe_unused]] const auto okUnseen = WriteText(
		UnseenPath(),
		QString::number(userId));
	return final;
}

void Watch(not_null<Session*> session) {
	const auto timer = session->lifetime().make_state<base::Timer>([=] {
		if (!session->account().loggingOut()) {
			Save(session, Reason::Live);
		}
	});
	timer->callEach(kLiveInterval);
	base::call_delayed(kLiveFirstDelay, session, [=] {
		if (!session->account().loggingOut()) {
			Save(session, Reason::Live);
		}
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
		const auto folder = Save(session, Reason::Frozen);
		if (!folder.isEmpty()) {
			QDir().mkpath(RootPath());
			[[maybe_unused]] const auto ok = WriteText(marker, folder);
		}
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

/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "api/api_chat_filters_sync.h"

#include "api/api_common.h"
#include "apiwrap.h"
#include "core/application.h"
#include "data/data_chat_filters_tree.h"
#include "data/data_session.h"
#include "data/data_user.h"
#include "history/history.h"
#include "lang/lang_keys.h"
#include "main/main_account.h"
#include "main/main_session.h"
#include "mtproto/protocol/mtproto_response.h"
#include "window/window_controller.h"

#include <QtCore/QDateTime>
#include <QtCore/QJsonArray>
#include <QtCore/QJsonDocument>
#include <QtCore/QJsonObject>

#include <map>

namespace Api {
namespace {

constexpr auto kChunkChars = 3500;
constexpr auto kMaxChunks = 60;
constexpr auto kSearchLimit = 100;
constexpr auto kDebounce = 4 * crl::time(1000);
constexpr auto kStartDelay = 8 * crl::time(1000);
constexpr auto kPollEvery = 15 * 60 * crl::time(1000);
constexpr auto kRetryDelay = 60 * crl::time(1000);
constexpr auto kIncompleteRetryDelay = 5 * crl::time(1000);
constexpr auto kIncompleteRetries = 3;

[[nodiscard]] QString Marker() {
	return u"ZSG-FOLDERS"_q;
}

struct Chunk {
	int32 id = 0;
	int64 rev = 0;
	int index = 0;
	int count = 0;
	QString text;
	QByteArray payload;
};

[[nodiscard]] std::optional<Chunk> ParseChunk(int32 id, const QString &text) {
	const auto newline = text.indexOf(u'\n');
	if (newline < 0) {
		return std::nullopt;
	}
	const auto header = text.left(newline).split(u' ');
	if (header.size() != 4
		|| header[0] != Marker()
		|| header[1] != u"v1"_q) {
		return std::nullopt;
	}
	const auto position = header[3].split(u'/');
	if (position.size() != 2) {
		return std::nullopt;
	}
	auto okRev = false, okIndex = false, okCount = false;
	const auto rev = header[2].toLongLong(&okRev);
	const auto index = position[0].toInt(&okIndex);
	const auto count = position[1].toInt(&okCount);
	if (!okRev
		|| !okIndex
		|| !okCount
		|| index < 1
		|| count < 1
		|| index > count) {
		return std::nullopt;
	}
	return Chunk{
		.id = id,
		.rev = rev,
		.index = index,
		.count = count,
		.text = text,
		.payload = text.mid(newline + 1).toLatin1(),
	};
}

[[nodiscard]] QByteArray Normalize(const QByteArray &json) {
	return QJsonDocument::fromJson(json).toJson(QJsonDocument::Compact);
}

} // namespace

LocalFoldersSync::LocalFoldersSync(
	not_null<Main::Session*> session,
	not_null<Data::LocalFolders*> folders)
: _session(session)
, _folders(folders)
, _timer([=] { sync(); })
, _poll([=] { sync(); }) {
	_folders->changed() | rpl::on_next([=] {
		if (!_muted) {
			schedule(kDebounce);
		}
	}, _lifetime);
	_poll.callEach(kPollEvery);
	schedule(kStartDelay);
}

void LocalFoldersSync::schedule(crl::time delay) {
	_timer.callOnce(delay);
}

void LocalFoldersSync::sync() {
	if (_syncing) {
		_dirty = true;
		return;
	}
	_syncing = true;
	_session->api().request(MTPmessages_Search(
		MTP_flags(MTPmessages_Search::Flag(0)),
		MTP_inputPeerSelf(),
		MTP_string(Marker()),
		MTP_inputPeerEmpty(),
		MTPInputPeer(),
		MTPVector<MTPReaction>(),
		MTP_int(0),
		MTP_inputMessagesFilterEmpty(),
		MTP_int(0),
		MTP_int(0),
		MTP_int(0),
		MTP_int(0),
		MTP_int(kSearchLimit),
		MTP_int(0),
		MTP_int(0),
		MTP_long(0)
	)).done([=](const MTPmessages_Messages &result) {
		auto list = std::vector<std::pair<int32, QString>>();
		const auto take = [&](const auto &data) {
			_session->data().processUsers(data.vusers());
			_session->data().processChats(data.vchats());
			for (const auto &message : data.vmessages().v) {
				message.match([&](const MTPDmessage &data) {
					list.emplace_back(data.vid().v, qs(data.vmessage()));
				}, [](const auto &) {});
			}
		};
		result.match([&](const MTPDmessages_messages &data) {
			take(data);
		}, [&](const MTPDmessages_messagesSlice &data) {
			take(data);
		}, [](const auto &) {});
		gotMessages(list);
	}).fail([=](const MTP::Error &error) {
		fail(error);
	}).send();
}

void LocalFoldersSync::gotMessages(
		const std::vector<std::pair<int32, QString>> &messages) {
	auto chunks = std::vector<Chunk>();
	for (const auto &[id, text] : messages) {
		if (auto chunk = ParseChunk(id, text)) {
			chunks.push_back(std::move(*chunk));
		}
	}
	auto groups = std::map<int64, std::vector<Chunk>>();
	for (const auto &chunk : chunks) {
		groups[chunk.rev].push_back(chunk);
	}
	// The newest complete version.
	auto best = std::vector<Chunk>();
	for (auto i = groups.rbegin(); i != groups.rend(); ++i) {
		const auto &group = i->second;
		const auto count = group.front().count;
		auto indices = base::flat_set<int>();
		auto consistent = true;
		for (const auto &chunk : group) {
			consistent = consistent && (chunk.count == count);
			indices.emplace(chunk.index);
		}
		if (consistent
			&& int(group.size()) == count
			&& int(indices.size()) == count) {
			best = group;
			ranges::sort(best, ranges::less(), &Chunk::index);
			break;
		}
	}
	if (best.empty() && !chunks.empty()) {
		// Somebody is in the middle of writing, let them finish.
		if (_incompleteRetries < kIncompleteRetries) {
			++_incompleteRetries;
			_syncing = false;
			schedule(kIncompleteRetryDelay);
			return;
		}
	}
	_incompleteRetries = 0;

	auto remoteJson = QByteArray();
	if (!best.empty()) {
		auto packed = QByteArray();
		for (const auto &chunk : best) {
			packed.append(chunk.payload);
		}
		remoteJson = qUncompress(QByteArray::fromBase64(packed));
		if (!remoteJson.isEmpty()) {
			_muted = true;
			_folders->mergeRemote(remoteJson);
			_muted = false;
		}
	}

	auto stale = std::vector<int32>();
	for (const auto &chunk : chunks) {
		if (!ranges::contains(best, chunk.id, &Chunk::id)) {
			stale.push_back(chunk.id);
		}
	}

	const auto desired = _folders->serializeForSync(remoteJson);
	const auto hasFolders = !QJsonDocument::fromJson(desired).object().value(
		u"folders"_q
	).toArray().isEmpty();
	const auto same = !remoteJson.isEmpty()
		&& (Normalize(desired) == Normalize(remoteJson));
	const auto requests = std::make_shared<int>(0);
	const auto oneDone = [=] {
		if (--*requests <= 0) {
			finish();
		}
	};
	const auto track = [&](auto &&request) {
		++*requests;
		_session->api().request(
			std::move(request)
		).done([=] {
			oneDone();
		}).fail([=](const MTP::Error &error) {
			*requests = 0;
			fail(error);
		}).send();
	};
	const auto deleteIds = [&](std::vector<int32> ids) {
		if (ids.empty()) {
			return;
		}
		auto list = QVector<MTPint>();
		for (const auto id : ids) {
			list.push_back(MTP_int(id));
		}
		track(MTPmessages_DeleteMessages(
			MTP_flags(MTPmessages_DeleteMessages::Flag(0)),
			MTP_vector<MTPint>(list)));
	};

	if (same || (!hasFolders && best.empty())) {
		deleteIds(stale);
		if (!*requests) {
			finish();
		}
		return;
	}

	const auto packed = qCompress(desired, 9).toBase64();
	const auto count = int((packed.size() + kChunkChars - 1) / kChunkChars);
	if (count > kMaxChunks) {
		const auto kb = int(packed.size() / 1024);
		if (_notifiedTooLargeKb != kb) {
			_notifiedTooLargeKb = kb;
			notify(tr::lng_zsg_folders_sync_too_large(
				tr::now,
				lt_size,
				QString::number(kb),
				lt_limit,
				QString::number(kMaxChunks * kChunkChars / 1024)));
		}
		deleteIds(stale);
		if (!*requests) {
			finish();
		}
		return;
	}
	_notifiedTooLargeKb = 0;

	const auto rev = int64(QDateTime::currentMSecsSinceEpoch());
	const auto history = _session->data().history(_session->user());
	for (auto i = 0; i != count; ++i) {
		const auto text = Marker()
			+ u" v1 %1 %2/%3\n"_q.arg(rev).arg(i + 1).arg(count)
			+ QString::fromLatin1(packed.mid(i * kChunkChars, kChunkChars));
		if (i < int(best.size())) {
			if (best[i].text != text) {
				track(MTPmessages_EditMessage(
					MTP_flags(MTPmessages_EditMessage::Flag::f_message),
					MTP_inputPeerSelf(),
					MTP_int(best[i].id),
					MTP_string(text),
					MTPInputMedia(),
					MTPReplyMarkup(),
					MTPVector<MTPMessageEntity>(),
					MTP_int(0),
					MTP_int(0),
					MTP_int(0),
					MTPInputRichMessage()));
			}
		} else {
			auto options = SendOptions();
			options.silent = true;
			auto message = MessageToSend(SendAction(history, options));
			message.textWithTags = TextWithTags{ text };
			_session->api().sendMessage(std::move(message));
		}
	}
	for (auto i = count; i < int(best.size()); ++i) {
		stale.push_back(best[i].id);
	}
	deleteIds(stale);
	if (!*requests) {
		finish();
	}
}

void LocalFoldersSync::finish() {
	_syncing = false;
	if (_dirty) {
		_dirty = false;
		schedule(kDebounce);
	}
}

void LocalFoldersSync::fail(const MTP::Error &error) {
	_syncing = false;
	const auto type = error.type();
	if (type.startsWith(u"FLOOD_WAIT_"_q)) {
		const auto seconds = std::max(type.mid(11).toInt(), 1);
		notify(tr::lng_zsg_folders_sync_flood(
			tr::now,
			lt_seconds,
			QString::number(seconds)));
		schedule((seconds + 2) * crl::time(1000));
	} else if (type == u"MESSAGE_NOT_MODIFIED"_q) {
		finish();
	} else {
		LOG(("ZaStoGram folders sync failed: %1").arg(type));
		schedule(kRetryDelay);
	}
}

void LocalFoldersSync::notify(const QString &text) {
	const auto account = not_null(&_session->account());
	if (const auto window = Core::App().windowFor(account)) {
		window->showToast({ .text = { text } });
	}
}

} // namespace Api

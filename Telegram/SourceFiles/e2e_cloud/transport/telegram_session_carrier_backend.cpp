/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "e2e_cloud/transport/telegram_session_carrier_backend.h"

#include "apiwrap.h"
#include "base/algorithm.h"
#include "base/call_delayed.h"
#include "base/random.h"
#include "base/unixtime.h"
#include "base/weak_ptr.h"
#include "data/data_channel.h"
#include "data/data_document.h"
#include "data/data_document_media.h"
#include "data/data_file_origin.h"
#include "data/data_session.h"
#include "data/data_types.h"
#include "core/file_location.h"
#include "history/history.h"
#include "history/history_item.h"
#include "main/main_session.h"
#include "mtproto/instance/mtp_instance.h"
#include "mtproto/instance/sender.h"
#include "storage/file_upload.h"
#include "storage/localimageloader.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>

#include <QtCore/QFile>
#include <QtCore/QScopeGuard>
#include <QtCore/QTemporaryDir>

#include <algorithm>
#include <array>
#include <limits>
#include <map>
#include <optional>
#include <utility>

namespace E2ECloud {
namespace {

inline constexpr auto kMaximumCarrierObjectSize = 18 * 1024 * 1024;
inline constexpr auto kMaximumDownloadPageBytes = 64 * 1024 * 1024;
inline constexpr auto kDiscoverySearchLimit = 100;
inline constexpr auto kDiscoveryTimeout = crl::time(15'000);
inline constexpr auto kCarrierOperationTimeout = crl::time(120'000);

[[nodiscard]] QByteArray EncodeCursor(MsgId messageId) {
	if (!messageId) {
		return {};
	}
	const auto value = std::uint32_t(messageId.bare);
	auto result = QByteArray();
	result.reserve(4);
	result.append(char(value >> 24));
	result.append(char(value >> 16));
	result.append(char(value >> 8));
	result.append(char(value));
	return result;
}

[[nodiscard]] std::optional<MsgId> DecodeCursor(const QByteArray &cursor) {
	if (cursor.isEmpty()) {
		return MsgId();
	} else if (cursor.size() != 4) {
		return std::nullopt;
	}
	const auto data = reinterpret_cast<const std::uint8_t*>(
		cursor.constData());
	const auto value = (std::uint32_t(data[0]) << 24)
		| (std::uint32_t(data[1]) << 16)
		| (std::uint32_t(data[2]) << 8)
		| std::uint32_t(data[3]);
	return (value && value <= std::uint32_t(std::numeric_limits<int>::max()))
		? std::optional<MsgId>(MsgId(int(value)))
		: std::nullopt;
}

[[nodiscard]] TelegramTransport::UploadResult ErrorResult(
		const MTP::Error &error) {
	const auto &type = error.type();
	return (type == u"CHAT_WRITE_FORBIDDEN"_q
		|| type == u"PEER_ID_INVALID"_q
		|| type == u"CHAT_ID_INVALID"_q
		|| type == u"CHANNEL_PRIVATE"_q
		|| type == u"MEDIA_INVALID"_q
		|| type == u"FILE_PARTS_INVALID"_q
		|| type == u"FILE_PART_INVALID"_q)
		? TelegramTransport::UploadResult::PermanentError
		: TelegramTransport::UploadResult::RetryableError;
}

[[nodiscard]] std::optional<std::uint64_t> CarrierRandomId(
		std::uint64_t telegramPeerIdBinding,
		const QByteArray &bytes) {
	const auto domain = QByteArray("TDE2E/carrier-random-id/v1");
	auto peerBytes = std::array<std::uint8_t, 8>();
	for (auto i = std::size_t(); i != peerBytes.size(); ++i) {
		peerBytes[i] = std::uint8_t(
			telegramPeerIdBinding >> (56 - (i * 8)));
	}
	auto digest = std::array<std::uint8_t, 32>();
	const auto context = EVP_MD_CTX_new();
	auto digestSize = 0U;
	const auto ok = context
		&& EVP_DigestInit_ex(context, EVP_sha256(), nullptr) == 1
		&& EVP_DigestUpdate(
			context,
			domain.constData(),
			domain.size()) == 1
		&& EVP_DigestUpdate(
			context,
			peerBytes.data(),
			peerBytes.size()) == 1
		&& EVP_DigestUpdate(
			context,
			bytes.constData(),
			bytes.size()) == 1
		&& EVP_DigestFinal_ex(
			context,
			digest.data(),
			&digestSize) == 1
		&& digestSize == digest.size();
	EVP_MD_CTX_free(context);
	if (!ok) {
		OPENSSL_cleanse(digest.data(), digest.size());
		return std::nullopt;
	}
	auto result = std::uint64_t();
	for (auto i = std::size_t(); i != 8; ++i) {
		result = (result << 8) | digest[i];
	}
	OPENSSL_cleanse(digest.data(), digest.size());
	return std::optional<std::uint64_t>(result ? result : 1);
}

[[nodiscard]] std::shared_ptr<FilePrepareResult> PrepareCarrierDocument(
		MTP::DcId dcId,
		const QString &filename,
		const QString &mimeType,
		const QByteArray &bytes) {
	const auto id = base::RandomValue<DocumentId>();
	auto result = MakePreparedFile({
		.id = id,
		.type = SendMediaType::File,
	});
	result->filename = filename;
	result->content = bytes;
	result->filesize = bytes.size();
	result->setFileData(bytes);
	result->document = MTP_document(
		MTP_flags(0),
		MTP_long(id),
		MTP_long(0),
		MTP_bytes(),
		MTP_int(base::unixtime::now()),
		MTP_string(mimeType),
		MTP_long(bytes.size()),
		MTP_vector<MTPPhotoSize>(),
		MTPVector<MTPVideoSize>(),
		MTP_int(dcId),
		MTP_vector<MTPDocumentAttribute>(QVector<MTPDocumentAttribute>{
			MTP_documentAttributeFilename(MTP_string(filename)),
		}));
	return result;
}

} // namespace

struct TelegramSessionCarrierBackend::State final : base::has_weak_ptr {
	struct PendingUpload {
		UploadCallback callback;
		std::uint64_t randomId = 0;
	};

	struct UploadedFile {
		MTPInputFile file;
		std::uint64_t randomId = 0;
	};

	struct DownloadEntry {
		not_null<DocumentData*> document;
		std::shared_ptr<Data::DocumentMedia> media;
		FullMsgId messageId;
		QString path;
		std::uint64_t senderTelegramUserIdBinding = 0;
		bool ownedDownload = false;
	};

	struct PendingDownload {
		DownloadCallback callback;
		QByteArray nextCursor;
		std::unique_ptr<QTemporaryDir> directory;
		std::vector<DownloadEntry> entries;
		std::vector<TelegramTransport::UntrustedObject> objects;
		bool complete = false;
	};

	State(
		not_null<Main::Session*> session,
		not_null<History*> history,
		std::uint64_t telegramPeerIdBinding,
		QString filename,
		QString mimeType,
		int maximumObjectSize,
		int maximumDownloadPageBytes,
		int minimumMessageIdExclusive,
		bool protectedCarrierFamily)
	: session(session)
	, peerId(history->peer->id)
	, telegramPeerIdBinding(telegramPeerIdBinding)
	, filename(std::move(filename))
	, mimeType(std::move(mimeType))
	, maximumObjectSize(maximumObjectSize)
	, maximumDownloadPageBytes(maximumDownloadPageBytes)
	, minimumMessageIdExclusive(minimumMessageIdExclusive)
	, protectedCarrierFamily(protectedCarrierFamily)
	, api(&session->mtp()) {
		session->uploader().documentReady(
		) | rpl::on_next([weak = base::weak_ptr(this)](
				const Storage::UploadedMedia &media) {
			if (weak) {
				weak->uploadReady(media);
			}
		}, lifetime);
		session->uploader().documentFailed(
		) | rpl::on_next([weak = base::weak_ptr(this)](FullMsgId id) {
			if (weak) {
				weak->uploadFailed(id);
			}
		}, lifetime);
		session->data().documentLoadProgress(
		) | rpl::on_next([weak = base::weak_ptr(this)](
				not_null<DocumentData*> document) {
			if (weak) {
				weak->downloadProgress(document);
			}
		}, lifetime);
	}

	[[nodiscard]] bool carrierMetadata(
			const QString &candidateFilename,
			const QString &candidateMimeType) const {
		return protectedCarrierFamily
			? IsProtectedGroupCarrierMetadata(
				candidateFilename,
				candidateMimeType)
			: candidateMimeType == mimeType
				&& candidateFilename == filename;
	}

	~State() {
		for (const auto &entry : uploads) {
			session->uploader().cancel(entry.first);
		}
		if (download) {
			for (const auto &entry : download->entries) {
				if (entry.ownedDownload && entry.document->loading()) {
					entry.document->cancel();
				}
				if (entry.ownedDownload) {
					entry.document->clearLocation();
				}
			}
		}
	}

	void uploadDocument(
			QByteArray bytes,
			QString filename,
			QString mimeType,
			UploadCallback callback) {
		if (!callback) {
			return;
		} else if (!carrierMetadata(filename, mimeType)
			|| bytes.isEmpty()
			|| bytes.size() > maximumObjectSize) {
			callback(TelegramTransport::UploadResult::PermanentError, {});
			return;
		}
		const auto id = FullMsgId(
			session->userPeerId(),
			session->data().nextLocalMessageId());
		const auto randomId = CarrierRandomId(
			telegramPeerIdBinding,
			bytes);
		if (!randomId) {
			callback(
				TelegramTransport::UploadResult::RetryableError,
				{});
			return;
		}
		if (uploads.contains(id)) {
			callback(
				TelegramTransport::UploadResult::RetryableError,
				{});
			return;
		}
		uploads.emplace(id, PendingUpload{
			.callback = std::move(callback),
			.randomId = *randomId,
		});
		session->uploader().upload(
			id,
			PrepareCarrierDocument(
				session->mtp().mainDcId(),
				filename,
				mimeType,
				bytes));
		base::call_delayed(
			kCarrierOperationTimeout,
			[weak = base::weak_ptr(this), id] {
				if (weak) {
					weak->uploadTimedOut(id);
				}
			});
	}

	void uploadTimedOut(FullMsgId id) {
		const auto i = uploads.find(id);
		if (i == uploads.end()) {
			return;
		}
		auto callback = std::move(i->second.callback);
		uploads.erase(i);
		session->uploader().cancel(id);
		callback(TelegramTransport::UploadResult::RetryableError, {});
	}

	void uploadReady(const Storage::UploadedMedia &media) {
		const auto i = uploads.find(media.fullId);
		if (i == uploads.end()) {
			return;
		}
		auto callback = std::move(i->second.callback);
		const auto randomId = i->second.randomId;
		uploads.erase(i);
		auto token = QByteArray();
		do {
			const auto random = base::RandomValue<std::array<std::uint8_t, 16>>();
			token = QByteArray(
				reinterpret_cast<const char*>(random.data()),
				random.size());
		} while (uploaded.contains(token));
		uploaded.emplace(token, UploadedFile{
			.file = media.info.file,
			.randomId = randomId,
		});
		callback(
			TelegramTransport::UploadResult::Accepted,
			UploadedCarrierFile{ std::move(token) });
	}

	void uploadFailed(FullMsgId id) {
		const auto i = uploads.find(id);
		if (i == uploads.end()) {
			return;
		}
		auto callback = std::move(i->second.callback);
		uploads.erase(i);
		callback(TelegramTransport::UploadResult::RetryableError, {});
	}

	void sendUploadedDocument(
			std::uint64_t peerId,
			UploadedCarrierFile carrierFile,
			QString filename,
			QString mimeType,
			SendCallback callback) {
		if (!callback) {
			return;
		}
		const auto i = uploaded.find(carrierFile.backendToken);
		if (peerId != telegramPeerIdBinding
			|| !carrierMetadata(filename, mimeType)
			|| i == uploaded.end()) {
			callback(TelegramTransport::UploadResult::PermanentError);
			return;
		}
		const auto file = i->second.file;
		const auto randomId = i->second.randomId;
		uploaded.erase(i);
		using MediaFlag = MTPDinputMediaUploadedDocument::Flag;
		const auto media = MTP_inputMediaUploadedDocument(
			MTP_flags(MediaFlag::f_force_file),
			file,
			MTPInputFile(),
			MTP_string(mimeType),
			MTP_vector<MTPDocumentAttribute>(QVector<MTPDocumentAttribute>{
				MTP_documentAttributeFilename(MTP_string(filename)),
			}),
			MTP_vector<MTPInputDocument>(),
			MTPInputPhoto(),
			MTP_int(0),
			MTP_int(0));
		auto sharedCallback = std::make_shared<SendCallback>(
			std::move(callback));
		const auto requestId = api.request(MTPmessages_SendMedia(
			MTP_flags(MTPmessages_SendMedia::Flag(0)),
			session->data().history(PeerId(peerId))->peer->input(),
			MTPInputReplyTo(),
			media,
			MTP_string(QString()),
			MTP_long(randomId),
			MTPReplyMarkup(),
			MTPVector<MTPMessageEntity>(),
			MTPint(),
			MTPint(),
			MTPInputPeer(),
			MTPInputQuickReplyShortcut(),
			MTPlong(),
			MTPlong(),
			MTPSuggestedPost()
		)).done([weak = base::weak_ptr(this), sharedCallback](
				const MTPUpdates &updates) mutable {
			if (weak && *sharedCallback) {
				weak->session->api().applyUpdates(updates);
				base::take(*sharedCallback)(
					TelegramTransport::UploadResult::Accepted);
			}
		}).fail([weak = base::weak_ptr(this), sharedCallback](
				const MTP::Error &error) mutable {
			if (weak && *sharedCallback) {
				base::take(*sharedCallback)(ErrorResult(error));
			}
		}).send();
		base::call_delayed(
			kCarrierOperationTimeout,
			[weak = base::weak_ptr(this), sharedCallback, requestId] {
				if (weak && *sharedCallback) {
					weak->api.request(requestId).cancel();
					base::take(*sharedCallback)(
						TelegramTransport::UploadResult::RetryableError);
				}
			});
	}

	void downloadDocuments(
			std::uint64_t peerId,
			QByteArray cursor,
			int limit,
			DownloadCallback callback) {
		const auto offset = DecodeCursor(cursor);
		if (!callback) {
			return;
		} else if (peerId != telegramPeerIdBinding
			|| !offset
			|| limit <= 0
			|| limit > 100) {
			callback(TelegramTransport::UploadResult::PermanentError, {});
			return;
		} else if (download) {
			callback(TelegramTransport::UploadResult::RetryableError, {});
			return;
		}
		download = PendingDownload{
			.callback = std::move(callback),
			.nextCursor = {},
			.directory = std::make_unique<QTemporaryDir>(),
			.entries = {},
			.objects = {},
			.complete = false,
		};
		if (!download->directory->isValid()) {
			finishDownload(TelegramTransport::UploadResult::RetryableError);
			return;
		}
		if (++downloadToken == 0) {
			++downloadToken;
		}
		const auto token = downloadToken;
		downloadRequestId = api.request(MTPmessages_Search(
			MTP_flags(MTPmessages_Search::Flag(0)),
			session->data().history(PeerId(peerId))->peer->input(),
			MTP_string(protectedCarrierFamily ? QString() : filename),
			MTP_inputPeerEmpty(),
			MTPInputPeer(),
			MTPVector<MTPReaction>(),
			MTP_int(0),
			MTP_inputMessagesFilterDocument(),
			MTP_int(0),
			MTP_int(0),
			MTP_int(*offset),
			MTP_int(0),
			MTP_int(limit),
			MTP_int(0),
			MTP_int(minimumMessageIdExclusive),
			MTP_long(0)
		)).done([weak = base::weak_ptr(this), limit, token](
				const MTPmessages_Messages &result) {
			if (weak
				&& weak->download
				&& weak->downloadToken == token) {
				weak->downloadRequestId = 0;
				weak->historyLoaded(result, limit);
			}
		}).fail([weak = base::weak_ptr(this), token](
				const MTP::Error &error) {
			if (weak
				&& weak->download
				&& weak->downloadToken == token) {
				weak->downloadRequestId = 0;
				weak->finishDownload(ErrorResult(error));
			}
		}).send();
		base::call_delayed(
			kCarrierOperationTimeout,
			[weak = base::weak_ptr(this), token] {
				if (weak) {
					weak->downloadTimedOut(token);
				}
			});
	}

	void downloadTimedOut(std::uint64_t token) {
		if (!download || token != downloadToken) {
			return;
		}
		if (downloadRequestId) {
			api.request(base::take(downloadRequestId)).cancel();
		}
		finishDownload(TelegramTransport::UploadResult::RetryableError);
	}

	void findDocument(
			std::uint64_t peerId,
			DiscoveryCallback callback) {
		if (!callback) {
			return;
		} else if (peerId != telegramPeerIdBinding) {
			callback(TelegramTransport::UploadResult::PermanentError, false);
			return;
		} else if (discovery) {
			callback(TelegramTransport::UploadResult::RetryableError, false);
			return;
		}
		discovery = std::move(callback);
		if (++discoveryToken == 0) {
			++discoveryToken;
		}
		const auto token = discoveryToken;
		discoveryRequestId = api.request(MTPmessages_Search(
			MTP_flags(MTPmessages_Search::Flag(0)),
			session->data().history(PeerId(peerId))->peer->input(),
			MTP_string(filename),
			MTP_inputPeerEmpty(),
			MTPInputPeer(),
			MTPVector<MTPReaction>(),
			MTP_int(0),
			MTP_inputMessagesFilterDocument(),
			MTP_int(0),
			MTP_int(0),
			MTP_int(0),
			MTP_int(0),
			MTP_int(kDiscoverySearchLimit),
			MTP_int(0),
			MTP_int(0),
			MTP_long(0)
		)).done([weak = base::weak_ptr(this), token](
				const MTPmessages_Messages &result) {
			if (weak
				&& weak->discovery
				&& weak->discoveryToken == token) {
				weak->discoveryRequestId = 0;
				weak->discoveryLoaded(result);
			}
		}).fail([weak = base::weak_ptr(this), token](
				const MTP::Error &error) {
			if (weak
				&& weak->discovery
				&& weak->discoveryToken == token) {
				weak->discoveryRequestId = 0;
				weak->finishDiscovery(ErrorResult(error), false);
			}
		}).send();
		const auto requestId = discoveryRequestId;
		base::call_delayed(
			kDiscoveryTimeout,
			[weak = base::weak_ptr(this), requestId, token] {
				if (weak) {
					weak->discoveryTimedOut(requestId, token);
				}
			});
	}

	void discoveryTimedOut(
			mtpRequestId requestId,
			std::uint64_t token) {
		if (!discovery
			|| discoveryRequestId != requestId
			|| discoveryToken != token) {
			return;
		}
		api.request(base::take(discoveryRequestId)).cancel();
		finishDiscovery(
			TelegramTransport::UploadResult::RetryableError,
			false);
	}

	void discoveryLoaded(const MTPmessages_Messages &result) {
		if (!discovery) {
			return;
		}
		auto messages = QVector<MTPMessage>();
		auto complete = false;
		auto valid = true;
		result.match([&](const MTPDmessages_messages &data) {
			session->data().processUsers(data.vusers());
			session->data().processChats(data.vchats());
			messages = data.vmessages().v;
			valid = messages.size() <= kDiscoverySearchLimit;
			complete = valid;
		}, [&](const MTPDmessages_messagesSlice &data) {
			session->data().processUsers(data.vusers());
			session->data().processChats(data.vchats());
			messages = data.vmessages().v;
			valid = messages.size() <= kDiscoverySearchLimit
				&& data.vcount().v >= int(messages.size());
			complete = valid && data.vcount().v == int(messages.size());
		}, [&](const MTPDmessages_channelMessages &data) {
			session->data().processUsers(data.vusers());
			session->data().processChats(data.vchats());
			messages = data.vmessages().v;
			valid = messages.size() <= kDiscoverySearchLimit
				&& data.vcount().v >= int(messages.size());
			complete = valid && data.vcount().v == int(messages.size());
		}, [&](const MTPDmessages_messagesNotModified &) {
			valid = false;
		});
		if (!valid) {
			finishDiscovery(
				TelegramTransport::UploadResult::RetryableError,
				false);
			return;
		}
		for (const auto &message : messages) {
			const auto messagePeerId = PeerFromMessage(message);
			if (!IdFromMessage(message)
				|| messagePeerId != peerId
				|| !session->data().peerLoaded(messagePeerId)
				|| !DateFromMessage(message)) {
				continue;
			}
			const auto item = session->data().addNewMessage(
				message,
				MessageFlags(),
				NewMessageType::Existing);
			const auto media = item ? item->media() : nullptr;
			const auto document = media ? media->document() : nullptr;
			if (document && carrierMetadata(
					document->filename(),
					document->mimeString())
				&& document->size > 0
				&& document->size <= maximumObjectSize) {
				finishDiscovery(
					TelegramTransport::UploadResult::Accepted,
					true);
				return;
			}
		}
		finishDiscovery(
			complete
				? TelegramTransport::UploadResult::Accepted
				: TelegramTransport::UploadResult::RetryableError,
			false);
	}

	void finishDiscovery(
			TelegramTransport::UploadResult result,
			bool present) {
		if (!discovery) {
			return;
		}
		auto callback = std::move(*discovery);
		discovery.reset();
		discoveryRequestId = 0;
		callback(result, present);
	}

	void historyLoaded(const MTPmessages_Messages &result, int limit) {
		if (!download) {
			return;
		}
		auto messages = QVector<MTPMessage>();
		auto valid = true;
		result.match([&](const MTPDmessages_messages &data) {
			session->data().processUsers(data.vusers());
			session->data().processChats(data.vchats());
			messages = data.vmessages().v;
			valid = messages.size() <= limit;
		}, [&](const MTPDmessages_messagesSlice &data) {
			session->data().processUsers(data.vusers());
			session->data().processChats(data.vchats());
			messages = data.vmessages().v;
			valid = messages.size() <= limit
				&& data.vcount().v >= int(messages.size());
		}, [&](const MTPDmessages_channelMessages &data) {
			session->data().processUsers(data.vusers());
			session->data().processChats(data.vchats());
			if (const auto channel = session->data().peer(peerId)->asChannel()) {
				channel->ptsReceived(data.vpts().v);
			}
			messages = data.vmessages().v;
			valid = messages.size() <= limit
				&& data.vcount().v >= int(messages.size());
		}, [&](const MTPDmessages_messagesNotModified &) {
			valid = false;
		});
		if (!valid) {
			finishDownload(TelegramTransport::UploadResult::RetryableError);
			return;
		}
		download->complete = messages.size() < limit;
		auto retainedBytes = std::int64_t();
		for (const auto &message : messages) {
			const auto messageId = IdFromMessage(message);
			if (!messageId) {
				continue;
			}
			const auto peerId = PeerFromMessage(message);
			if (peerId != this->peerId
				|| !session->data().peerLoaded(peerId)
				|| !DateFromMessage(message)) {
				download->nextCursor = EncodeCursor(messageId);
				continue;
			}
			const auto item = session->data().addNewMessage(
				message,
				MessageFlags(),
				NewMessageType::Existing);
			if (!item) {
				download->nextCursor = EncodeCursor(messageId);
				continue;
			}
			const auto media = item->media();
			const auto document = media ? media->document() : nullptr;
			if (!document
				|| !carrierMetadata(
					document->filename(),
					document->mimeString())
				|| document->size <= 0
				|| document->size > maximumObjectSize) {
				download->nextCursor = EncodeCursor(messageId);
				continue;
			}
			if (retainedBytes + document->size
					> maximumDownloadPageBytes) {
				download->complete = false;
				break;
			}
			retainedBytes += document->size;
			download->nextCursor = EncodeCursor(messageId);
			const auto path = download->directory->filePath(
				QString::number(download->entries.size()) + u".tde2e"_q);
			auto documentMedia = document->createMediaView();
			download->entries.push_back({
				.document = document,
				.media = std::move(documentMedia),
				.messageId = item->fullId(),
				.path = path,
				.senderTelegramUserIdBinding = peerIsUser(item->from()->id)
					? peerToUser(item->from()->id).bare
					: 0,
			});
		}
		if (download->entries.empty()) {
			finishDownload(TelegramTransport::UploadResult::Accepted);
			return;
		}
		startingDownloads = true;
		for (auto i = download->entries.begin();
				i != download->entries.end();
				++i) {
			if (std::any_of(
					download->entries.begin(),
					i,
					[&](const DownloadEntry &entry) {
						return entry.document == i->document;
					})
				|| i->media->loaded(true)
				|| i->document->loading()) {
				continue;
			}
			i->ownedDownload = true;
			i->document->save(
				Data::FileOrigin(i->messageId),
				i->path);
		}
		startingDownloads = false;
		collectDownloaded();
	}

	void downloadProgress(not_null<DocumentData*> document) {
		if (!startingDownloads && download && std::any_of(
			download->entries.begin(),
			download->entries.end(),
			[&](const DownloadEntry &entry) {
				return entry.document == document;
			})) {
			collectDownloaded();
		}
	}

	void collectDownloaded() {
		if (!download) {
			return;
		}
		auto objects = std::vector<TelegramTransport::UntrustedObject>();
		objects.reserve(download->entries.size());
		for (const auto &entry : download->entries) {
			if (!entry.media->loaded(true)) {
				if (!entry.document->loading()) {
					finishDownload(
						TelegramTransport::UploadResult::RetryableError);
				}
				return;
			}
			auto bytes = entry.media->bytes();
			if (bytes.isEmpty()) {
				auto location = Core::FileLocation();
				auto path = entry.path;
				const auto accessEnabled = !entry.ownedDownload;
				if (accessEnabled) {
					location = entry.document->location(true);
					if (!location.accessEnable()) {
						finishDownload(
							TelegramTransport::UploadResult::RetryableError);
						return;
					}
					path = location.name();
				}
				const auto accessGuard = qScopeGuard([&] {
					if (accessEnabled) {
						location.accessDisable();
					}
				});
				auto file = QFile(path);
				if (!file.open(QIODevice::ReadOnly)) {
					finishDownload(
						TelegramTransport::UploadResult::RetryableError);
					return;
				}
				const auto size = file.size();
				if (size <= 0
					|| size != entry.document->size
					|| size > maximumObjectSize) {
					finishDownload(
						TelegramTransport::UploadResult::RetryableError);
					return;
				}
				bytes = file.read(size);
				if (bytes.size() != size) {
					finishDownload(
						TelegramTransport::UploadResult::RetryableError);
					return;
				}
			}
			if (bytes.isEmpty()
				|| bytes.size() > maximumObjectSize) {
				finishDownload(
					TelegramTransport::UploadResult::PermanentError);
				return;
			}
			objects.push_back({
				.bytes = std::move(bytes),
				.observedTelegramPeerIdBinding = telegramPeerIdBinding,
				.observedSenderTelegramUserIdBinding =
					entry.senderTelegramUserIdBinding,
				.observedMessageId = entry.messageId.msg.bare,
			});
		}
		download->objects = std::move(objects);
		finishDownload(TelegramTransport::UploadResult::Accepted);
	}

	void finishDownload(TelegramTransport::UploadResult result) {
		if (!download) {
			return;
		}
		if (downloadRequestId) {
			api.request(base::take(downloadRequestId)).cancel();
		}
		auto pending = std::move(*download);
		download.reset();
		auto callback = std::move(pending.callback);
		auto page = CarrierDownloadPage();
		if (result == TelegramTransport::UploadResult::Accepted) {
			page.untrustedObjects = std::move(pending.objects);
			page.nextCursor = std::move(pending.nextCursor);
			page.complete = pending.complete;
		}
		for (const auto &entry : pending.entries) {
			if (result != TelegramTransport::UploadResult::Accepted
				&& entry.ownedDownload
				&& entry.document->loading()) {
				entry.document->cancel();
			}
			if (entry.ownedDownload) {
				entry.document->clearLocation();
			}
		}
		callback(result, std::move(page));
	}

	const not_null<Main::Session*> session;
	const PeerId peerId;
	const std::uint64_t telegramPeerIdBinding = 0;
	const QString filename;
	const QString mimeType;
	const int maximumObjectSize = 0;
	const int maximumDownloadPageBytes = 0;
	const int minimumMessageIdExclusive = 0;
	const bool protectedCarrierFamily = false;
	MTP::Sender api;
	std::map<FullMsgId, PendingUpload> uploads;
	std::map<QByteArray, UploadedFile> uploaded;
	std::optional<PendingDownload> download;
	mtpRequestId downloadRequestId = 0;
	std::uint64_t downloadToken = 0;
	std::optional<DiscoveryCallback> discovery;
	mtpRequestId discoveryRequestId = 0;
	std::uint64_t discoveryToken = 0;
	bool startingDownloads = false;
	rpl::lifetime lifetime;
};

TelegramSessionCarrierBackend::TelegramSessionCarrierBackend(
		not_null<Main::Session*> session,
		not_null<History*> history,
		std::uint64_t telegramPeerIdBinding)
: _state(std::make_unique<State>(
	  session,
	  history,
	  telegramPeerIdBinding,
	  ProtectedLegacyCarrierFilename(),
	  ProtectedCarrierMimeType(),
	  kMaximumCarrierObjectSize,
	  kMaximumDownloadPageBytes,
	  0,
	  true)) {
}

TelegramSessionCarrierBackend::TelegramSessionCarrierBackend(
		not_null<Main::Session*> session,
		not_null<History*> history,
		std::uint64_t telegramPeerIdBinding,
		QString filename,
		QString mimeType,
		int maximumObjectSize,
		int maximumDownloadPageBytes,
		int minimumMessageIdExclusive)
: _state((!filename.isEmpty()
		&& !mimeType.isEmpty()
		&& maximumObjectSize > 0
		&& maximumObjectSize <= kMaximumCarrierObjectSize
		&& maximumDownloadPageBytes >= maximumObjectSize
		&& maximumDownloadPageBytes <= kMaximumDownloadPageBytes
		&& minimumMessageIdExclusive >= 0)
		? std::make_unique<State>(
			session,
			history,
			telegramPeerIdBinding,
			std::move(filename),
			std::move(mimeType),
			maximumObjectSize,
			maximumDownloadPageBytes,
			minimumMessageIdExclusive,
			false)
		: nullptr) {
}

TelegramSessionCarrierBackend::~TelegramSessionCarrierBackend() = default;

void TelegramSessionCarrierBackend::uploadDocument(
		QByteArray bytes,
		QString filename,
		QString mimeType,
		UploadCallback callback) {
	if (!_state) {
		if (callback) {
			callback(TelegramTransport::UploadResult::PermanentError, {});
		}
		return;
	}
	_state->uploadDocument(
		std::move(bytes),
		std::move(filename),
		std::move(mimeType),
		std::move(callback));
}

void TelegramSessionCarrierBackend::sendUploadedDocument(
		std::uint64_t telegramPeerId,
		UploadedCarrierFile file,
		QString filename,
		QString mimeType,
		SendCallback callback) {
	if (!_state) {
		if (callback) {
			callback(TelegramTransport::UploadResult::PermanentError);
		}
		return;
	}
	_state->sendUploadedDocument(
		telegramPeerId,
		std::move(file),
		std::move(filename),
		std::move(mimeType),
		std::move(callback));
}

void TelegramSessionCarrierBackend::downloadDocuments(
		std::uint64_t telegramPeerId,
		QByteArray cursor,
		int limit,
		DownloadCallback callback) {
	if (!_state) {
		if (callback) {
			callback(TelegramTransport::UploadResult::PermanentError, {});
		}
		return;
	}
	_state->downloadDocuments(
		telegramPeerId,
		std::move(cursor),
		limit,
		std::move(callback));
}

void TelegramSessionCarrierBackend::findDocument(
		std::uint64_t telegramPeerId,
		DiscoveryCallback callback) {
	if (!_state) {
		if (callback) {
			callback(TelegramTransport::UploadResult::PermanentError, false);
		}
		return;
	}
	_state->findDocument(telegramPeerId, std::move(callback));
}

} // namespace E2ECloud

/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "e2e_cloud/desktop/desktop_service.h"

#include "base/call_delayed.h"
#include "base/unixtime.h"
#include "crl/crl.h"
#include "core/application.h"
#include "data/data_session.h"
#include "data/data_peer.h"
#include "data/data_document.h"
#include "data/data_document_media.h"
#include "e2e_cloud/archive/archive_epoch_crypto.h"
#include "e2e_cloud/archive/archived_content_reader.h"
#include "e2e_cloud/archive/archived_content_outbox.h"
#include "e2e_cloud/archive/history_grant_service.h"
#include "e2e_cloud/archive/persistent_archive_state.h"
#include "e2e_cloud/content/protected_message_body.h"
#include "e2e_cloud/files/file_chunk_file_store.h"
#include "e2e_cloud/files/file_chunk_envelope.h"
#include "e2e_cloud/files/persistent_file_transfer.h"
#include "e2e_cloud/files/private_file_manifest.h"
#include "e2e_cloud/group/persistent_group_ledger.h"
#include "e2e_cloud/identity/safety_gossip.h"
#include "e2e_cloud/mls/key_package_lifecycle.h"
#include "e2e_cloud/mls/mls_outbox_reconciler.h"
#include "e2e_cloud/mls/observed_key_package.h"
#include "e2e_cloud/mls/openmls_application_engine.h"
#include "e2e_cloud/mls/openmls_group_change_engine.h"
#include "e2e_cloud/mls/openmls_inbound_group_change.h"
#include "e2e_cloud/protocol/group_bootstrap.h"
#include "e2e_cloud/protocol/group_bootstrap_transaction.h"
#include "e2e_cloud/protocol/group_change_transaction.h"
#include "e2e_cloud/protocol/freshness_protocol.h"
#include "e2e_cloud/protocol/observed_group_change_sync.h"
#include "e2e_cloud/protocol/observed_content_processor.h"
#include "e2e_cloud/protocol/public_join_catchup.h"
#include "e2e_cloud/storage/aes_gcm_local_record_protector.h"
#include "e2e_cloud/storage/file_atomic_blob_store.h"
#include "e2e_cloud/storage/local_record_key_derivation.h"
#include "e2e_cloud/storage/persistent_conversation_metadata.h"
#include "e2e_cloud/storage/persistent_content_sync_state.h"
#include "e2e_cloud/storage/persistent_control_observation_state.h"
#include "e2e_cloud/storage/persistent_freshness_trust.h"
#include "e2e_cloud/storage/persistent_inbound_journal.h"
#include "e2e_cloud/storage/persistent_key_package_pool.h"
#include "e2e_cloud/storage/persistent_mls_state.h"
#include "e2e_cloud/storage/persistent_outbox.h"
#include "e2e_cloud/transport/telegram_carrier_transport.h"
#include "e2e_cloud/transport/file_chunk_download_controller.h"
#include "e2e_cloud/transport/observed_content_sync_controller.h"
#include "e2e_cloud/transport/outbox_upload_controller.h"
#include "main/main_session.h"
#include "history/history.h"
#include "history/history_item.h"
#include "lang/lang_keys.h"
#include "storage/storage_account.h"
#include "storage/localimageloader.h"
#include "ui/chat/attach/attach_prepare.h"
#include "ui/image/image_location_factory.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <QtCore/QBuffer>
#include <QtCore/QDir>
#include <QtCore/QFile>
#include <QtCore/QFileInfo>
#include <QtCore/QMimeDatabase>
#include <QtCore/QSaveFile>
#include <QtCore/QScopeGuard>
#include <QtGui/QImage>
#include <QtGui/QImageReader>

#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <limits>
#include <set>
#include <utility>

namespace E2ECloud {
namespace {

inline constexpr auto kControlSyncOverlap = std::size_t(32);
inline constexpr auto kProtectedPeersPref = "e2e_cloud_protected_peers_v1";
inline constexpr auto kMaximumProtectedPeerMarkers = std::size_t(65'536);
inline constexpr auto kProtectedPeerMarkerMagic = std::array<std::uint8_t, 8>{
	'T', 'D', 'E', '2', 'E', 'P', 'P', '1'
};

void AppendUint32(QByteArray &result, std::uint32_t value) {
	result.append(char(value >> 24));
	result.append(char(value >> 16));
	result.append(char(value >> 8));
	result.append(char(value));
}

void AppendUint64(QByteArray &result, std::uint64_t value) {
	for (auto shift = 56; shift >= 0; shift -= 8) {
		result.append(char(value >> shift));
	}
}

[[nodiscard]] std::uint32_t ReadUint32(const std::uint8_t *bytes) {
	return (std::uint32_t(bytes[0]) << 24)
		| (std::uint32_t(bytes[1]) << 16)
		| (std::uint32_t(bytes[2]) << 8)
		| std::uint32_t(bytes[3]);
}

[[nodiscard]] std::uint64_t ReadUint64(const std::uint8_t *bytes) {
	auto result = std::uint64_t();
	for (auto i = 0; i != 8; ++i) {
		result = (result << 8) | bytes[i];
	}
	return result;
}

[[nodiscard]] QByteArray EncodeProtectedPeerMarkers(
		std::uint64_t telegramUserIdBinding,
		const std::set<std::uint64_t> &peers) {
	auto result = QByteArray();
	result.reserve(int(
		kProtectedPeerMarkerMagic.size()
		+ 8
		+ 4
		+ (peers.size() * 8)));
	result.append(
		reinterpret_cast<const char*>(kProtectedPeerMarkerMagic.data()),
		kProtectedPeerMarkerMagic.size());
	AppendUint64(result, telegramUserIdBinding);
	AppendUint32(result, std::uint32_t(peers.size()));
	for (const auto peer : peers) {
		AppendUint64(result, peer);
	}
	return result;
}

[[nodiscard]] auto DecodeProtectedPeerMarkers(
		const QByteArray &encoded,
		std::uint64_t telegramUserIdBinding)
-> std::optional<std::set<std::uint64_t>> {
	if (encoded.isEmpty()) {
		return std::set<std::uint64_t>();
	}
	constexpr auto kHeaderSize = std::size_t(8 + 8 + 4);
	if (encoded.size() < 0 || std::size_t(encoded.size()) < kHeaderSize) {
		return std::nullopt;
	}
	const auto bytes = reinterpret_cast<const std::uint8_t*>(
		encoded.constData());
	if (!std::equal(
			begin(kProtectedPeerMarkerMagic),
			end(kProtectedPeerMarkerMagic),
			bytes)
		|| ReadUint64(bytes + 8) != telegramUserIdBinding) {
		return std::nullopt;
	}
	const auto count = std::size_t(ReadUint32(bytes + 16));
	if (count > kMaximumProtectedPeerMarkers
		|| std::size_t(encoded.size()) != kHeaderSize + (count * 8)) {
		return std::nullopt;
	}
	auto result = std::set<std::uint64_t>();
	auto previous = std::uint64_t();
	for (auto i = std::size_t(); i != count; ++i) {
		const auto peer = ReadUint64(bytes + kHeaderSize + (i * 8));
		if (!peer || (i && peer <= previous)) {
			return std::nullopt;
		}
		result.emplace(peer);
		previous = peer;
	}
	return result;
}

[[nodiscard]] Argon2idConfig DesktopArgon2idConfig() {
	return {
		.parameterVersion = 1,
		.memoryKibibytes = 64 * 1024,
		.iterations = 3,
		.parallelism = 1,
	};
}

void SelectCloudVaultOffMain(
		std::vector<QByteArray> candidates,
		QByteArray password,
		std::uint64_t telegramUserIdBinding,
		std::optional<CloudVaultAnchor> localAnchor,
		CloudVaultSyncController::SelectionCompletion completion) {
	crl::async([
		candidates = std::move(candidates),
		password = std::move(password),
		telegramUserIdBinding,
		localAnchor,
		completion = std::move(completion)
	]() mutable {
		auto passwordKdf = Argon2idPasswordKdf();
		auto sha256 = OpenSslSha256Provider();
		auto codec = CloudVaultCodecV1(passwordKdf, sha256);
		auto selector = CloudVaultSelector(codec, sha256);
		auto result = selector.select(
			std::move(candidates),
			std::move(password),
			telegramUserIdBinding,
			localAnchor);
		crl::on_main([
			completion = std::move(completion),
			result = std::move(result)
		]() mutable {
			completion(std::move(result));
		});
	});
}

void CreateCloudVaultOffMain(
		std::uint64_t telegramUserIdBinding,
		QByteArray password,
		Argon2idConfig config,
		std::function<void(std::optional<CreatedCloudVault>)> completion) {
	crl::async([
		telegramUserIdBinding,
		password = std::move(password),
		config,
		completion = std::move(completion)
	]() mutable {
		auto passwordKdf = Argon2idPasswordKdf();
		auto sha256 = OpenSslSha256Provider();
		auto codec = CloudVaultCodecV1(passwordKdf, sha256);
		auto identity = GenerateAccountPrivateIdentity();
		auto result = identity
			? codec.create(
				telegramUserIdBinding,
				std::move(*identity),
				std::move(password),
				config)
			: std::nullopt;
		crl::on_main([
			completion = std::move(completion),
			result = std::move(result)
		]() mutable {
			completion(std::move(result));
		});
	});
}

template <typename Id>
[[nodiscard]] std::optional<Id> RandomId() {
	auto result = Id();
	return (RAND_bytes(result.bytes.data(), result.bytes.size()) == 1
		&& bool(result))
		? std::optional<Id>(result)
		: std::nullopt;
}

[[nodiscard]] QString ConversationDirectory(
		std::uint64_t telegramUserIdBinding,
		ConversationId conversationId) {
	const auto encoded = QByteArray(
		reinterpret_cast<const char*>(conversationId.bytes.data()),
		int(conversationId.bytes.size())).toHex();
	return cWorkingDir()
		+ u"tdata/e2e_cloud/"_q
		+ QString::number(telegramUserIdBinding)
		+ u"/"_q
		+ QString::fromLatin1(encoded)
		+ u"/"_q;
}

[[nodiscard]] QString StagedProtectedImageDirectory(
		std::uint64_t telegramUserIdBinding,
		ConversationId conversationId) {
	return ConversationDirectory(telegramUserIdBinding, conversationId)
		+ u"staged-images/"_q;
}

[[nodiscard]] QString StagedProtectedFileDirectory(
		std::uint64_t telegramUserIdBinding,
		ConversationId conversationId) {
	return ConversationDirectory(telegramUserIdBinding, conversationId)
		+ u"staged-files/"_q;
}

[[nodiscard]] bool IsStagedProtectedImage(
		std::uint64_t telegramUserIdBinding,
		ConversationId conversationId,
		const QString &path) {
	const auto info = QFileInfo(path);
	const auto directory = QDir::cleanPath(
		StagedProtectedImageDirectory(
			telegramUserIdBinding,
			conversationId));
	return QDir::cleanPath(info.absolutePath()) == directory
		&& info.fileName().startsWith(u"image-"_q)
		&& info.fileName().endsWith(u".png"_q);
}

[[nodiscard]] bool IsStagedProtectedFile(
		std::uint64_t telegramUserIdBinding,
		ConversationId conversationId,
		const QString &path) {
	const auto info = QFileInfo(path);
	const auto directory = QDir::cleanPath(
		StagedProtectedFileDirectory(
			telegramUserIdBinding,
			conversationId));
	return QDir::cleanPath(info.absolutePath()) == directory
		&& info.fileName().startsWith(u"file-"_q)
		&& info.fileName().endsWith(u".source"_q);
}

[[nodiscard]] bool IsStagedProtectedSource(
		std::uint64_t telegramUserIdBinding,
		ConversationId conversationId,
		const QString &path) {
	return IsStagedProtectedImage(
		telegramUserIdBinding,
		conversationId,
		path) || IsStagedProtectedFile(
		telegramUserIdBinding,
		conversationId,
		path);
}

void RemoveStagedProtectedSource(
		std::uint64_t telegramUserIdBinding,
		ConversationId conversationId,
		const QString &path) {
	if (IsStagedProtectedSource(
			telegramUserIdBinding,
			conversationId,
			path)) {
		QFile::remove(path);
	}
}

[[nodiscard]] std::optional<QString> PrepareStagedProtectedFile(
		std::uint64_t telegramUserIdBinding,
		ConversationId conversationId) {
	const auto id = RandomId<ObjectId>();
	if (!id) {
		return std::nullopt;
	}
	const auto directory = StagedProtectedFileDirectory(
		telegramUserIdBinding,
		conversationId);
	if (!QDir().mkpath(directory)) {
		return std::nullopt;
	}
	const auto encoded = QByteArray(
		reinterpret_cast<const char*>(id->bytes.data()),
		int(id->bytes.size())).toHex();
	return directory
		+ u"file-"_q
		+ QString::fromLatin1(encoded)
		+ u".source"_q;
}

void CleanupStagedProtectedSources(
		const QString &conversationDirectory,
		const QString &keepPath) {
	const auto keep = keepPath.isEmpty()
		? QString()
		: QDir::cleanPath(QFileInfo(keepPath).absoluteFilePath());
	for (const auto &name : { u"staged-files"_q, u"staged-images"_q }) {
		auto directory = QDir(conversationDirectory + name + u"/"_q);
		if (!directory.exists()) {
			continue;
		}
		const auto entries = directory.entryInfoList(
			QDir::Files
				| QDir::Hidden
				| QDir::System
				| QDir::NoDotAndDotDot);
		for (const auto &entry : entries) {
			if (keep.isEmpty()
				|| QDir::cleanPath(entry.absoluteFilePath()) != keep) {
				QFile::remove(entry.absoluteFilePath());
			}
		}
		if (directory.entryList(
			QDir::AllEntries | QDir::NoDotAndDotDot).isEmpty()) {
			QDir(conversationDirectory).rmdir(name);
		}
	}
}

[[nodiscard]] std::optional<QString> StageProtectedImage(
		std::uint64_t telegramUserIdBinding,
		ConversationId conversationId,
		const QImage &image) {
	const auto id = RandomId<ObjectId>();
	if (!id || image.isNull() || !image.size().isValid()) {
		return std::nullopt;
	}
	const auto directory = StagedProtectedImageDirectory(
		telegramUserIdBinding,
		conversationId);
	if (!QDir().mkpath(directory)) {
		return std::nullopt;
	}
	const auto encoded = QByteArray(
		reinterpret_cast<const char*>(id->bytes.data()),
		int(id->bytes.size())).toHex();
	const auto path = directory
		+ u"image-"_q
		+ QString::fromLatin1(encoded)
		+ u".png"_q;
	auto output = QSaveFile(path);
	if (!output.open(QIODevice::WriteOnly)) {
		return std::nullopt;
	}
	output.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner);
	if (!image.save(&output, "PNG") || !output.commit()) {
		output.cancelWriting();
		return std::nullopt;
	}
	return path;
}

bool DiscardUncommittedConversationDirectory(const QString &directory) {
	auto target = QDir(directory);
	return !target.exists() || target.removeRecursively();
}

[[nodiscard]] QString ConversationSetupMarker(const QString &directory) {
	return directory + u"setup.pending"_q;
}

[[nodiscard]] bool BeginConversationSetup(const QString &directory) {
	if (!QDir().mkpath(directory)) {
		return false;
	}
	auto file = QSaveFile(ConversationSetupMarker(directory));
	if (!file.open(QIODevice::WriteOnly)) {
		return false;
	}
	file.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner);
	const auto marker = QByteArray("TDE2ESETUP1");
	if (file.write(marker) != marker.size()) {
		file.cancelWriting();
		return false;
	}
	return file.commit();
}

[[nodiscard]] bool FinishConversationSetup(const QString &directory) {
	const auto marker = ConversationSetupMarker(directory);
	return !QFileInfo::exists(marker) || QFile::remove(marker);
}

[[nodiscard]] bool ConversationSetupPending(const QString &directory) {
	return QFileInfo::exists(ConversationSetupMarker(directory));
}

[[nodiscard]] bool IsProtectedGroupPeerBinding(
		not_null<Main::Session*> session,
		std::uint64_t telegramPeerIdBinding) {
	if (!telegramPeerIdBinding) {
		return false;
	}
	const auto peerId = PeerId(telegramPeerIdBinding);
	if (!peerIsChat(peerId) && !peerIsChannel(peerId)) {
		return false;
	}
	const auto peer = session->data().peerLoaded(peerId);
	return !peer || peer->isChat() || peer->isMegagroup();
}

[[nodiscard]] bool BootstrapMatchesConversation(
		const VerifiedPublicGroupBootstrap &verified,
		const CloudVaultConversation &conversation) {
	return verified.genesis.conversationId == conversation.conversationId
		&& verified.genesis.telegramPeerIdBinding
			== conversation.telegramPeerIdBinding
		&& verified.genesis.ownerAccountId == conversation.ownerAccountId
		&& verified.checkpoint.conversationId
			== conversation.conversationId
		&& PublicGroupBootstrapCanReachCheckpoint(
			verified,
			conversation.checkpoint);
}

[[nodiscard]] bool ValidConversationCheckpoint(
		const Checkpoint &checkpoint,
		ConversationId conversationId) {
	return checkpoint.conversationId == conversationId
		&& checkpoint.generation
		&& checkpoint.stateHash;
}

[[nodiscard]] QString AccountDirectory(
		std::uint64_t telegramUserIdBinding) {
	return cWorkingDir()
		+ u"tdata/e2e_cloud/"_q
		+ QString::number(telegramUserIdBinding)
		+ u"/"_q;
}

[[nodiscard]] QString CloudVaultAnchorPath(
		std::uint64_t telegramUserIdBinding) {
	return AccountDirectory(telegramUserIdBinding) + u"vault.anchor"_q;
}

[[nodiscard]] std::optional<ConversationId> DecodeConversationDirectory(
		const QString &name) {
	const auto encoded = name.toLatin1();
	if (encoded.size() != 64
		|| !std::all_of(
			encoded.begin(),
			encoded.end(),
			[](char value) {
				return std::isxdigit(static_cast<unsigned char>(value));
			})) {
		return std::nullopt;
	}
	const auto bytes = QByteArray::fromHex(encoded);
	if (bytes.size() != 32) {
		return std::nullopt;
	}
	auto result = ConversationId();
	std::copy_n(
		reinterpret_cast<const std::uint8_t*>(bytes.constData()),
		result.bytes.size(),
		result.bytes.begin());
	return result ? std::optional<ConversationId>(result) : std::nullopt;
}

void Cleanse(QByteArray &bytes) {
	if (!bytes.isEmpty()) {
		OPENSSL_cleanse(bytes.data(), bytes.size());
	}
	bytes.clear();
}

inline constexpr auto kProtectedFilePreviewSide = 320;
inline constexpr auto kProtectedFilePreviewQuality = 82;

struct ProtectedHistoryFile {
	QString filename;
	QString mimeType;
	std::uint64_t size = 0;
	std::optional<PrivateFilePreview> preview;
};

template <typename Id>
[[nodiscard]] QByteArray ProtectedHistoryIdBytes(Id id) {
	return QByteArray(
		reinterpret_cast<const char*>(id.bytes.data()),
		int(id.bytes.size()));
}

[[nodiscard]] DocumentId ProtectedHistoryDocumentId(
		ConversationId conversationId,
		ObjectId eventObjectId,
		const Sha256Provider &sha256) {
	auto input = QByteArray("TDE2E/protected-history-document/v1");
	input.append(ProtectedHistoryIdBytes(conversationId));
	input.append(ProtectedHistoryIdBytes(eventObjectId));
	const auto digest = sha256.digest(input);
	auto result = std::uint64_t();
	for (auto index = 0; index != 8; ++index) {
		result = (result << 8) | digest.bytes[index];
	}
	return result ? result : 1;
}

[[nodiscard]] not_null<DocumentData*> CreateProtectedHistoryDocument(
		not_null<Main::Session*> session,
		ConversationId conversationId,
		ObjectId eventObjectId,
		TimeId date,
		const ProtectedHistoryFile &file,
		const Sha256Provider &sha256) {
	auto attributes = QVector<MTPDocumentAttribute>{
		MTP_documentAttributeFilename(MTP_string(file.filename)),
	};
	auto thumbnail = ImageWithLocation();
	if (file.preview) {
		auto buffer = QBuffer();
		buffer.setData(file.preview->jpegBytes);
		if (buffer.open(QIODevice::ReadOnly)) {
			auto reader = QImageReader(&buffer, "JPG");
			const auto size = reader.size();
			if (size.isValid()
				&& size.width() <= kProtectedFilePreviewSide
				&& size.height() <= kProtectedFilePreviewSide) {
				auto image = reader.read();
				if (!image.isNull()) {
					thumbnail = Images::FromImageInMemory(
						image,
						"JPG",
						file.preview->jpegBytes);
				}
			}
		}
		if (file.mimeType.startsWith(u"video/"_q)) {
			attributes.push_back(MTP_documentAttributeVideo(
				MTP_flags(MTPDdocumentAttributeVideo::Flags(0)),
				MTP_double(file.preview->durationMilliseconds / 1000.),
				MTP_int(file.preview->width),
				MTP_int(file.preview->height),
				MTPint(),
				MTPdouble(),
				MTPstring()));
		} else {
			attributes.push_back(MTP_documentAttributeImageSize(
				MTP_int(file.preview->width),
				MTP_int(file.preview->height)));
		}
	}
	const auto result = session->data().document(
		ProtectedHistoryDocumentId(
			conversationId,
			eventObjectId,
			sha256),
		0,
		QByteArray(),
		date,
		attributes,
		file.mimeType,
		InlineImageLocation(),
		thumbnail,
		ImageWithLocation(),
		false,
		0,
		file.size);
	if (result->loading()) {
		result->cancel();
	}
	result->resetCancelled();
	result->status = FileReady;
	return result;
}

[[nodiscard]] ObjectId FreshnessResponseObjectId(
		ObjectId challengeObjectId,
		ClientId witnessClientId,
		const Sha256Provider &sha256) {
	auto input = QByteArray("TDE2E/freshness-response-object/v1");
	input.append(
		reinterpret_cast<const char*>(challengeObjectId.bytes.data()),
		challengeObjectId.bytes.size());
	input.append(
		reinterpret_cast<const char*>(witnessClientId.bytes.data()),
		witnessClientId.bytes.size());
	const auto digest = sha256.digest(input);
	auto result = ObjectId();
	std::copy(digest.bytes.begin(), digest.bytes.end(), result.bytes.begin());
	return result;
}

inline constexpr auto kDesktopFileChunkSize = std::uint32_t(1024 * 1024);
inline constexpr auto kFileDownloadPageBytes = 16 * 1024 * 1024;
inline constexpr auto kFileDownloadExtraObjects = std::uint64_t(1024);
inline constexpr auto kFileDownloadExtraPages = std::uint64_t(1024);
inline constexpr auto kFileDownloadExtraBytes
	= std::uint64_t(16) * 1024 * 1024;
inline constexpr auto kFileCleanupChunksPerTurn = std::uint32_t(64);
inline constexpr auto kFileRetryInitialDelay = crl::time(1000);
inline constexpr auto kFileRetryMaximumDelay = crl::time(30'000);
inline constexpr auto kFileDownloadMaximumRetries = 20;

[[nodiscard]] crl::time FileRetryDelay(int attempt) {
	const auto shift = std::min(attempt, 5);
	return std::min(
		kFileRetryMaximumDelay,
		kFileRetryInitialDelay * (crl::time(1) << shift));
}

struct HashedFile {
	std::uint64_t size = 0;
	Digest hash;
	std::optional<PrivateFilePreview> preview;
};

[[nodiscard]] std::optional<PrivateFilePreview> PrepareFilePreview(
		const QString &path,
		const QString &mimeType = QString()) {
	const auto mime = mimeType.isEmpty()
		? QMimeDatabase().mimeTypeForFile(
			path,
			QMimeDatabase::MatchExtension).name()
		: mimeType;
	auto information = FileLoadTask::ReadMediaInformation(
		path,
		QByteArray(),
		mime);
	if (!information) {
		return std::nullopt;
	}
	auto image = QImage();
	auto duration = crl::time();
	if (const auto data = std::get_if<Ui::PreparedFileInformation::Image>(
			&information->media)) {
		image = data->data;
	} else if (const auto data = std::get_if<
			Ui::PreparedFileInformation::Video>(&information->media)) {
		image = data->thumbnail;
		duration = std::max(data->duration, crl::time());
	} else if (const auto data = std::get_if<
			Ui::PreparedFileInformation::Song>(&information->media)) {
		image = data->cover;
		duration = std::max(data->duration, crl::time());
	}
	if (image.isNull() || image.width() <= 0 || image.height() <= 0) {
		return std::nullopt;
	}
	auto dimensions = image.size();
	if (dimensions.width() > kMaximumPrivateFilePreviewDimension
		|| dimensions.height() > kMaximumPrivateFilePreviewDimension) {
		dimensions.scale(
			kMaximumPrivateFilePreviewDimension,
			kMaximumPrivateFilePreviewDimension,
			Qt::KeepAspectRatio);
	}
	if (!dimensions.isValid() || dimensions.isEmpty()) {
		return std::nullopt;
	}
	if (image.width() > kProtectedFilePreviewSide
		|| image.height() > kProtectedFilePreviewSide) {
		image = image.scaled(
			kProtectedFilePreviewSide,
			kProtectedFilePreviewSide,
			Qt::KeepAspectRatio,
			Qt::SmoothTransformation);
	}
	auto bytes = QByteArray();
	auto buffer = QBuffer(&bytes);
	if (!buffer.open(QIODevice::WriteOnly)
		|| !image.save(&buffer, "JPG", kProtectedFilePreviewQuality)
		|| bytes.isEmpty()
		|| bytes.size() > kMaximumPrivateFilePreviewSize) {
		return std::nullopt;
	}
	return PrivateFilePreview{
		.width = std::uint32_t(dimensions.width()),
		.height = std::uint32_t(dimensions.height()),
		.durationMilliseconds = std::uint32_t(std::min<std::uint64_t>(
			std::uint64_t(duration),
			std::numeric_limits<std::uint32_t>::max())),
		.jpegBytes = std::move(bytes),
	};
}

[[nodiscard]] std::optional<HashedFile> HashFile(
		const QString &path,
		std::shared_ptr<std::atomic_bool> cancellation = nullptr,
		bool preparePreview = false,
		const QString &stagedPath = QString(),
		const QString &previewMimeType = QString()) {
	auto file = QFile(path);
	if (!file.open(QIODevice::ReadOnly)
		|| file.size() < 0
		|| std::uint64_t(file.size()) > kMaximumProtectedFileSize) {
		return std::nullopt;
	}
	const auto originalSize = file.size();
	auto staged = std::unique_ptr<QSaveFile>();
	if (!stagedPath.isEmpty()) {
		staged = std::make_unique<QSaveFile>(stagedPath);
		if (!staged->open(QIODevice::WriteOnly)) {
			return std::nullopt;
		}
		staged->setPermissions(
			QFileDevice::ReadOwner | QFileDevice::WriteOwner);
	}
	const auto context = EVP_MD_CTX_new();
	if (!context || EVP_DigestInit_ex(context, EVP_sha256(), nullptr) != 1) {
		EVP_MD_CTX_free(context);
		if (staged) {
			staged->cancelWriting();
		}
		return std::nullopt;
	}
	auto processed = qint64();
	auto ok = true;
	while (processed != originalSize) {
		if (cancellation
			&& cancellation->load(std::memory_order_relaxed)) {
			ok = false;
			break;
		}
		auto bytes = file.read(std::min<qint64>(
			kDesktopFileChunkSize,
			originalSize - processed));
		const auto size = bytes.size();
		const auto copied = !staged
			|| staged->write(bytes) == bytes.size();
		const auto updated = copied
			&& !bytes.isEmpty()
			&& EVP_DigestUpdate(
				context,
				bytes.constData(),
				bytes.size()) == 1;
		Cleanse(bytes);
		if (!updated) {
			ok = false;
			break;
		}
		processed += size;
	}
	auto result = HashedFile{
		.size = std::uint64_t(originalSize),
		.hash = {},
		.preview = {},
	};
	auto hashSize = 0U;
	ok = ok
		&& (!cancellation
			|| !cancellation->load(std::memory_order_relaxed))
		&& file.size() == originalSize
		&& EVP_DigestFinal_ex(
			context,
			result.hash.bytes.data(),
			&hashSize) == 1
		&& hashSize == result.hash.bytes.size();
	EVP_MD_CTX_free(context);
	auto stagedCommitted = false;
	if (ok && staged) {
		stagedCommitted = staged->commit();
		ok = stagedCommitted;
	} else if (staged) {
		staged->cancelWriting();
	}
	if (ok && preparePreview) {
		result.preview = PrepareFilePreview(
			stagedCommitted ? stagedPath : path,
			previewMimeType);
		ok = !cancellation
			|| !cancellation->load(std::memory_order_relaxed);
	}
	if (!ok && stagedCommitted) {
		QFile::remove(stagedPath);
	}
	return (ok && result.hash)
		? std::optional<HashedFile>(result)
		: std::nullopt;
}

} // namespace

struct DesktopService::PendingGroupCreation {
	enum class Phase {
		Creating,
		AwaitingAdmission,
		Active,
		Removed,
	};

	struct PendingFileDownload {
		struct PendingWrite {
			PendingWrite(
					std::unique_ptr<QSaveFile> output,
					EVP_MD_CTX *digest,
					PrivateFileManifest manifest)
			: output(std::move(output))
			, digest(digest)
			, manifest(std::move(manifest)) {
			}

			~PendingWrite() {
				EVP_MD_CTX_free(digest);
			}

			std::unique_ptr<QSaveFile> output;
			EVP_MD_CTX *digest = nullptr;
			PrivateFileManifest manifest;
			std::uint64_t written = 0;
			std::uint32_t nextChunkIndex = 0;
			std::uint32_t cleanupChunkIndex = 0;
			bool committed = false;
		};

		ObjectId eventObjectId;
		FileId fileId;
		QString path;
		std::set<std::uint32_t> missingChunkIndices;
		std::function<void(ProtectedFileSaveResult)> callback;
		std::unique_ptr<PendingWrite> write;
		std::uint64_t retryToken = 0;
		int retryAttempt = 0;
		int retryCount = 0;
		bool legacyCarrier = false;
	};

	PendingGroupCreation(
			QString directory,
			LocalRecordKey &&localRecordKey,
			not_null<Main::Session*> session,
			std::uint64_t telegramPeerIdBinding,
			ConversationId conversationId,
			const Sha256Provider &sha256)
	: conversationId(conversationId)
	, telegramPeerIdBinding(telegramPeerIdBinding)
	, directory(std::move(directory))
	, protector(std::move(localRecordKey))
	, metadataBlob(this->directory + u"conversation.meta"_q)
	, journalBlob(this->directory + u"bootstrap.wal"_q)
	, mlsBlob(this->directory + u"mls.state"_q)
	, archiveBlob(this->directory + u"archive.state"_q)
	, groupBlob(this->directory + u"group.state"_q)
	, outboxBlob(this->directory + u"outbox.state"_q)
	, changeJournalBlob(this->directory + u"group-change.wal"_q)
	, changeInboxBlob(this->directory + u"group-change-inbox.state"_q)
	, keyPackagePoolBlob(this->directory + u"key-packages.state"_q)
	, freshnessTrustBlob(this->directory + u"freshness-trust.state"_q)
	, inboundJournalBlob(this->directory + u"content-inbound.state"_q)
	, controlInboundJournalBlob(
		this->directory + u"control-inbound.state"_q)
	, contentIndexBlob(this->directory + u"content-index.state"_q)
	, controlSyncBlob(this->directory + u"control-sync.state"_q)
	, contentSyncBlob(this->directory + u"content-sync.state"_q)
	, fileTransferBlob(this->directory + u"file-transfer.state"_q)
	, metadata(metadataBlob, protector)
	, journal(journalBlob, protector)
	, mlsState(mlsBlob, protector)
	, archiveState(archiveBlob, protector)
	, groupLedger(groupBlob, protector, sha256)
	, outbox(outboxBlob, protector)
	, changeJournal(changeJournalBlob, protector)
	, changeInbox(
		changeInboxBlob,
		protector,
		envelopeCodec,
		sha256)
	, keyPackages(
		keyPackagePoolBlob,
		protector,
		envelopeCodec,
		sha256)
	, freshnessTrust(freshnessTrustBlob, protector)
	, inboundJournal(inboundJournalBlob, protector)
	, controlInboundJournal(
		controlInboundJournalBlob,
		protector,
		InboundJournalDomain::Control)
	, contentStore(
		conversationId,
		this->directory + u"content-records"_q,
		contentIndexBlob,
		protector,
		sha256)
	, controlSyncState(
		controlSyncBlob,
		protector)
	, contentSyncState(contentSyncBlob, protector)
	, fileTransfer(fileTransferBlob, protector)
	, chunkStore(this->directory + u"file-chunks"_q, protector)
	, backend(
		session,
		session->data().history(PeerId(telegramPeerIdBinding)),
		telegramPeerIdBinding)
	, transport(conversationId, telegramPeerIdBinding, backend)
	, controlBackend(
		session,
		session->data().history(PeerId(telegramPeerIdBinding)),
		telegramPeerIdBinding,
		ProtectedControlCarrierFilename(),
		ProtectedCarrierMimeType(),
		ProtectedCarrierMaximumObjectSize())
	, controlTransport(
		conversationId,
		telegramPeerIdBinding,
		controlBackend)
	, contentBackend(
		session,
		session->data().history(PeerId(telegramPeerIdBinding)),
		telegramPeerIdBinding,
		ProtectedContentCarrierFilename(),
		ProtectedCarrierMimeType(),
		ProtectedCarrierMaximumObjectSize())
	, contentTransport(
		conversationId,
		telegramPeerIdBinding,
		contentBackend) {
	}

	~PendingGroupCreation() {
		if (fileHashCancellation) {
			fileHashCancellation->store(true, std::memory_order_relaxed);
		}
		if (fileFinalHashCancellation) {
			fileFinalHashCancellation->store(true, std::memory_order_relaxed);
		}
	}

	ConversationId conversationId;
	std::uint64_t telegramPeerIdBinding = 0;
	QString directory;
	AesGcmLocalRecordProtector protector;
	FileAtomicBlobStore metadataBlob;
	FileAtomicBlobStore journalBlob;
	FileAtomicBlobStore mlsBlob;
	FileAtomicBlobStore archiveBlob;
	FileAtomicBlobStore groupBlob;
	FileAtomicBlobStore outboxBlob;
	FileAtomicBlobStore changeJournalBlob;
	FileAtomicBlobStore changeInboxBlob;
	FileAtomicBlobStore keyPackagePoolBlob;
	FileAtomicBlobStore freshnessTrustBlob;
	FileAtomicBlobStore inboundJournalBlob;
	FileAtomicBlobStore controlInboundJournalBlob;
	FileAtomicBlobStore contentIndexBlob;
	FileAtomicBlobStore controlSyncBlob;
	FileAtomicBlobStore contentSyncBlob;
	FileAtomicBlobStore fileTransferBlob;
	EnvelopeCodecV1 envelopeCodec;
	PersistentConversationMetadata metadata;
	PersistentGroupBootstrapJournal journal;
	PersistentMlsStateStore mlsState;
	PersistentArchiveState archiveState;
	PersistentGroupLedger groupLedger;
	PersistentOutboxStore outbox;
	PersistentGroupChangeJournal changeJournal;
	PersistentGroupChangeInbox changeInbox;
	PersistentKeyPackagePool keyPackages;
	PersistentFreshnessTrust freshnessTrust;
	PersistentInboundJournal inboundJournal;
	PersistentInboundJournal controlInboundJournal;
	PersistentContentStore contentStore;
	PersistentControlObservationState controlSyncState;
	PersistentContentSyncState contentSyncState;
	PersistentFileTransfer fileTransfer;
	FileChunkFileStore chunkStore;
	std::unique_ptr<FreshnessGate> freshnessGate;
	std::unique_ptr<OpenMlsApplicationEngine> applicationEngine;
	std::unique_ptr<OutboxCoordinator> outboxCoordinator;
	std::unique_ptr<OutboxUploadController> uploadController;
	TelegramSessionCarrierBackend backend;
	TelegramCarrierTransport transport;
	TelegramSessionCarrierBackend controlBackend;
	TelegramCarrierTransport controlTransport;
	TelegramSessionCarrierBackend contentBackend;
	TelegramCarrierTransport contentTransport;
	CloudVaultConversation conversation;
	Checkpoint joinTargetCheckpoint;
	std::optional<PreparedCloudVaultUpdate> vaultUpdate;
	std::unique_ptr<PublicBootstrapSyncController> observation;
	std::unique_ptr<ObservedContentSyncController> contentObservation;
	std::unique_ptr<TelegramSessionCarrierBackend> fileDownloadBackend;
	std::unique_ptr<TelegramCarrierTransport> fileDownloadTransport;
	std::unique_ptr<FileChunkDownloadController> fileDownloadController;
	std::optional<PendingFileDownload> pendingFileDownload;
	QString filePreparationPath;
	QString filePreparationFilename;
	QString filePreparationMimeType;
	std::optional<HashedFile> filePreparationSource;
	std::set<AccountId> safetyWitnesses;
	struct MaterializedHistoryEntry {
		ObjectId eventObjectId;
		ObjectId latestMutationEventObjectId;
		FullMsgId fullId;
	};
	std::vector<MaterializedHistoryEntry> materializedHistory;
	std::map<ObjectId, QString> localProtectedFilePaths;
	std::uint64_t materializedHistoryPeerIdBinding = 0;
	std::size_t materializedHistoryLimit = 0;
	std::uint64_t safetyWitnessGeneration = 0;
	std::uint64_t groupObservationRetryToken = 0;
	std::uint64_t fileRetryToken = 0;
	bool ownSafetyGossipObserved = false;
	bool observationDirty = false;
	bool contentObservationDirty = false;
	bool vaultPreflightRequired = true;
	bool uploadInProgress = false;
	bool fileHashInProgress = false;
	bool fileHashCancelRequested = false;
	bool fileFinalHashInProgress = false;
	bool queuedContentReconciled = false;
	int groupObservationRetryAttempt = 0;
	int fileRetryAttempt = 0;
	std::shared_ptr<std::atomic_bool> fileHashCancellation;
	std::shared_ptr<std::atomic_bool> fileFinalHashCancellation;
	Phase phase = Phase::Creating;
};

struct DesktopService::PendingGroupJoin {
	PendingGroupJoin(
			not_null<Main::Session*> session,
			CloudVaultConversation conversation)
	: conversation(conversation)
	, backend(
		session,
		session->data().history(PeerId(
			conversation.telegramPeerIdBinding)),
		conversation.telegramPeerIdBinding)
	, transport(
		conversation.conversationId,
		conversation.telegramPeerIdBinding,
		backend)
	, controlBackend(
		session,
		session->data().history(PeerId(
			conversation.telegramPeerIdBinding)),
		conversation.telegramPeerIdBinding,
		ProtectedControlCarrierFilename(),
		ProtectedCarrierMimeType(),
		ProtectedCarrierMaximumObjectSize())
	, controlTransport(
		conversation.conversationId,
		conversation.telegramPeerIdBinding,
		controlBackend) {
	}

	CloudVaultConversation conversation;
	EnvelopeCodecV1 envelopeCodec;
	TelegramSessionCarrierBackend backend;
	TelegramCarrierTransport transport;
	TelegramSessionCarrierBackend controlBackend;
	TelegramCarrierTransport controlTransport;
	std::unique_ptr<PublicBootstrapSyncController> sync;
};

struct DesktopService::PendingGroupDiscovery {
	PendingGroupDiscovery(
			not_null<Main::Session*> session,
			std::uint64_t telegramPeerIdBinding)
	: telegramPeerIdBinding(telegramPeerIdBinding)
	, backend(
		session,
		session->data().history(PeerId(telegramPeerIdBinding)),
		telegramPeerIdBinding,
		ProtectedControlCarrierFilename(),
		ProtectedCarrierMimeType(),
		ProtectedCarrierMaximumObjectSize()) {
	}

	std::uint64_t telegramPeerIdBinding = 0;
	EnvelopeCodecV1 envelopeCodec;
	TelegramSessionCarrierBackend backend;
	std::unique_ptr<PublicBootstrapDiscoveryController> sync;
};

enum class DesktopService::LocalGroupRecoveryResult {
	Missing,
	Complete,
	Restored,
	Invalid,
};

enum class DesktopService::FileTransferCancellationResult {
	Finished,
	RetryableCleanupFailure,
	Failure,
};

enum class DesktopService::QueuedContentRecoveryResult {
	Ready,
	Recovered,
	PersistenceFailed,
	Invalid,
};

DesktopService::DesktopService(not_null<Main::Session*> session)
: _session(session)
, _telegramUserIdBinding(session->userId().bare)
, _telegramSelfPeerId(session->userPeerId().value)
, _vaultCodec(_passwordKdf, _sha256)
, _vaultSelector(_vaultCodec, _sha256)
, _vaultAnchorBlob(CloudVaultAnchorPath(_telegramUserIdBinding))
, _vaultAnchor(_vaultAnchorBlob, _telegramUserIdBinding)
, _backend(std::make_unique<TelegramSessionCarrierBackend>(
	_session,
	_session->data().history(_session->userPeerId()),
	_telegramSelfPeerId,
	CloudVaultCarrierFilename(),
	CloudVaultCarrierMimeType(),
	CloudVaultMaximumCarrierSize()))
, _remote(std::make_unique<TelegramCloudVaultTransport>(
	_telegramSelfPeerId,
	*_backend)) {
	auto protectedPeers = DecodeProtectedPeerMarkers(
		_session->local().readPref<QByteArray>(kProtectedPeersPref),
		_telegramUserIdBinding);
	if (protectedPeers) {
		_presentationProtectedPeers = std::move(*protectedPeers);
	} else {
		_presentationProtectedPeersValid = false;
	}
	const auto anchorLoad = _vaultAnchor.load();
	if (anchorLoad == CloudVaultAnchorLoadResult::StorageError
		|| anchorLoad == CloudVaultAnchorLoadResult::InvalidSnapshot) {
		_vaultState = DesktopVaultState::SecurityBlocked;
	}
	_session->data().newItemAdded(
	) | rpl::on_next([weak = base::weak_ptr(this)](
			not_null<HistoryItem*> item) {
		if (weak) {
			weak->handleNewTelegramItem(item);
		}
	}, _lifetime);
	Core::App().passcodeLockValue(
	) | rpl::on_next([weak = base::weak_ptr(this)](bool locked) {
		if (locked && weak) {
			weak->lock();
		}
	}, _lifetime);
	_vaultState.value(
	) | rpl::on_next([weak = base::weak_ptr(this)](DesktopVaultState state) {
		if (state == DesktopVaultState::SecurityBlocked && weak) {
			weak->scheduleSecurityLock();
		}
	}, _lifetime);
}

DesktopService::~DesktopService() {
	if (_pendingGroupCreation) {
		clearMaterializedProtectedHistory(*_pendingGroupCreation);
	}
	for (const auto &entry : _groups) {
		clearMaterializedProtectedHistory(*entry.second);
		if (!entry.second->fileTransfer.pending()) {
			RemoveStagedProtectedSource(
				_telegramUserIdBinding,
				entry.first,
				entry.second->filePreparationPath);
		}
	}
	Cleanse(_pendingUnlockPassword);
	Cleanse(_unlockedPassword);
}

DesktopVaultState DesktopService::vaultState() const {
	return _vaultState.current();
}

rpl::producer<DesktopVaultState> DesktopService::vaultStateValue() const {
	return _vaultState.value();
}

const UnlockedCloudVault *DesktopService::vault() const {
	return vaultReady() ? &*_vault : nullptr;
}

bool DesktopService::vaultReady() const {
	return _vaultState.current() == DesktopVaultState::Ready && bool(_vault);
}

bool DesktopService::hasProtectedRuntimeState() const {
	return _vault
		|| _sync
		|| _pendingCreation
		|| _pendingGroupCreation
		|| _pendingGroupJoin
		|| _pendingGroupDiscovery
		|| !_groups.empty()
		|| !_pendingUnlockPassword.isEmpty()
		|| !_unlockedPassword.isEmpty();
}

void DesktopService::scheduleSecurityLock() {
	if (_securityLockScheduled || !hasProtectedRuntimeState()) {
		return;
	}
	_securityLockScheduled = true;
	crl::on_main([weak = base::weak_ptr(this)] {
		if (!weak) {
			return;
		}
		weak->_securityLockScheduled = false;
		if (weak->_vaultState.current() == DesktopVaultState::SecurityBlocked
			&& weak->hasProtectedRuntimeState()) {
			weak->lock();
		}
	});
}

void DesktopService::ensureVaultDiscovery() {
	const auto state = _vaultState.current();
	if (_sync
		|| !_vaultAnchor.loaded()
		|| (state != DesktopVaultState::Uninitialized
			&& state != DesktopVaultState::Missing
			&& state != DesktopVaultState::DiscoveryRetryableError
			&& state != DesktopVaultState::DiscoveryPermanentError)) {
		return;
	}
	_vaultState = DesktopVaultState::Discovering;
	_sync = std::make_unique<CloudVaultSyncController>(
		_telegramUserIdBinding,
		*_remote,
		_vaultSelector,
		[weak = base::weak_ptr(this)](CloudVaultSyncCompletion result) {
			if (weak) {
				weak->applyVaultDiscoveryResult(std::move(result));
			}
		},
		SelectCloudVaultOffMain);
	if (!_sync->startDiscovery()) {
		_sync.reset();
		_vaultState = DesktopVaultState::DiscoveryRetryableError;
	}
}

bool DesktopService::unlock(QByteArray password) {
	const auto state = _vaultState.current();
	if (_sync
		|| _pendingCreation
		|| !_vaultAnchor.loaded()
		|| (state != DesktopVaultState::Locked
			&& state != DesktopVaultState::WrongPasswordOrDamaged
			&& state != DesktopVaultState::RetryableTransportError
			&& state != DesktopVaultState::PermanentTransportError)
		|| password.isEmpty()) {
		return false;
	}
	Cleanse(_pendingUnlockPassword);
	_pendingUnlockPassword = password;
	_vault.reset();
	_vaultState = DesktopVaultState::Loading;
	_sync = std::make_unique<CloudVaultSyncController>(
		_telegramUserIdBinding,
		*_remote,
		_vaultSelector,
		[weak = base::weak_ptr(this)](CloudVaultSyncCompletion result) {
			if (weak) {
				weak->applySyncResult(std::move(result));
			}
		},
		SelectCloudVaultOffMain);
	if (!_sync->start(std::move(password), _vaultAnchor.anchor())) {
		_sync.reset();
		Cleanse(_pendingUnlockPassword);
		_vaultState = DesktopVaultState::Locked;
		return false;
	}
	return true;
}

bool DesktopService::createVault(QByteArray password) {
	if (_sync
		|| _pendingCreation
		|| _vault
		|| _vaultAnchor.anchor()
		|| _vaultState.current() != DesktopVaultState::Missing
		|| password.isEmpty()) {
		return false;
	}
	Cleanse(_pendingUnlockPassword);
	_pendingUnlockPassword = password;
	Cleanse(password);
	_vaultState = DesktopVaultState::Creating;
	_sync = std::make_unique<CloudVaultSyncController>(
		_telegramUserIdBinding,
		*_remote,
		_vaultSelector,
		[weak = base::weak_ptr(this)](CloudVaultSyncCompletion result) {
			if (weak) {
				weak->applyVaultCreationDiscoveryResult(
					std::move(result));
			}
		},
		SelectCloudVaultOffMain);
	const auto started = _sync->startDiscovery();
	if (!started) {
		_sync.reset();
		Cleanse(_pendingUnlockPassword);
		_vaultState = DesktopVaultState::DiscoveryRetryableError;
	}
	return started;
}

bool DesktopService::retryCreateVault() {
	if (!_pendingCreation
		|| _vaultState.current()
			!= DesktopVaultState::RetryableTransportError) {
		return false;
	}
	uploadPendingCreation();
	return true;
}

DesktopGroupCreationState DesktopService::groupCreationState() const {
	return _groupCreationState.current();
}

rpl::producer<DesktopGroupCreationState>
DesktopService::groupCreationStateValue() const {
	return _groupCreationState.value();
}

bool DesktopService::createProtectedGroup(
		not_null<PeerData*> peer,
		HistoryAccess defaultHistoryAccess) {
	const auto operationState = _groupCreationState.current();
	if (!_vault
		|| _vaultState.current() != DesktopVaultState::Ready
		|| (operationState != DesktopGroupCreationState::Idle
			&& operationState != DesktopGroupCreationState::Ready)
		|| _pendingGroupCreation
		|| _pendingGroupJoin
		|| _pendingGroupDiscovery
		|| (!peer->isChat() && !peer->isMegagroup())
		|| std::any_of(
			begin(_vault->conversations),
			end(_vault->conversations),
			[&](const CloudVaultConversation &conversation) {
				return conversation.telegramPeerIdBinding == peer->id.value;
			})
		|| !IsValidHistoryAccess(defaultHistoryAccess)) {
		return false;
	}
	_groupCreationState = DesktopGroupCreationState::Preparing;
	const auto conversationId = RandomId<ConversationId>();
	const auto clientId = RandomId<ClientId>();
	const auto genesisObjectId = RandomId<ObjectId>();
	const auto credentialObjectId = RandomId<ObjectId>();
	const auto mlsPublicObjectId = RandomId<ObjectId>();
	const auto archiveActivationEventId = RandomId<ObjectId>();
	const auto ownerHistoryGrantObjectId = RandomId<ObjectId>();
	const auto archiveKey = ArchiveEpochCrypto().generateKey();
	if (!conversationId
		|| !clientId
		|| !genesisObjectId
		|| !credentialObjectId
		|| !mlsPublicObjectId
		|| !archiveActivationEventId
		|| !ownerHistoryGrantObjectId
		|| !archiveKey) {
		_groupCreationState = DesktopGroupCreationState::LocalFailure;
		return false;
	}
	auto localRecordKey = DeriveConversationLocalRecordKey(
		_vault->masterKey,
		_telegramUserIdBinding,
		*conversationId);
	if (!localRecordKey) {
		_groupCreationState = DesktopGroupCreationState::LocalFailure;
		return false;
	}
	auto operation = std::make_unique<PendingGroupCreation>(
		ConversationDirectory(_telegramUserIdBinding, *conversationId),
		std::move(*localRecordKey),
		_session,
		peer->id.value,
		*conversationId,
		_sha256);
	if (operation->metadata.load(*conversationId)
			!= ConversationMetadataLoadResult::Missing
		|| operation->journal.load(*conversationId)
			!= GroupBootstrapJournalLoadResult::Empty
		|| operation->mlsState.load(*conversationId)
			!= MlsStateLoadResult::Missing
		|| operation->archiveState.load(*conversationId)
			!= ArchiveStateLoadResult::Missing
		|| operation->groupLedger.load(*conversationId)
			!= GroupLedgerLoadResult::Missing
		|| operation->outbox.load()
			!= PersistentOutboxLoadResult::Empty
		|| operation->changeJournal.load(*conversationId)
			!= GroupChangeJournalLoadResult::Empty
		|| operation->changeInbox.load(*conversationId)
			!= GroupChangeInboxLoadResult::Missing
		|| operation->keyPackages.load(*conversationId, peer->id.value)
			!= KeyPackagePoolLoadResult::Empty
		|| operation->freshnessTrust.load(*conversationId)
			!= FreshnessTrustLoadResult::Missing
		|| operation->inboundJournal.load()
			!= InboundJournalLoadResult::Missing
		|| operation->controlInboundJournal.load()
			!= InboundJournalLoadResult::Missing
		|| operation->contentStore.load()
			!= ContentStoreLoadResult::Missing
		|| operation->controlSyncState.load(*conversationId)
			!= ControlObservationStateLoadResult::Missing
		|| operation->contentSyncState.load(*conversationId)
			!= ContentSyncStateLoadResult::Missing
		|| operation->fileTransfer.load(*conversationId)
			!= FileTransferLoadResult::Empty) {
		_groupCreationState = DesktopGroupCreationState::LocalFailure;
		return false;
	}
	CleanupStagedProtectedSources(operation->directory, QString());
	auto bootstrap = PrepareProtectedGroupBootstrap({
		.conversationId = *conversationId,
		.telegramPeerIdBinding = peer->id.value,
		.ownerTelegramUserIdBinding = _telegramUserIdBinding,
		.ownerClientId = *clientId,
		.policy = { .defaultHistoryAccess = defaultHistoryAccess },
		.genesisObjectId = *genesisObjectId,
		.ownerCredentialObjectId = *credentialObjectId,
		.initialMlsPublicObjectId = *mlsPublicObjectId,
		.archiveActivationEventId = *archiveActivationEventId,
		.ownerHistoryGrantObjectId = *ownerHistoryGrantObjectId,
		.ownerIdentity = &_vault->identity,
		.initialArchiveKey = &*archiveKey,
	},
	OpenMlsBridge(),
	MlsContextCodecV1(),
	MlsRosterCodecV1(),
	EnvelopeCodecV1(),
	_sha256);
	if (!bootstrap.prepared) {
		_groupCreationState = DesktopGroupCreationState::LocalFailure;
		return false;
	}
	const auto conversation = CloudVaultConversation{
		.conversationId = *conversationId,
		.telegramPeerIdBinding = peer->id.value,
		.checkpoint = bootstrap.prepared->checkpoint,
		.ownerAccountId = bootstrap.prepared->ownerAccountId,
	};
	const auto envelopeCodec = EnvelopeCodecV1();
	if (!BeginConversationSetup(operation->directory)) {
		DiscardUncommittedConversationDirectory(operation->directory);
		_groupCreationState = DesktopGroupCreationState::LocalFailure;
		return false;
	}
	auto coordinator = GroupBootstrapTransactionCoordinator(
		operation->journal,
		operation->mlsState,
		operation->archiveState,
		operation->groupLedger,
		operation->outbox,
		envelopeCodec,
		_sha256);
	auto transaction = MakeGroupBootstrapTransaction(
		std::move(*bootstrap.prepared),
		_vault->identity.credential,
		operation->outbox.revision());
	if (coordinator.apply(std::move(transaction))
			!= GroupBootstrapApplyStatus::Applied) {
		DiscardUncommittedConversationDirectory(operation->directory);
		_groupCreationState = DesktopGroupCreationState::LocalFailure;
		return false;
	}
	if (operation->freshnessTrust.initialize(true)
			!= FreshnessTrustCommitResult::Committed
		|| operation->metadata.initialize({
			.conversationId = *conversationId,
			.telegramPeerIdBinding = peer->id.value,
			.accountId = conversation.ownerAccountId,
			.clientId = *clientId,
		}) != ConversationMetadataCommitResult::Committed) {
		DiscardUncommittedConversationDirectory(operation->directory);
		_groupCreationState = DesktopGroupCreationState::LocalFailure;
		return false;
	}
	(void)FinishConversationSetup(operation->directory);
	rememberProtectedPeerForPresentation(peer->id.value);
	operation->conversation = conversation;
	operation->freshnessGate = std::make_unique<FreshnessGate>(
		conversation.checkpoint,
		true);
	_pendingGroupCreation = std::move(operation);
	publishNextBootstrapObject();
	return true;
}

bool DesktopService::retryProtectedGroupCreation() {
	const auto state = _groupCreationState.current();
	if (!vaultReady()
		|| (state != DesktopGroupCreationState::RetryableTransportError
			&& state != DesktopGroupCreationState::PermanentTransportError)
		|| _pendingGroupJoin) {
		return false;
	}
	if (!_pendingGroupCreation) {
		auto admissions = std::vector<ConversationId>();
		for (const auto &[conversationId, group] : _groups) {
			if (group->phase
					== PendingGroupCreation::Phase::AwaitingAdmission) {
				admissions.push_back(conversationId);
			}
		}
		if (!admissions.empty()) {
			_groupCreationState
				= DesktopGroupCreationState::AwaitingAdmission;
		}
		auto restartedAdmission = false;
		auto admissionRestartFailed = false;
		for (const auto conversationId : admissions) {
			if (_pendingGroupCreation
				|| _pendingGroupJoin
				|| _pendingGroupDiscovery) {
				return true;
			}
			auto i = _groups.find(conversationId);
			if (i == end(_groups)
				|| i->second->phase
					!= PendingGroupCreation::Phase::AwaitingAdmission) {
				continue;
			}
			if (!i->second->observation) {
				beginGroupObservation(conversationId);
			}
			if (_pendingGroupCreation
				|| _pendingGroupJoin
				|| _pendingGroupDiscovery) {
				return true;
			} else if (!vaultReady()
				|| _groupCreationState.current()
					!= DesktopGroupCreationState::AwaitingAdmission) {
				return false;
			}
			i = _groups.find(conversationId);
			const auto stillAwaiting = i != end(_groups)
				&& i->second->phase
					== PendingGroupCreation::Phase::AwaitingAdmission;
			const auto restarted = stillAwaiting
				&& bool(i->second->observation);
			restartedAdmission = restartedAdmission || restarted;
			admissionRestartFailed = admissionRestartFailed
				|| (stillAwaiting && !restarted);
		}
		if (!admissions.empty()) {
			const auto stillAwaiting = std::any_of(
				begin(_groups),
				end(_groups),
				[](const auto &entry) {
					return entry.second->phase
						== PendingGroupCreation::Phase::AwaitingAdmission;
				});
			if (stillAwaiting && admissionRestartFailed) {
				_groupCreationState
					= DesktopGroupCreationState::RetryableTransportError;
				return false;
			}
			return restartedAdmission || !stillAwaiting;
		}
		_groupCreationState = DesktopGroupCreationState::Ready;
		resumePendingGroupCreation();
		return true;
	} else if (_pendingGroupCreation->uploadInProgress) {
		return false;
	}
	if (_pendingGroupCreation->vaultUpdate) {
		uploadPendingConversationIndex();
	} else {
		publishNextBootstrapObject();
	}
	return true;
}

std::vector<DesktopProtectedGroupSummary>
DesktopService::protectedGroups() const {
	auto result = std::vector<DesktopProtectedGroupSummary>();
	if (!vaultReady()) {
		return result;
	}
	result.reserve(_groups.size());
	for (const auto &[conversationId, group] : _groups) {
		const auto state = group->groupLedger.state();
		const auto removed = group->phase
			== PendingGroupCreation::Phase::Removed;
		result.push_back({
			.conversationId = conversationId,
			.telegramPeerIdBinding = group->telegramPeerIdBinding,
			.title = _session->data().peer(
				PeerId(group->telegramPeerIdBinding))->name(),
			.generation = state ? state->generation() : 0,
			.contentCount = group->contentStore.size(),
			.active = group->phase == PendingGroupCreation::Phase::Active,
			.removed = removed,
			.sendingAllowed = !removed
				&& group->freshnessGate
				&& group->freshnessGate->sendingAllowed(),
			.fileTransferPending = group->fileHashInProgress
				|| !group->filePreparationPath.isEmpty()
				|| bool(group->fileTransfer.pending()),
		});
	}
	std::sort(
		begin(result),
		end(result),
		[](const auto &a, const auto &b) {
			return a.title.compare(b.title, Qt::CaseInsensitive) < 0;
		});
	return result;
}

std::optional<ConversationId> DesktopService::protectedConversationForPeer(
		std::uint64_t telegramPeerIdBinding) const {
	if (!vaultReady() || !telegramPeerIdBinding) {
		return std::nullopt;
	}
	auto result = std::optional<ConversationId>();
	const auto consider = [&](
			ConversationId conversationId,
			std::uint64_t peerId) {
		if (peerId != telegramPeerIdBinding) {
			return true;
		} else if (result && *result != conversationId) {
			return false;
		}
		result = conversationId;
		return true;
	};
	for (const auto &[conversationId, group] : _groups) {
		if (!consider(conversationId, group->telegramPeerIdBinding)) {
			return std::nullopt;
		}
	}
	if (_vault) {
		for (const auto &conversation : _vault->conversations) {
			if (!consider(
					conversation.conversationId,
					conversation.telegramPeerIdBinding)) {
				return std::nullopt;
			}
		}
	}
	if (_pendingGroupCreation
		&& !consider(
			_pendingGroupCreation->conversation.conversationId,
			_pendingGroupCreation->telegramPeerIdBinding)) {
		return std::nullopt;
	}
	return result;
}

bool DesktopService::isProtectedPeerForPresentation(
		std::uint64_t telegramPeerIdBinding,
		std::uint64_t linkedTelegramPeerIdBinding) {
	if (!telegramPeerIdBinding) {
		return false;
	}
	const auto known = [&](std::uint64_t peerId) {
		return peerId
			&& (!_presentationProtectedPeersValid
				|| _presentationProtectedPeers.contains(peerId)
				|| protectedConversationForPeer(peerId).has_value());
	};
	if (known(telegramPeerIdBinding)) {
		return true;
	} else if (!known(linkedTelegramPeerIdBinding)) {
		return false;
	}
	rememberProtectedPeerForPresentation(telegramPeerIdBinding);
	return true;
}

void DesktopService::rememberProtectedPeerForPresentation(
		std::uint64_t telegramPeerIdBinding) {
	if (!telegramPeerIdBinding
		|| !_presentationProtectedPeersValid
		|| _presentationProtectedPeers.contains(telegramPeerIdBinding)) {
		return;
	}
	if (_presentationProtectedPeers.size()
			>= kMaximumProtectedPeerMarkers) {
		_presentationProtectedPeersValid = false;
		_session->local().writePrefNow<QByteArray>(
			kProtectedPeersPref,
			QByteArray("invalid"));
		return;
	}
	_presentationProtectedPeers.emplace(telegramPeerIdBinding);
	_session->local().writePrefNow<QByteArray>(
		kProtectedPeersPref,
		EncodeProtectedPeerMarkers(
			_telegramUserIdBinding,
			_presentationProtectedPeers));
	_session->data().notifyHistoryChangeDelayed(
		_session->data().history(PeerId(telegramPeerIdBinding)));
}

std::vector<ProtectedContentRecord> DesktopService::protectedContent(
		ConversationId conversationId,
		std::size_t offset,
		std::size_t limit,
		std::optional<ObjectKind> kind) const {
	if (!vaultReady()) {
		return {};
	}
	const auto i = _groups.find(conversationId);
	return (i != end(_groups))
		? i->second->contentStore.records(offset, limit, kind)
		: std::vector<ProtectedContentRecord>();
}

std::size_t DesktopService::protectedContentCount(
		ConversationId conversationId,
		std::optional<ObjectKind> kind) const {
	if (!vaultReady()) {
		return 0;
	}
	const auto i = _groups.find(conversationId);
	return (i != end(_groups)) ? i->second->contentStore.size(kind) : 0;
}

void DesktopService::materializeProtectedHistory(
		ConversationId conversationId,
		std::uint64_t telegramPeerIdBinding,
		std::size_t limit) {
	const auto i = _groups.find(conversationId);
	if (!vaultReady()
		|| i == end(_groups)
		|| !telegramPeerIdBinding
		|| !limit) {
		return;
	}
	auto &group = *i->second;
	if (group.materializedHistoryPeerIdBinding != telegramPeerIdBinding) {
		clearMaterializedProtectedHistory(group);
		group.materializedHistoryPeerIdBinding = telegramPeerIdBinding;
	}
	group.materializedHistoryLimit = std::max(
		group.materializedHistoryLimit,
		limit);
	refreshMaterializedProtectedHistory(group);
}

void DesktopService::clearMaterializedProtectedHistory(
		PendingGroupCreation &group) {
	for (const auto &entry : group.materializedHistory) {
		const auto item = _session->data().message(entry.fullId);
		if (item && item->isE2ECloudDecrypted()) {
			item->history()->destroyMessage(item);
		}
	}
	group.materializedHistory.clear();
}

void DesktopService::refreshMaterializedProtectedHistory(
		PendingGroupCreation &group) {
	if (!group.materializedHistoryLimit) {
		return;
	}
	const auto total = group.contentStore.size();
	struct RenderedRecord {
		ObjectId eventObjectId;
		AccountId senderAccountId;
		std::uint64_t unixTime = 0;
		std::uint64_t editUnixTime = 0;
		QString text;
		std::optional<ProtectedHistoryFile> file;
		ObjectId latestMutationEventObjectId;
		bool deleted = false;
	};
	struct RenderedMutation {
		ObjectId eventObjectId;
		AccountId senderAccountId;
		ProtectedMessageAction action = ProtectedMessageAction::Edit;
		std::uint64_t unixTime = 0;
		QString text;
	};
	auto rendered = std::vector<RenderedRecord>();
	rendered.reserve(group.materializedHistoryLimit);
	auto mutationsByTarget = std::map<
		ObjectId,
		std::vector<RenderedMutation>>();
	const auto applyMutations = [&](RenderedRecord &entry) {
		const auto i = mutationsByTarget.find(entry.eventObjectId);
		if (i == end(mutationsByTarget)) {
			return;
		}
		const auto deletion = std::find_if(
			begin(i->second),
			end(i->second),
			[&](const RenderedMutation &mutation) {
				return mutation.senderAccountId == entry.senderAccountId
					&& mutation.action
						== ProtectedMessageAction::Delete;
			});
		if (deletion != end(i->second)) {
			entry.deleted = true;
			entry.latestMutationEventObjectId = deletion->eventObjectId;
		} else if (!entry.file) {
			const auto edit = std::find_if(
				begin(i->second),
				end(i->second),
				[&](const RenderedMutation &mutation) {
					return mutation.senderAccountId == entry.senderAccountId
						&& mutation.action
							== ProtectedMessageAction::Edit;
				});
			if (edit != end(i->second)) {
				entry.text = u"🔒 "_q + edit->text;
				entry.editUnixTime = edit->unixTime;
				entry.latestMutationEventObjectId = edit->eventObjectId;
			}
		}
		mutationsByTarget.erase(i);
	};
	const auto processRecords = [&](
			std::vector<ProtectedContentRecord> &records) {
		for (auto i = records.rbegin(); i != records.rend(); ++i) {
			const auto &record = *i;
			if (record.objectKind == ObjectKind::EncryptedMessageBody) {
				auto body = ProtectedMessageBodyCodecV1().decodePlaintext(
					record.plaintext);
				if (!body) {
					continue;
				}
				const auto text = QString::fromUtf8(body->textUtf8);
				Cleanse(body->textUtf8);
				if (body->action != ProtectedMessageAction::Create) {
					mutationsByTarget[body->targetEventObjectId].push_back({
						.eventObjectId = record.eventObjectId,
						.senderAccountId = record.senderAccountId,
						.action = body->action,
						.unixTime = record.unixTime,
						.text = text,
					});
					continue;
				}
				auto entry = RenderedRecord{
					.eventObjectId = record.eventObjectId,
					.senderAccountId = record.senderAccountId,
					.unixTime = record.unixTime,
					.text = u"🔒 "_q + text,
				};
				applyMutations(entry);
				if (!entry.deleted) {
					rendered.push_back(std::move(entry));
				}
			} else if (record.objectKind
					== ObjectKind::EncryptedFileManifest) {
				const auto manifest = PrivateFileManifestCodecV1()
					.decodePlaintext(record.plaintext);
				if (!manifest) {
					continue;
				}
				auto entry = RenderedRecord{
					.eventObjectId = record.eventObjectId,
					.senderAccountId = record.senderAccountId,
					.unixTime = record.unixTime,
					.text = u"🔒"_q,
					.file = ProtectedHistoryFile{
						.filename = QString::fromUtf8(
							manifest->filenameUtf8),
						.mimeType = QString::fromUtf8(
							manifest->mimeTypeUtf8),
						.size = manifest->context.plaintextSize,
						.preview = manifest->preview,
					},
				};
				applyMutations(entry);
				if (!entry.deleted) {
					rendered.push_back(std::move(entry));
				}
			}
			if (rendered.size() == group.materializedHistoryLimit) {
				break;
			}
		}
		for (auto &record : records) {
			Cleanse(record.plaintext);
		}
	};
	const auto firstCount = std::min(total, group.materializedHistoryLimit);
	auto offset = total - firstCount;
	auto records = group.contentStore.records(
		total - firstCount,
		firstCount);
	processRecords(records);
	while (rendered.size() < group.materializedHistoryLimit && offset) {
		const auto count = std::min(offset, group.materializedHistoryLimit);
		offset -= count;
		records = group.contentStore.records(offset, count);
		processRecords(records);
	}
	std::reverse(begin(rendered), end(rendered));
	auto appendFrom = std::size_t();
	if (group.materializedHistory.size() <= rendered.size()) {
		appendFrom = group.materializedHistory.size();
		for (auto index = std::size_t(); index != appendFrom; ++index) {
			const auto &entry = group.materializedHistory[index];
			const auto item = _session->data().message(entry.fullId);
			if (entry.eventObjectId != rendered[index].eventObjectId
				|| entry.latestMutationEventObjectId
					!= rendered[index].latestMutationEventObjectId
				|| !item
				|| !item->isE2ECloudDecrypted()) {
				appendFrom = 0;
				break;
			}
		}
	} else {
		appendFrom = 0;
	}
	if (!appendFrom && !group.materializedHistory.empty()) {
		clearMaterializedProtectedHistory(group);
	}
	const auto security = protectedSecurity(group.conversationId);
	const auto history = _session->data().history(PeerId(
		group.materializedHistoryPeerIdBinding
			? group.materializedHistoryPeerIdBinding
			: group.telegramPeerIdBinding));
	for (auto index = appendFrom; index != rendered.size(); ++index) {
		const auto &record = rendered[index];
		auto member = static_cast<const DesktopProtectedMember*>(nullptr);
		if (security) {
			const auto found = std::find_if(
				begin(security->members),
				end(security->members),
				[&](const DesktopProtectedMember &value) {
					return value.accountId == record.senderAccountId;
				});
			member = (found != end(security->members)) ? &*found : nullptr;
		}
		const auto knownMember = member && member->telegramUserIdBinding;
		auto flags = MessageFlags();
		auto from = PeerId();
		if (knownMember) {
			flags |= MessageFlag::HasFromId;
			from = peerFromUser(UserId(member->telegramUserIdBinding));
			if (member->local) {
				flags |= MessageFlag::Outgoing;
			}
		}
		const auto maximumTime = std::uint64_t(
			std::numeric_limits<TimeId>::max());
		auto fields = HistoryItemCommonFields{
			.id = _session->data().nextLocalMessageId(),
			.flags = flags,
			.from = from,
			.date = TimeId(std::min(record.unixTime, maximumTime)),
			.e2eCloudEditDate = TimeId(std::min(
				record.editUnixTime,
				maximumTime)),
			.e2eCloudDecrypted = true,
			.e2eCloudConversationId = ProtectedHistoryIdBytes(
				group.conversationId),
			.e2eCloudEventObjectId = ProtectedHistoryIdBytes(
				record.eventObjectId),
		};
		const auto item = [&] {
			if (!record.file) {
				return history->addExistingLocalMessage(
					std::move(fields),
					TextWithEntities{ .text = record.text },
					MTP_messageMediaEmpty());
			}
			const auto document = CreateProtectedHistoryDocument(
				_session,
				group.conversationId,
				record.eventObjectId,
				fields.date,
				*record.file,
				_sha256);
			const auto local = group.localProtectedFilePaths.find(
				record.eventObjectId);
			if (local != end(group.localProtectedFilePaths)
				&& QFileInfo(local->second).isFile()) {
				document->setLocation(Core::FileLocation(local->second));
			}
			return history->addExistingLocalMessage(
				std::move(fields),
				document,
				TextWithEntities{ .text = record.text });
		}();
		group.materializedHistory.push_back({
			.eventObjectId = record.eventObjectId,
			.latestMutationEventObjectId
				= record.latestMutationEventObjectId,
			.fullId = item->fullId(),
		});
	}
	_session->data().notifyHistoryChangeDelayed(history);
}

std::optional<DesktopProtectedSecurity> DesktopService::protectedSecurity(
		ConversationId conversationId) const {
	const auto i = _groups.find(conversationId);
	if (!vaultReady() || i == end(_groups)) {
		return std::nullopt;
	}
	const auto &group = *i->second;
	const auto state = group.groupLedger.state();
	const auto localAccountId = DeriveAccountId(
		_vault->identity.credential,
		_sha256);
	if (!state || !localAccountId) {
		return std::nullopt;
	}
	const auto owner = std::find_if(
		begin(state->members()),
		end(state->members()),
		[](const GroupMember &member) {
			return member.role == GroupRole::Owner;
		});
	auto accountIds = std::vector<AccountId>();
	accountIds.reserve(state->members().size());
	for (const auto &member : state->members()) {
		accountIds.push_back(member.accountId);
	}
	const auto groupDigest = (owner != end(state->members()))
		? DeriveGroupSafetyDigest(
			conversationId,
			owner->accountId,
			accountIds,
			_sha256)
		: std::nullopt;
	if (!groupDigest) {
		return std::nullopt;
	}
	const auto localMember = state->member(*localAccountId);
	const auto administrationAllowed = localMember
		&& group.freshnessGate
		&& group.freshnessGate->administrationAllowed();
	const auto hasPermission = [&](AdminPermission permission) {
		return administrationAllowed
			&& (localMember->role == GroupRole::Owner
				|| (localMember->role == GroupRole::Administrator
					&& (localMember->adminPermissions
						& PermissionMask(permission))));
	};
	auto witnesses = (group.safetyWitnessGeneration == state->generation())
		? group.safetyWitnesses
		: std::set<AccountId>();
	if (state->member(*localAccountId)) {
		witnesses.emplace(*localAccountId);
	}
	auto result = DesktopProtectedSecurity{
		.generation = state->generation(),
		.groupSafetyCode = FormatSafetyCode(*groupDigest).value_or(QString()),
		.memberCount = state->members().size(),
		.witnessCount = 0,
		.defaultHistoryAccess = state->policy().defaultHistoryAccess,
		.canSetRoles = administrationAllowed
			&& localMember->role == GroupRole::Owner,
		.canRemoveMembers = hasPermission(AdminPermission::RemoveMembers),
		.canGrantHistory = hasPermission(AdminPermission::GrantHistory),
		.canGrantFullHistory = hasPermission(
			AdminPermission::GrantFullHistory),
		.canChangeDefaultHistory = hasPermission(
			AdminPermission::ChangeDefaultHistory),
		.members = {},
	};
	result.members.reserve(state->members().size());
	for (const auto &member : state->members()) {
		auto accountDigest = Digest();
		accountDigest.bytes = member.accountId.bytes;
		const auto pairwise = (member.accountId != *localAccountId)
			? DerivePairwiseSafetyDigest(
				*localAccountId,
				member.accountId,
				_sha256)
			: std::nullopt;
		result.members.push_back({
			.accountId = member.accountId,
			.telegramUserIdBinding = member.telegramUserIdBinding,
			.role = member.role,
			.historyAccess = member.historyAccess,
			.clientCount = member.clients.size(),
			.accountSafetyCode = FormatSafetyCode(accountDigest)
				.value_or(QString()),
			.pairwiseSafetyCode = pairwise
				? FormatSafetyCode(*pairwise).value_or(QString())
				: QString(),
			.local = member.accountId == *localAccountId,
		});
		if (witnesses.contains(member.accountId)) {
			++result.witnessCount;
		}
	}
	std::sort(
		begin(result.members),
		end(result.members),
		[](const auto &a, const auto &b) {
			return (a.role != b.role)
				? a.role == GroupRole::Owner
				: a.telegramUserIdBinding < b.telegramUserIdBinding;
		});
	return result;
}

bool DesktopService::sendProtectedText(
		ConversationId conversationId,
		QString text) {
	return !text.isEmpty() && queueProtectedMessageBody(
		conversationId,
		{
			.unixTime = std::uint64_t(base::unixtime::now()),
			.textUtf8 = text.toUtf8(),
		});
}

bool DesktopService::editProtectedText(
		ConversationId conversationId,
		ObjectId targetEventObjectId,
		QString text) {
	if (text.isEmpty()) {
		return false;
	}
	return queueProtectedMessageBody(
		conversationId,
		{
			.action = ProtectedMessageAction::Edit,
			.targetEventObjectId = targetEventObjectId,
			.textUtf8 = text.toUtf8(),
		});
}

bool DesktopService::deleteProtectedMessage(
		ConversationId conversationId,
		ObjectId targetEventObjectId) {
	const auto i = _groups.find(conversationId);
	const auto pending = (i != end(_groups))
		? i->second->fileTransfer.pending()
		: nullptr;
	const auto cancelMatchingFile = pending
		&& pending->eventObjectId == targetEventObjectId;
	if (!queueProtectedMessageBody(
		conversationId,
		{
			.action = ProtectedMessageAction::Delete,
			.targetEventObjectId = targetEventObjectId,
		},
		false)) {
		return false;
	}
	// Persist the deletion before cancelling its matching transfer. The
	// cancellation pump removes only the manifest pair, so this tombstone
	// remains queued and is published immediately after local cleanup.
	auto cancellationFailed = false;
	if (cancelMatchingFile && !pending->cancelRequested) {
		const auto requested = i->second->fileTransfer.requestCancel();
		if (requested != FileTransferCommitResult::Committed
			&& requested != FileTransferCommitResult::AlreadyCommitted) {
			cancellationFailed = true;
		} else if (i->second->fileFinalHashCancellation) {
			i->second->fileFinalHashCancellation->store(
				true,
				std::memory_order_relaxed);
		}
	}
	pumpActiveOutbox(conversationId);
	if (cancellationFailed) {
		setContentState(conversationId, DesktopContentState::LocalFailure);
	}
	return true;
}

bool DesktopService::queueProtectedMessageBody(
		ConversationId conversationId,
		ProtectedMessageBody body,
		bool pump) {
	const auto i = _groups.find(conversationId);
	if (!vaultReady()
		|| i == end(_groups)
		|| i->second->observation
		|| i->second->observationDirty
		|| i->second->fileHashInProgress
		|| !i->second->filePreparationPath.isEmpty()
		|| i->second->phase != PendingGroupCreation::Phase::Active) {
		return false;
	}
	auto &group = *i->second;
	const auto metadata = group.metadata.metadata();
	const auto state = group.groupLedger.state();
	const auto epoch = group.archiveState.currentEpoch();
	if (!metadata || !state || !epoch) {
		setContentState(conversationId, DesktopContentState::LocalFailure);
		return false;
	}
	if (body.action == ProtectedMessageAction::Create) {
		if (!body.unixTime || body.targetEventObjectId) {
			return false;
		}
	} else {
		auto target = group.contentStore.record(body.targetEventObjectId);
		const auto targetGuard = qScopeGuard([&] {
			if (target) {
				Cleanse(target->plaintext);
			}
		});
		if (!target
			|| target->senderAccountId != metadata->accountId
			|| (body.action == ProtectedMessageAction::Edit
				&& target->objectKind != ObjectKind::EncryptedMessageBody)
			|| (target->objectKind != ObjectKind::EncryptedMessageBody
				&& target->objectKind != ObjectKind::EncryptedFileManifest)) {
			return false;
		}
		if (target->objectKind == ObjectKind::EncryptedMessageBody) {
			auto targetBody = ProtectedMessageBodyCodecV1().decodePlaintext(
				target->plaintext);
			const auto targetIsCreate = targetBody
				&& targetBody->action == ProtectedMessageAction::Create;
			if (targetBody) {
				Cleanse(targetBody->textUtf8);
			}
			if (!targetIsCreate) {
				return false;
			}
		}
		auto latestTime = target->unixTime;
		auto records = group.contentStore.records(
			0,
			group.contentStore.size(),
			ObjectKind::EncryptedMessageBody);
		for (auto &record : records) {
			auto mutation = ProtectedMessageBodyCodecV1().decodePlaintext(
				record.plaintext);
			if (mutation
				&& mutation->action != ProtectedMessageAction::Create
				&& mutation->targetEventObjectId
					== body.targetEventObjectId) {
			latestTime = std::max(latestTime, mutation->unixTime);
			}
			if (mutation) {
				Cleanse(mutation->textUtf8);
			}
			Cleanse(record.plaintext);
		}
		const auto now = std::uint64_t(base::unixtime::now());
		if (latestTime
			== std::uint64_t(std::numeric_limits<std::int64_t>::max())) {
			return false;
		}
		body.unixTime = std::max(now, latestTime + 1);
	}
	const auto eventObjectId = RandomId<ObjectId>();
	const auto contentObjectId = RandomId<ObjectId>();
	auto plaintext = ProtectedMessageBodyCodecV1().encodePlaintext(body);
	const auto plaintextGuard = qScopeGuard([&] {
		if (plaintext) {
			Cleanse(*plaintext);
		}
	});
	if (!eventObjectId
		|| !contentObjectId
		|| !plaintext
		|| !initializeActivePipeline(group)) {
		setContentState(
			conversationId,
			(_vaultState.current() == DesktopVaultState::SecurityBlocked)
				? DesktopContentState::SecurityBlocked
				: DesktopContentState::LocalFailure);
		return false;
	}
	if (group.freshnessGate->state() == FreshnessState::Required
		&& !group.outbox.size()
		&& !queueFreshnessChallenge(group)) {
		setContentState(conversationId, DesktopContentState::LocalFailure);
		return false;
	}
	const auto queued = QueueArchivedContent({
		.conversationId = conversationId,
		.eventObjectId = *eventObjectId,
		.contentObjectId = *contentObjectId,
		.objectKind = ObjectKind::EncryptedMessageBody,
		.senderAccountId = metadata->accountId,
		.senderClientId = metadata->clientId,
		.telegramPeerIdBinding = group.telegramPeerIdBinding,
		.groupGeneration = state->generation(),
		.archiveEpochGeneration = epoch->generation,
		.archiveEpochKey = &epoch->key,
		.senderSigningPrivateKey = &_vault->identity.signingPrivateKey,
		.plaintext = *plaintext,
		.mlsContext = QByteArray("TDE2E/archived-content/v1"),
	},
	ArchiveEpochCrypto(),
	EncryptedArchivedContentCodecV1(),
	ArchivedContentDescriptorCodecV1(),
	group.envelopeCodec,
	_sha256,
	*group.outboxCoordinator);
	if (queued != ArchivedContentQueueResult::Queued) {
		setContentState(conversationId, DesktopContentState::LocalFailure);
		return false;
	}
	group.queuedContentReconciled = false;
	const auto stored = group.contentStore.append({
		.conversationId = conversationId,
		.eventObjectId = *eventObjectId,
		.contentObjectId = *contentObjectId,
		.objectKind = ObjectKind::EncryptedMessageBody,
		.groupGeneration = state->generation(),
		.senderAccountId = metadata->accountId,
		.senderClientId = metadata->clientId,
		.unixTime = body.unixTime,
		.observedTelegramMessageId = 0,
		.plaintext = *plaintext,
	});
	if (stored == ContentStoreAppendResult::Conflict) {
		_vaultState = DesktopVaultState::SecurityBlocked;
		setContentState(conversationId, DesktopContentState::SecurityBlocked);
		return false;
	} else if (stored == ContentStoreAppendResult::InvalidRecord
		|| stored == ContentStoreAppendResult::PersistenceFailed) {
		setContentState(conversationId, DesktopContentState::LocalFailure);
		return false;
	}
	if (stored == ContentStoreAppendResult::Stored) {
		notifyContentRevision();
	}
	group.queuedContentReconciled = true;
	if (pump) {
		pumpActiveOutbox(conversationId);
	}
	return true;
}

bool DesktopService::sendProtectedFile(
		ConversationId conversationId,
		QString path) {
	const auto i = _groups.find(conversationId);
	if (!vaultReady()
		|| i == end(_groups)
		|| path.isEmpty()
		|| i->second->observation
		|| i->second->observationDirty
		|| i->second->fileHashInProgress
		|| !i->second->filePreparationPath.isEmpty()
		|| i->second->fileTransfer.pending()
		|| i->second->phase != PendingGroupCreation::Phase::Active) {
		return false;
	}
	auto &group = *i->second;
	// An earlier protected object may still own the outbox or upload slot.
	// Staging is independent; pumpActiveOutbox creates this file's durable
	// manifest only after both become empty, preserving their exact order.
	const auto sourceInfo = QFileInfo(path);
	const auto absolutePath = sourceInfo.absoluteFilePath();
	if (absolutePath.isEmpty() || !sourceInfo.isFile()) {
		return false;
	}
	const auto ownedSource = IsStagedProtectedSource(
		_telegramUserIdBinding,
		conversationId,
		absolutePath);
	const auto stagedPath = ownedSource
		? std::optional<QString>(absolutePath)
		: PrepareStagedProtectedFile(
			_telegramUserIdBinding,
			conversationId);
	if (!stagedPath) {
		return false;
	}
	const auto mimeType = QMimeDatabase().mimeTypeForFile(
		absolutePath,
		QMimeDatabase::MatchExtension).name();
	group.filePreparationPath = *stagedPath;
	group.filePreparationFilename = IsStagedProtectedImage(
		_telegramUserIdBinding,
		conversationId,
		absolutePath)
		? u"image.png"_q
		: sourceInfo.fileName();
	group.filePreparationMimeType = mimeType;
	group.filePreparationSource.reset();
	group.fileHashCancelRequested = false;
	group.fileHashInProgress = true;
	const auto cancellation = std::make_shared<std::atomic_bool>(false);
	group.fileHashCancellation = cancellation;
	setContentState(conversationId, DesktopContentState::Synchronizing);
	notifyFileTransferRevision();
	const auto operationEpoch = _operationEpoch;
	crl::async([weak = base::weak_ptr(this),
			conversationId,
			absolutePath,
			stagedPath = *stagedPath,
			mimeType,
			ownedSource,
			cancellation,
			operationEpoch] {
		const auto source = HashFile(
			absolutePath,
			cancellation,
			true,
			ownedSource ? QString() : stagedPath,
			mimeType);
		crl::on_main([weak,
				conversationId,
				stagedPath,
				cancellation,
				operationEpoch,
				source] {
			if (!weak || weak->_operationEpoch != operationEpoch) {
				return;
			}
			const auto i = weak->_groups.find(conversationId);
			if (i == end(weak->_groups)
				|| !i->second->fileHashInProgress
				|| i->second->fileHashCancellation != cancellation
				|| i->second->filePreparationPath != stagedPath) {
				return;
			}
			auto &group = *i->second;
			group.fileHashInProgress = false;
			group.fileHashCancellation.reset();
			if (group.fileHashCancelRequested) {
				group.fileHashCancelRequested = false;
				RemoveStagedProtectedSource(
					weak->_telegramUserIdBinding,
					conversationId,
					group.filePreparationPath);
				group.filePreparationPath.clear();
				group.filePreparationFilename.clear();
				group.filePreparationMimeType.clear();
				group.filePreparationSource.reset();
				weak->notifyFileTransferRevision();
				weak->pumpActiveOutbox(conversationId);
				return;
			} else if (!source) {
				RemoveStagedProtectedSource(
					weak->_telegramUserIdBinding,
					conversationId,
					group.filePreparationPath);
				group.filePreparationPath.clear();
				group.filePreparationFilename.clear();
				group.filePreparationMimeType.clear();
				group.filePreparationSource.reset();
				weak->notifyFileTransferRevision();
				weak->setContentState(
					conversationId,
					DesktopContentState::LocalFailure);
				return;
			}
			group.filePreparationSource = source;
			weak->pumpActiveOutbox(conversationId);
		});
	});
	return true;
}

bool DesktopService::sendProtectedImage(
		ConversationId conversationId,
		const QImage &image) {
	const auto path = StageProtectedImage(
		_telegramUserIdBinding,
		conversationId,
		image);
	if (!path) {
		return false;
	} else if (!sendProtectedFile(conversationId, *path)) {
		RemoveStagedProtectedSource(
			_telegramUserIdBinding,
			conversationId,
			*path);
		return false;
	}
	return true;
}

bool DesktopService::cancelProtectedFileTransfer(
		ConversationId conversationId) {
	const auto i = _groups.find(conversationId);
	if (!vaultReady()
		|| i == end(_groups)
		|| i->second->phase != PendingGroupCreation::Phase::Active) {
		return false;
	}
	auto &group = *i->second;
	if (group.fileHashInProgress) {
		if (!group.fileHashCancellation) {
			setContentState(conversationId, DesktopContentState::LocalFailure);
			return false;
		}
		group.fileHashCancelRequested = true;
		group.fileHashCancellation->store(true, std::memory_order_relaxed);
		setContentState(conversationId, DesktopContentState::Synchronizing);
		return true;
	} else if (!group.filePreparationPath.isEmpty()) {
		RemoveStagedProtectedSource(
			_telegramUserIdBinding,
			conversationId,
			group.filePreparationPath);
		group.filePreparationPath.clear();
		group.filePreparationFilename.clear();
		group.filePreparationMimeType.clear();
		group.filePreparationSource.reset();
		notifyFileTransferRevision();
		pumpActiveOutbox(conversationId);
		return true;
	} else if (!group.fileTransfer.pending()) {
		return false;
	}
	const auto requested = group.fileTransfer.requestCancel();
	if (requested != FileTransferCommitResult::Committed
		&& requested != FileTransferCommitResult::AlreadyCommitted) {
		setContentState(conversationId, DesktopContentState::LocalFailure);
		return false;
	}
	if (group.fileFinalHashCancellation) {
		group.fileFinalHashCancellation->store(
			true,
			std::memory_order_relaxed);
	}
	pumpActiveOutbox(conversationId);
	return true;
}

bool DesktopService::saveProtectedFile(
		ConversationId conversationId,
		ObjectId eventObjectId,
		QString path,
		std::function<void(ProtectedFileSaveResult)> callback) {
	if (!vaultReady()) {
		if (callback) {
			callback(ProtectedFileSaveResult::SecurityBlocked);
		}
		return false;
	}
	const auto i = _groups.find(conversationId);
	auto record = (i != end(_groups))
		? i->second->contentStore.record(eventObjectId)
		: std::nullopt;
	const auto recordGuard = qScopeGuard([&] {
		if (record) {
			Cleanse(record->plaintext);
		}
	});
	const auto manifest = (record
		&& record->objectKind == ObjectKind::EncryptedFileManifest)
		? PrivateFileManifestCodecV1().decodePlaintext(record->plaintext)
		: std::nullopt;
	if (!manifest
		|| path.isEmpty()
		|| record->observedTelegramMessageId <= 0
		|| record->observedTelegramMessageId
			> std::numeric_limits<int>::max()) {
		if (callback) {
			callback(ProtectedFileSaveResult::InvalidRequest);
		}
		return false;
	}
	auto &group = *i->second;
	if (group.observation
		|| group.observationDirty
		|| group.pendingFileDownload) {
		if (callback) {
			callback(ProtectedFileSaveResult::Busy);
		}
		return false;
	}
	auto missing = std::set<std::uint32_t>();
	for (auto index = std::uint32_t();
			index != manifest->context.chunkCount;
			++index) {
		if (!group.chunkStore.hasChunk(
			conversationId,
			manifest->context.fileId,
			index)) {
			missing.emplace(index);
		}
	}
	group.pendingFileDownload = PendingGroupCreation::PendingFileDownload{
		.eventObjectId = eventObjectId,
		.fileId = manifest->context.fileId,
		.path = std::move(path),
		.missingChunkIndices = std::move(missing),
		.callback = std::move(callback),
		.legacyCarrier = false,
	};
	if (group.pendingFileDownload->missingChunkIndices.empty()) {
		const auto started = writePendingProtectedFile(conversationId);
		if (!started) {
			finishFileChunkDownload(
				conversationId,
				ProtectedFileSaveResult::LocalFailure);
		}
		return started;
	}
	if (!beginFileChunkDownload(conversationId, false)) {
		finishFileChunkDownload(
			conversationId,
			ProtectedFileSaveResult::LocalFailure);
		return false;
	}
	return true;
}

bool DesktopService::beginFileChunkDownload(
		ConversationId conversationId,
		bool legacyCarrier) {
	const auto i = _groups.find(conversationId);
	if (!vaultReady()
		|| i == end(_groups)
		|| !i->second->pendingFileDownload) {
		return false;
	}
	auto &group = *i->second;
	auto record = group.contentStore.record(
		group.pendingFileDownload->eventObjectId);
	const auto recordGuard = qScopeGuard([&] {
		if (record) {
			Cleanse(record->plaintext);
		}
	});
	const auto manifest = (record
		&& record->objectKind == ObjectKind::EncryptedFileManifest)
		? PrivateFileManifestCodecV1().decodePlaintext(record->plaintext)
		: std::nullopt;
	if (!manifest
		|| manifest->context.fileId != group.pendingFileDownload->fileId
		|| record->observedTelegramMessageId <= 0
		|| record->observedTelegramMessageId
			> std::numeric_limits<int>::max()) {
		return false;
	}
	const auto chunkCount = std::uint64_t(manifest->context.chunkCount);
	if (chunkCount > std::numeric_limits<std::uint64_t>::max()
			- kFileDownloadExtraObjects
		|| chunkCount > (std::numeric_limits<std::uint64_t>::max()
			- kFileDownloadExtraBytes
			- manifest->context.plaintextSize) / 2048) {
		return false;
	}
	const auto maximumObjects = chunkCount + kFileDownloadExtraObjects;
	const auto maximumPages = (maximumObjects + 99) / 100
		+ kFileDownloadExtraPages;
	const auto maximumBytes = manifest->context.plaintextSize
		+ (chunkCount * 2048)
		+ kFileDownloadExtraBytes;
	const auto filename = legacyCarrier
		? ProtectedContentCarrierFilename()
		: ProtectedFileChunkCarrierFilename(manifest->context.fileId);
	group.pendingFileDownload->legacyCarrier = legacyCarrier;
	group.fileDownloadController.reset();
	group.fileDownloadTransport.reset();
	group.fileDownloadBackend = std::make_unique<
		TelegramSessionCarrierBackend>(
			_session,
			_session->data().history(PeerId(group.telegramPeerIdBinding)),
			group.telegramPeerIdBinding,
			filename,
			ProtectedCarrierMimeType(),
			ProtectedFileChunkMaximumObjectSize(),
			kFileDownloadPageBytes,
			int(record->observedTelegramMessageId));
	group.fileDownloadTransport = std::make_unique<TelegramCarrierTransport>(
		conversationId,
		group.telegramPeerIdBinding,
		*group.fileDownloadBackend);
	const auto eventObjectId = group.pendingFileDownload->eventObjectId;
	const auto operationEpoch = _operationEpoch;
	group.fileDownloadController = std::make_unique<
		FileChunkDownloadController>(
			conversationId,
			group.telegramPeerIdBinding,
			record->observedTelegramMessageId,
			maximumPages,
			maximumObjects,
			maximumBytes,
			*group.fileDownloadTransport,
			[weak = base::weak_ptr(this), conversationId](
					std::vector<TelegramTransport::UntrustedObject> objects) {
				return weak
					? weak->processFileChunkDownloadPage(
						conversationId,
						std::move(objects))
					: FileChunkDownloadPageStatus::PersistenceFailed;
			},
			[weak = base::weak_ptr(this),
					conversationId,
					eventObjectId,
					operationEpoch](
					FileChunkDownloadCompletion completion) {
				crl::on_main([weak,
						conversationId,
						eventObjectId,
						operationEpoch,
						completion] {
					if (weak) {
						weak->applyFileChunkDownload(
							conversationId,
							eventObjectId,
							operationEpoch,
							completion);
					}
				});
			});
	return group.fileDownloadController->start();
}

void DesktopService::scheduleFileDownloadRetry(
		ConversationId conversationId,
		ObjectId eventObjectId,
		bool legacyCarrier) {
	const auto i = _groups.find(conversationId);
	if (!vaultReady()
		|| i == end(_groups)
		|| !i->second->pendingFileDownload
		|| i->second->pendingFileDownload->eventObjectId != eventObjectId) {
		return;
	}
	auto &pending = *i->second->pendingFileDownload;
	const auto delay = FileRetryDelay(pending.retryAttempt);
	pending.retryAttempt = std::min(pending.retryAttempt + 1, 6);
	++pending.retryCount;
	if (++pending.retryToken == 0) {
		++pending.retryToken;
	}
	const auto token = pending.retryToken;
	base::call_delayed(delay, [weak = base::weak_ptr(this),
			conversationId,
			eventObjectId,
			legacyCarrier,
			token] {
		if (!weak || !weak->vaultReady()) {
			return;
		}
		const auto i = weak->_groups.find(conversationId);
		if (i == end(weak->_groups)
			|| !i->second->pendingFileDownload
			|| i->second->pendingFileDownload->eventObjectId
				!= eventObjectId
			|| i->second->pendingFileDownload->retryToken != token) {
			return;
		}
		if (!weak->beginFileChunkDownload(
				conversationId,
				legacyCarrier)) {
			weak->finishFileChunkDownload(
				conversationId,
				ProtectedFileSaveResult::LocalFailure);
		}
	});
}

FileChunkDownloadPageStatus DesktopService::processFileChunkDownloadPage(
		ConversationId conversationId,
		std::vector<TelegramTransport::UntrustedObject> objects) {
	if (!vaultReady()) {
		return FileChunkDownloadPageStatus::SecurityBlocked;
	}
	const auto i = _groups.find(conversationId);
	if (i == end(_groups) || !i->second->pendingFileDownload) {
		return FileChunkDownloadPageStatus::PersistenceFailed;
	}
	auto &group = *i->second;
	const auto metadata = group.metadata.metadata();
	if (!metadata) {
		return FileChunkDownloadPageStatus::PersistenceFailed;
	}
	const auto processed = ProcessObservedFileChunkPage(
		objects,
		group.pendingFileDownload->fileId,
		{
			.conversationId = conversationId,
			.accountId = metadata->accountId,
			.clientId = metadata->clientId,
			.telegramPeerIdBinding = group.telegramPeerIdBinding,
		},
		group.envelopeCodec,
		_sha256,
		group.groupLedger,
		group.contentStore,
		group.chunkStore);
	if (processed.status == ObservedContentProcessStatus::SecurityBlocked) {
		return FileChunkDownloadPageStatus::SecurityBlocked;
	} else if (processed.status != ObservedContentProcessStatus::Processed) {
		return FileChunkDownloadPageStatus::PersistenceFailed;
	}
	const auto missingBefore = group.pendingFileDownload
		->missingChunkIndices.size();
	for (const auto index : processed.availableChunkIndices) {
		group.pendingFileDownload->missingChunkIndices.erase(index);
	}
	if (group.pendingFileDownload->missingChunkIndices.size()
			< missingBefore) {
		group.pendingFileDownload->retryAttempt = 0;
		group.pendingFileDownload->retryCount = 0;
	}
	return group.pendingFileDownload->missingChunkIndices.empty()
		? FileChunkDownloadPageStatus::Complete
		: FileChunkDownloadPageStatus::Incomplete;
}

void DesktopService::applyFileChunkDownload(
		ConversationId conversationId,
		ObjectId eventObjectId,
		std::uint64_t operationEpoch,
		FileChunkDownloadCompletion completion) {
	if (!vaultReady() || _operationEpoch != operationEpoch) {
		return;
	}
	const auto i = _groups.find(conversationId);
	if (i == end(_groups)
		|| !i->second->pendingFileDownload
		|| i->second->pendingFileDownload->eventObjectId
			!= eventObjectId) {
		return;
	}
	auto &group = *i->second;
	const auto wasLegacy = group.pendingFileDownload->legacyCarrier;
	group.fileDownloadController.reset();
	group.fileDownloadTransport.reset();
	group.fileDownloadBackend.reset();
	if (completion.status == FileChunkDownloadStatus::SecurityBlocked
		|| completion.status == FileChunkDownloadStatus::InvalidPagination
		|| completion.status == FileChunkDownloadStatus::LimitExceeded) {
		_vaultState = DesktopVaultState::SecurityBlocked;
		setContentState(
			conversationId,
			DesktopContentState::SecurityBlocked);
		finishFileChunkDownload(
			conversationId,
			ProtectedFileSaveResult::SecurityBlocked);
		return;
	} else if (completion.status == FileChunkDownloadStatus::Complete) {
		if (++group.pendingFileDownload->retryToken == 0) {
			++group.pendingFileDownload->retryToken;
		}
		if (!writePendingProtectedFile(conversationId)) {
			finishFileChunkDownload(
				conversationId,
				ProtectedFileSaveResult::LocalFailure);
		}
		return;
	} else if (completion.status == FileChunkDownloadStatus::Missing
		&& !wasLegacy) {
		if (beginFileChunkDownload(conversationId, true)) {
			return;
		}
	} else if ((completion.status
				== FileChunkDownloadStatus::RetryableTransportError
			|| completion.status == FileChunkDownloadStatus::Missing)
		&& group.pendingFileDownload->retryCount
			< kFileDownloadMaximumRetries) {
		scheduleFileDownloadRetry(
			conversationId,
			eventObjectId,
			(completion.status
				== FileChunkDownloadStatus::RetryableTransportError)
				? wasLegacy
				: false);
		return;
	}
	const auto result = (completion.status
			== FileChunkDownloadStatus::RetryableTransportError)
		? ProtectedFileSaveResult::RetryableTransportError
		: (completion.status
			== FileChunkDownloadStatus::PermanentTransportError)
		? ProtectedFileSaveResult::PermanentTransportError
		: (completion.status == FileChunkDownloadStatus::Missing)
		? ProtectedFileSaveResult::MissingChunks
		: ProtectedFileSaveResult::LocalFailure;
	finishFileChunkDownload(conversationId, result);
}

bool DesktopService::writePendingProtectedFile(
		ConversationId conversationId) {
	const auto i = _groups.find(conversationId);
	if (!vaultReady()
		|| i == end(_groups)
		|| !i->second->pendingFileDownload
		|| i->second->pendingFileDownload->write) {
		return false;
	}
	auto &group = *i->second;
	auto record = group.contentStore.record(
		group.pendingFileDownload->eventObjectId);
	const auto recordGuard = qScopeGuard([&] {
		if (record) {
			Cleanse(record->plaintext);
		}
	});
	auto manifest = (record
		&& record->objectKind == ObjectKind::EncryptedFileManifest)
		? PrivateFileManifestCodecV1().decodePlaintext(record->plaintext)
		: std::nullopt;
	if (!manifest
		|| manifest->context.fileId != group.pendingFileDownload->fileId) {
		return false;
	}
	auto output = std::make_unique<QSaveFile>(
		group.pendingFileDownload->path);
	if (!output->open(QIODevice::WriteOnly)) {
		return false;
	}
	const auto digest = EVP_MD_CTX_new();
	if (!digest || EVP_DigestInit_ex(digest, EVP_sha256(), nullptr) != 1) {
		EVP_MD_CTX_free(digest);
		output->cancelWriting();
		return false;
	}
	const auto eventObjectId = group.pendingFileDownload->eventObjectId;
	group.pendingFileDownload->write = std::make_unique<
		PendingGroupCreation::PendingFileDownload::PendingWrite>(
			std::move(output),
			digest,
			std::move(*manifest));
	const auto operationEpoch = _operationEpoch;
	crl::on_main([weak = base::weak_ptr(this),
			conversationId,
			eventObjectId,
			operationEpoch] {
		if (weak) {
			weak->continuePendingProtectedFileWrite(
				conversationId,
				eventObjectId,
				operationEpoch);
		}
	});
	return true;
}

void DesktopService::continuePendingProtectedFileWrite(
		ConversationId conversationId,
		ObjectId eventObjectId,
		std::uint64_t operationEpoch) {
	if (!vaultReady() || _operationEpoch != operationEpoch) {
		return;
	}
	const auto i = _groups.find(conversationId);
	if (i == end(_groups)
		|| !i->second->pendingFileDownload
		|| i->second->pendingFileDownload->eventObjectId != eventObjectId
		|| !i->second->pendingFileDownload->write) {
		return;
	}
	auto &group = *i->second;
	auto &write = *group.pendingFileDownload->write;
	const auto scheduleNext = [=] {
		crl::on_main([weak = base::weak_ptr(this),
				conversationId,
				eventObjectId,
				operationEpoch] {
			if (weak) {
				weak->continuePendingProtectedFileWrite(
					conversationId,
					eventObjectId,
					operationEpoch);
			}
		});
	};
	if (write.committed) {
		const auto remaining = write.manifest.context.chunkCount
			- write.cleanupChunkIndex;
		const auto endIndex = write.cleanupChunkIndex
			+ std::min(remaining, kFileCleanupChunksPerTurn);
		while (write.cleanupChunkIndex != endIndex) {
			(void)group.chunkStore.removeChunk(
				conversationId,
				write.manifest.context.fileId,
				write.cleanupChunkIndex++);
		}
		if (write.cleanupChunkIndex
				!= write.manifest.context.chunkCount) {
			scheduleNext();
		} else {
			finishFileChunkDownload(
				conversationId,
				ProtectedFileSaveResult::Saved);
		}
		return;
	}
	if (write.nextChunkIndex != write.manifest.context.chunkCount) {
		const auto index = write.nextChunkIndex;
		const auto stored = group.chunkStore.read(
			conversationId,
			write.manifest.context.fileId,
			index);
		auto plaintext = (stored.status == FileChunkReadStatus::Found)
			? AesGcmFileChunkCipher().decrypt(
				write.manifest.key,
				write.manifest.context,
				index,
				stored.chunk.exactCiphertext)
			: std::nullopt;
		const auto written = plaintext
			? write.output->write(*plaintext)
			: -1;
		const auto updated = plaintext
			&& written == plaintext->size()
			&& EVP_DigestUpdate(
				write.digest,
				plaintext->constData(),
				plaintext->size()) == 1;
		if (!updated) {
			if (plaintext) {
				Cleanse(*plaintext);
			}
			(void)group.chunkStore.removeChunk(
				conversationId,
				write.manifest.context.fileId,
				index);
			finishFileChunkDownload(
				conversationId,
				ProtectedFileSaveResult::LocalFailure);
			return;
		}
		write.written += std::uint64_t(plaintext->size());
		++write.nextChunkIndex;
		Cleanse(*plaintext);
		scheduleNext();
		return;
	}
	auto hash = Digest();
	auto hashSize = 0U;
	const auto verified = write.written
			== write.manifest.context.plaintextSize
		&& EVP_DigestFinal_ex(
			write.digest,
			hash.bytes.data(),
			&hashSize) == 1
		&& hashSize == hash.bytes.size()
		&& hash == write.manifest.plaintextHash;
	EVP_MD_CTX_free(write.digest);
	write.digest = nullptr;
	if (!verified || !write.output->commit()) {
		finishFileChunkDownload(
			conversationId,
			ProtectedFileSaveResult::LocalFailure);
		return;
	}
	write.output.reset();
	write.committed = true;
	scheduleNext();
}

void DesktopService::finishFileChunkDownload(
		ConversationId conversationId,
		ProtectedFileSaveResult result) {
	const auto i = _groups.find(conversationId);
	if (i == end(_groups) || !i->second->pendingFileDownload) {
		return;
	}
	auto &group = *i->second;
	group.fileDownloadController.reset();
	group.fileDownloadTransport.reset();
	group.fileDownloadBackend.reset();
	if (result == ProtectedFileSaveResult::Saved) {
		group.localProtectedFilePaths.insert_or_assign(
			group.pendingFileDownload->eventObjectId,
			group.pendingFileDownload->path);
	}
	auto callback = std::move(group.pendingFileDownload->callback);
	group.pendingFileDownload.reset();
	if (group.observationDirty) {
		beginGroupObservation(conversationId);
	}
	if (callback) {
		callback(result);
	}
}

bool DesktopService::setProtectedDefaultHistory(
		ConversationId conversationId,
		HistoryAccess historyAccess) {
	if (!IsValidHistoryAccess(historyAccess)) {
		return false;
	}
	return applyAdministrativeTransition(conversationId, {
		.kind = GroupTransitionKind::SetDefaultHistory,
		.targetRole = GroupRole::Member,
		.historyAccess = historyAccess,
	});
}

bool DesktopService::setProtectedMemberHistory(
		ConversationId conversationId,
		AccountId accountId,
		HistoryAccess historyAccess) {
	if (!accountId || !IsValidHistoryAccess(historyAccess)) {
		return false;
	}
	return applyAdministrativeTransition(conversationId, {
		.kind = GroupTransitionKind::SetMemberHistory,
		.targetAccountId = accountId,
		.targetRole = GroupRole::Member,
		.historyAccess = historyAccess,
	});
}

bool DesktopService::setProtectedMemberRole(
		ConversationId conversationId,
		AccountId accountId,
		GroupRole role) {
	if (!accountId
		|| (role != GroupRole::Member
			&& role != GroupRole::Administrator)) {
		return false;
	}
	return applyAdministrativeTransition(conversationId, {
		.kind = GroupTransitionKind::SetRole,
		.targetAccountId = accountId,
		.targetRole = role,
		.targetAdminPermissions = (role == GroupRole::Administrator)
			? kDefaultAdminPermissions
			: 0,
		.historyAccess = {},
	});
}

bool DesktopService::removeProtectedMember(
		ConversationId conversationId,
		AccountId accountId) {
	if (!accountId) {
		return false;
	}
	return applyAdministrativeTransition(conversationId, {
		.kind = GroupTransitionKind::RemoveMember,
		.targetAccountId = accountId,
		.targetRole = GroupRole::Member,
		.historyAccess = {},
	});
}

DesktopContentState DesktopService::contentState(
		ConversationId conversationId) const {
	const auto i = _contentStates.find(conversationId);
	return (i != end(_contentStates))
		? i->second
		: DesktopContentState::Idle;
}

rpl::producer<DesktopContentState> DesktopService::contentStateValue() const {
	return _contentState.value();
}

void DesktopService::setContentState(
		ConversationId conversationId,
		DesktopContentState state) {
	_contentStates[conversationId] = state;
	_contentState.force_assign(state);
}

rpl::producer<std::uint64_t> DesktopService::contentRevisionValue() const {
	return _contentRevision.value();
}

void DesktopService::notifyContentRevision() {
	for (const auto &entry : _groups) {
		refreshMaterializedProtectedHistory(*entry.second);
	}
	const auto revision = _contentRevision.current();
	if (revision != std::numeric_limits<std::uint64_t>::max()) {
		_contentRevision = revision + 1;
	}
}

auto DesktopService::fileTransferRevisionValue() const
-> rpl::producer<std::uint64_t> {
	return _fileTransferRevision.value();
}

void DesktopService::notifyFileTransferRevision() {
	const auto revision = _fileTransferRevision.current();
	if (revision != std::numeric_limits<std::uint64_t>::max()) {
		_fileTransferRevision = revision + 1;
	}
}

rpl::producer<std::uint64_t> DesktopService::securityRevisionValue() const {
	return _securityRevision.value();
}

void DesktopService::notifySecurityRevision() {
	const auto revision = _securityRevision.current();
	if (revision != std::numeric_limits<std::uint64_t>::max()) {
		_securityRevision = revision + 1;
	}
}

void DesktopService::synchronizeProtectedContent(
		ConversationId conversationId) {
	if (!vaultReady()) {
		return;
	}
	beginGroupObservation(conversationId);
	pumpActiveOutbox(conversationId);
	beginContentObservation(conversationId);
}

void DesktopService::lock() {
	const auto securityBlocked = _vaultState.current()
		== DesktopVaultState::SecurityBlocked;
	const auto knownVault = _vault || _vaultAnchor.anchor().has_value();
	if (++_operationEpoch == 0) {
		++_operationEpoch;
	}
	_sync.reset();
	_pendingCreation.reset();
	if (_pendingGroupCreation) {
		clearMaterializedProtectedHistory(*_pendingGroupCreation);
	}
	for (const auto &entry : _groups) {
		clearMaterializedProtectedHistory(*entry.second);
		if (!entry.second->fileTransfer.pending()) {
			RemoveStagedProtectedSource(
				_telegramUserIdBinding,
				entry.first,
				entry.second->filePreparationPath);
		}
	}
	_pendingGroupCreation.reset();
	_pendingGroupJoin.reset();
	_pendingGroupDiscovery.reset();
	_groupDiscoveryQueue.clear();
	_groups.clear();
	_vault.reset();
	Cleanse(_pendingUnlockPassword);
	Cleanse(_unlockedPassword);
	if (securityBlocked) {
		_vaultState = DesktopVaultState::SecurityBlocked;
	} else if (knownVault) {
		_vaultState = DesktopVaultState::Locked;
	} else {
		_vaultState = DesktopVaultState::Uninitialized;
	}
	_groupCreationState = DesktopGroupCreationState::Idle;
	_contentState = DesktopContentState::Idle;
	_contentStates.clear();
	notifyFileTransferRevision();
	notifyContentRevision();
	notifySecurityRevision();
}

void DesktopService::applyVaultDiscoveryResult(
		CloudVaultSyncCompletion result) {
	_sync.reset();
	switch (result.status) {
	case CloudVaultSyncStatus::Present:
		_vaultState = DesktopVaultState::Locked;
		break;
	case CloudVaultSyncStatus::Missing:
		_vaultState = _vaultAnchor.anchor()
			? DesktopVaultState::SecurityBlocked
			: DesktopVaultState::Missing;
		break;
	case CloudVaultSyncStatus::RetryableTransportError:
		_vaultState = DesktopVaultState::DiscoveryRetryableError;
		break;
	case CloudVaultSyncStatus::PermanentTransportError:
		_vaultState = DesktopVaultState::DiscoveryPermanentError;
		break;
	case CloudVaultSyncStatus::CapacityExceeded:
	case CloudVaultSyncStatus::InvalidPagination:
	case CloudVaultSyncStatus::Selected:
	case CloudVaultSyncStatus::Unreadable:
	case CloudVaultSyncStatus::IdentityConflict:
	case CloudVaultSyncStatus::ForkDetected:
	case CloudVaultSyncStatus::RollbackDetected:
	case CloudVaultSyncStatus::ChainGap:
		_vaultState = DesktopVaultState::SecurityBlocked;
		break;
	case CloudVaultSyncStatus::Cancelled:
		_vaultState = DesktopVaultState::Uninitialized;
		break;
	}
}

void DesktopService::applyVaultCreationDiscoveryResult(
		CloudVaultSyncCompletion result) {
	_sync.reset();
	if (result.status == CloudVaultSyncStatus::Missing) {
		const auto operationEpoch = _operationEpoch;
		CreateCloudVaultOffMain(
			_telegramUserIdBinding,
			_pendingUnlockPassword,
			DesktopArgon2idConfig(),
			[weak = base::weak_ptr(this), operationEpoch](
					std::optional<CreatedCloudVault> created) mutable {
				if (!weak
					|| weak->_operationEpoch != operationEpoch
					|| weak->_vaultState.current()
						!= DesktopVaultState::Creating
					|| weak->_sync
					|| weak->_pendingCreation) {
					return;
				}
				weak->_pendingCreation = std::move(created);
				if (weak->_pendingCreation) {
					weak->uploadPendingCreation();
				} else {
					Cleanse(weak->_pendingUnlockPassword);
					weak->_vaultState
						= DesktopVaultState::WrongPasswordOrDamaged;
				}
			});
		return;
	} else if (result.status == CloudVaultSyncStatus::Present) {
		_vaultState = DesktopVaultState::Locked;
	} else if (result.status
			== CloudVaultSyncStatus::RetryableTransportError) {
		_vaultState = DesktopVaultState::DiscoveryRetryableError;
	} else if (result.status
			== CloudVaultSyncStatus::PermanentTransportError) {
		_vaultState = DesktopVaultState::DiscoveryPermanentError;
	} else if (result.status == CloudVaultSyncStatus::Cancelled) {
		_vaultState = DesktopVaultState::Missing;
	} else {
		_vaultState = DesktopVaultState::SecurityBlocked;
	}
	Cleanse(_pendingUnlockPassword);
}

void DesktopService::applySyncResult(CloudVaultSyncCompletion result) {
	_sync.reset();
	switch (result.status) {
	case CloudVaultSyncStatus::Selected:
		if (result.vault) {
			auto selected = std::move(*result.vault);
			if (!commitVaultAnchor(selected)) {
				_vaultState = DesktopVaultState::SecurityBlocked;
			} else {
				_vault = std::move(selected);
				Cleanse(_unlockedPassword);
				_unlockedPassword = std::move(_pendingUnlockPassword);
				_vaultState = DesktopVaultState::Ready;
				resumePendingGroupCreation();
			}
		} else {
			_vaultState = DesktopVaultState::WrongPasswordOrDamaged;
		}
		break;
	case CloudVaultSyncStatus::Present:
		_vaultState = DesktopVaultState::SecurityBlocked;
		break;
	case CloudVaultSyncStatus::Missing:
		_vaultState = DesktopVaultState::Missing;
		break;
	case CloudVaultSyncStatus::Unreadable:
		_vaultState = DesktopVaultState::WrongPasswordOrDamaged;
		break;
	case CloudVaultSyncStatus::RetryableTransportError:
		_vaultState = DesktopVaultState::RetryableTransportError;
		break;
	case CloudVaultSyncStatus::PermanentTransportError:
		_vaultState = DesktopVaultState::PermanentTransportError;
		break;
	case CloudVaultSyncStatus::CapacityExceeded:
	case CloudVaultSyncStatus::IdentityConflict:
	case CloudVaultSyncStatus::ForkDetected:
	case CloudVaultSyncStatus::RollbackDetected:
	case CloudVaultSyncStatus::ChainGap:
	case CloudVaultSyncStatus::InvalidPagination:
		_vaultState = DesktopVaultState::SecurityBlocked;
		break;
	case CloudVaultSyncStatus::Cancelled:
		_vaultState = DesktopVaultState::Locked;
		break;
	}
	if (_vaultState.current() != DesktopVaultState::Ready) {
		Cleanse(_pendingUnlockPassword);
	}
}

void DesktopService::uploadPendingCreation() {
	if (!_pendingCreation) {
		return;
	}
	_vaultState = DesktopVaultState::Creating;
	const auto operationEpoch = _operationEpoch;
	_remote->uploadExact(
		_pendingCreation->encoded,
		[weak = base::weak_ptr(this), operationEpoch](
				TelegramTransport::UploadResult result) {
			if (!weak
				|| weak->_operationEpoch != operationEpoch
				|| !weak->_pendingCreation) {
				return;
			}
			if (result == TelegramTransport::UploadResult::Accepted) {
				if (!weak->commitVaultAnchor(
						weak->_pendingCreation->unlocked)) {
					weak->_pendingCreation.reset();
					Cleanse(weak->_pendingUnlockPassword);
					weak->_vaultState = DesktopVaultState::SecurityBlocked;
					return;
				}
				weak->_vault = std::move(weak->_pendingCreation->unlocked);
				weak->_pendingCreation.reset();
				Cleanse(weak->_unlockedPassword);
				weak->_unlockedPassword = std::move(
					weak->_pendingUnlockPassword);
				weak->_vaultState = DesktopVaultState::Ready;
				weak->resumePendingGroupCreation();
			} else if (result
					== TelegramTransport::UploadResult::RetryableError) {
				weak->_vaultState
					= DesktopVaultState::RetryableTransportError;
			} else {
				weak->_pendingCreation.reset();
				Cleanse(weak->_pendingUnlockPassword);
				weak->_vaultState
					= DesktopVaultState::PermanentTransportError;
			}
		});
}

void DesktopService::beginGroupVaultPreflight() {
	if (!vaultReady()) {
		return;
	}
	if (!_pendingGroupCreation
		|| !_pendingGroupCreation->vaultPreflightRequired
		|| _sync
		|| _unlockedPassword.isEmpty()) {
		_groupCreationState = DesktopGroupCreationState::LocalFailure;
		return;
	}
	if (!_vaultAnchor.anchor()) {
		_groupCreationState = DesktopGroupCreationState::LocalFailure;
		return;
	}
	_groupCreationState = DesktopGroupCreationState::UpdatingVault;
	_sync = std::make_unique<CloudVaultSyncController>(
		_telegramUserIdBinding,
		*_remote,
		_vaultSelector,
		[weak = base::weak_ptr(this)](CloudVaultSyncCompletion result) {
			if (weak) {
				weak->applyGroupVaultSyncResult(std::move(result));
			}
		},
		SelectCloudVaultOffMain);
	if (!_sync->start(_unlockedPassword, _vaultAnchor.anchor())) {
		_sync.reset();
		_groupCreationState = DesktopGroupCreationState::LocalFailure;
	}
}

void DesktopService::applyGroupVaultSyncResult(
		CloudVaultSyncCompletion result) {
	if (!vaultReady()) {
		return;
	}
	_sync.reset();
	if (!_pendingGroupCreation) {
		return;
	}
	if (result.status == CloudVaultSyncStatus::RetryableTransportError) {
		_groupCreationState = DesktopGroupCreationState::RetryableTransportError;
		return;
	} else if (result.status == CloudVaultSyncStatus::PermanentTransportError) {
		_groupCreationState = DesktopGroupCreationState::PermanentTransportError;
		return;
	} else if (result.status != CloudVaultSyncStatus::Selected
		|| !result.vault) {
		_vaultState = DesktopVaultState::SecurityBlocked;
		_groupCreationState = DesktopGroupCreationState::LocalFailure;
		return;
	}
	auto selected = std::move(*result.vault);
	if (!commitVaultAnchor(selected)) {
		_vaultState = DesktopVaultState::SecurityBlocked;
		_groupCreationState = DesktopGroupCreationState::LocalFailure;
		return;
	}
	_vault = std::move(selected);
	const auto &conversation = _pendingGroupCreation->conversation;
	auto conversations = _vault->conversations;
	const auto existing = std::find_if(
		begin(conversations),
		end(conversations),
		[&](const CloudVaultConversation &value) {
			return value.conversationId == conversation.conversationId
				|| value.telegramPeerIdBinding
					== conversation.telegramPeerIdBinding;
		});
	if (existing != end(conversations)) {
		if (existing->conversationId != conversation.conversationId
			|| existing->telegramPeerIdBinding
				!= conversation.telegramPeerIdBinding
			|| existing->ownerAccountId != conversation.ownerAccountId
			|| existing->checkpoint.conversationId
				!= conversation.conversationId
			|| (existing->checkpoint.generation
					== conversation.checkpoint.generation
				&& existing->checkpoint != conversation.checkpoint)
			|| existing->checkpoint.generation
				> conversation.checkpoint.generation) {
			_vaultState = DesktopVaultState::SecurityBlocked;
			_groupCreationState = DesktopGroupCreationState::LocalFailure;
			return;
		} else if (*existing == conversation) {
			_pendingGroupCreation->vaultPreflightRequired = false;
			publishNextBootstrapObject();
			return;
		}
		*existing = conversation;
	} else {
		conversations.push_back(conversation);
	}
	_pendingGroupCreation->vaultUpdate = _vaultCodec.prepareUpdate(
		*_vault,
		std::move(conversations));
	if (!_pendingGroupCreation->vaultUpdate) {
		_groupCreationState = DesktopGroupCreationState::LocalFailure;
		return;
	}
	_pendingGroupCreation->vaultPreflightRequired = false;
	uploadPendingConversationIndex();
}

void DesktopService::uploadPendingConversationIndex() {
	if (!vaultReady()
		|| !_pendingGroupCreation
		|| !_pendingGroupCreation->vaultUpdate
		|| _pendingGroupCreation->uploadInProgress) {
		return;
	}
	_pendingGroupCreation->uploadInProgress = true;
	_groupCreationState = DesktopGroupCreationState::UpdatingVault;
	const auto operationEpoch = _operationEpoch;
	_remote->uploadExact(
		_pendingGroupCreation->vaultUpdate->encoded,
		[weak = base::weak_ptr(this), operationEpoch](
				TelegramTransport::UploadResult result) {
			if (!weak
				|| !weak->vaultReady()
				|| weak->_operationEpoch != operationEpoch
				|| !weak->_pendingGroupCreation
				|| !weak->_pendingGroupCreation->vaultUpdate
				|| !weak->_vault) {
				return;
			}
			weak->_pendingGroupCreation->uploadInProgress = false;
			if (result == TelegramTransport::UploadResult::Accepted) {
				if (!weak->commitVaultAnchor(
						*weak->_pendingGroupCreation->vaultUpdate,
						weak->_vault->identity)) {
					weak->_vaultState = DesktopVaultState::SecurityBlocked;
					weak->_groupCreationState
						= DesktopGroupCreationState::LocalFailure;
					return;
				}
				auto update = std::move(
					*weak->_pendingGroupCreation->vaultUpdate);
				weak->_pendingGroupCreation->vaultUpdate.reset();
				if (!weak->_vaultCodec.applyPublished(
						*weak->_vault,
						std::move(update))) {
					weak->_vaultState = DesktopVaultState::SecurityBlocked;
					weak->_groupCreationState
						= DesktopGroupCreationState::LocalFailure;
					return;
				}
				weak->publishNextBootstrapObject();
			} else if (result
					== TelegramTransport::UploadResult::RetryableError) {
				weak->_groupCreationState
					= DesktopGroupCreationState::RetryableTransportError;
			} else {
				weak->_groupCreationState
					= DesktopGroupCreationState::PermanentTransportError;
			}
		});
}

void DesktopService::publishNextBootstrapObject() {
	if (!vaultReady()
		|| !_pendingGroupCreation
		|| _pendingGroupCreation->uploadInProgress
		|| _pendingGroupCreation->vaultUpdate) {
		return;
	}
	auto &group = *_pendingGroupCreation;
	if (group.phase == PendingGroupCreation::Phase::Active) {
		const auto recovered = recoverQueuedContentHistory(group);
		if (recovered == QueuedContentRecoveryResult::Invalid) {
			_vaultState = DesktopVaultState::SecurityBlocked;
			_groupCreationState = DesktopGroupCreationState::LocalFailure;
			return;
		} else if (recovered
				== QueuedContentRecoveryResult::PersistenceFailed) {
			_groupCreationState = DesktopGroupCreationState::LocalFailure;
			return;
		}
	}
	if (const auto pending = group.fileTransfer.pending();
		pending
		&& group.phase == PendingGroupCreation::Phase::Removed
		&& !pending->cancelRequested) {
		const auto requested = group.fileTransfer.requestCancel();
		if (requested != FileTransferCommitResult::Committed
			&& requested != FileTransferCommitResult::AlreadyCommitted) {
			_groupCreationState = DesktopGroupCreationState::LocalFailure;
			return;
		}
	}
	if (const auto pending = group.fileTransfer.pending();
		pending
		&& pending->cancelRequested) {
		const auto result = finishFileTransferCancellation(group);
		if (result
				== FileTransferCancellationResult::RetryableCleanupFailure) {
			_groupCreationState
				= DesktopGroupCreationState::PublishingBootstrap;
			scheduleFileTransferRetry(group.conversationId);
			return;
		} else if (result == FileTransferCancellationResult::Failure) {
			_groupCreationState = DesktopGroupCreationState::LocalFailure;
			return;
		}
	}
	if (group.phase == PendingGroupCreation::Phase::Removed
		&& !group.outbox.clear()) {
		_groupCreationState = DesktopGroupCreationState::LocalFailure;
		return;
	}
	if (_pendingGroupCreation->phase == PendingGroupCreation::Phase::Active
		&& _pendingGroupCreation->freshnessGate
		&& _pendingGroupCreation->freshnessGate->state()
			== FreshnessState::Required
		&& !_pendingGroupCreation->outbox.size()
		&& !queueFreshnessChallenge(*_pendingGroupCreation)) {
		_groupCreationState = DesktopGroupCreationState::LocalFailure;
		return;
	}
	auto item = _pendingGroupCreation->outbox.front(
		_pendingGroupCreation->conversationId);
	const auto itemGuard = qScopeGuard([&] {
		if (item) {
			CleanseOutboxItem(*item);
		}
	});
	if (!item) {
		if (_pendingGroupCreation->vaultPreflightRequired) {
			beginGroupVaultPreflight();
			return;
		}
		const auto conversationId = _pendingGroupCreation->conversationId;
		const auto phase = _pendingGroupCreation->phase;
		if (phase == PendingGroupCreation::Phase::Creating) {
			_pendingGroupCreation->phase = PendingGroupCreation::Phase::Active;
		}
		_groups[conversationId] = std::move(_pendingGroupCreation);
		if (_groups[conversationId]->phase
				== PendingGroupCreation::Phase::Active
			&& (!resumeObservedJoinHistory(conversationId)
				|| !initializeActivePipeline(*_groups[conversationId]))) {
			_groupCreationState = DesktopGroupCreationState::LocalFailure;
			setContentState(
				conversationId,
				DesktopContentState::LocalFailure);
			return;
		}
		if (phase == PendingGroupCreation::Phase::AwaitingAdmission) {
			_groupCreationState = DesktopGroupCreationState::AwaitingAdmission;
		} else if (_groups[conversationId]->freshnessGate
				&& !_groups[conversationId]
					->freshnessGate->sendingAllowed()
				&& phase != PendingGroupCreation::Phase::Removed) {
			_groupCreationState = DesktopGroupCreationState::AwaitingFreshness;
		} else {
			_groupCreationState = DesktopGroupCreationState::Ready;
		}
		beginGroupObservation(conversationId);
		beginContentObservation(conversationId);
		resumeDeferredGroupObservations();
		resumePendingGroupCreation();
		startNextGroupDiscovery();
		return;
	} else if (item->stage != OutboxItemStage::Sealed
		|| !item->sealed) {
		_groupCreationState = DesktopGroupCreationState::LocalFailure;
		return;
	}
	const auto persistedEnvelope = _pendingGroupCreation->envelopeCodec.decode(
		*item->sealed);
	if (_pendingGroupCreation->phase == PendingGroupCreation::Phase::Active
		&& persistedEnvelope
		&& persistedEnvelope->objectKind
			== ObjectKind::FreshnessChallenge
		&& !resumeQueuedFreshnessChallenge(
			*_pendingGroupCreation,
			*item->sealed)) {
		_groupCreationState = DesktopGroupCreationState::LocalFailure;
		return;
	}
	const auto objectId = item->sealed->objectId;
	_pendingGroupCreation->uploadInProgress = true;
	_groupCreationState = DesktopGroupCreationState::PublishingBootstrap;
	_pendingGroupCreation->transport.uploadExact(
		*item->sealed,
		[weak = base::weak_ptr(this), objectId](
				TelegramTransport::UploadResult result) {
			if (!weak
				|| !weak->vaultReady()
				|| !weak->_pendingGroupCreation) {
				return;
			}
			weak->_pendingGroupCreation->uploadInProgress = false;
			if (result == TelegramTransport::UploadResult::Accepted) {
				if (!weak->prepareFileManifestAcknowledgement(
						*weak->_pendingGroupCreation,
						objectId)
					|| !weak->_pendingGroupCreation->outbox.remove(objectId)) {
					weak->_groupCreationState
						= DesktopGroupCreationState::LocalFailure;
					return;
				}
				const auto reconciled = ReconcileMlsOutboxReceipts(
					weak->_pendingGroupCreation->mlsState,
					weak->_pendingGroupCreation->outbox,
					weak->_pendingGroupCreation->envelopeCodec,
					weak->_pendingGroupCreation->inboundJournal);
				if (reconciled == MlsReceiptReconcileResult::ObjectIdConflict) {
					weak->_vaultState = DesktopVaultState::SecurityBlocked;
					weak->_groupCreationState
						= DesktopGroupCreationState::LocalFailure;
					return;
				} else if (reconciled
						!= MlsReceiptReconcileResult::Reconciled
					&& reconciled
						!= MlsReceiptReconcileResult::NothingToDo) {
					weak->_groupCreationState
						= DesktopGroupCreationState::LocalFailure;
					return;
				}
				weak->publishNextBootstrapObject();
			} else if (result
					== TelegramTransport::UploadResult::RetryableError) {
				weak->_groupCreationState
					= DesktopGroupCreationState::RetryableTransportError;
			} else {
				weak->_groupCreationState
					= DesktopGroupCreationState::PermanentTransportError;
			}
		});
}

void DesktopService::resumePendingGroupCreation() {
	if (!vaultReady() || _pendingGroupCreation) {
		return;
	}
	for (const auto &conversation : _vault->conversations) {
		rememberProtectedPeerForPresentation(
			conversation.telegramPeerIdBinding);
	}
	for (const auto &conversation : _vault->conversations) {
		if (_groups.contains(conversation.conversationId)) {
			continue;
		}
		const auto directory = ConversationDirectory(
			_telegramUserIdBinding,
			conversation.conversationId);
		if (QFileInfo::exists(directory + u"conversation.meta"_q)
			&& ConversationSetupPending(directory)) {
			(void)FinishConversationSetup(directory);
		}
		const auto result = restoreLocalGroup(
			conversation.conversationId,
			&conversation);
		if (result == LocalGroupRecoveryResult::Restored) {
			publishNextBootstrapObject();
			return;
		} else if (result == LocalGroupRecoveryResult::Missing) {
			if (ConversationSetupPending(directory)) {
				if (!DiscardUncommittedConversationDirectory(directory)) {
					_groupCreationState
						= DesktopGroupCreationState::LocalFailure;
					return;
				}
			} else if (QDir(directory).exists()) {
				_vaultState = DesktopVaultState::SecurityBlocked;
				_groupCreationState = DesktopGroupCreationState::LocalFailure;
				return;
			}
			beginIndexedGroupJoin(conversation);
			return;
		} else if (result == LocalGroupRecoveryResult::Invalid) {
			_vaultState = DesktopVaultState::SecurityBlocked;
			_groupCreationState = DesktopGroupCreationState::LocalFailure;
			return;
		}
	}
	auto entries = QDir(AccountDirectory(_telegramUserIdBinding))
		.entryList(
			QDir::Dirs | QDir::NoDotAndDotDot | QDir::NoSymLinks,
			QDir::Name);
	auto cleanupFailed = false;
	auto unexpectedDirectory = false;
	entries.erase(
		std::remove_if(
			entries.begin(),
			entries.end(),
			[&](const QString &entry) {
				const auto conversationId = DecodeConversationDirectory(entry);
				if (!conversationId) {
					return true;
				}
				const auto directory = ConversationDirectory(
					_telegramUserIdBinding,
					*conversationId);
				if (QFileInfo::exists(directory + u"conversation.meta"_q)) {
					if (ConversationSetupPending(directory)) {
						(void)FinishConversationSetup(directory);
					}
					return false;
				}
				if (!ConversationSetupPending(directory)) {
					unexpectedDirectory = true;
					return false;
				}
				const auto discarded
					= DiscardUncommittedConversationDirectory(directory);
				cleanupFailed = cleanupFailed || !discarded;
				return discarded;
			}),
		entries.end());
	if (cleanupFailed) {
		_groupCreationState = DesktopGroupCreationState::LocalFailure;
		return;
	} else if (unexpectedDirectory || entries.size() > 512) {
		_vaultState = DesktopVaultState::SecurityBlocked;
		_groupCreationState = DesktopGroupCreationState::LocalFailure;
		return;
	}
	auto indexed = std::set<ConversationId>();
	for (const auto &conversation : _vault->conversations) {
		indexed.emplace(conversation.conversationId);
	}
	for (const auto &entry : entries) {
		const auto conversationId = DecodeConversationDirectory(entry);
		if (!conversationId || indexed.contains(*conversationId)) {
			continue;
		}
		const auto result = restoreLocalGroup(*conversationId, nullptr);
		if (result == LocalGroupRecoveryResult::Restored) {
			publishNextBootstrapObject();
			return;
		} else if (result == LocalGroupRecoveryResult::Invalid) {
			_vaultState = DesktopVaultState::SecurityBlocked;
			_groupCreationState = DesktopGroupCreationState::LocalFailure;
			return;
		}
	}
	queueLoadedGroupDiscoveries();
	startNextGroupDiscovery();
}

void DesktopService::beginIndexedGroupJoin(
		const CloudVaultConversation &conversation) {
	if (!vaultReady()
		|| _pendingGroupJoin
		|| _pendingGroupCreation
		|| _groups.contains(conversation.conversationId)) {
		return;
	}
	if (!IsProtectedGroupPeerBinding(
			_session,
			conversation.telegramPeerIdBinding)) {
		_vaultState = DesktopVaultState::SecurityBlocked;
		_groupCreationState = DesktopGroupCreationState::LocalFailure;
		return;
	}
	_pendingGroupJoin = std::make_unique<PendingGroupJoin>(
		_session,
		conversation);
	_groupCreationState = DesktopGroupCreationState::Preparing;
	_pendingGroupJoin->sync =
		std::make_unique<PublicBootstrapSyncController>(
			conversation.conversationId,
			conversation.telegramPeerIdBinding,
			conversation.ownerAccountId,
			_pendingGroupJoin->controlTransport,
			_pendingGroupJoin->envelopeCodec,
			_sha256,
			[weak = base::weak_ptr(this)](
					PublicBootstrapSyncCompletion result) {
				if (weak) {
					weak->applyPublicBootstrapSyncResult(std::move(result));
				}
			});
	if (!_pendingGroupJoin->sync->startForJoin()) {
		_pendingGroupJoin.reset();
		_groupCreationState
			= DesktopGroupCreationState::RetryableTransportError;
		resumeDeferredGroupObservations();
	}
}

void DesktopService::applyPublicBootstrapSyncResult(
		PublicBootstrapSyncCompletion result) {
	if (!vaultReady() || !_pendingGroupJoin) {
		return;
	}
	_pendingGroupJoin->sync.reset();
	if (result.status == PublicBootstrapSyncStatus::RetryableTransportError
		|| result.status == PublicBootstrapSyncStatus::Missing) {
		_pendingGroupJoin.reset();
		_groupCreationState = DesktopGroupCreationState::RetryableTransportError;
		resumeDeferredGroupObservations();
		return;
	} else if (result.status
			== PublicBootstrapSyncStatus::PermanentTransportError) {
		_pendingGroupJoin.reset();
		_groupCreationState = DesktopGroupCreationState::PermanentTransportError;
		resumeDeferredGroupObservations();
		return;
	} else if (result.status != PublicBootstrapSyncStatus::Verified
		|| !result.verified) {
		_pendingGroupJoin.reset();
		_vaultState = DesktopVaultState::SecurityBlocked;
		_groupCreationState = DesktopGroupCreationState::LocalFailure;
		return;
	}
	auto conversation = _pendingGroupJoin->conversation;
	auto verified = std::move(*result.verified);
	if (!BootstrapMatchesConversation(verified, conversation)) {
		_pendingGroupJoin.reset();
		_vaultState = DesktopVaultState::SecurityBlocked;
		_groupCreationState = DesktopGroupCreationState::LocalFailure;
		return;
	}
	_pendingGroupJoin.reset();
	if (!prepareGroupJoin(
			std::move(conversation),
			std::move(verified),
			false)) {
		_groupCreationState = DesktopGroupCreationState::LocalFailure;
		resumeDeferredGroupObservations();
	}
}

bool DesktopService::prepareGroupJoin(
		CloudVaultConversation conversation,
		VerifiedPublicGroupBootstrap verified,
		bool discovered) {
	if (!vaultReady()
		|| _pendingGroupCreation
		|| _groups.contains(conversation.conversationId)
		|| !BootstrapMatchesConversation(verified, conversation)) {
		return false;
	}
	const auto accountId = DeriveAccountId(
		_vault->identity.credential,
		_sha256);
	const auto clientId = RandomId<ClientId>();
	auto localRecordKey = DeriveConversationLocalRecordKey(
		_vault->masterKey,
		_telegramUserIdBinding,
		conversation.conversationId);
	if (!accountId || !clientId || !localRecordKey) {
		_groupCreationState = DesktopGroupCreationState::LocalFailure;
		return false;
	}
	auto operation = std::make_unique<PendingGroupCreation>(
		ConversationDirectory(
			_telegramUserIdBinding,
			conversation.conversationId),
		std::move(*localRecordKey),
		_session,
		conversation.telegramPeerIdBinding,
		conversation.conversationId,
		_sha256);
	if (operation->metadata.load(conversation.conversationId)
			!= ConversationMetadataLoadResult::Missing
		|| operation->journal.load(conversation.conversationId)
			!= GroupBootstrapJournalLoadResult::Empty
		|| operation->mlsState.load(conversation.conversationId)
			!= MlsStateLoadResult::Missing
		|| operation->archiveState.load(conversation.conversationId)
			!= ArchiveStateLoadResult::Missing
		|| operation->groupLedger.load(conversation.conversationId)
			!= GroupLedgerLoadResult::Missing
		|| operation->outbox.load() != PersistentOutboxLoadResult::Empty
		|| operation->changeJournal.load(conversation.conversationId)
			!= GroupChangeJournalLoadResult::Empty
		|| operation->changeInbox.load(conversation.conversationId)
			!= GroupChangeInboxLoadResult::Missing
		|| operation->keyPackages.load(
			conversation.conversationId,
			conversation.telegramPeerIdBinding)
			!= KeyPackagePoolLoadResult::Empty
		|| operation->freshnessTrust.load(conversation.conversationId)
			!= FreshnessTrustLoadResult::Missing
		|| operation->inboundJournal.load()
			!= InboundJournalLoadResult::Missing
		|| operation->controlInboundJournal.load()
			!= InboundJournalLoadResult::Missing
		|| operation->contentStore.load()
			!= ContentStoreLoadResult::Missing
		|| operation->controlSyncState.load(conversation.conversationId)
			!= ControlObservationStateLoadResult::Missing
		|| operation->contentSyncState.load(conversation.conversationId)
			!= ContentSyncStateLoadResult::Missing
		|| operation->fileTransfer.load(conversation.conversationId)
			!= FileTransferLoadResult::Empty) {
		_groupCreationState = DesktopGroupCreationState::LocalFailure;
		return false;
	}
	CleanupStagedProtectedSources(operation->directory, QString());
	const auto createdAt = std::uint64_t(base::unixtime::now());
	auto keyPackage = PrepareClientKeyPackage({
		.client = {
			.conversationId = conversation.conversationId,
			.accountId = *accountId,
			.clientId = *clientId,
			.telegramPeerIdBinding = conversation.telegramPeerIdBinding,
		},
		.currentGeneration = verified.state.generation(),
		.telegramUserIdBinding = _telegramUserIdBinding,
		.createdAt = createdAt,
		.accountCredential = &_vault->identity.credential,
		.accountSigningPrivateKey = &_vault->identity.signingPrivateKey,
	},
	OpenMlsBridge(),
	MlsContextCodecV1(),
	ClientKeyPackagePublicationCodecV1(),
	operation->envelopeCodec,
	_sha256);
	if (keyPackage.status != PrepareClientKeyPackageStatus::Prepared
		|| !keyPackage.entry) {
		_groupCreationState = DesktopGroupCreationState::LocalFailure;
		return false;
	}
	if (!BeginConversationSetup(operation->directory)) {
		DiscardUncommittedConversationDirectory(operation->directory);
		_groupCreationState = DesktopGroupCreationState::LocalFailure;
		return false;
	}
	if (operation->groupLedger.initialize(
			verified.genesis,
			verified.state,
			verified.checkpoint,
			verified.ownerCredential)
			!= GroupLedgerCommitResult::Committed
		|| operation->freshnessTrust.initialize(false)
			!= FreshnessTrustCommitResult::Committed
		|| operation->keyPackages.add(std::move(*keyPackage.entry))
			!= KeyPackagePoolMutationResult::Committed
		|| operation->keyPackages.enqueuePending(
			operation->outbox,
			createdAt) != KeyPackagePoolEnqueueResult::Queued
		|| operation->metadata.initialize({
			.conversationId = conversation.conversationId,
			.telegramPeerIdBinding = conversation.telegramPeerIdBinding,
			.accountId = *accountId,
			.clientId = *clientId,
		}) != ConversationMetadataCommitResult::Committed) {
		DiscardUncommittedConversationDirectory(operation->directory);
		_groupCreationState = DesktopGroupCreationState::LocalFailure;
		return false;
	}
	(void)FinishConversationSetup(operation->directory);
	rememberProtectedPeerForPresentation(
		conversation.telegramPeerIdBinding);
	operation->conversation = conversation;
	operation->joinTargetCheckpoint = conversation.checkpoint;
	operation->freshnessGate = std::make_unique<FreshnessGate>(
		verified.checkpoint,
		false);
	operation->vaultPreflightRequired = discovered;
	operation->phase = PendingGroupCreation::Phase::AwaitingAdmission;
	_pendingGroupCreation = std::move(operation);
	publishNextBootstrapObject();
	return true;
}

bool DesktopService::queueFreshnessChallenge(
		PendingGroupCreation &group) {
	if (!vaultReady()
		|| !group.freshnessGate
		|| group.freshnessGate->state() != FreshnessState::Required) {
		return false;
	}
	const auto metadata = group.metadata.metadata();
	const auto nonce = RandomId<ChallengeNonce>();
	const auto objectId = RandomId<ObjectId>();
	if (!metadata
		|| !nonce
		|| !objectId
		|| !group.freshnessGate->beginChallenge(*nonce)) {
		return false;
	}
	const auto challenge = group.freshnessGate->challenge();
	const auto envelope = challenge
		? PrepareFreshnessChallengeEnvelope({
			.challenge = *challenge,
			.requesterAccountId = metadata->accountId,
			.requesterClientId = metadata->clientId,
			.telegramPeerIdBinding = group.telegramPeerIdBinding,
			.objectId = *objectId,
			.requesterSigningPrivateKey =
				&_vault->identity.signingPrivateKey,
		}, group.envelopeCodec, _sha256)
		: std::nullopt;
	if (!envelope || !group.outbox.appendSealed(*envelope)) {
		group.freshnessGate->requireFreshness(
			group.groupLedger.checkpoint());
		return false;
	}
	return true;
}

bool DesktopService::resumeQueuedFreshnessChallenge(
		PendingGroupCreation &group,
		const EncodedEnvelope &encoded) {
	if (!vaultReady()) {
		return false;
	}
	const auto metadata = group.metadata.metadata();
	const auto envelope = group.envelopeCodec.decode(encoded);
	const auto challenge = envelope
		? FreshnessChallengeCodecV1().decode(envelope->payload)
		: std::nullopt;
	if (!metadata
		|| !group.freshnessGate
		|| !envelope
		|| !challenge
		|| challenge->conversationId != group.conversationId
		|| challenge->knownCheckpoint
			!= group.freshnessGate->knownCheckpoint()
		|| envelope->conversationId != group.conversationId
		|| envelope->objectKind != ObjectKind::FreshnessChallenge
		|| envelope->senderAccountId != metadata->accountId
		|| envelope->senderClientId != metadata->clientId
		|| envelope->telegramPeerIdBinding
			!= group.telegramPeerIdBinding
		|| envelope->epochOrGeneration
			!= challenge->knownCheckpoint.generation
		|| envelope->payloadHash != _sha256.digest(envelope->payload)) {
		return false;
	}
	const auto state = group.freshnessGate->state();
	return (state == FreshnessState::Required)
		? group.freshnessGate->beginChallenge(challenge->nonce)
		: (state == FreshnessState::WaitingForWitness
			&& group.freshnessGate->challenge() == challenge);
}

bool DesktopService::processObservedFreshness(
		ConversationId conversationId,
		const std::vector<TelegramTransport::UntrustedObject> &objects) {
	const auto i = _groups.find(conversationId);
	if (!vaultReady()
		|| i == end(_groups)
		|| i->second->phase != PendingGroupCreation::Phase::Active) {
		return false;
	}
	auto &group = *i->second;
	const auto metadata = group.metadata.metadata();
	if (!metadata || !group.freshnessGate) {
		return false;
	}
	auto changed = false;
	for (const auto &object : objects) {
		if (group.freshnessGate->sendingAllowed()) {
			const auto challenge = VerifyObservedFreshnessChallenge(
				object,
				conversationId,
				group.telegramPeerIdBinding,
				group.envelopeCodec,
				group.groupLedger,
				_sha256);
			if (!challenge
				|| (challenge->requesterAccountId == metadata->accountId
					&& challenge->requesterClientId
						== metadata->clientId)) {
				continue;
			}
			const auto replay = group.controlInboundJournal.lookup(
				conversationId,
				challenge->objectId,
				challenge->payloadHash);
			if (replay == InboundJournalLookup::Accepted) {
				continue;
			} else if (replay == InboundJournalLookup::ObjectIdConflict) {
				_vaultState = DesktopVaultState::SecurityBlocked;
				_groupCreationState = DesktopGroupCreationState::LocalFailure;
				setContentState(
					conversationId,
					DesktopContentState::SecurityBlocked);
				return false;
			} else if (replay == InboundJournalLookup::StorageError) {
				_groupCreationState = DesktopGroupCreationState::LocalFailure;
				setContentState(
					conversationId,
					DesktopContentState::LocalFailure);
				return false;
			}
			const auto responseObjectId = FreshnessResponseObjectId(
				challenge->objectId,
				metadata->clientId,
				_sha256);
			const auto response = PrepareFreshnessResponseEnvelope({
				.challenge = challenge->challenge,
				.witnessCheckpoint = group.groupLedger.checkpoint(),
				.witnessAccountId = metadata->accountId,
				.witnessClientId = metadata->clientId,
				.telegramPeerIdBinding = group.telegramPeerIdBinding,
				.objectId = responseObjectId,
				.witnessSigningPrivateKey =
					&_vault->identity.signingPrivateKey,
			}, group.envelopeCodec, _sha256);
			const auto alreadyPublished = response && std::any_of(
				begin(objects),
				end(objects),
				[&](const auto &candidate) {
					return candidate.bytes == response->bytes;
				});
			const auto queued = response
				? QueueFreshnessResponseOnce({
					.conversationId = conversationId,
					.challengeObjectId = challenge->objectId,
					.challengePayloadHash = challenge->payloadHash,
					.responseEnvelope = *response,
					.responseAlreadyPublished = alreadyPublished,
				}, group.outbox, group.controlInboundJournal)
				: FreshnessResponseQueueResult::InvalidArguments;
			if (queued == FreshnessResponseQueueResult::Queued) {
				changed = true;
			} else if (queued
					== FreshnessResponseQueueResult::ObjectIdConflict) {
				_vaultState = DesktopVaultState::SecurityBlocked;
				_groupCreationState = DesktopGroupCreationState::LocalFailure;
				setContentState(
					conversationId,
					DesktopContentState::SecurityBlocked);
				return false;
			} else if (queued
					== FreshnessResponseQueueResult::InvalidArguments
				|| queued
					== FreshnessResponseQueueResult::PersistenceFailed) {
				_groupCreationState = DesktopGroupCreationState::LocalFailure;
				setContentState(
					conversationId,
					DesktopContentState::LocalFailure);
				return false;
			}
		} else if (group.freshnessGate->state()
				== FreshnessState::WaitingForWitness) {
			const auto response = VerifyObservedFreshnessResponse(
				object,
				conversationId,
				group.telegramPeerIdBinding,
				group.envelopeCodec,
				group.groupLedger,
				_sha256);
			if (!response) {
				continue;
			}
			const auto verifier = AccountFreshnessResponseVerifier(
				group.groupLedger);
			const auto accepted = group.freshnessGate->acceptResponse(
				response->response,
				verifier);
			if (accepted == FreshnessResponseResult::Accepted) {
				const auto committed = group.freshnessTrust.confirm();
				if (committed != FreshnessTrustCommitResult::Committed
					&& committed
						!= FreshnessTrustCommitResult::AlreadyCommitted) {
					group.freshnessGate->requireFreshness(
						group.groupLedger.checkpoint());
					_groupCreationState
						= DesktopGroupCreationState::LocalFailure;
					return false;
				}
				_groupCreationState = DesktopGroupCreationState::Ready;
				changed = true;
			} else if (accepted == FreshnessResponseResult::ForkDetected) {
				_vaultState = DesktopVaultState::SecurityBlocked;
				_groupCreationState = DesktopGroupCreationState::LocalFailure;
				return false;
			} else if (accepted
					== FreshnessResponseResult::ResynchronizationRequired) {
				const auto target = group.freshnessGate
					->resynchronizationTarget();
				const auto knownTarget = target
					? group.groupLedger.checkpointAt(target->generation)
					: std::nullopt;
				const auto caughtUp = target
					&& knownTarget == target
					&& group.freshnessGate
						->completeResynchronization(
							*target,
							verifier)
					&& group.freshnessGate->advanceTrustedCheckpoint(
						group.groupLedger.checkpoint());
				if (caughtUp) {
					const auto committed = group.freshnessTrust.confirm();
					if (committed != FreshnessTrustCommitResult::Committed
						&& committed
							!= FreshnessTrustCommitResult::AlreadyCommitted) {
						group.freshnessGate->requireFreshness(
							group.groupLedger.checkpoint());
						_groupCreationState
							= DesktopGroupCreationState::LocalFailure;
						return false;
					}
					_groupCreationState = DesktopGroupCreationState::Ready;
				} else {
					_groupCreationState
						= DesktopGroupCreationState::AwaitingFreshness;
				}
				changed = true;
			}
		}
	}
	return changed;
}

bool DesktopService::processObservedSafetyGossip(
		ConversationId conversationId,
		const std::vector<TelegramTransport::UntrustedObject> &objects) {
	const auto i = _groups.find(conversationId);
	if (!vaultReady()
		|| i == end(_groups)
		|| (i->second->phase != PendingGroupCreation::Phase::Active
			&& i->second->phase != PendingGroupCreation::Phase::Removed)) {
		return false;
	}
	auto &group = *i->second;
	const auto metadata = group.metadata.metadata();
	const auto state = group.groupLedger.state();
	if (!metadata || !state) {
		return false;
	}
	const auto sameGeneration = group.safetyWitnessGeneration
		== state->generation();
	auto witnesses = sameGeneration
		? group.safetyWitnesses
		: std::set<AccountId>();
	auto ownCurrentGossipObserved = sameGeneration
		&& group.ownSafetyGossipObserved;
	for (const auto &object : objects) {
		const auto observed = VerifyObservedSafetyGossip(
			object,
			conversationId,
			group.telegramPeerIdBinding,
			group.envelopeCodec,
			group.groupLedger,
			_sha256);
		if (observed.result == SafetyGossipVerifyResult::ForkDetected
			|| observed.result
				== SafetyGossipVerifyResult::IdentityConflict
			|| observed.result
				== SafetyGossipVerifyResult::FutureCheckpoint) {
			_vaultState = DesktopVaultState::SecurityBlocked;
			_groupCreationState = DesktopGroupCreationState::LocalFailure;
			setContentState(
				conversationId,
				DesktopContentState::SecurityBlocked);
			return true;
		} else if (observed.result != SafetyGossipVerifyResult::Verified
			|| !observed.verified
			|| observed.verified->gossip.checkpoint
				!= group.groupLedger.checkpoint()) {
			continue;
		}
		witnesses.emplace(observed.verified->gossip.reporterAccountId);
		if (observed.verified->gossip.reporterAccountId
				== metadata->accountId
			&& observed.verified->gossip.reporterClientId
				== metadata->clientId) {
			ownCurrentGossipObserved = true;
		}
	}
	witnesses.emplace(metadata->accountId);
	const auto witnessChanged = group.safetyWitnessGeneration
			!= state->generation()
		|| group.safetyWitnesses != witnesses;
	group.safetyWitnessGeneration = state->generation();
	group.safetyWitnesses = std::move(witnesses);
	group.ownSafetyGossipObserved = ownCurrentGossipObserved;
	if (witnessChanged) {
		notifySecurityRevision();
	}
	if (group.phase != PendingGroupCreation::Phase::Active
		|| ownCurrentGossipObserved) {
		return witnessChanged;
	}
	const auto gossipId = DeriveSafetyGossipObjectId(
		group.groupLedger.checkpoint(),
		metadata->accountId,
		metadata->clientId,
		_sha256);
	if (!gossipId || group.outbox.contains(gossipId)) {
		return witnessChanged;
	}
	const auto envelope = PrepareSafetyGossipEnvelope({
		.gossipId = gossipId,
		.reporterAccountId = metadata->accountId,
		.reporterClientId = metadata->clientId,
		.telegramPeerIdBinding = group.telegramPeerIdBinding,
		.reporterSigningPrivateKey = &_vault->identity.signingPrivateKey,
	}, group.groupLedger, group.envelopeCodec, _sha256);
	if (!envelope || !group.outbox.appendSealed(*envelope)) {
		setContentState(conversationId, DesktopContentState::LocalFailure);
		return true;
	}
	return true;
}

bool DesktopService::synchronizeObservedGroupChanges(
		ConversationId conversationId,
		const std::vector<TelegramTransport::UntrustedObject> &objects) {
	const auto i = _groups.find(conversationId);
	if (!vaultReady()
		|| i == end(_groups)
		|| _pendingGroupCreation
		|| i->second->phase != PendingGroupCreation::Phase::Active) {
		return false;
	}
	auto &group = *i->second;
	const auto metadata = group.metadata.metadata();
	const auto accountId = DeriveAccountId(
		_vault->identity.credential,
		_sha256);
	if (!metadata
		|| !accountId
		|| metadata->accountId != *accountId
		|| !group.freshnessGate) {
		_vaultState = DesktopVaultState::SecurityBlocked;
		_groupCreationState = DesktopGroupCreationState::LocalFailure;
		return true;
	}
	const auto synchronized = SynchronizeObservedGroupChanges(
		objects,
		{
			.conversationId = conversationId,
			.accountId = *accountId,
			.clientId = metadata->clientId,
			.telegramPeerIdBinding = group.telegramPeerIdBinding,
		},
		std::uint64_t(base::unixtime::now()),
		group.envelopeCodec,
		OpenMlsBridge(),
		MlsContextCodecV1(),
		MlsRosterCodecV1(),
		GroupControlCodecV1(),
		_sha256,
		group.mlsState,
		group.archiveState,
		group.groupLedger,
		group.changeJournal,
		group.changeInbox);
	if (synchronized.status == ObservedGroupChangeSyncStatus::NoChange) {
		return false;
	} else if (synchronized.status
			== ObservedGroupChangeSyncStatus::WaitingForObjects
		&& !synchronized.appliedTransitions) {
		return false;
	} else if (synchronized.status
			== ObservedGroupChangeSyncStatus::ForkDetected
		|| synchronized.status
			== ObservedGroupChangeSyncStatus::InvalidState) {
		_vaultState = DesktopVaultState::SecurityBlocked;
		_groupCreationState = DesktopGroupCreationState::LocalFailure;
		return true;
	} else if (synchronized.status
			== ObservedGroupChangeSyncStatus::PersistenceFailure) {
		_groupCreationState = DesktopGroupCreationState::LocalFailure;
		return true;
	}
	const auto checkpoint = group.groupLedger.checkpoint();
	if (synchronized.status
			== ObservedGroupChangeSyncStatus::LocalClientRemoved) {
		group.phase = PendingGroupCreation::Phase::Removed;
		group.freshnessGate->requireFreshness(checkpoint);
	} else if (group.freshnessGate->state() == FreshnessState::Ready) {
		if (!group.freshnessGate->advanceTrustedCheckpoint(checkpoint)) {
			_vaultState = DesktopVaultState::SecurityBlocked;
			_groupCreationState = DesktopGroupCreationState::LocalFailure;
			return true;
		}
	} else if (group.freshnessGate->state()
			== FreshnessState::ResynchronizationRequired) {
		const auto target = group.freshnessGate->resynchronizationTarget();
		const auto knownTarget = target
			? group.groupLedger.checkpointAt(target->generation)
			: std::nullopt;
		const auto verifier = AccountFreshnessResponseVerifier(
			group.groupLedger);
		if (target
			&& knownTarget == target
			&& group.freshnessGate->completeResynchronization(
				*target,
				verifier)
			&& group.freshnessGate->advanceTrustedCheckpoint(checkpoint)) {
			const auto committed = group.freshnessTrust.confirm();
			if (committed != FreshnessTrustCommitResult::Committed
				&& committed
					!= FreshnessTrustCommitResult::AlreadyCommitted) {
				group.freshnessGate->requireFreshness(checkpoint);
				_groupCreationState = DesktopGroupCreationState::LocalFailure;
				return true;
			}
		}
	}
	group.conversation.checkpoint = checkpoint;
	notifySecurityRevision();
	_pendingGroupCreation = std::move(i->second);
	_groups.erase(i);
	_pendingGroupCreation->vaultPreflightRequired = true;
	publishNextBootstrapObject();
	return true;
}

void DesktopService::publishQueuedGroupOutbox(
		ConversationId conversationId) {
	const auto i = _groups.find(conversationId);
	if (!vaultReady()
		|| i == end(_groups)
		|| _pendingGroupCreation
		|| !i->second->outbox.size()) {
		return;
	}
	if (i->second->phase == PendingGroupCreation::Phase::Active) {
		pumpActiveOutbox(conversationId);
		return;
	}
	_pendingGroupCreation = std::move(i->second);
	_groups.erase(i);
	_pendingGroupCreation->vaultPreflightRequired = false;
	publishNextBootstrapObject();
}

DesktopService::QueuedContentRecoveryResult
DesktopService::recoverQueuedContentHistory(
		PendingGroupCreation &group) {
	// The adjacent content-envelope/descriptor pair is the cross-store WAL.
	// Materialize its local history record before either object can be sent;
	// regenerating the pair would reuse stable IDs with different ciphertext.
	if (group.queuedContentReconciled) {
		return QueuedContentRecoveryResult::Ready;
	} else if (!group.outbox.loaded() || !group.contentStore.loaded()) {
		return QueuedContentRecoveryResult::PersistenceFailed;
	}
	auto items = group.outbox.items(group.conversationId);
	const auto itemsGuard = qScopeGuard([&] {
		for (auto &item : items) {
			CleanseOutboxItem(item);
		}
	});
	auto recovered = false;
	for (auto index = std::size_t(); index != items.size();) {
		const auto &contentItem = items[index];
		if (contentItem.stage != OutboxItemStage::Sealed
			|| !contentItem.sealed) {
			++index;
			continue;
		}
		const auto envelope = group.envelopeCodec.decode(
			*contentItem.sealed);
		if (!envelope) {
			return QueuedContentRecoveryResult::Invalid;
		} else if (envelope->objectKind
				!= ObjectKind::EncryptedMessageBody
			&& envelope->objectKind
				!= ObjectKind::EncryptedFileManifest) {
			++index;
			continue;
		}
		const auto encrypted = EncryptedArchivedContentCodecV1().decode(
			envelope->payload);
		if (!encrypted
			|| envelope->payloadHash != _sha256.digest(envelope->payload)
			|| encrypted->conversationId != group.conversationId
			|| encrypted->contentObjectId != envelope->objectId
			|| encrypted->objectKind != envelope->objectKind
			|| encrypted->groupGeneration != envelope->epochOrGeneration
			|| encrypted->senderAccountId != envelope->senderAccountId
			|| encrypted->senderClientId != envelope->senderClientId
			|| QByteArray(
				reinterpret_cast<const char*>(encrypted->signature.data()),
				encrypted->signature.size()) != envelope->authenticationData
			|| index + 1 == items.size()) {
			return QueuedContentRecoveryResult::Invalid;
		}
		const auto &eventItem = items[index + 1];
		if (eventItem.draft.conversationId != group.conversationId
			|| eventItem.draft.objectId != encrypted->eventObjectId) {
			return QueuedContentRecoveryResult::Invalid;
		}
		if (eventItem.stage == OutboxItemStage::Sealed) {
			if (!eventItem.sealed
				|| !group.contentStore.contains(encrypted->eventObjectId)) {
				return QueuedContentRecoveryResult::Invalid;
			}
			auto stored = group.contentStore.record(
				encrypted->eventObjectId);
			const auto storedGuard = qScopeGuard([&] {
				if (stored) {
					Cleanse(stored->plaintext);
				}
			});
			if (!stored) {
				return QueuedContentRecoveryResult::PersistenceFailed;
			} else if (stored->conversationId != group.conversationId
				|| stored->eventObjectId != encrypted->eventObjectId
				|| stored->contentObjectId != encrypted->contentObjectId
				|| stored->objectKind != encrypted->objectKind
				|| stored->groupGeneration != encrypted->groupGeneration
				|| stored->senderAccountId != encrypted->senderAccountId
				|| stored->senderClientId != encrypted->senderClientId) {
				return QueuedContentRecoveryResult::Invalid;
			}
		} else if (eventItem.stage == OutboxItemStage::Draft
			&& !eventItem.sealed
			&& eventItem.draft.authenticatedData
				== QByteArray("TDE2E/archived-content/v1")) {
			auto opened = OpenLiveArchivedContent(
				group.conversationId,
				group.telegramPeerIdBinding,
				{
					.conversationId = group.conversationId,
					.eventObjectId = eventItem.draft.objectId,
					.senderAccountId = envelope->senderAccountId,
					.senderClientId = envelope->senderClientId,
					.plaintext = eventItem.draft.plaintext,
				},
				*envelope,
				group.groupLedger,
				EncryptedArchivedContentCodecV1(),
				ArchivedContentDescriptorCodecV1(),
				_sha256);
			const auto openedGuard = qScopeGuard([&] {
				if (opened.content) {
					Cleanse(opened.content->plaintext);
				}
			});
			if (opened.status != ArchivedContentOpenStatus::Opened
				|| !opened.content) {
				return QueuedContentRecoveryResult::Invalid;
			}
			auto unixTime = std::uint64_t();
			if (opened.content->objectKind
					== ObjectKind::EncryptedMessageBody) {
				auto body = ProtectedMessageBodyCodecV1().decodePlaintext(
					opened.content->plaintext);
				if (!body) {
					return QueuedContentRecoveryResult::Invalid;
				}
				unixTime = body->unixTime;
				Cleanse(body->textUtf8);
			} else {
				auto manifest = PrivateFileManifestCodecV1().decodePlaintext(
					opened.content->plaintext);
				if (!manifest
					|| manifest->context.conversationId
						!= group.conversationId) {
					return QueuedContentRecoveryResult::Invalid;
				}
				unixTime = manifest->unixTime;
				Cleanse(manifest->filenameUtf8);
				Cleanse(manifest->mimeTypeUtf8);
				if (manifest->preview) {
					Cleanse(manifest->preview->jpegBytes);
				}
			}
			const auto stored = group.contentStore.append({
				.conversationId = group.conversationId,
				.eventObjectId = opened.content->eventObjectId,
				.contentObjectId = opened.content->contentObjectId,
				.objectKind = opened.content->objectKind,
				.groupGeneration = opened.content->groupGeneration,
				.senderAccountId = opened.content->senderAccountId,
				.senderClientId = opened.content->senderClientId,
				.unixTime = unixTime,
				.observedTelegramMessageId = 0,
				.plaintext = opened.content->plaintext,
			});
			if (stored == ContentStoreAppendResult::Conflict
				|| stored == ContentStoreAppendResult::InvalidRecord) {
				return QueuedContentRecoveryResult::Invalid;
			} else if (stored
					== ContentStoreAppendResult::PersistenceFailed) {
				return QueuedContentRecoveryResult::PersistenceFailed;
			} else if (stored == ContentStoreAppendResult::Stored) {
				recovered = true;
			}
		} else {
			return QueuedContentRecoveryResult::Invalid;
		}
		index += 2;
	}
	group.queuedContentReconciled = true;
	if (recovered) {
		notifyContentRevision();
	}
	return recovered
		? QueuedContentRecoveryResult::Recovered
		: QueuedContentRecoveryResult::Ready;
}

bool DesktopService::initializeActivePipeline(
		PendingGroupCreation &group) {
	if (!vaultReady()) {
		return false;
	}
	const auto recovered = recoverQueuedContentHistory(group);
	if (recovered == QueuedContentRecoveryResult::Invalid) {
		_vaultState = DesktopVaultState::SecurityBlocked;
		return false;
	} else if (recovered
			== QueuedContentRecoveryResult::PersistenceFailed) {
		return false;
	}
	if (group.applicationEngine
		&& group.outboxCoordinator
		&& group.uploadController) {
		return group.applicationEngine->ready();
	}
	const auto metadata = group.metadata.metadata();
	if (!metadata
		|| !group.freshnessGate
		|| group.phase != PendingGroupCreation::Phase::Active) {
		return false;
	}
	group.applicationEngine = std::make_unique<OpenMlsApplicationEngine>(
		OpenMlsClientContext{
			.conversationId = group.conversationId,
			.accountId = metadata->accountId,
			.clientId = metadata->clientId,
			.telegramPeerIdBinding = group.telegramPeerIdBinding,
		},
		OpenMlsBridge(),
		MlsContextCodecV1(),
		group.envelopeCodec,
		_sha256,
		group.mlsState);
	if (!group.applicationEngine->ready()) {
		group.applicationEngine.reset();
		return false;
	}
	group.outboxCoordinator = std::make_unique<OutboxCoordinator>(
		*group.freshnessGate,
		group.outbox,
		*group.applicationEngine);
	const auto conversationId = group.conversationId;
	group.uploadController = std::make_unique<OutboxUploadController>(
		*group.outboxCoordinator,
		group.transport,
		[weak = base::weak_ptr(this), conversationId](ObjectId objectId) {
			return weak && weak->prepareActiveUploadAcknowledgement(
				conversationId,
				objectId);
		},
		[weak = base::weak_ptr(this), conversationId](
				UploadCompletion completion) {
			if (weak) {
				weak->completeActiveUpload(
					conversationId,
					std::move(completion));
			}
		});
	return true;
}

void DesktopService::pumpActiveOutbox(ConversationId conversationId) {
	const auto i = _groups.find(conversationId);
	if (!vaultReady()
		|| i == end(_groups)
		|| i->second->phase != PendingGroupCreation::Phase::Active) {
		return;
	}
	if (!initializeActivePipeline(*i->second)) {
		setContentState(
			conversationId,
			(_vaultState.current() == DesktopVaultState::SecurityBlocked)
				? DesktopContentState::SecurityBlocked
				: DesktopContentState::LocalFailure);
		return;
	}
	auto &group = *i->second;
	if (_pendingGroupCreation
		|| _pendingGroupJoin
		|| _pendingGroupDiscovery) {
		group.observationDirty = true;
		return;
	}
	if (group.observation) {
		setContentState(
			conversationId,
			DesktopContentState::Synchronizing);
		return;
	} else if (group.observationDirty && !group.outbox.size()) {
		beginGroupObservation(conversationId);
		const auto current = _groups.find(conversationId);
		if (current == end(_groups)) {
			return;
		} else if (current->second->observation) {
			setContentState(
				conversationId,
				DesktopContentState::Synchronizing);
			return;
		} else if (current->second->observationDirty) {
			return;
		}
	}
	if (const auto pending = group.fileTransfer.pending();
		pending && pending->cancelRequested) {
		if (group.fileFinalHashInProgress
			|| group.uploadInProgress
			|| (group.uploadController
				&& group.uploadController->uploadInProgress())) {
			setContentState(
				conversationId,
				DesktopContentState::Synchronizing);
		} else if (const auto result = finishFileTransferCancellation(group);
			result == FileTransferCancellationResult::RetryableCleanupFailure) {
			setContentState(
				conversationId,
				DesktopContentState::Synchronizing);
			scheduleFileTransferRetry(conversationId);
		} else if (result == FileTransferCancellationResult::Failure) {
			setContentState(
				conversationId,
				DesktopContentState::LocalFailure);
		} else {
			pumpActiveOutbox(conversationId);
		}
		return;
	}
	if (group.fileHashInProgress) {
		setContentState(
			conversationId,
			DesktopContentState::Synchronizing);
		return;
	} else if (group.filePreparationSource
		&& !group.outbox.size()
		&& !group.uploadInProgress
		&& (!group.uploadController
			|| !group.uploadController->uploadInProgress())
		&& !commitPreparedFileTransfer(conversationId)) {
		return;
	}
	if (!group.freshnessGate->sendingAllowed()) {
		if (group.freshnessGate->state() == FreshnessState::Required
			&& !group.outbox.size()
			&& !queueFreshnessChallenge(group)) {
			setContentState(
				conversationId,
				DesktopContentState::LocalFailure);
			return;
		}
		auto item = group.outbox.front(conversationId);
		const auto itemGuard = qScopeGuard([&] {
			if (item) {
				CleanseOutboxItem(*item);
			}
		});
		const auto envelope = (item && item->sealed)
			? group.envelopeCodec.decode(*item->sealed)
			: std::nullopt;
		if (!item
			|| item->stage != OutboxItemStage::Sealed
			|| !item->sealed
			|| !envelope
			|| envelope->objectKind != ObjectKind::FreshnessChallenge) {
			setContentState(
				conversationId,
				DesktopContentState::AwaitingFreshness);
			return;
		}
		if (!resumeQueuedFreshnessChallenge(group, *item->sealed)) {
			setContentState(
				conversationId,
				DesktopContentState::LocalFailure);
			return;
		}
		if (group.uploadInProgress) {
			return;
		}
		const auto objectId = item->sealed->objectId;
		group.uploadInProgress = true;
		group.transport.uploadExact(
			*item->sealed,
			[weak = base::weak_ptr(this), conversationId, objectId](
					TelegramTransport::UploadResult result) {
				if (!weak || !weak->vaultReady()) {
					return;
				}
				const auto i = weak->_groups.find(conversationId);
				if (i == end(weak->_groups)) {
					return;
				}
				auto &group = *i->second;
				group.uploadInProgress = false;
				if (result == TelegramTransport::UploadResult::Accepted) {
					if (group.fileTransfer.pending()) {
						weak->resetFileTransferRetry(group);
					}
					if (!group.outbox.remove(objectId)) {
						weak->setContentState(
							conversationId,
							DesktopContentState::LocalFailure);
						return;
					}
					weak->setContentState(
						conversationId,
						DesktopContentState::AwaitingFreshness);
					weak->beginGroupObservation(conversationId);
				} else if (result
						== TelegramTransport::UploadResult::RetryableError) {
					weak->setContentState(
						conversationId,
						DesktopContentState::RetryableTransportError);
					if (group.fileTransfer.pending()) {
						weak->scheduleFileTransferRetry(conversationId);
					}
				} else {
					weak->setContentState(
						conversationId,
						DesktopContentState::PermanentTransportError);
				}
				if (const auto pending = group.fileTransfer.pending();
					pending && pending->cancelRequested) {
					weak->pumpActiveOutbox(conversationId);
				}
			});
		return;
	}
	if (const auto pending = group.fileTransfer.pending(); pending) {
		if (!pending->manifestPublished) {
			if (!queuePendingFileManifest(conversationId)) {
				return;
			}
		} else if (!group.outbox.contains(pending->eventObjectId)
			&& !group.outbox.contains(pending->contentObjectId)) {
			(void)pumpFileTransfer(conversationId);
			return;
		}
	}
	const auto pumped = group.uploadController->pump();
	switch (pumped) {
	case UploadPumpResult::Empty:
		setContentState(conversationId, DesktopContentState::Ready);
		beginContentObservation(conversationId);
		break;
	case UploadPumpResult::Started:
	case UploadPumpResult::UploadInProgress:
		setContentState(conversationId, DesktopContentState::Synchronizing);
		break;
	case UploadPumpResult::AwaitingFreshness:
		setContentState(
			conversationId,
			DesktopContentState::AwaitingFreshness);
		break;
	case UploadPumpResult::InvalidItem:
	case UploadPumpResult::ProtectionFailed:
	case UploadPumpResult::PersistenceFailed:
		setContentState(conversationId, DesktopContentState::LocalFailure);
		break;
	}
}

bool DesktopService::prepareActiveUploadAcknowledgement(
		ConversationId conversationId,
		ObjectId objectId) {
	const auto i = _groups.find(conversationId);
	if (!vaultReady() || i == end(_groups)) {
		return false;
	}
	return prepareFileManifestAcknowledgement(*i->second, objectId);
}

bool DesktopService::prepareFileManifestAcknowledgement(
		PendingGroupCreation &group,
		ObjectId objectId) {
	const auto pending = group.fileTransfer.pending();
	if (!pending
		|| pending->manifestPublished
		|| objectId != pending->eventObjectId) {
		return true;
	} else if (!group.outbox.contains(pending->eventObjectId)
		|| group.outbox.contains(pending->contentObjectId)) {
		return false;
	}
	const auto currentEpoch = group.archiveState.currentEpoch();
	const auto archiveEpochGeneration = pending->archiveEpochGeneration
		? pending->archiveEpochGeneration
		: (currentEpoch ? currentEpoch->generation : 0);
	const auto marked = group.fileTransfer.markManifestPublished(
		archiveEpochGeneration);
	return marked == FileTransferCommitResult::Committed
		|| marked == FileTransferCommitResult::AlreadyCommitted;
}

bool DesktopService::commitPreparedFileTransfer(
		ConversationId conversationId) {
	const auto i = _groups.find(conversationId);
	if (!vaultReady() || i == end(_groups)) {
		return false;
	}
	auto &group = *i->second;
	const auto metadata = group.metadata.metadata();
	const auto state = group.groupLedger.state();
	const auto epoch = group.archiveState.currentEpoch();
	const auto source = group.filePreparationSource;
	if (!metadata
		|| !state
		|| !epoch
		|| !source
		|| group.filePreparationPath.isEmpty()
		|| group.filePreparationFilename.isEmpty()
		|| group.filePreparationMimeType.isEmpty()
		|| group.fileTransfer.pending()
		|| group.outbox.size()
		|| group.uploadInProgress
		|| (group.uploadController
			&& group.uploadController->uploadInProgress())
		|| source->size > kMaximumProtectedFileSize) {
		RemoveStagedProtectedSource(
			_telegramUserIdBinding,
			conversationId,
			group.filePreparationPath);
		group.filePreparationPath.clear();
		group.filePreparationFilename.clear();
		group.filePreparationMimeType.clear();
		group.filePreparationSource.reset();
		setContentState(conversationId, DesktopContentState::LocalFailure);
		return false;
	}
	const auto material = GenerateFileEncryptionMaterial();
	const auto eventObjectId = RandomId<ObjectId>();
	const auto contentObjectId = RandomId<ObjectId>();
	if (!material || !eventObjectId || !contentObjectId) {
		RemoveStagedProtectedSource(
			_telegramUserIdBinding,
			conversationId,
			group.filePreparationPath);
		group.filePreparationPath.clear();
		group.filePreparationFilename.clear();
		group.filePreparationMimeType.clear();
		group.filePreparationSource.reset();
		setContentState(conversationId, DesktopContentState::LocalFailure);
		return false;
	}
	const auto chunkCount = source->size
		? std::uint32_t(1 + ((source->size - 1) / kDesktopFileChunkSize))
		: 0;
	const auto manifest = PrivateFileManifest{
		.context = {
			.conversationId = conversationId,
			.fileId = material->fileId,
			.plaintextSize = source->size,
			.chunkSize = kDesktopFileChunkSize,
			.chunkCount = chunkCount,
			.noncePrefix = material->noncePrefix,
		},
		.key = FileEncryptionKey(std::array<std::uint8_t, 32>(
			material->key.bytes())),
		.plaintextHash = source->hash,
		.unixTime = std::uint64_t(base::unixtime::now()),
		.filenameUtf8 = group.filePreparationFilename.toUtf8(),
		.mimeTypeUtf8 = group.filePreparationMimeType.toUtf8(),
		.preview = source->preview,
	};
	auto manifestPlaintext = PrivateFileManifestCodecV1()
		.encodePlaintext(manifest);
	const auto manifestGuard = qScopeGuard([&] {
		if (manifestPlaintext) {
			Cleanse(*manifestPlaintext);
		}
	});
	if (!manifestPlaintext) {
		RemoveStagedProtectedSource(
			_telegramUserIdBinding,
			conversationId,
			group.filePreparationPath);
		group.filePreparationPath.clear();
		group.filePreparationFilename.clear();
		group.filePreparationMimeType.clear();
		group.filePreparationSource.reset();
		setContentState(conversationId, DesktopContentState::LocalFailure);
		return false;
	} else if (group.freshnessGate->state() == FreshnessState::Required
		&& !queueFreshnessChallenge(group)) {
		setContentState(conversationId, DesktopContentState::LocalFailure);
		return false;
	}
	const auto sourcePath = group.filePreparationPath;
	auto transfer = PendingFileTransfer{
		.conversationId = conversationId,
		.eventObjectId = *eventObjectId,
		.contentObjectId = *contentObjectId,
		.groupGeneration = state->generation(),
		.archiveEpochGeneration = epoch->generation,
		.manifestPublished = false,
		.nextChunkIndex = 0,
		.sourcePathUtf8 = group.filePreparationPath.toUtf8(),
		.manifestPlaintext = *manifestPlaintext,
	};
	const auto queued = group.fileTransfer.begin(std::move(transfer));
	if (queued != FileTransferCommitResult::Committed) {
		RemoveStagedProtectedSource(
			_telegramUserIdBinding,
			conversationId,
			sourcePath);
		group.filePreparationPath.clear();
		group.filePreparationFilename.clear();
		group.filePreparationMimeType.clear();
		group.filePreparationSource.reset();
		setContentState(conversationId, DesktopContentState::LocalFailure);
		return false;
	}
	if (!IsStagedProtectedSource(
			_telegramUserIdBinding,
			conversationId,
			sourcePath)) {
		group.localProtectedFilePaths.insert_or_assign(
			*eventObjectId,
			sourcePath);
	}
	group.filePreparationPath.clear();
	group.filePreparationFilename.clear();
	group.filePreparationMimeType.clear();
	group.filePreparationSource.reset();
	notifyFileTransferRevision();
	return true;
}

DesktopService::FileTransferCancellationResult
DesktopService::finishFileTransferCancellation(
		PendingGroupCreation &group) {
	const auto pending = group.fileTransfer.pending();
	const auto manifest = pending
		? PrivateFileManifestCodecV1().decodePlaintext(
			pending->manifestPlaintext)
		: std::nullopt;
	if (!pending
		|| !pending->cancelRequested
		|| !manifest
		|| group.fileFinalHashInProgress
		|| group.uploadInProgress
		|| (group.uploadController
			&& group.uploadController->uploadInProgress())
		|| !group.outbox.removePair(
			pending->eventObjectId,
			pending->contentObjectId)) {
		return FileTransferCancellationResult::Failure;
	}
	const auto sourcePath = QString::fromUtf8(pending->sourcePathUtf8);
	if (!group.chunkStore.removeChunksBefore(
		group.conversationId,
		manifest->context.fileId,
		manifest->context.chunkCount)) {
		return FileTransferCancellationResult::RetryableCleanupFailure;
	}
	group.localProtectedFilePaths.erase(pending->eventObjectId);
	const auto cleared = group.fileTransfer.clear();
	if (cleared != FileTransferCommitResult::Committed
		&& cleared != FileTransferCommitResult::AlreadyCommitted) {
		return FileTransferCancellationResult::Failure;
	}
	resetFileTransferRetry(group);
	RemoveStagedProtectedSource(
		_telegramUserIdBinding,
		group.conversationId,
		sourcePath);
	notifyFileTransferRevision();
	return FileTransferCancellationResult::Finished;
}

void DesktopService::completeActiveUpload(
		ConversationId conversationId,
		UploadCompletion completion) {
	const auto i = _groups.find(conversationId);
	if (!vaultReady() || i == end(_groups)) {
		return;
	}
	auto &group = *i->second;
	if (!completion.outboxUpdated) {
		setContentState(conversationId, DesktopContentState::LocalFailure);
		return;
	} else if (const auto pending = group.fileTransfer.pending();
		pending && pending->cancelRequested) {
		pumpActiveOutbox(conversationId);
		return;
	} else if (completion.transportResult
			== TelegramTransport::UploadResult::RetryableError) {
		setContentState(
			conversationId,
			DesktopContentState::RetryableTransportError);
		if (group.fileTransfer.pending()) {
			scheduleFileTransferRetry(conversationId);
		}
		return;
	} else if (completion.transportResult
			== TelegramTransport::UploadResult::PermanentError) {
		setContentState(
			conversationId,
			DesktopContentState::PermanentTransportError);
		return;
	}
	const auto receipt = group.mlsState.receipt(completion.objectId);
	if (receipt) {
		const auto envelope = group.envelopeCodec.decode(receipt->envelope);
		const auto reconciled = envelope
			? ReconcileObservedMlsReceipt(
				*envelope,
				group.envelopeCodec,
				group.mlsState,
				group.inboundJournal)
			: ObservedMlsReceiptReconcileResult::ObjectIdConflict;
		if (reconciled != ObservedMlsReceiptReconcileResult::Reconciled) {
			const auto state = (reconciled
					== ObservedMlsReceiptReconcileResult::ObjectIdConflict)
				? DesktopContentState::SecurityBlocked
				: DesktopContentState::LocalFailure;
			setContentState(conversationId, state);
			if (state == DesktopContentState::SecurityBlocked) {
				_vaultState = DesktopVaultState::SecurityBlocked;
			}
			return;
		}
	}
	if (group.fileTransfer.pending()) {
		resetFileTransferRetry(group);
	}
	pumpActiveOutbox(conversationId);
}

bool DesktopService::pumpFileTransfer(ConversationId conversationId) {
	const auto i = _groups.find(conversationId);
	if (!vaultReady()
		|| i == end(_groups)
		|| i->second->phase != PendingGroupCreation::Phase::Active) {
		return false;
	}
	auto &group = *i->second;
	const auto pending = group.fileTransfer.pending();
	if (!pending) {
		return false;
	} else if (!pending->manifestPublished) {
		setContentState(conversationId, DesktopContentState::LocalFailure);
		return true;
	} else if (!group.freshnessGate
		|| !group.freshnessGate->sendingAllowed()) {
		setContentState(
			conversationId,
			DesktopContentState::AwaitingFreshness);
		return true;
	} else if (group.uploadInProgress
		|| (group.uploadController
			&& group.uploadController->uploadInProgress())) {
		return true;
	}
	const auto manifest = PrivateFileManifestCodecV1().decodePlaintext(
		pending->manifestPlaintext);
	if (!manifest) {
		setContentState(conversationId, DesktopContentState::LocalFailure);
		return true;
	} else if (!group.chunkStore.removeChunksBefore(
		conversationId,
		manifest->context.fileId,
		pending->nextChunkIndex)) {
		setContentState(
			conversationId,
			DesktopContentState::Synchronizing);
		scheduleFileTransferRetry(conversationId);
		return true;
	} else if (pending->nextChunkIndex == manifest->context.chunkCount) {
		(void)finalizeFileTransfer(conversationId);
		return true;
	}
	auto source = QFile(QString::fromUtf8(pending->sourcePathUtf8));
	const auto index = pending->nextChunkIndex;
	const auto offset = std::uint64_t(manifest->context.chunkSize) * index;
	const auto expected = (index + 1 < manifest->context.chunkCount)
		? std::uint64_t(manifest->context.chunkSize)
		: manifest->context.plaintextSize - offset;
	if (!source.open(QIODevice::ReadOnly)
		|| source.size() < 0
		|| std::uint64_t(source.size()) != manifest->context.plaintextSize
		|| !source.seek(qint64(offset))) {
		setContentState(conversationId, DesktopContentState::LocalFailure);
		return true;
	}
	auto plaintext = source.read(qint64(expected));
	const auto prepared = IdempotentFileChunkProtector(
		AesGcmFileChunkCipher(),
		group.chunkStore).prepare(
			manifest->key,
			manifest->context,
			index,
			plaintext);
	Cleanse(plaintext);
	const auto metadata = group.metadata.metadata();
	const auto envelope = (metadata && prepared.exactCiphertext)
		? PrepareFileChunkEnvelope({
			.conversationId = conversationId,
			.senderAccountId = metadata->accountId,
			.senderClientId = metadata->clientId,
			.telegramPeerIdBinding = group.telegramPeerIdBinding,
			.groupGeneration = pending->groupGeneration,
			.fileId = manifest->context.fileId,
			.chunkIndex = index,
			.chunkCount = manifest->context.chunkCount,
			.senderSigningPrivateKey = &_vault->identity.signingPrivateKey,
			.exactCiphertext = *prepared.exactCiphertext,
		}, group.envelopeCodec, _sha256)
		: std::nullopt;
	if (prepared.result != FileChunkPrepareResult::Ready || !envelope) {
		setContentState(conversationId, DesktopContentState::LocalFailure);
		return true;
	}
	group.uploadInProgress = true;
	setContentState(conversationId, DesktopContentState::Synchronizing);
	group.transport.uploadExact(
		envelope->encoded,
		[weak = base::weak_ptr(this), conversationId, index](
				TelegramTransport::UploadResult result) {
			if (weak) {
				weak->completeFileChunkUpload(
					conversationId,
					index,
					result);
			}
		});
	return true;
}

void DesktopService::completeFileChunkUpload(
		ConversationId conversationId,
		std::uint32_t chunkIndex,
		TelegramTransport::UploadResult result) {
	const auto i = _groups.find(conversationId);
	if (!vaultReady() || i == end(_groups)) {
		return;
	}
	auto &group = *i->second;
	group.uploadInProgress = false;
	if (const auto pending = group.fileTransfer.pending();
		pending && pending->cancelRequested) {
		pumpActiveOutbox(conversationId);
		return;
	}
	if (result == TelegramTransport::UploadResult::RetryableError) {
		setContentState(
			conversationId,
			DesktopContentState::RetryableTransportError);
		scheduleFileTransferRetry(conversationId);
		return;
	} else if (result == TelegramTransport::UploadResult::PermanentError) {
		setContentState(
			conversationId,
			DesktopContentState::PermanentTransportError);
		return;
	}
	const auto pending = group.fileTransfer.pending();
	const auto manifest = pending
		? PrivateFileManifestCodecV1().decodePlaintext(
			pending->manifestPlaintext)
		: std::nullopt;
	if (!manifest) {
		setContentState(conversationId, DesktopContentState::LocalFailure);
		return;
	}
	if (group.fileTransfer.advance(chunkIndex)
			!= FileTransferCommitResult::Committed) {
		setContentState(conversationId, DesktopContentState::LocalFailure);
		return;
	}
	resetFileTransferRetry(group);
	(void)group.chunkStore.removeChunk(
		conversationId,
		manifest->context.fileId,
		chunkIndex);
	pumpActiveOutbox(conversationId);
}

void DesktopService::scheduleFileTransferRetry(
		ConversationId conversationId) {
	const auto i = _groups.find(conversationId);
	auto group = (i != end(_groups)) ? i->second.get() : nullptr;
	if (!group
		&& _pendingGroupCreation
		&& _pendingGroupCreation->conversationId == conversationId) {
		group = _pendingGroupCreation.get();
	}
	if (!vaultReady() || !group || !group->fileTransfer.pending()) {
		return;
	}
	const auto delay = FileRetryDelay(group->fileRetryAttempt);
	group->fileRetryAttempt = std::min(group->fileRetryAttempt + 1, 6);
	if (++group->fileRetryToken == 0) {
		++group->fileRetryToken;
	}
	const auto token = group->fileRetryToken;
	base::call_delayed(delay, [weak = base::weak_ptr(this),
			conversationId,
			token] {
		if (!weak || !weak->vaultReady()) {
			return;
		}
		const auto i = weak->_groups.find(conversationId);
		auto group = (i != end(weak->_groups)) ? i->second.get() : nullptr;
		const auto publishing = !group
			&& weak->_pendingGroupCreation
			&& weak->_pendingGroupCreation->conversationId == conversationId;
		if (publishing) {
			group = weak->_pendingGroupCreation.get();
		}
		if (!group
			|| group->fileRetryToken != token
			|| !group->fileTransfer.pending()) {
			return;
		}
		if (publishing) {
			weak->publishNextBootstrapObject();
		} else {
			weak->pumpActiveOutbox(conversationId);
		}
	});
}

void DesktopService::resetFileTransferRetry(
		PendingGroupCreation &group) {
	group.fileRetryAttempt = 0;
	if (++group.fileRetryToken == 0) {
		++group.fileRetryToken;
	}
}

bool DesktopService::queuePendingFileManifest(
		ConversationId conversationId) {
	const auto i = _groups.find(conversationId);
	if (!vaultReady() || i == end(_groups)) {
		return false;
	}
	auto &group = *i->second;
	const auto pending = group.fileTransfer.pending();
	const auto manifest = pending
		? PrivateFileManifestCodecV1().decodePlaintext(
			pending->manifestPlaintext)
		: std::nullopt;
	auto source = QFile(pending
		? QString::fromUtf8(pending->sourcePathUtf8)
		: QString());
	const auto sourceMatches = pending
		&& manifest
		&& source.open(QIODevice::ReadOnly)
		&& source.size() >= 0
		&& std::uint64_t(source.size())
			== manifest->context.plaintextSize;
	const auto metadata = group.metadata.metadata();
	const auto epoch = (pending && pending->archiveEpochGeneration)
		? group.archiveState.epoch(pending->archiveEpochGeneration)
		: group.archiveState.currentEpoch();
	if (!pending
		|| !manifest
		|| !sourceMatches
		|| !metadata
		|| !epoch
		|| !group.groupLedger.wasClientActiveAt(
			metadata->accountId,
			metadata->clientId,
			pending->groupGeneration)
		|| !group.archiveState.epochWasActiveAt(
			epoch->generation,
			pending->groupGeneration)
		|| !group.outboxCoordinator) {
		setContentState(conversationId, DesktopContentState::LocalFailure);
		return false;
	}
	const auto hasEvent = group.outbox.contains(pending->eventObjectId);
	const auto hasContent = group.outbox.contains(pending->contentObjectId);
	if (!hasEvent && !hasContent) {
		const auto queued = QueueArchivedContent({
			.conversationId = conversationId,
			.eventObjectId = pending->eventObjectId,
			.contentObjectId = pending->contentObjectId,
			.objectKind = ObjectKind::EncryptedFileManifest,
			.senderAccountId = metadata->accountId,
			.senderClientId = metadata->clientId,
			.telegramPeerIdBinding = group.telegramPeerIdBinding,
			.groupGeneration = pending->groupGeneration,
			.archiveEpochGeneration = epoch->generation,
			.archiveEpochKey = &epoch->key,
			.senderSigningPrivateKey = &_vault->identity.signingPrivateKey,
			.plaintext = pending->manifestPlaintext,
			.mlsContext = QByteArray("TDE2E/archived-content/v1"),
		},
		ArchiveEpochCrypto(),
		EncryptedArchivedContentCodecV1(),
		ArchivedContentDescriptorCodecV1(),
		group.envelopeCodec,
		_sha256,
		*group.outboxCoordinator);
		if (queued != ArchivedContentQueueResult::Queued) {
			setContentState(
				conversationId,
				DesktopContentState::LocalFailure);
			return false;
		}
		group.queuedContentReconciled = false;
	}
	const auto stored = group.contentStore.append({
		.conversationId = conversationId,
		.eventObjectId = pending->eventObjectId,
		.contentObjectId = pending->contentObjectId,
		.objectKind = ObjectKind::EncryptedFileManifest,
		.groupGeneration = pending->groupGeneration,
		.senderAccountId = metadata->accountId,
		.senderClientId = metadata->clientId,
		.unixTime = manifest->unixTime,
		.observedTelegramMessageId = 0,
		.plaintext = pending->manifestPlaintext,
	});
	if (stored == ContentStoreAppendResult::Conflict) {
		_vaultState = DesktopVaultState::SecurityBlocked;
		setContentState(conversationId, DesktopContentState::SecurityBlocked);
		return false;
	} else if (stored == ContentStoreAppendResult::InvalidRecord
		|| stored == ContentStoreAppendResult::PersistenceFailed) {
		setContentState(conversationId, DesktopContentState::LocalFailure);
		return false;
	}
	if (stored == ContentStoreAppendResult::Stored) {
		notifyContentRevision();
	}
	group.queuedContentReconciled = true;
	return true;
}

bool DesktopService::finalizeFileTransfer(
		ConversationId conversationId) {
	const auto i = _groups.find(conversationId);
	if (!vaultReady() || i == end(_groups)) {
		return false;
	}
	auto &group = *i->second;
	const auto pending = group.fileTransfer.pending();
	const auto manifest = pending
		? PrivateFileManifestCodecV1().decodePlaintext(
			pending->manifestPlaintext)
		: std::nullopt;
	if (!pending
		|| !pending->manifestPublished
		|| !manifest
		|| pending->nextChunkIndex != manifest->context.chunkCount) {
		setContentState(conversationId, DesktopContentState::LocalFailure);
		return false;
	} else if (group.fileFinalHashInProgress) {
		return true;
	}
	const auto eventObjectId = pending->eventObjectId;
	const auto sourcePath = QString::fromUtf8(pending->sourcePathUtf8);
	const auto operationEpoch = _operationEpoch;
	const auto cancellation = std::make_shared<std::atomic_bool>(false);
	group.fileFinalHashInProgress = true;
	group.fileFinalHashCancellation = cancellation;
	setContentState(conversationId, DesktopContentState::Synchronizing);
	crl::async([weak = base::weak_ptr(this),
			conversationId,
			eventObjectId,
			sourcePath,
			cancellation,
			operationEpoch] {
		const auto source = HashFile(sourcePath, cancellation);
		crl::on_main([weak,
				conversationId,
				eventObjectId,
				sourcePath,
				cancellation,
				operationEpoch,
				source] {
			if (!weak || weak->_operationEpoch != operationEpoch) {
				return;
			}
			const auto i = weak->_groups.find(conversationId);
			if (i == end(weak->_groups)
				|| i->second->fileFinalHashCancellation != cancellation) {
				return;
			}
			auto &group = *i->second;
			group.fileFinalHashInProgress = false;
			group.fileFinalHashCancellation.reset();
			const auto pending = group.fileTransfer.pending();
			if (!pending
				|| pending->eventObjectId != eventObjectId
				|| QString::fromUtf8(pending->sourcePathUtf8) != sourcePath) {
				return;
			} else if (pending->cancelRequested) {
				weak->pumpActiveOutbox(conversationId);
				return;
			}
			const auto manifest = pending
				? PrivateFileManifestCodecV1().decodePlaintext(
					pending->manifestPlaintext)
				: std::nullopt;
			if (!manifest
				|| pending->nextChunkIndex
					!= manifest->context.chunkCount
				|| !source
				|| source->size != manifest->context.plaintextSize
				|| source->hash != manifest->plaintextHash) {
				weak->setContentState(
					conversationId,
					DesktopContentState::LocalFailure);
				return;
			}
			if (!group.chunkStore.removeChunksBefore(
				conversationId,
				manifest->context.fileId,
				manifest->context.chunkCount)) {
				weak->setContentState(
					conversationId,
					DesktopContentState::Synchronizing);
				weak->scheduleFileTransferRetry(conversationId);
				return;
			}
			const auto cleared = group.fileTransfer.clear();
			if (cleared != FileTransferCommitResult::Committed
				&& cleared != FileTransferCommitResult::AlreadyCommitted) {
				weak->setContentState(
					conversationId,
					DesktopContentState::LocalFailure);
				return;
			}
			weak->resetFileTransferRetry(group);
			RemoveStagedProtectedSource(
				weak->_telegramUserIdBinding,
				conversationId,
				sourcePath);
			weak->notifyFileTransferRevision();
			weak->pumpActiveOutbox(conversationId);
		});
	});
	return true;
}

void DesktopService::beginGroupObservation(ConversationId conversationId) {
	const auto i = _groups.find(conversationId);
	if (!vaultReady()
		|| i == end(_groups)
		|| (i->second->phase != PendingGroupCreation::Phase::Active
			&& i->second->phase
				!= PendingGroupCreation::Phase::AwaitingAdmission)) {
		return;
	}
	auto &group = *i->second;
	if (_pendingGroupCreation
		|| _pendingGroupJoin
		|| _pendingGroupDiscovery) {
		group.observationDirty = true;
		return;
	}
	if (group.observation) {
		group.observationDirty = true;
		return;
	} else if (group.contentObservation
		|| group.uploadInProgress
		|| group.fileHashInProgress
		|| group.fileFinalHashInProgress
		|| group.pendingFileDownload
		|| (group.outbox.size()
			&& (!group.freshnessGate
				|| group.freshnessGate->sendingAllowed()))) {
		group.observationDirty = true;
		return;
	}
	group.observationDirty = false;
	group.observation = std::make_unique<PublicBootstrapSyncController>(
		conversationId,
		group.telegramPeerIdBinding,
		group.conversation.ownerAccountId,
		group.controlTransport,
		group.envelopeCodec,
		_sha256,
		[weak = base::weak_ptr(this), conversationId](
				PublicBootstrapSyncCompletion result) {
			if (weak) {
				weak->applyGroupObservation(
					conversationId,
					std::move(result));
			}
		});
	const auto boundary = group.controlSyncState.newestObservedMessageId();
	const auto started = boundary
		? (group.phase == PendingGroupCreation::Phase::AwaitingAdmission)
			? group.observation->startForJoinFromBoundary(boundary)
			: group.observation->startFromBoundary(boundary)
		: (group.phase == PendingGroupCreation::Phase::AwaitingAdmission)
		? group.observation->startForJoin()
		: group.observation->start();
	if (!started) {
		group.observation.reset();
		group.observationDirty = true;
		setContentState(
			conversationId,
			DesktopContentState::RetryableTransportError);
		if (group.phase
				== PendingGroupCreation::Phase::AwaitingAdmission) {
			_groupCreationState
				= DesktopGroupCreationState::RetryableTransportError;
		}
		scheduleGroupObservationRetry(conversationId);
	}
}

void DesktopService::resumeDeferredGroupObservations() {
	if (!vaultReady()
		|| _pendingGroupCreation
		|| _pendingGroupJoin
		|| _pendingGroupDiscovery) {
		return;
	}
	auto conversations = std::vector<ConversationId>();
	for (const auto &[conversationId, group] : _groups) {
		if (group->observationDirty && !group->observation) {
			conversations.push_back(conversationId);
		}
	}
	for (const auto conversationId : conversations) {
		if (_pendingGroupCreation
			|| _pendingGroupJoin
			|| _pendingGroupDiscovery) {
			return;
		}
		beginGroupObservation(conversationId);
	}
}

void DesktopService::scheduleGroupObservationRetry(
		ConversationId conversationId) {
	const auto i = _groups.find(conversationId);
	if (!vaultReady()
		|| i == end(_groups)
		|| i->second->observation
		|| !i->second->observationDirty) {
		return;
	}
	auto &group = *i->second;
	const auto delay = FileRetryDelay(group.groupObservationRetryAttempt);
	group.groupObservationRetryAttempt = std::min(
		group.groupObservationRetryAttempt + 1,
		6);
	if (++group.groupObservationRetryToken == 0) {
		++group.groupObservationRetryToken;
	}
	const auto token = group.groupObservationRetryToken;
	base::call_delayed(delay, [weak = base::weak_ptr(this),
			conversationId,
			token] {
		if (!weak || !weak->vaultReady()) {
			return;
		}
		const auto i = weak->_groups.find(conversationId);
		if (i == end(weak->_groups)
			|| i->second->groupObservationRetryToken != token
			|| i->second->observation
			|| !i->second->observationDirty) {
			return;
		}
		weak->beginGroupObservation(conversationId);
	});
}

void DesktopService::resetGroupObservationRetry(
		PendingGroupCreation &group) {
	group.groupObservationRetryAttempt = 0;
	if (++group.groupObservationRetryToken == 0) {
		++group.groupObservationRetryToken;
	}
}

void DesktopService::beginContentObservation(
		ConversationId conversationId) {
	const auto i = _groups.find(conversationId);
	if (!vaultReady()
		|| i == end(_groups)
		|| (i->second->phase != PendingGroupCreation::Phase::Active
			&& i->second->phase != PendingGroupCreation::Phase::Removed)) {
		return;
	}
	auto &group = *i->second;
	if (group.contentObservation
		|| group.observation
		|| group.observationDirty) {
		group.contentObservationDirty = true;
		return;
	}
	group.contentObservationDirty = false;
	group.contentObservation =
		std::make_unique<ObservedContentSyncController>(
			conversationId,
			group.telegramPeerIdBinding,
			group.contentTransport,
			_sha256,
			[weak = base::weak_ptr(this), conversationId](
					std::vector<TelegramTransport::UntrustedObject> objects) {
				return weak
					? weak->processObservedContentPage(
						conversationId,
						std::move(objects))
					: ObservedContentPageResult::PersistenceFailed;
			},
			[weak = base::weak_ptr(this), conversationId](
					ObservedContentSyncCompletion completion) {
				if (weak) {
					weak->applyContentObservation(
						conversationId,
						std::move(completion));
				}
			},
			[weak = base::weak_ptr(this), conversationId](
					const std::vector<
						TelegramTransport::UntrustedObject> &objects,
					std::size_t objectLimit) {
				return weak
					? weak->previewObservedFileManifests(
						conversationId,
						objects,
						objectLimit)
					: ObservedContentPageResult::PersistenceFailed;
			});
	setContentState(conversationId, DesktopContentState::Synchronizing);
	if (!group.contentObservation->start(
			group.contentSyncState.newestObservedMessageId())) {
		group.contentObservation.reset();
		setContentState(conversationId, DesktopContentState::LocalFailure);
	}
}

ObservedContentPageResult DesktopService::previewObservedFileManifests(
		ConversationId conversationId,
		const std::vector<TelegramTransport::UntrustedObject> &objects,
		std::size_t objectLimit) {
	if (!vaultReady()) {
		return ObservedContentPageResult::SecurityBlocked;
	}
	const auto i = _groups.find(conversationId);
	if (i == end(_groups)) {
		return ObservedContentPageResult::PersistenceFailed;
	}
	auto &group = *i->second;
	const auto metadata = group.metadata.metadata();
	if (!metadata) {
		return ObservedContentPageResult::PersistenceFailed;
	}
	const auto processed = ProcessObservedFileManifestPreview(
		objects,
		objectLimit,
		{
			.conversationId = conversationId,
			.accountId = metadata->accountId,
			.clientId = metadata->clientId,
			.telegramPeerIdBinding = group.telegramPeerIdBinding,
		},
		group.envelopeCodec,
		_sha256,
		group.archiveState,
		group.groupLedger,
		group.contentStore,
		group.chunkStore);
	if (processed.status == ObservedContentProcessStatus::SecurityBlocked) {
		_vaultState = DesktopVaultState::SecurityBlocked;
		setContentState(
			conversationId,
			DesktopContentState::SecurityBlocked);
		return ObservedContentPageResult::SecurityBlocked;
	} else if (processed.status
			== ObservedContentProcessStatus::RetryRequired) {
		return ObservedContentPageResult::RetryRequired;
	} else if (processed.status
			== ObservedContentProcessStatus::PersistenceFailed
		|| processed.status == ObservedContentProcessStatus::InvalidState) {
		setContentState(conversationId, DesktopContentState::LocalFailure);
		return ObservedContentPageResult::PersistenceFailed;
	}
	if (processed.stats.manifestsStored) {
		notifyContentRevision();
	}
	return ObservedContentPageResult::Persisted;
}

ObservedContentPageResult DesktopService::processObservedContentPage(
		ConversationId conversationId,
		std::vector<TelegramTransport::UntrustedObject> objects) {
	if (!vaultReady()) {
		return ObservedContentPageResult::SecurityBlocked;
	}
	const auto i = _groups.find(conversationId);
	if (i == end(_groups)) {
		return ObservedContentPageResult::PersistenceFailed;
	}
	auto &group = *i->second;
	const auto metadata = group.metadata.metadata();
	if (!metadata) {
		return ObservedContentPageResult::PersistenceFailed;
	}
	const auto processed = ProcessObservedContentPage(
		objects,
		{
			.conversationId = conversationId,
			.accountId = metadata->accountId,
			.clientId = metadata->clientId,
			.telegramPeerIdBinding = group.telegramPeerIdBinding,
		},
		_telegramUserIdBinding,
		group.envelopeCodec,
		OpenMlsBridge(),
		MlsContextCodecV1(),
		_sha256,
		group.mlsState,
		group.archiveState,
		group.groupLedger,
		group.inboundJournal,
		group.contentStore,
		group.chunkStore);
	if (processed.status == ObservedContentProcessStatus::SecurityBlocked) {
		_vaultState = DesktopVaultState::SecurityBlocked;
		setContentState(
			conversationId,
			DesktopContentState::SecurityBlocked);
		return ObservedContentPageResult::SecurityBlocked;
	} else if (processed.status
			== ObservedContentProcessStatus::RetryRequired) {
		return ObservedContentPageResult::RetryRequired;
	} else if (processed.status
			== ObservedContentProcessStatus::PersistenceFailed
		|| processed.status == ObservedContentProcessStatus::InvalidState) {
		setContentState(conversationId, DesktopContentState::LocalFailure);
		return ObservedContentPageResult::PersistenceFailed;
	}
	if (processed.stats.messagesStored
		|| processed.stats.manifestsStored) {
		notifyContentRevision();
	}
	return ObservedContentPageResult::Persisted;
}

void DesktopService::applyContentObservation(
		ConversationId conversationId,
		ObservedContentSyncCompletion completion) {
	if (!vaultReady()) {
		return;
	}
	const auto i = _groups.find(conversationId);
	if (i == end(_groups)) {
		return;
	}
	auto &group = *i->second;
	const auto rerun = group.contentObservationDirty;
	group.contentObservationDirty = false;
	group.contentObservation.reset();
	const auto resumeControlObservation = qScopeGuard([&] {
		const auto current = _groups.find(conversationId);
		if (_vaultState.current() == DesktopVaultState::Ready
			&& current != end(_groups)
			&& current->second->observationDirty
			&& !current->second->observation) {
			beginGroupObservation(conversationId);
		}
	});
	switch (completion.status) {
	case ObservedContentSyncStatus::Complete:
		if (completion.previousBoundaryMessageId
				!= group.contentSyncState.newestObservedMessageId()
			|| (completion.nextBoundaryMessageId
				&& (!completion.newestObservedMessageId
					|| completion.nextBoundaryMessageId
						> completion.newestObservedMessageId))) {
			_vaultState = DesktopVaultState::SecurityBlocked;
			setContentState(
				conversationId,
				DesktopContentState::SecurityBlocked);
			return;
		}
		if (completion.nextBoundaryMessageId) {
			const auto committed = group.contentSyncState.advance(
				completion.nextBoundaryMessageId);
			if (committed == ContentSyncStateCommitResult::InvalidBoundary) {
				_vaultState = DesktopVaultState::SecurityBlocked;
				setContentState(
					conversationId,
					DesktopContentState::SecurityBlocked);
				return;
			} else if (committed
					== ContentSyncStateCommitResult::PersistenceFailed) {
				setContentState(
					conversationId,
					DesktopContentState::LocalFailure);
				return;
			}
		}
		setContentState(conversationId, DesktopContentState::Ready);
		if (rerun) {
			beginContentObservation(conversationId);
		}
		break;
	case ObservedContentSyncStatus::RetryRequired:
	case ObservedContentSyncStatus::RetryableTransportError:
		setContentState(
			conversationId,
			DesktopContentState::RetryableTransportError);
		break;
	case ObservedContentSyncStatus::PermanentTransportError:
		setContentState(
			conversationId,
			DesktopContentState::PermanentTransportError);
		break;
	case ObservedContentSyncStatus::SecurityBlocked:
	case ObservedContentSyncStatus::InvalidPagination:
		_vaultState = DesktopVaultState::SecurityBlocked;
		setContentState(
			conversationId,
			DesktopContentState::SecurityBlocked);
		break;
	case ObservedContentSyncStatus::PersistenceFailed:
		setContentState(conversationId, DesktopContentState::LocalFailure);
		break;
	case ObservedContentSyncStatus::Cancelled:
		setContentState(conversationId, DesktopContentState::Idle);
		break;
	}
}

void DesktopService::applyGroupObservation(
		ConversationId conversationId,
		PublicBootstrapSyncCompletion result) {
	if (!vaultReady()) {
		return;
	}
	const auto i = _groups.find(conversationId);
	if (i == end(_groups)) {
		return;
	}
	const auto awaiting = i->second->phase
		== PendingGroupCreation::Phase::AwaitingAdmission;
	const auto rerun = i->second->observationDirty;
	i->second->observationDirty = false;
	i->second->observation.reset();
	if (result.status == PublicBootstrapSyncStatus::ObjectConflict
		|| result.status == PublicBootstrapSyncStatus::Ambiguous
		|| result.status == PublicBootstrapSyncStatus::CapacityExceeded
		|| result.status == PublicBootstrapSyncStatus::InvalidPagination) {
		_vaultState = DesktopVaultState::SecurityBlocked;
		_groupCreationState = DesktopGroupCreationState::LocalFailure;
		return;
	}
	if (_pendingGroupCreation
		|| _pendingGroupJoin
		|| _pendingGroupDiscovery) {
		i->second->observationDirty = true;
		return;
	}
	if (result.status != PublicBootstrapSyncStatus::Verified
		&& result.status != PublicBootstrapSyncStatus::Incremental) {
		i->second->observationDirty = true;
		const auto permanent = result.status
			== PublicBootstrapSyncStatus::PermanentTransportError;
		setContentState(
			conversationId,
			permanent
				? DesktopContentState::PermanentTransportError
				: DesktopContentState::RetryableTransportError);
		if (awaiting) {
			_groupCreationState = permanent
				? DesktopGroupCreationState::PermanentTransportError
				: DesktopGroupCreationState::RetryableTransportError;
		}
		if (!permanent) {
			scheduleGroupObservationRetry(conversationId);
		}
		return;
	}
	resetGroupObservationRetry(*i->second);
	auto changed = false;
	if (awaiting) {
		changed = completeObservedJoin(
			conversationId,
			result);
	} else {
		const auto processingFailed = [&] {
			const auto state = contentState(conversationId);
			return _vaultState.current()
					== DesktopVaultState::SecurityBlocked
				|| _groupCreationState.current()
					== DesktopGroupCreationState::LocalFailure
				|| state == DesktopContentState::SecurityBlocked
				|| state == DesktopContentState::LocalFailure;
		};
		const auto synchronized = synchronizeObservedGroupChanges(
			conversationId,
			result.untrustedObjects);
		if (synchronized
			|| !_groups.contains(conversationId)
			|| processingFailed()) {
			return;
		}
		const auto safetyChanged = processObservedSafetyGossip(
			conversationId,
			result.untrustedObjects);
		if (processingFailed()) {
			return;
		}
		const auto freshnessChanged = processObservedFreshness(
			conversationId,
			result.untrustedObjects);
		if (processingFailed()) {
			return;
		}
		const auto grantAccepted = acceptObservedHistoryGrant(
			conversationId,
			result.untrustedObjects);
		if (processingFailed()) {
			return;
		}
		const auto admitted = admitObservedClient(
			conversationId,
			result.untrustedObjects);
		if (processingFailed() || !_groups.contains(conversationId)) {
			return;
		}
		changed = safetyChanged
			|| freshnessChanged
			|| grantAccepted
			|| admitted;
		auto &group = *_groups.find(conversationId)->second;
		if ((result.previousBoundaryMessageId
				&& result.previousBoundaryMessageId
					!= group.controlSyncState
						.newestObservedMessageId())
			|| !result.newestObservedMessageId) {
			_vaultState = DesktopVaultState::SecurityBlocked;
			_groupCreationState = DesktopGroupCreationState::LocalFailure;
			setContentState(
				conversationId,
				DesktopContentState::SecurityBlocked);
			return;
		}
		auto nextBoundaryMessageId = result.previousBoundaryMessageId;
		if (!nextBoundaryMessageId) {
			if (result.untrustedObjects.empty()) {
				_vaultState = DesktopVaultState::SecurityBlocked;
				_groupCreationState = DesktopGroupCreationState::LocalFailure;
				setContentState(
					conversationId,
					DesktopContentState::SecurityBlocked);
				return;
			}
			const auto index = std::min(
				kControlSyncOverlap,
				result.untrustedObjects.size() - 1);
			nextBoundaryMessageId = result.untrustedObjects[index]
				.observedMessageId;
		} else if (result.untrustedObjects.size() > kControlSyncOverlap) {
			nextBoundaryMessageId = result.untrustedObjects[
				kControlSyncOverlap].observedMessageId;
		}
		const auto committed = group.controlSyncState.advance(
			nextBoundaryMessageId,
			group.groupLedger.checkpoint(),
			group.safetyWitnesses,
			group.ownSafetyGossipObserved);
		if (committed
				== ControlObservationStateCommitResult::InvalidState) {
			_vaultState = DesktopVaultState::SecurityBlocked;
			_groupCreationState = DesktopGroupCreationState::LocalFailure;
			setContentState(
				conversationId,
				DesktopContentState::SecurityBlocked);
			return;
		} else if (committed
				== ControlObservationStateCommitResult::PersistenceFailed) {
			_groupCreationState = DesktopGroupCreationState::LocalFailure;
			setContentState(
				conversationId,
				DesktopContentState::LocalFailure);
			return;
		}
		if (rerun) {
			beginGroupObservation(conversationId);
			return;
		} else if (!admitted) {
			publishQueuedGroupOutbox(conversationId);
		}
	}
	if (!changed && rerun) {
		beginGroupObservation(conversationId);
	}
	pumpActiveOutbox(conversationId);
	startNextGroupDiscovery();
}

void DesktopService::handleNewTelegramItem(not_null<HistoryItem*> item) {
	const auto peer = item->history()->peer;
	if (!peer->isChat() && !peer->isMegagroup()) {
		return;
	}
	const auto media = item->media();
	const auto document = media ? media->document() : nullptr;
	if (!document
		|| !IsProtectedGroupCarrierMetadata(
			document->filename(),
			document->mimeString())) {
		return;
	}
	const auto peerId = item->history()->peer->id.value;
	if (!vaultReady()) {
		return;
	}
	if (document->filename() == ProtectedContentCarrierFilename()) {
		for (const auto &[conversationId, group] : _groups) {
			if (group->telegramPeerIdBinding == peerId) {
				beginContentObservation(conversationId);
			}
		}
		return;
	} else if (document->filename() != ProtectedControlCarrierFilename()
		&& document->filename() != ProtectedLegacyCarrierFilename()) {
		return;
	}
	auto conversations = std::vector<ConversationId>();
	for (const auto &[conversationId, group] : _groups) {
		if (group->telegramPeerIdBinding == peerId) {
			conversations.push_back(conversationId);
		}
	}
	for (const auto conversationId : conversations) {
		beginGroupObservation(conversationId);
	}
	if (conversations.empty()) {
		queueGroupDiscovery(peerId);
	}
}

void DesktopService::queueLoadedGroupDiscoveries() {
	if (!vaultReady()) {
		return;
	}
	auto peerIds = std::vector<std::uint64_t>();
	_session->data().enumerateGroups([&](not_null<PeerData*> peer) {
		const auto history = _session->data().historyLoaded(peer);
		if (history && history->hasE2ECloudGroupCarrier()) {
			peerIds.push_back(peer->id.value);
		}
	});
	for (const auto peerId : peerIds) {
		queueGroupDiscovery(peerId);
	}
}

void DesktopService::queueGroupDiscovery(
		std::uint64_t telegramPeerIdBinding) {
	const auto peer = telegramPeerIdBinding
		? _session->data().peerLoaded(PeerId(telegramPeerIdBinding))
		: nullptr;
	if (!telegramPeerIdBinding
		|| !peer
		|| (!peer->isChat() && !peer->isMegagroup())
		|| !_vault
		|| _vaultState.current() != DesktopVaultState::Ready
		|| std::any_of(
			begin(_vault->conversations),
			end(_vault->conversations),
			[&](const CloudVaultConversation &conversation) {
				return conversation.telegramPeerIdBinding
					== telegramPeerIdBinding;
			})) {
		return;
	}
	_groupDiscoveryQueue.emplace(telegramPeerIdBinding);
	startNextGroupDiscovery();
}

void DesktopService::startNextGroupDiscovery() {
	const auto operationState = _groupCreationState.current();
	if (_pendingGroupDiscovery
		|| _pendingGroupCreation
		|| _pendingGroupJoin
		|| !vaultReady()
		|| (operationState != DesktopGroupCreationState::Idle
			&& operationState != DesktopGroupCreationState::Ready)
		|| std::any_of(
			begin(_groups),
			end(_groups),
			[](const auto &entry) {
				return entry.second->observation
					|| entry.second->observationDirty;
			})) {
		return;
	}
	while (!_groupDiscoveryQueue.empty()) {
		const auto peerId = *_groupDiscoveryQueue.begin();
		_groupDiscoveryQueue.erase(_groupDiscoveryQueue.begin());
		if (std::any_of(
				begin(_vault->conversations),
				end(_vault->conversations),
				[&](const CloudVaultConversation &conversation) {
					return conversation.telegramPeerIdBinding == peerId;
				})
			|| std::any_of(
				begin(_groups),
				end(_groups),
				[&](const auto &entry) {
					return entry.second->telegramPeerIdBinding == peerId;
				})) {
			continue;
		}
		_pendingGroupDiscovery =
			std::make_unique<PendingGroupDiscovery>(_session, peerId);
		_pendingGroupDiscovery->sync =
			std::make_unique<PublicBootstrapDiscoveryController>(
				peerId,
				_pendingGroupDiscovery->backend,
				_pendingGroupDiscovery->envelopeCodec,
				_sha256,
				[weak = base::weak_ptr(this)](
						PublicBootstrapSyncCompletion result) {
					if (weak) {
						weak->applyGroupDiscovery(std::move(result));
					}
				});
		_groupCreationState = DesktopGroupCreationState::Preparing;
		if (!_pendingGroupDiscovery->sync->start()) {
			_pendingGroupDiscovery.reset();
			_groupDiscoveryQueue.emplace(peerId);
			_groupCreationState
				= DesktopGroupCreationState::RetryableTransportError;
			resumeDeferredGroupObservations();
			return;
		}
		return;
	}
}

void DesktopService::applyGroupDiscovery(
		PublicBootstrapSyncCompletion result) {
	if (!vaultReady() || !_pendingGroupDiscovery) {
		return;
	}
	const auto peerId = _pendingGroupDiscovery->telegramPeerIdBinding;
	_pendingGroupDiscovery->sync.reset();
	_pendingGroupDiscovery.reset();
	if (result.status == PublicBootstrapSyncStatus::ObjectConflict
		|| result.status == PublicBootstrapSyncStatus::Ambiguous
		|| result.status == PublicBootstrapSyncStatus::CapacityExceeded
		|| result.status == PublicBootstrapSyncStatus::InvalidPagination) {
		_groupCreationState = DesktopGroupCreationState::Ready;
		resumeDeferredGroupObservations();
		startNextGroupDiscovery();
		return;
	} else if (result.status
				== PublicBootstrapSyncStatus::RetryableTransportError
		|| result.status
				== PublicBootstrapSyncStatus::PermanentTransportError) {
		_groupDiscoveryQueue.emplace(peerId);
		_groupCreationState = (result.status
				== PublicBootstrapSyncStatus::PermanentTransportError)
			? DesktopGroupCreationState::PermanentTransportError
			: DesktopGroupCreationState::RetryableTransportError;
		resumeDeferredGroupObservations();
		return;
	} else if (result.status != PublicBootstrapSyncStatus::Verified
		|| !result.verified) {
		_groupCreationState = DesktopGroupCreationState::Ready;
		resumeDeferredGroupObservations();
		startNextGroupDiscovery();
		return;
	}
	auto verified = std::move(*result.verified);
	if (verified.genesis.telegramPeerIdBinding != peerId
		|| std::any_of(
			begin(_vault->conversations),
			end(_vault->conversations),
			[&](const CloudVaultConversation &conversation) {
				return conversation.conversationId
					== verified.genesis.conversationId
					|| conversation.telegramPeerIdBinding == peerId;
			})) {
		_groupCreationState = DesktopGroupCreationState::Ready;
		resumeDeferredGroupObservations();
		startNextGroupDiscovery();
		return;
	}
	auto conversation = CloudVaultConversation{
		.conversationId = verified.genesis.conversationId,
		.telegramPeerIdBinding = peerId,
		.checkpoint = verified.checkpoint,
		.ownerAccountId = verified.genesis.ownerAccountId,
	};
	if (!prepareGroupJoin(
			std::move(conversation),
			std::move(verified),
			true)) {
		_groupCreationState = DesktopGroupCreationState::LocalFailure;
		resumeDeferredGroupObservations();
		startNextGroupDiscovery();
	}
}

bool DesktopService::completeObservedJoin(
		ConversationId conversationId,
		const PublicBootstrapSyncCompletion &result) {
	const auto i = _groups.find(conversationId);
	if (!vaultReady()
		|| i == end(_groups)
		|| _pendingGroupCreation
		|| i->second->phase
			!= PendingGroupCreation::Phase::AwaitingAdmission) {
		return false;
	}
	auto &group = *i->second;
	const auto metadata = group.metadata.metadata();
	const auto accountId = DeriveAccountId(
		_vault->identity.credential,
		_sha256);
	if (!metadata
		|| !accountId
		|| metadata->accountId != *accountId) {
		_vaultState = DesktopVaultState::SecurityBlocked;
		_groupCreationState = DesktopGroupCreationState::LocalFailure;
		return false;
	}
	const auto staged = StagePublicJoinObjects(
		result.untrustedObjects,
		conversationId,
		group.telegramPeerIdBinding,
		group.envelopeCodec,
		_sha256,
		group.changeInbox);
	if (staged == PublicJoinInboxStageStatus::ForkDetected
		|| staged == PublicJoinInboxStageStatus::InvalidState) {
		_vaultState = DesktopVaultState::SecurityBlocked;
		_groupCreationState = DesktopGroupCreationState::LocalFailure;
		return false;
	} else if (staged != PublicJoinInboxStageStatus::Staged) {
		_groupCreationState = DesktopGroupCreationState::LocalFailure;
		return false;
	}
	const auto objects = ReconstructPublicJoinObjects(
		conversationId,
		group.telegramPeerIdBinding,
		group.envelopeCodec,
		group.changeInbox);
	if (!objects) {
		_groupCreationState = DesktopGroupCreationState::LocalFailure;
		return false;
	}
	const auto persistObservation = [&] {
		const auto previous
			= group.controlSyncState.newestObservedMessageId();
		if (!result.newestObservedMessageId
			|| result.newestObservedMessageId < previous
			|| result.previousBoundaryMessageId != previous) {
			_vaultState = DesktopVaultState::SecurityBlocked;
			_groupCreationState = DesktopGroupCreationState::LocalFailure;
			return false;
		}
		group.safetyWitnessGeneration
			= group.groupLedger.checkpoint().generation;
		group.safetyWitnesses = { metadata->accountId };
		group.ownSafetyGossipObserved = false;
		const auto committed = group.controlSyncState.advance(
			result.newestObservedMessageId,
			group.groupLedger.checkpoint(),
			group.safetyWitnesses,
			false);
		if (committed == ControlObservationStateCommitResult::InvalidState) {
			_vaultState = DesktopVaultState::SecurityBlocked;
			_groupCreationState = DesktopGroupCreationState::LocalFailure;
			return false;
		} else if (committed
				== ControlObservationStateCommitResult::PersistenceFailed) {
			_groupCreationState = DesktopGroupCreationState::LocalFailure;
			return false;
		}
		return true;
	};
	auto catchup = CatchUpPublicJoin(
		*objects,
		conversationId,
		group.telegramPeerIdBinding,
		*accountId,
		metadata->clientId,
		_vault->identity.credential,
		std::uint64_t(base::unixtime::now()),
		group.envelopeCodec,
		_sha256,
		group.groupLedger,
		group.keyPackages);
	if (catchup.status == PublicJoinCatchupStatus::Waiting) {
		const auto current = group.groupLedger.checkpoint();
		const auto target = group.joinTargetCheckpoint;
		if (!ValidConversationCheckpoint(target, conversationId)) {
			_vaultState = DesktopVaultState::SecurityBlocked;
			_groupCreationState = DesktopGroupCreationState::LocalFailure;
		} else if (current.generation >= target.generation) {
			if (group.groupLedger.checkpointAt(target.generation) != target) {
				_vaultState = DesktopVaultState::SecurityBlocked;
				_groupCreationState = DesktopGroupCreationState::LocalFailure;
			} else {
				(void)persistObservation();
			}
		}
		return false;
	} else if (catchup.status == PublicJoinCatchupStatus::UpdatedWaiting) {
		if (!group.changeInbox.discardAppliedTransitions(
				group.groupLedger.checkpoint().generation)) {
			_groupCreationState = DesktopGroupCreationState::LocalFailure;
			return false;
		}
		const auto current = group.groupLedger.checkpoint();
		const auto target = group.joinTargetCheckpoint;
		if (!ValidConversationCheckpoint(target, conversationId)
			|| (current.generation >= target.generation
				&& group.groupLedger.checkpointAt(target.generation)
					!= target)) {
			_vaultState = DesktopVaultState::SecurityBlocked;
			_groupCreationState = DesktopGroupCreationState::LocalFailure;
			return false;
		} else if (current.generation < target.generation) {
			return false;
		}
		(void)persistObservation();
		return false;
	} else if (catchup.status == PublicJoinCatchupStatus::ForkDetected
		|| catchup.status == PublicJoinCatchupStatus::InvalidState) {
		_vaultState = DesktopVaultState::SecurityBlocked;
		_groupCreationState = DesktopGroupCreationState::LocalFailure;
		return false;
	} else if (catchup.status
			== PublicJoinCatchupStatus::PersistenceFailure
		|| catchup.status != PublicJoinCatchupStatus::Ready
		|| !catchup.bundle) {
		_groupCreationState = DesktopGroupCreationState::LocalFailure;
		return false;
	}
	const auto target = group.joinTargetCheckpoint;
	if (!ValidConversationCheckpoint(target, conversationId)
		|| group.groupLedger.checkpoint().generation < target.generation
		|| group.groupLedger.checkpointAt(target.generation) != target) {
		_vaultState = DesktopVaultState::SecurityBlocked;
		_groupCreationState = DesktopGroupCreationState::LocalFailure;
		return false;
	}
	auto bundle = std::move(*catchup.bundle);
	const auto installed = InstallClientKeyPackageForWelcome(
		bundle.targetKeyPackage,
		std::uint64_t(base::unixtime::now()),
		OpenMlsBridge(),
		_sha256,
		group.keyPackages,
		group.mlsState);
	if (installed != InstallClientKeyPackageStatus::Installed
		&& installed != InstallClientKeyPackageStatus::AlreadyInstalled) {
		_groupCreationState = DesktopGroupCreationState::LocalFailure;
		return false;
	}
	auto prepared = PrepareOpenMlsInboundJoin({
		.local = {
			.conversationId = conversationId,
			.accountId = *accountId,
			.clientId = metadata->clientId,
			.telegramPeerIdBinding = group.telegramPeerIdBinding,
		},
		.transitionEnvelope = std::move(bundle.transitionEnvelope),
		.commitEnvelope = std::move(bundle.commitEnvelope),
		.welcomeEnvelope = std::move(bundle.welcomeEnvelope),
		.archiveDistributionEnvelope =
			std::move(bundle.archiveDistributionEnvelope),
		.targetCredential = std::move(bundle.targetCredential),
		.targetKeyPackage = bundle.targetKeyPackage,
	},
	OpenMlsBridge(),
	MlsContextCodecV1(),
	MlsRosterCodecV1(),
	GroupControlCodecV1(),
	_sha256,
	group.mlsState,
	group.archiveState,
	group.groupLedger);
	if (prepared.status != OpenMlsInboundGroupChangeStatus::Prepared
		|| !prepared.prepared) {
		_groupCreationState = DesktopGroupCreationState::LocalFailure;
		return false;
	}
	auto coordinator = GroupChangeTransactionCoordinator(
		group.changeJournal,
		group.mlsState,
		group.archiveState,
		group.groupLedger,
		_sha256);
	const auto applied = coordinator.apply(
		std::move(prepared.prepared->transaction));
	if (applied != GroupChangeApplyStatus::Applied
		&& coordinator.recover() != GroupChangeApplyStatus::Recovered) {
		_groupCreationState = DesktopGroupCreationState::LocalFailure;
		return false;
	}
	const auto finalized = FinalizeClientKeyPackageWelcome(
		bundle.targetKeyPackage,
		OpenMlsBridge(),
		_sha256,
		group.keyPackages,
		group.mlsState);
	if (finalized != FinalizeClientKeyPackageStatus::Finalized
		&& finalized != FinalizeClientKeyPackageStatus::AlreadyFinalized) {
		_groupCreationState = DesktopGroupCreationState::LocalFailure;
		return false;
	}
	group.phase = PendingGroupCreation::Phase::Active;
	group.conversation.checkpoint = group.groupLedger.checkpoint();
	group.freshnessGate->requireFreshness(group.conversation.checkpoint);
	if (!group.changeInbox.discardAppliedTransitions(
			group.groupLedger.checkpoint().generation)) {
		_groupCreationState = DesktopGroupCreationState::LocalFailure;
		return false;
	}
	(void)acceptObservedHistoryGrant(conversationId, *objects);
	if (_vaultState.current() == DesktopVaultState::SecurityBlocked
		|| _groupCreationState.current()
			== DesktopGroupCreationState::LocalFailure
		|| contentState(conversationId)
			== DesktopContentState::SecurityBlocked
		|| contentState(conversationId)
			== DesktopContentState::LocalFailure) {
		return false;
	}
	if (!group.changeInbox.discardJoinOnlyObjects()
		|| !persistObservation()) {
		_groupCreationState = DesktopGroupCreationState::LocalFailure;
		return false;
	}
	notifySecurityRevision();
	_pendingGroupCreation = std::move(i->second);
	_groups.erase(i);
	_pendingGroupCreation->vaultPreflightRequired = true;
	publishNextBootstrapObject();
	return true;
}

bool DesktopService::acceptObservedHistoryGrant(
		ConversationId conversationId,
		const std::vector<TelegramTransport::UntrustedObject> &objects) {
	const auto i = _groups.find(conversationId);
	if (!vaultReady() || i == end(_groups)) {
		return false;
	}
	auto &group = *i->second;
	const auto metadata = group.metadata.metadata();
	const auto accountId = DeriveAccountId(
		_vault->identity.credential,
		_sha256);
	if (!metadata || !accountId || metadata->accountId != *accountId) {
		return false;
	}
	for (const auto &object : objects) {
		const auto envelope = group.envelopeCodec.decodeUntrusted(
			object.bytes);
		if (!envelope
			|| envelope->objectKind != ObjectKind::HistoryGrant
			|| envelope->conversationId != conversationId
			|| envelope->telegramPeerIdBinding
				!= group.telegramPeerIdBinding
			|| object.observedTelegramPeerIdBinding
				!= group.telegramPeerIdBinding
			|| object.observedMessageId <= 0
			|| envelope->payloadHash != _sha256.digest(envelope->payload)) {
			continue;
		}
		const auto grant = EncryptedHistoryGrantCodecV1().decode(
			envelope->payload);
		const auto state = grant
			? group.groupLedger.stateAt(grant->groupGeneration)
			: std::nullopt;
		const auto issuer = state
			? state->member(grant->issuerAccountId)
			: nullptr;
		if (!grant
			|| grant->recipientAccountId != *accountId
			|| grant->grantId != envelope->objectId
			|| grant->issuerAccountId != envelope->senderAccountId
			|| grant->issuerClientId != envelope->senderClientId
			|| grant->groupGeneration != envelope->epochOrGeneration
			|| envelope->authenticationData != QByteArray(
				reinterpret_cast<const char*>(grant->signature.data()),
				int(grant->signature.size()))
			|| !issuer
			|| issuer->telegramUserIdBinding
				!= object.observedSenderTelegramUserIdBinding) {
			continue;
		}
		const auto accepted = AcceptAuthorizedHistoryGrant({
			.conversationId = conversationId,
			.telegramPeerIdBinding = group.telegramPeerIdBinding,
			.recipientAccountId = *accountId,
			.recipientArchivePrivateKey =
				&_vault->identity.archiveHpkePrivateKey,
			.grant = &*grant,
		},
		group.groupLedger,
		group.archiveState,
		_sha256,
		OpenMlsBridge());
		if (accepted == HistoryGrantServiceStatus::Accepted
			|| accepted == HistoryGrantServiceStatus::AlreadyAccepted) {
			return true;
		} else if (accepted == HistoryGrantServiceStatus::ArchiveConflict) {
			_vaultState = DesktopVaultState::SecurityBlocked;
			_groupCreationState = DesktopGroupCreationState::LocalFailure;
			setContentState(
				conversationId,
				DesktopContentState::SecurityBlocked);
			return false;
		} else if (accepted
				== HistoryGrantServiceStatus::PersistenceFailure) {
			_groupCreationState = DesktopGroupCreationState::LocalFailure;
			setContentState(
				conversationId,
				DesktopContentState::LocalFailure);
			return false;
		}
	}
	return false;
}

bool DesktopService::resumeObservedJoinHistory(
		ConversationId conversationId) {
	const auto i = _groups.find(conversationId);
	if (!vaultReady() || i == end(_groups)) {
		return false;
	}
	auto &group = *i->second;
	const auto objects = ReconstructPublicJoinObjects(
		conversationId,
		group.telegramPeerIdBinding,
		group.envelopeCodec,
		group.changeInbox);
	if (!objects) {
		return false;
	}
	(void)acceptObservedHistoryGrant(conversationId, *objects);
	if (_vaultState.current() == DesktopVaultState::SecurityBlocked
		|| _groupCreationState.current()
			== DesktopGroupCreationState::LocalFailure
		|| contentState(conversationId)
			== DesktopContentState::SecurityBlocked
		|| contentState(conversationId)
			== DesktopContentState::LocalFailure) {
		return false;
	}
	return group.changeInbox.discardJoinOnlyObjects();
}

bool DesktopService::applyAdministrativeTransition(
		ConversationId conversationId,
		GroupTransition transition) {
	const auto i = _groups.find(conversationId);
	const auto operationState = _groupCreationState.current();
	if (!vaultReady()
		|| i == end(_groups)
		|| (operationState != DesktopGroupCreationState::Idle
			&& operationState != DesktopGroupCreationState::Ready)
		|| _pendingGroupCreation
		|| _pendingGroupJoin
		|| _pendingGroupDiscovery) {
		return false;
	}
	auto &group = *i->second;
	const auto state = group.groupLedger.state();
	const auto metadata = group.metadata.metadata();
	const auto actorAccountId = DeriveAccountId(
		_vault->identity.credential,
		_sha256);
	const auto removal = transition.kind == GroupTransitionKind::RemoveMember
		|| transition.kind == GroupTransitionKind::RemoveClient;
	const auto policy = transition.kind == GroupTransitionKind::SetRole
		|| transition.kind == GroupTransitionKind::TransferOwnership
		|| transition.kind == GroupTransitionKind::SetDefaultHistory
		|| transition.kind == GroupTransitionKind::SetMemberHistory;
	if ((!removal && !policy)
		|| !state
		|| !metadata
		|| !actorAccountId
		|| group.observation
		|| group.observationDirty
		|| group.contentObservation
		|| group.phase != PendingGroupCreation::Phase::Active
		|| group.fileHashInProgress
		|| !group.filePreparationPath.isEmpty()
		|| group.fileFinalHashInProgress
		|| group.fileTransfer.pending()
		|| group.pendingFileDownload
		|| group.uploadInProgress
		|| group.outbox.size()
		|| (group.uploadController
			&& group.uploadController->uploadInProgress())
		|| !group.freshnessGate
		|| !group.freshnessGate->administrationAllowed()
		|| metadata->accountId != *actorAccountId
		|| !state->memberByClient(metadata->clientId)
		|| state->generation()
			== std::numeric_limits<std::uint64_t>::max()) {
		return false;
	}
	const auto transitionId = RandomId<ObjectId>();
	const auto commitObjectId = RandomId<ObjectId>();
	const auto distributionObjectId = RandomId<ObjectId>();
	const auto nextArchiveKey = ArchiveEpochCrypto().generateKey();
	if (!transitionId
		|| !commitObjectId
		|| !distributionObjectId
		|| !nextArchiveKey) {
		return false;
	}
	transition.conversationId = conversationId;
	transition.transitionId = *transitionId;
	transition.previousGeneration = state->generation();
	transition.generation = state->generation() + 1;
	const auto context = OpenMlsClientContext{
		.conversationId = conversationId,
		.accountId = *actorAccountId,
		.clientId = metadata->clientId,
		.telegramPeerIdBinding = group.telegramPeerIdBinding,
	};
	auto prepared = removal
		? PrepareOpenMlsRemoval({
			.actor = context,
			.currentGroupState = state,
			.currentCheckpoint = group.groupLedger.checkpoint(),
			.transition = transition,
			.actorCredential = &_vault->identity.credential,
			.actorSigningPrivateKey = &_vault->identity.signingPrivateKey,
			.nextArchiveKey = &*nextArchiveKey,
			.mlsCommitObjectId = *commitObjectId,
			.archiveDistributionObjectId = *distributionObjectId,
		},
		OpenMlsBridge(),
		MlsContextCodecV1(),
		MlsRosterCodecV1(),
		GroupControlCodecV1(),
		group.envelopeCodec,
		_sha256,
		group.mlsState,
		group.archiveState,
		group.groupLedger)
		: PrepareOpenMlsPolicyChange({
			.actor = context,
			.currentGroupState = state,
			.currentCheckpoint = group.groupLedger.checkpoint(),
			.transition = transition,
			.actorCredential = &_vault->identity.credential,
			.actorSigningPrivateKey = &_vault->identity.signingPrivateKey,
			.nextArchiveKey = &*nextArchiveKey,
			.mlsCommitObjectId = *commitObjectId,
			.archiveDistributionObjectId = *distributionObjectId,
		},
		OpenMlsBridge(),
		MlsContextCodecV1(),
		MlsRosterCodecV1(),
		GroupControlCodecV1(),
		group.envelopeCodec,
		_sha256,
		group.mlsState,
		group.archiveState,
		group.groupLedger);
	if (prepared.status != OpenMlsGroupChangePrepareStatus::Prepared
		|| !prepared.prepared) {
		return false;
	}
	auto &preparedChange = *prepared.prepared;
	if (transition.kind == GroupTransitionKind::SetMemberHistory) {
		const auto grantId = RandomId<ObjectId>();
		auto grant = (grantId && preparedChange.transaction.archiveEpoch)
			? CreateAdmissionHistoryGrant({
				.grant = {
					.conversationId = conversationId,
					.grantId = *grantId,
					.issuerAccountId = *actorAccountId,
					.issuerClientId = metadata->clientId,
					.recipientAccountId = transition.targetAccountId,
					.telegramPeerIdBinding = group.telegramPeerIdBinding,
					.groupGeneration = transition.generation,
					.historyAccess = transition.historyAccess,
					.issuerSigningPrivateKey =
						&_vault->identity.signingPrivateKey,
				},
				.signedTransition =
					&preparedChange.transaction.signedTransition,
				.applied = &preparedChange.applied,
				.admittedCredential = nullptr,
				.archiveEpoch = &*preparedChange.transaction.archiveEpoch,
			},
			group.groupLedger,
			group.archiveState,
			_sha256,
			OpenMlsBridge())
			: CreateAuthorizedHistoryGrantOutcome();
		const auto payload = grant.grant
			? EncryptedHistoryGrantCodecV1().encode(*grant.grant)
			: std::nullopt;
		const auto envelope = (grantId && grant.grant && payload)
			? group.envelopeCodec.encode({
				.conversationId = conversationId,
				.objectKind = ObjectKind::HistoryGrant,
				.senderAccountId = *actorAccountId,
				.senderClientId = metadata->clientId,
				.telegramPeerIdBinding = group.telegramPeerIdBinding,
				.epochOrGeneration = transition.generation,
				.objectId = *grantId,
				.payloadHash = _sha256.digest(*payload),
				.payload = *payload,
				.authenticationData = QByteArray(
					reinterpret_cast<const char*>(
						grant.grant->signature.data()),
					int(grant.grant->signature.size())),
			})
			: std::nullopt;
		if (!envelope) {
			return false;
		}
		preparedChange.transaction.outboxEnvelopes.push_back(*envelope);
	}
	auto coordinator = GroupChangeTransactionCoordinator(
		group.changeJournal,
		group.mlsState,
		group.archiveState,
		group.groupLedger,
		group.outbox,
		_sha256);
	if (coordinator.apply(std::move(preparedChange.transaction))
			!= GroupChangeApplyStatus::Applied) {
		return false;
	}
	group.conversation.checkpoint = group.groupLedger.checkpoint();
	setContentState(conversationId, DesktopContentState::Synchronizing);
	notifySecurityRevision();
	_pendingGroupCreation = std::move(i->second);
	_groups.erase(i);
	_pendingGroupCreation->vaultPreflightRequired = true;
	publishNextBootstrapObject();
	return true;
}

bool DesktopService::admitObservedClient(
		ConversationId conversationId,
		const std::vector<TelegramTransport::UntrustedObject> &objects) {
	const auto i = _groups.find(conversationId);
	if (!vaultReady() || i == end(_groups) || _pendingGroupCreation) {
		return false;
	}
	auto &group = *i->second;
	const auto state = group.groupLedger.state();
	const auto metadata = group.metadata.metadata();
	const auto actorAccountId = DeriveAccountId(
		_vault->identity.credential,
		_sha256);
	if (!state
		|| !metadata
		|| !actorAccountId
		|| !group.freshnessGate
		|| !group.freshnessGate->administrationAllowed()
		|| metadata->accountId != *actorAccountId
		|| !state->memberByClient(metadata->clientId)) {
		return false;
	}
	for (const auto &object : objects) {
			auto observed = VerifyObservedClientKeyPackage(
			object,
			conversationId,
			group.telegramPeerIdBinding,
			state->generation(),
			std::uint64_t(base::unixtime::now()),
			group.envelopeCodec,
			_sha256);
		if (!observed.verified) {
			continue;
		}
		const auto &candidate = *observed.verified;
		const auto targetAccountId = candidate.envelope.senderAccountId;
		const auto targetClientId = candidate.envelope.senderClientId;
		const auto existingMember = state->member(targetAccountId);
		if (state->memberByClient(targetClientId)
			|| (existingMember
				&& existingMember->telegramUserIdBinding
					!= candidate.telegramUserIdBinding)
			|| (!existingMember
				&& state->memberByTelegramUserId(
					candidate.telegramUserIdBinding))) {
			continue;
		}
		if (state->generation()
			== std::numeric_limits<std::uint64_t>::max()) {
			_vaultState = DesktopVaultState::SecurityBlocked;
			_groupCreationState = DesktopGroupCreationState::LocalFailure;
			return false;
		}
		const auto transitionId = RandomId<ObjectId>();
		const auto commitObjectId = RandomId<ObjectId>();
		const auto distributionObjectId = RandomId<ObjectId>();
		const auto welcomeObjectId = RandomId<ObjectId>();
		const auto historyGrantObjectId = RandomId<ObjectId>();
		const auto nextArchiveKey = ArchiveEpochCrypto().generateKey();
		if (!transitionId
			|| !commitObjectId
			|| !distributionObjectId
			|| !welcomeObjectId
			|| !historyGrantObjectId
			|| !nextArchiveKey) {
			return false;
		}
		const auto historyAccess = existingMember
			? existingMember->historyAccess
			: state->policy().defaultHistoryAccess;
		const auto transition = GroupTransition{
			.conversationId = conversationId,
			.transitionId = *transitionId,
			.previousGeneration = state->generation(),
			.generation = state->generation() + 1,
			.kind = existingMember
				? GroupTransitionKind::AddClient
				: GroupTransitionKind::AddMember,
			.targetAccountId = targetAccountId,
			.targetClientId = targetClientId,
			.targetTelegramUserIdBinding = candidate.telegramUserIdBinding,
			.targetRole = GroupRole::Member,
			.targetAdminPermissions = 0,
			.historyAccess = historyAccess,
		};
		auto prepared = PrepareOpenMlsAdmission({
			.actor = {
				.conversationId = conversationId,
				.accountId = *actorAccountId,
				.clientId = metadata->clientId,
				.telegramPeerIdBinding = group.telegramPeerIdBinding,
			},
			.currentGroupState = state,
			.currentCheckpoint = group.groupLedger.checkpoint(),
			.transition = transition,
			.actorCredential = &_vault->identity.credential,
			.actorSigningPrivateKey = &_vault->identity.signingPrivateKey,
			.targetCredential = &candidate.publication.accountCredential,
			.targetClientAuthorization =
				&candidate.publication.authorization,
			.targetKeyPackage = candidate.publication.keyPackage,
			.nextArchiveKey = &*nextArchiveKey,
			.mlsCommitObjectId = *commitObjectId,
			.archiveDistributionObjectId = *distributionObjectId,
			.welcomeObjectId = *welcomeObjectId,
		},
		OpenMlsBridge(),
		MlsContextCodecV1(),
		MlsRosterCodecV1(),
		GroupControlCodecV1(),
		group.envelopeCodec,
		_sha256,
		group.mlsState,
		group.archiveState,
		group.groupLedger);
		if (!prepared.prepared) {
			continue;
		}
		auto &preparedChange = *prepared.prepared;
		auto grant = preparedChange.transaction.archiveEpoch
			? CreateAdmissionHistoryGrant({
				.grant = {
					.conversationId = conversationId,
					.grantId = *historyGrantObjectId,
					.issuerAccountId = *actorAccountId,
					.issuerClientId = metadata->clientId,
					.recipientAccountId = targetAccountId,
					.telegramPeerIdBinding =
						group.telegramPeerIdBinding,
					.groupGeneration = transition.generation,
					.historyAccess = historyAccess,
					.issuerSigningPrivateKey =
						&_vault->identity.signingPrivateKey,
				},
				.signedTransition =
					&preparedChange.transaction.signedTransition,
				.applied = &preparedChange.applied,
				.admittedCredential =
					&candidate.publication.accountCredential,
				.archiveEpoch = &*preparedChange.transaction.archiveEpoch,
			},
			group.groupLedger,
			group.archiveState,
			_sha256,
			OpenMlsBridge())
			: CreateAuthorizedHistoryGrantOutcome();
		const auto grantPayload = grant.grant
			? EncryptedHistoryGrantCodecV1().encode(*grant.grant)
			: std::nullopt;
		const auto grantEnvelope = (grant.grant && grantPayload)
			? group.envelopeCodec.encode({
				.conversationId = conversationId,
				.objectKind = ObjectKind::HistoryGrant,
				.senderAccountId = *actorAccountId,
				.senderClientId = metadata->clientId,
				.telegramPeerIdBinding = group.telegramPeerIdBinding,
				.epochOrGeneration = transition.generation,
				.objectId = *historyGrantObjectId,
				.payloadHash = _sha256.digest(*grantPayload),
				.payload = *grantPayload,
				.authenticationData = QByteArray(
					reinterpret_cast<const char*>(
						grant.grant->signature.data()),
					int(grant.grant->signature.size())),
			})
			: std::nullopt;
		if (!grantEnvelope) {
			_groupCreationState = DesktopGroupCreationState::LocalFailure;
			return false;
		}
		preparedChange.transaction.outboxEnvelopes.push_back(
			*grantEnvelope);
		auto coordinator = GroupChangeTransactionCoordinator(
			group.changeJournal,
			group.mlsState,
			group.archiveState,
			group.groupLedger,
			group.outbox,
			_sha256);
		if (coordinator.apply(std::move(
				preparedChange.transaction))
				!= GroupChangeApplyStatus::Applied) {
			_groupCreationState = DesktopGroupCreationState::LocalFailure;
			return false;
		}
		group.conversation.checkpoint = group.groupLedger.checkpoint();
		notifySecurityRevision();
		_pendingGroupCreation = std::move(i->second);
		_groups.erase(i);
		_pendingGroupCreation->vaultPreflightRequired = true;
		publishNextBootstrapObject();
		return true;
	}
	return false;
}

DesktopService::LocalGroupRecoveryResult DesktopService::restoreLocalGroup(
		ConversationId conversationId,
		const CloudVaultConversation *indexedConversation) {
	auto localRecordKey = DeriveConversationLocalRecordKey(
		_vault->masterKey,
		_telegramUserIdBinding,
		conversationId);
	if (!localRecordKey) {
		return LocalGroupRecoveryResult::Invalid;
	}
	const auto directory = ConversationDirectory(
		_telegramUserIdBinding,
		conversationId);
	auto metadataBlob = FileAtomicBlobStore(
		directory + u"conversation.meta"_q);
	auto metadataProtector = AesGcmLocalRecordProtector(
		std::move(*localRecordKey));
	auto metadata = PersistentConversationMetadata(
		metadataBlob,
		metadataProtector);
	const auto metadataLoad = metadata.load(conversationId);
	if (metadataLoad == ConversationMetadataLoadResult::Missing) {
		return LocalGroupRecoveryResult::Missing;
	} else if (metadataLoad != ConversationMetadataLoadResult::Loaded
		|| !metadata.metadata()) {
		return LocalGroupRecoveryResult::Invalid;
	}
	const auto accountId = DeriveAccountId(
		_vault->identity.credential,
		_sha256);
	const auto &localMetadata = *metadata.metadata();
	if (!accountId
		|| localMetadata.accountId != *accountId
		|| !IsProtectedGroupPeerBinding(
			_session,
			localMetadata.telegramPeerIdBinding)
		|| (indexedConversation
			&& indexedConversation->telegramPeerIdBinding
				!= localMetadata.telegramPeerIdBinding)) {
		return LocalGroupRecoveryResult::Invalid;
	}
	rememberProtectedPeerForPresentation(
		localMetadata.telegramPeerIdBinding);
	auto operationKey = DeriveConversationLocalRecordKey(
		_vault->masterKey,
		_telegramUserIdBinding,
		conversationId);
	if (!operationKey) {
		return LocalGroupRecoveryResult::Invalid;
	}
	auto operation = std::make_unique<PendingGroupCreation>(
		directory,
		std::move(*operationKey),
		_session,
		localMetadata.telegramPeerIdBinding,
		conversationId,
		_sha256);
	const auto metadataReload = operation->metadata.load(conversationId);
	const auto journalLoad = operation->journal.load(conversationId);
	const auto mlsLoad = operation->mlsState.load(conversationId);
	const auto archiveLoad = operation->archiveState.load(conversationId);
	const auto groupLoad = operation->groupLedger.load(conversationId);
	const auto outboxLoad = operation->outbox.load();
	const auto changeJournalLoad = operation->changeJournal.load(
		conversationId);
	const auto changeInboxLoad = operation->changeInbox.load(conversationId);
	const auto keyPackageLoad = operation->keyPackages.load(
		conversationId,
		localMetadata.telegramPeerIdBinding);
	const auto freshnessTrustLoad = operation->freshnessTrust.load(
		conversationId);
	const auto inboundJournalLoad = operation->inboundJournal.load();
	const auto controlInboundJournalLoad = operation->controlInboundJournal.load();
	const auto contentStoreLoad = operation->contentStore.load();
	const auto controlSyncLoad = operation->controlSyncState.load(
		conversationId);
	const auto contentSyncLoad = operation->contentSyncState.load(
		conversationId);
	const auto fileTransferLoad = operation->fileTransfer.load(
		conversationId);
	if (metadataReload != ConversationMetadataLoadResult::Loaded
		|| journalLoad == GroupBootstrapJournalLoadResult::StorageError
		|| journalLoad
			== GroupBootstrapJournalLoadResult::AuthenticationFailed
		|| journalLoad == GroupBootstrapJournalLoadResult::InvalidSnapshot
		|| mlsLoad == MlsStateLoadResult::StorageError
		|| mlsLoad == MlsStateLoadResult::AuthenticationFailed
		|| mlsLoad == MlsStateLoadResult::InvalidSnapshot
		|| archiveLoad == ArchiveStateLoadResult::StorageError
		|| archiveLoad == ArchiveStateLoadResult::AuthenticationFailed
		|| archiveLoad == ArchiveStateLoadResult::InvalidSnapshot
		|| groupLoad == GroupLedgerLoadResult::StorageError
		|| groupLoad == GroupLedgerLoadResult::AuthenticationFailed
		|| groupLoad == GroupLedgerLoadResult::InvalidSnapshot
		|| outboxLoad == PersistentOutboxLoadResult::StorageError
		|| outboxLoad == PersistentOutboxLoadResult::AuthenticationFailed
		|| outboxLoad == PersistentOutboxLoadResult::InvalidSnapshot
		|| changeJournalLoad == GroupChangeJournalLoadResult::StorageError
		|| changeJournalLoad
			== GroupChangeJournalLoadResult::AuthenticationFailed
		|| changeJournalLoad == GroupChangeJournalLoadResult::InvalidSnapshot
		|| changeInboxLoad == GroupChangeInboxLoadResult::StorageError
		|| changeInboxLoad
			== GroupChangeInboxLoadResult::AuthenticationFailed
		|| changeInboxLoad == GroupChangeInboxLoadResult::InvalidSnapshot
		|| keyPackageLoad == KeyPackagePoolLoadResult::StorageError
		|| keyPackageLoad == KeyPackagePoolLoadResult::AuthenticationFailed
		|| keyPackageLoad == KeyPackagePoolLoadResult::InvalidSnapshot
		|| freshnessTrustLoad == FreshnessTrustLoadResult::StorageError
		|| freshnessTrustLoad
			== FreshnessTrustLoadResult::AuthenticationFailed
		|| freshnessTrustLoad == FreshnessTrustLoadResult::InvalidSnapshot) {
		return LocalGroupRecoveryResult::Invalid;
	}
	if (inboundJournalLoad == InboundJournalLoadResult::ReadFailed
		|| inboundJournalLoad
			== InboundJournalLoadResult::AuthenticationFailed
		|| inboundJournalLoad == InboundJournalLoadResult::InvalidSnapshot
		|| controlInboundJournalLoad == InboundJournalLoadResult::ReadFailed
		|| controlInboundJournalLoad
			== InboundJournalLoadResult::AuthenticationFailed
		|| controlInboundJournalLoad
			== InboundJournalLoadResult::InvalidSnapshot
		|| contentStoreLoad == ContentStoreLoadResult::ReadFailed
		|| contentStoreLoad == ContentStoreLoadResult::AuthenticationFailed
		|| contentStoreLoad == ContentStoreLoadResult::InvalidSnapshot
		|| controlSyncLoad == ControlObservationStateLoadResult::ReadFailed
		|| controlSyncLoad
			== ControlObservationStateLoadResult::AuthenticationFailed
		|| controlSyncLoad
			== ControlObservationStateLoadResult::InvalidSnapshot
		|| contentSyncLoad == ContentSyncStateLoadResult::ReadFailed
		|| contentSyncLoad
			== ContentSyncStateLoadResult::AuthenticationFailed
		|| contentSyncLoad == ContentSyncStateLoadResult::InvalidSnapshot) {
		return LocalGroupRecoveryResult::Invalid;
	}
	if (fileTransferLoad == FileTransferLoadResult::ReadFailed
		|| fileTransferLoad == FileTransferLoadResult::AuthenticationFailed
		|| fileTransferLoad == FileTransferLoadResult::InvalidSnapshot) {
		return LocalGroupRecoveryResult::Invalid;
	}
	const auto pendingFileTransfer = operation->fileTransfer.pending();
	CleanupStagedProtectedSources(
		operation->directory,
		pendingFileTransfer
			? QString::fromUtf8(pendingFileTransfer->sourcePathUtf8)
			: QString());
	if (journalLoad == GroupBootstrapJournalLoadResult::Pending) {
		const auto envelopeCodec = EnvelopeCodecV1();
		auto coordinator = GroupBootstrapTransactionCoordinator(
			operation->journal,
			operation->mlsState,
			operation->archiveState,
			operation->groupLedger,
			operation->outbox,
			envelopeCodec,
			_sha256);
		if (coordinator.recover() != GroupBootstrapApplyStatus::Recovered) {
			return LocalGroupRecoveryResult::Invalid;
		}
	}
	if (changeJournalLoad == GroupChangeJournalLoadResult::Pending) {
		auto coordinator = GroupChangeTransactionCoordinator(
			operation->changeJournal,
			operation->mlsState,
			operation->archiveState,
			operation->groupLedger,
			operation->outbox,
			_sha256);
		if (coordinator.recover() != GroupChangeApplyStatus::Recovered) {
			return LocalGroupRecoveryResult::Invalid;
		}
	}
	const auto receiptReconciliation = ReconcileMlsOutboxReceipts(
		operation->mlsState,
		operation->outbox,
		operation->envelopeCodec,
		operation->inboundJournal);
	if (receiptReconciliation != MlsReceiptReconcileResult::Reconciled
		&& receiptReconciliation != MlsReceiptReconcileResult::NothingToDo) {
		return LocalGroupRecoveryResult::Invalid;
	}
	const auto state = operation->groupLedger.state();
	const auto localMember = state ? state->member(*accountId) : nullptr;
	const auto activeClient = localMember && std::find(
		begin(localMember->clients),
		end(localMember->clients),
		localMetadata.clientId) != end(localMember->clients);
	const auto removed = operation->mlsState.removed()
		&& operation->mlsState.removalTombstone()
		&& !activeClient;
	const auto awaitingAdmission = !activeClient
		&& !removed
		&& !operation->mlsState.revision()
		&& !operation->archiveState.revision()
		&& !operation->keyPackages.entries().empty();
	if (awaitingAdmission) {
		if (!state) {
			return LocalGroupRecoveryResult::Invalid;
		}
		const auto currentTime = std::uint64_t(base::unixtime::now());
		const auto boundPackage = std::any_of(
			begin(operation->keyPackages.entries()),
			end(operation->keyPackages.entries()),
			[&](const StoredClientKeyPackage &entry) {
				const auto envelope = operation->envelopeCodec.decode(
					entry.publicationEnvelope);
				const auto publication = envelope
					? VerifyClientKeyPackageEnvelope(
						*envelope,
						conversationId,
						localMetadata.telegramPeerIdBinding,
						state->generation(),
						_sha256)
					: VerifyClientKeyPackageEnvelopeOutcome();
				const auto expectedObjectId = (envelope
						&& publication.publication)
					? DeriveClientKeyPackageObjectId(
						conversationId,
						localMetadata.accountId,
						localMetadata.clientId,
						state->generation(),
						_telegramUserIdBinding,
						publication.publication->accountCredential,
						publication.publication->keyPackage,
						_sha256)
					: std::nullopt;
				return envelope
					&& publication.result
						== ClientKeyPackageEnvelopeResult::Verified
					&& publication.publication
					&& expectedObjectId
					&& envelope->objectId == *expectedObjectId
					&& ClientAuthorizationUsableAt(
						publication.publication->authorization,
						currentTime);
			});
		if (!boundPackage) {
			auto keyPackage = PrepareClientKeyPackage({
				.client = {
					.conversationId = conversationId,
					.accountId = localMetadata.accountId,
					.clientId = localMetadata.clientId,
					.telegramPeerIdBinding
						= localMetadata.telegramPeerIdBinding,
				},
				.currentGeneration = state->generation(),
				.telegramUserIdBinding = _telegramUserIdBinding,
				.createdAt = currentTime,
				.accountCredential = &_vault->identity.credential,
				.accountSigningPrivateKey
					= &_vault->identity.signingPrivateKey,
			},
			OpenMlsBridge(),
			MlsContextCodecV1(),
			ClientKeyPackagePublicationCodecV1(),
			operation->envelopeCodec,
			_sha256);
			if (keyPackage.status
					!= PrepareClientKeyPackageStatus::Prepared
				|| !keyPackage.entry
				|| operation->keyPackages.add(std::move(*keyPackage.entry))
					!= KeyPackagePoolMutationResult::Committed) {
				return LocalGroupRecoveryResult::Invalid;
			}
		}
		const auto queued = operation->keyPackages.enqueuePending(
			operation->outbox,
			currentTime);
		if (queued != KeyPackagePoolEnqueueResult::Queued
			&& queued != KeyPackagePoolEnqueueResult::NothingToDo) {
			return LocalGroupRecoveryResult::Invalid;
		}
	}
	const auto localIsGenesisOwner = state
		&& state->generation() == 1
		&& localMember
		&& localMember->role == GroupRole::Owner
		&& activeClient;
	if (freshnessTrustLoad == FreshnessTrustLoadResult::Missing) {
		if (operation->freshnessTrust.initialize(localIsGenesisOwner)
				!= FreshnessTrustCommitResult::Committed) {
			return LocalGroupRecoveryResult::Invalid;
		}
	}
	if (!state
		|| !operation->mlsState.loaded()
		|| (awaitingAdmission
			? archiveLoad != ArchiveStateLoadResult::Missing
			: !operation->archiveState.loaded())
		|| !operation->groupLedger.loaded()
		|| !operation->groupLedger.revision()
		|| !operation->outbox.loaded()
		|| (!awaitingAdmission
			&& ((!activeClient && !removed)
				|| !operation->mlsState.revision()
				|| !operation->archiveState.revision()))) {
		return LocalGroupRecoveryResult::Invalid;
	}
	const auto owner = std::find_if(
		begin(state->members()),
		end(state->members()),
		[](const GroupMember &member) {
			return member.role == GroupRole::Owner;
		});
	if (owner == end(state->members())) {
		return LocalGroupRecoveryResult::Invalid;
	}
	const auto genesisState = operation->groupLedger.stateAt(1);
	if (!genesisState) {
		return LocalGroupRecoveryResult::Invalid;
	}
	const auto genesisOwner = std::find_if(
		begin(genesisState->members()),
		end(genesisState->members()),
		[](const GroupMember &member) {
			return member.role == GroupRole::Owner;
		});
	if (genesisOwner == end(genesisState->members())) {
		return LocalGroupRecoveryResult::Invalid;
	}
	if (controlSyncLoad == ControlObservationStateLoadResult::Loaded) {
		const auto storedCheckpoint = operation->controlSyncState.checkpoint();
		const auto expectedCheckpoint = operation->groupLedger.checkpointAt(
			storedCheckpoint.generation);
		if (!expectedCheckpoint
			|| *expectedCheckpoint != storedCheckpoint
			|| !operation->controlSyncState.safetyWitnesses().contains(
				localMetadata.accountId)) {
			return LocalGroupRecoveryResult::Invalid;
		}
		if (storedCheckpoint == operation->groupLedger.checkpoint()) {
			operation->safetyWitnessGeneration = storedCheckpoint.generation;
			operation->safetyWitnesses
				= operation->controlSyncState.safetyWitnesses();
			operation->ownSafetyGossipObserved
				= operation->controlSyncState.ownSafetyGossipObserved();
		} else {
			operation->safetyWitnessGeneration = state->generation();
			operation->safetyWitnesses = { localMetadata.accountId };
			operation->ownSafetyGossipObserved = false;
		}
	} else if (controlSyncLoad
			== ControlObservationStateLoadResult::LegacyLoaded) {
		operation->safetyWitnessGeneration = state->generation();
		operation->safetyWitnesses = { localMetadata.accountId };
		operation->ownSafetyGossipObserved = false;
		const auto migrated = operation->controlSyncState.advance(
			operation->controlSyncState.newestObservedMessageId(),
			operation->groupLedger.checkpoint(),
			operation->safetyWitnesses,
			false);
		if (migrated != ControlObservationStateCommitResult::Committed) {
			return LocalGroupRecoveryResult::Invalid;
		}
	}
	const auto localConversation = CloudVaultConversation{
		.conversationId = conversationId,
		.telegramPeerIdBinding = localMetadata.telegramPeerIdBinding,
		.checkpoint = operation->groupLedger.checkpoint(),
		.ownerAccountId = genesisOwner->accountId,
	};
	if (awaitingAdmission) {
		operation->phase = PendingGroupCreation::Phase::AwaitingAdmission;
	} else if (removed) {
		operation->phase = PendingGroupCreation::Phase::Removed;
	} else {
		operation->phase = PendingGroupCreation::Phase::Active;
	}
	operation->freshnessGate = std::make_unique<FreshnessGate>(
		operation->groupLedger.checkpoint(),
		operation->freshnessTrust.trusted() && !removed);
	const auto indexedMatches = indexedConversation
		&& indexedConversation->conversationId
			== localConversation.conversationId
		&& indexedConversation->telegramPeerIdBinding
			== localConversation.telegramPeerIdBinding
		&& indexedConversation->ownerAccountId
			== localConversation.ownerAccountId;
	const auto localAhead = indexedMatches
		&& indexedConversation->checkpoint.generation
			< localConversation.checkpoint.generation;
	const auto indexedAhead = indexedMatches
		&& awaitingAdmission
		&& indexedConversation->checkpoint.generation
			> localConversation.checkpoint.generation;
	if (indexedConversation
		&& *indexedConversation != localConversation
		&& !localAhead
		&& !indexedAhead) {
		return LocalGroupRecoveryResult::Invalid;
	}
	operation->joinTargetCheckpoint = awaitingAdmission
		? (indexedConversation
			? indexedConversation->checkpoint
			: localConversation.checkpoint)
		: Checkpoint();
	if (indexedConversation
		&& !localAhead
		&& operation->phase == PendingGroupCreation::Phase::Active) {
		operation->conversation = *indexedConversation;
		_groups[conversationId] = std::move(operation);
		if (!resumeObservedJoinHistory(conversationId)
			|| !initializeActivePipeline(*_groups[conversationId])) {
			_groups.erase(conversationId);
			return LocalGroupRecoveryResult::Invalid;
		}
		beginGroupObservation(conversationId);
		beginContentObservation(conversationId);
		pumpActiveOutbox(conversationId);
		return LocalGroupRecoveryResult::Complete;
	} else if (!operation->outbox.size()
		&& !(removed && operation->fileTransfer.pending())) {
		const auto requiresVaultUpdate = localAhead
			|| (!indexedConversation
				&& (awaitingAdmission || localIsGenesisOwner));
		if (requiresVaultUpdate) {
			operation->conversation = localConversation;
			operation->vaultPreflightRequired = true;
			_pendingGroupCreation = std::move(operation);
			return LocalGroupRecoveryResult::Restored;
		} else if (!indexedConversation) {
			return LocalGroupRecoveryResult::Invalid;
		}
		operation->conversation = *indexedConversation;
		if (!awaitingAdmission && !operation->freshnessTrust.trusted()) {
			operation->vaultPreflightRequired = false;
			_pendingGroupCreation = std::move(operation);
			return LocalGroupRecoveryResult::Restored;
		}
		_groups[conversationId] = std::move(operation);
		if (!awaitingAdmission
			&& !removed
			&& (!resumeObservedJoinHistory(conversationId)
				|| !initializeActivePipeline(*_groups[conversationId]))) {
			_groups.erase(conversationId);
			return LocalGroupRecoveryResult::Invalid;
		}
		if (awaitingAdmission) {
			_groupCreationState = DesktopGroupCreationState::AwaitingAdmission;
		}
		beginGroupObservation(conversationId);
		if (!awaitingAdmission) {
			beginContentObservation(conversationId);
		}
		return LocalGroupRecoveryResult::Complete;
	}
	operation->conversation = (indexedConversation && !localAhead)
		? *indexedConversation
		: localConversation;
	operation->vaultPreflightRequired = !indexedConversation || localAhead;
	_pendingGroupCreation = std::move(operation);
	return LocalGroupRecoveryResult::Restored;
}

bool DesktopService::commitVaultAnchor(const UnlockedCloudVault &vault) {
	const auto accountId = DeriveAccountId(
		vault.identity.credential,
		_sha256);
	if (!accountId) {
		return false;
	}
	const auto result = _vaultAnchor.commit({
		.generation = vault.generation,
		.blobDigest = vault.blobDigest,
		.accountId = *accountId,
	});
	return result == CloudVaultAnchorCommitResult::Committed
		|| result == CloudVaultAnchorCommitResult::AlreadyCommitted;
}

bool DesktopService::commitVaultAnchor(
		const PreparedCloudVaultUpdate &update,
		const AccountPrivateIdentity &identity) {
	const auto accountId = DeriveAccountId(identity.credential, _sha256);
	if (!accountId) {
		return false;
	}
	const auto result = _vaultAnchor.commit({
		.generation = update.generation,
		.blobDigest = update.blobDigest,
		.accountId = *accountId,
	});
	return result == CloudVaultAnchorCommitResult::Committed
		|| result == CloudVaultAnchorCommitResult::AlreadyCommitted;
}

} // namespace E2ECloud

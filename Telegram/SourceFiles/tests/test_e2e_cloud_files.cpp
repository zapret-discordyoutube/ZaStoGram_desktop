/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "e2e_cloud/files/file_chunk_crypto.h"
#include "e2e_cloud/files/file_chunk_envelope.h"
#include "e2e_cloud/files/file_chunk_file_store.h"
#include "e2e_cloud/files/idempotent_file_chunk_protector.h"
#include "e2e_cloud/files/private_file_manifest.h"
#include "e2e_cloud/core/envelope_codec.h"
#include "e2e_cloud/content/protected_message_body.h"
#include "e2e_cloud/identity/account_identity.h"
#include "e2e_cloud/storage/aes_gcm_local_record_protector.h"

#include <QtCore/QDir>
#include <QtCore/QElapsedTimer>
#include <QtCore/QFile>
#include <QtCore/QFileInfo>
#include <QtCore/QLockFile>
#include <QtCore/QTemporaryDir>

#include <algorithm>
#include <cstdio>
#include <limits>

namespace {

using namespace E2ECloud;

template <typename Id>
[[nodiscard]] Id FilledId(std::uint8_t value) {
	auto result = Id();
	result.bytes.fill(value);
	return result;
}

[[nodiscard]] int Fail(const char *message) {
	std::fprintf(stderr, "%s\n", message);
	return 1;
}

[[nodiscard]] FileEncryptionKey MakeKey(std::uint8_t value = 7) {
	auto bytes = std::array<std::uint8_t, 32>();
	bytes.fill(value);
	return FileEncryptionKey(std::move(bytes));
}

[[nodiscard]] QByteArray FilledBytes(int size, char value) {
	auto result = QByteArray();
	result.resize(size);
	std::fill(result.data(), result.data() + result.size(), value);
	return result;
}

[[nodiscard]] FileChunkContext MakeContext() {
	auto result = FileChunkContext{
		.conversationId = FilledId<ConversationId>(1),
		.fileId = FilledId<FileId>(2),
		.plaintextSize = 64 * 1024 + 13,
		.chunkSize = 64 * 1024,
		.chunkCount = 2,
		.noncePrefix = {},
	};
	result.noncePrefix.fill(3);
	return result;
}

[[nodiscard]] int ScenarioMaterialGeneration() {
	auto first = GenerateFileEncryptionMaterial();
	auto second = GenerateFileEncryptionMaterial();
	if (!first
		|| !second
		|| !first->fileId
		|| !first->key.valid()
		|| first->fileId == second->fileId
		|| first->noncePrefix == second->noncePrefix) {
		return Fail("file encryption material was missing or reused");
	}
	return 0;
}

[[nodiscard]] int ScenarioChunkRoundTripAndResume() {
	const auto cipher = AesGcmFileChunkCipher();
	const auto context = MakeContext();
	const auto key = MakeKey();
	const auto firstPlaintext = FilledBytes(64 * 1024, 'a');
	const auto lastPlaintext = FilledBytes(13, 'b');
	const auto first = cipher.encrypt(key, context, 0, firstPlaintext);
	const auto retry = cipher.encrypt(key, context, 0, firstPlaintext);
	const auto last = cipher.encrypt(key, context, 1, lastPlaintext);
	if (!first
		|| !retry
		|| !last
		|| first != retry
		|| first == last
		|| first->size() != 64 * 1024 + 122
		|| cipher.decrypt(key, context, 0, *first) != firstPlaintext
		|| cipher.decrypt(key, context, 1, *last) != lastPlaintext) {
		return Fail("file chunks were not independently resumable");
	}
	return 0;
}

[[nodiscard]] int ScenarioChunkBindsContextAndTag() {
	const auto cipher = AesGcmFileChunkCipher();
	const auto context = MakeContext();
	const auto key = MakeKey();
	const auto plaintext = FilledBytes(13, 'x');
	const auto encoded = cipher.encrypt(key, context, 1, plaintext);
	if (!encoded) {
		return Fail("file chunk tamper setup failed");
	}
	for (const auto offset : { 0, 10, 42, 74, 78, 82, 90, 94, 102, 121 }) {
		auto tampered = *encoded;
		tampered[offset] = char(std::uint8_t(tampered[offset]) ^ 1);
		if (cipher.decrypt(key, context, 1, tampered)) {
			return Fail("file chunk accepted modified context or ciphertext");
		}
	}
	auto wrongConversation = context;
	wrongConversation.conversationId = FilledId<ConversationId>(9);
	auto wrongFile = context;
	wrongFile.fileId = FilledId<FileId>(9);
	if (cipher.decrypt(key, context, 0, *encoded)
		|| cipher.decrypt(key, wrongConversation, 1, *encoded)
		|| cipher.decrypt(key, wrongFile, 1, *encoded)) {
		return Fail("file chunk was reusable across context or index");
	}
	return 0;
}

[[nodiscard]] int ScenarioChunkRejectsInvalidLayout() {
	const auto cipher = AesGcmFileChunkCipher();
	auto context = MakeContext();
	const auto key = MakeKey();
	context.chunkCount = 3;
	if (IsValidFileChunkContext(context)
		|| cipher.encrypt(key, context, 0, FilledBytes(64 * 1024, 'a'))) {
		return Fail("file chunk accepted an inconsistent file layout");
	}
	context = MakeContext();
	if (cipher.encrypt(key, context, 1, FilledBytes(12, 'a'))
		|| cipher.encrypt(key, context, 2, FilledBytes(13, 'a'))) {
		return Fail("file chunk accepted a wrong index or plaintext length");
	}
	context = MakeContext();
	context.plaintextSize = kMaximumProtectedFileSize + 1;
	context.chunkCount = std::uint32_t(
		1 + ((context.plaintextSize - 1) / context.chunkSize));
	if (IsValidFileChunkContext(context)) {
		return Fail("file chunk accepted an oversized protected file");
	}
	return 0;
}

[[nodiscard]] int ScenarioEmptyFileLayout() {
	auto context = MakeContext();
	context.plaintextSize = 0;
	context.chunkCount = 0;
	if (!IsValidFileChunkContext(context)
		|| AesGcmFileChunkCipher().encrypt(
			MakeKey(),
			context,
			0,
			QByteArray())) {
		return Fail("empty file layout was not represented without chunks");
	}
	return 0;
}

[[nodiscard]] PrivateFileManifest MakeManifest() {
	return {
		.context = MakeContext(),
		.key = MakeKey(),
		.plaintextHash = FilledId<Digest>(8),
		.unixTime = 1'725'000'000,
		.filenameUtf8 = QByteArray("archive.any-extension"),
		.mimeTypeUtf8 = QByteArray("application/x-private"),
	};
}

[[nodiscard]] int ScenarioPrivateManifestRoundTrip() {
	const auto codec = PrivateFileManifestCodecV1();
	auto manifest = MakeManifest();
	const auto expectedKey = manifest.key.bytes();
	const auto encoded = codec.encodePlaintext(manifest);
	const auto decoded = encoded
		? codec.decodePlaintext(*encoded)
		: std::nullopt;
	if (!encoded
		|| !decoded
		|| decoded->context.conversationId
			!= manifest.context.conversationId
		|| decoded->context.fileId != manifest.context.fileId
		|| decoded->context.plaintextSize != manifest.context.plaintextSize
		|| decoded->context.chunkSize != manifest.context.chunkSize
		|| decoded->context.chunkCount != manifest.context.chunkCount
		|| decoded->context.noncePrefix != manifest.context.noncePrefix
		|| decoded->key.bytes() != expectedKey
		|| decoded->plaintextHash != manifest.plaintextHash
		|| decoded->unixTime != manifest.unixTime
		|| decoded->filenameUtf8 != manifest.filenameUtf8
		|| decoded->mimeTypeUtf8 != manifest.mimeTypeUtf8) {
		return Fail("private file manifest did not preserve file metadata");
	}
	auto trailing = *encoded;
	trailing.append('x');
	if (codec.decodePlaintext(trailing)) {
		return Fail("private file manifest accepted trailing bytes");
	}
	return 0;
}

[[nodiscard]] int ScenarioPrivateManifestRejectsUnsafeName() {
	const auto codec = PrivateFileManifestCodecV1();
	auto manifest = MakeManifest();
	manifest.filenameUtf8 = QByteArray("../secret.txt");
	if (codec.encodePlaintext(manifest)) {
		return Fail("private file manifest accepted path traversal metadata");
	}
	manifest.filenameUtf8 = QByteArray("\xC0\xAF", 2);
	if (codec.encodePlaintext(manifest)) {
		return Fail("private file manifest accepted an invalid UTF-8 name");
	}
	manifest.filenameUtf8 = QByteArray("safe.bin");
	manifest.mimeTypeUtf8 = QByteArray("text/plain\r\nInjected: yes");
	if (codec.encodePlaintext(manifest)) {
		return Fail("private file manifest accepted header injection metadata");
	}
	manifest.mimeTypeUtf8 = QByteArray("text/\xFF", 6);
	if (codec.encodePlaintext(manifest)) {
		return Fail("private file manifest accepted invalid UTF-8 metadata");
	}
	manifest = MakeManifest();
	manifest.unixTime = std::numeric_limits<std::uint64_t>::max();
	if (codec.encodePlaintext(manifest)) {
		return Fail("private file manifest accepted overflowing timestamp");
	}
	auto encoded = codec.encodePlaintext(MakeManifest());
	if (!encoded) {
		return Fail("private file manifest timestamp test did not encode");
	}
	std::fill_n(encoded->data() + 162, 8, char(0xFF));
	if (codec.decodePlaintext(*encoded)) {
		return Fail("private file manifest decoded overflowing timestamp");
	}
	return 0;
}

class MemoryChunkStore final : public FileChunkCiphertextStore {
public:
	[[nodiscard]] FileChunkReadResult read(
			ConversationId,
			FileId,
			std::uint32_t) const override {
		if (readError) {
			return { .status = FileChunkReadStatus::Error, .chunk = {} };
		} else if (!chunk) {
			return { .status = FileChunkReadStatus::Missing, .chunk = {} };
		}
		return { .status = FileChunkReadStatus::Found, .chunk = *chunk };
	}

	[[nodiscard]] FileChunkAuthorizationReadResult authorization(
			ConversationId,
			FileId) const override {
		return authorizedManifest
			? FileChunkAuthorizationReadResult{
				.status = FileChunkAuthorizationReadStatus::Found,
				.authorization = *authorizedManifest,
			}
			: FileChunkAuthorizationReadResult{
				.status = FileChunkAuthorizationReadStatus::Missing,
				.authorization = {},
			};
	}

	FileChunkAuthorizeResult authorize(
			FileChunkAuthorization value) override {
		if (!authorizedManifest) {
			authorizedManifest = value;
			return FileChunkAuthorizeResult::Authorized;
		}
		return IsSameFileChunkAuthorization(*authorizedManifest, value)
			? FileChunkAuthorizeResult::AlreadyAuthorized
			: FileChunkAuthorizeResult::Conflict;
	}

	FileChunkStoreResult storeIfAbsent(
			ConversationId,
			FileId,
			std::uint32_t,
			StoredFileChunk value) override {
		++storeCalls;
		if (writeError) {
			return FileChunkStoreResult::Error;
		} else if (chunk) {
			return FileChunkStoreResult::AlreadyExists;
		}
		chunk = std::move(value);
		return FileChunkStoreResult::Stored;
	}

	std::optional<StoredFileChunk> chunk;
	std::optional<FileChunkAuthorization> authorizedManifest;
	int storeCalls = 0;
	bool readError = false;
	bool writeError = false;
};

[[nodiscard]] FileChunkAuthorization MakeAuthorization() {
	return {
		.context = MakeContext(),
		.senderAccountId = FilledId<AccountId>(5),
		.senderClientId = FilledId<ClientId>(6),
		.manifestEventObjectId = FilledId<ObjectId>(7),
		.manifestDigest = FilledId<Digest>(8),
		.groupGeneration = 9,
	};
}

[[nodiscard]] int ScenarioIdempotentChunkLedger() {
	const auto cipher = AesGcmFileChunkCipher();
	auto store = MemoryChunkStore();
	auto protector = IdempotentFileChunkProtector(cipher, store);
	const auto context = MakeContext();
	const auto key = MakeKey();
	const auto plaintext = FilledBytes(13, 'x');
	const auto first = protector.prepare(key, context, 1, plaintext);
	const auto retry = protector.prepare(key, context, 1, plaintext);
	if (first.result != FileChunkPrepareResult::Ready
		|| !first.exactCiphertext
		|| retry.result != FileChunkPrepareResult::Ready
		|| retry.exactCiphertext != first.exactCiphertext
		|| !HasExactFileChunkCiphertext(
			store.read(context.conversationId, context.fileId, 1),
			*first.exactCiphertext)
		|| store.storeCalls != 1) {
		return Fail("file chunk ledger did not reuse exact ciphertext");
	}
	store.chunk->plaintextHash.bytes[0] ^= 1;
	if (!HasExactFileChunkCiphertext(
			store.read(context.conversationId, context.fileId, 1),
			*first.exactCiphertext)) {
		return Fail("file chunk self-observation depended on hash meaning");
	}
	store.chunk->plaintextHash.bytes[0] ^= 1;
	const auto changed = protector.prepare(
		key,
		context,
		1,
		FilledBytes(13, 'y'));
	if (changed.result != FileChunkPrepareResult::SourceChanged
		|| changed.exactCiphertext) {
		return Fail("file chunk ledger reused a nonce for changed source bytes");
	}
	return 0;
}

[[nodiscard]] int ScenarioChunkLedgerFailsClosed() {
	const auto cipher = AesGcmFileChunkCipher();
	auto store = MemoryChunkStore();
	auto protector = IdempotentFileChunkProtector(cipher, store);
	const auto context = MakeContext();
	const auto key = MakeKey();
	const auto plaintext = FilledBytes(13, 'x');
	store.writeError = true;
	if (protector.prepare(key, context, 1, plaintext).result
			!= FileChunkPrepareResult::StorageFailed) {
		return Fail("file chunk escaped before nonce-ledger persistence");
	}
	store.writeError = false;
	const auto ready = protector.prepare(key, context, 1, plaintext);
	if (ready.result != FileChunkPrepareResult::Ready || !store.chunk) {
		return Fail("file chunk ledger recovery setup failed");
	}
	store.chunk->exactCiphertext[store.chunk->exactCiphertext.size() - 1] ^= 1;
	if (protector.prepare(key, context, 1, plaintext).result
			!= FileChunkPrepareResult::StorageFailed) {
		return Fail("file chunk ledger accepted corrupted persisted ciphertext");
	}
	return 0;
}

[[nodiscard]] int ScenarioChunkStoreRejectsOversizedRecord() {
	auto localKey = LocalRecordKey();
	localKey.fill(42);
	const auto protector = AesGcmLocalRecordProtector(std::move(localKey));
	auto directory = QTemporaryDir();
	if (!directory.isValid()) {
		return Fail("file chunk temporary directory was unavailable");
	}
	const auto conversationId = FilledId<ConversationId>(43);
	const auto fileId = FilledId<FileId>(44);
	const auto hex = [](const auto &identifier) {
		return QString::fromLatin1(QByteArray(
			reinterpret_cast<const char*>(identifier.bytes.data()),
			int(identifier.bytes.size())).toHex());
	};
	const auto chunkDirectory = QDir(directory.path()).filePath(
		hex(conversationId) + QLatin1Char('/') + hex(fileId));
	if (!QDir().mkpath(chunkDirectory)) {
		return Fail("file chunk fixture directory could not be created");
	}
	const auto path = QDir(chunkDirectory).filePath("0.fcl");
	auto file = QFile(path);
	constexpr auto kMaximumProtectedChunkSize = qint64(
		4 * 1024 * 1024 + 122 + 114 + 42);
	if (!file.open(QIODevice::WriteOnly)
		|| !file.seek(kMaximumProtectedChunkSize)
		|| file.write("x", 1) != 1) {
		return Fail("oversized file chunk fixture could not be created");
	}
	file.close();
	const auto stored = FileChunkFileStore(
		directory.path(),
		protector).read(conversationId, fileId, 0);
	if (stored.status != FileChunkReadStatus::Error
		|| !stored.chunk.exactCiphertext.isEmpty()) {
		return Fail("file chunk read allocated an oversized local record");
	}
	return 0;
}

[[nodiscard]] int ScenarioChunkAuthorizationLedger() {
	auto localKey = LocalRecordKey();
	localKey.fill(42);
	const auto protector = AesGcmLocalRecordProtector(std::move(localKey));
	auto directory = QTemporaryDir();
	if (!directory.isValid()) {
		return Fail("file authorization temporary directory was unavailable");
	}
	const auto authorization = MakeAuthorization();
	auto store = FileChunkFileStore(directory.path(), protector);
	if (store.authorization(
			authorization.context.conversationId,
			authorization.context.fileId).status
			!= FileChunkAuthorizationReadStatus::Missing
		|| store.authorize(authorization)
			!= FileChunkAuthorizeResult::Authorized
		|| store.authorize(authorization)
			!= FileChunkAuthorizeResult::AlreadyAuthorized) {
		return Fail("file manifest authorization was not idempotent");
	}
	const auto restored = FileChunkFileStore(
		directory.path(),
		protector).authorization(
			authorization.context.conversationId,
			authorization.context.fileId);
	auto conflicting = authorization;
	conflicting.senderClientId = FilledId<ClientId>(10);
	if (restored.status != FileChunkAuthorizationReadStatus::Found
		|| !IsSameFileChunkAuthorization(
			restored.authorization,
			authorization)
		|| store.authorize(std::move(conflicting))
			!= FileChunkAuthorizeResult::Conflict) {
		return Fail("file manifest authorization conflict was not detected");
	}
	return 0;
}

[[nodiscard]] int ScenarioChunkStoreEnforcesQuota() {
	auto localKey = LocalRecordKey();
	localKey.fill(42);
	const auto protector = AesGcmLocalRecordProtector(std::move(localKey));
	auto directory = QTemporaryDir();
	if (!directory.isValid()) {
		return Fail("file chunk quota temporary directory was unavailable");
	}
	const auto context = MakeContext();
	auto store = FileChunkFileStore(directory.path(), protector, 1);
	if (store.storeIfAbsent(
			context.conversationId,
			context.fileId,
			0,
			{
				.plaintextHash = FilledId<Digest>(11),
				.exactCiphertext = QByteArray("ciphertext"),
			}) != FileChunkStoreResult::QuotaExceeded
		|| store.read(
			context.conversationId,
			context.fileId,
			0).status != FileChunkReadStatus::Missing) {
		return Fail("file chunk cache exceeded its storage quota");
	}
	return 0;
}

[[nodiscard]] int ScenarioChunkStoreLockContentionIsNonBlocking() {
	auto localKey = LocalRecordKey();
	localKey.fill(42);
	const auto protector = AesGcmLocalRecordProtector(std::move(localKey));
	auto directory = QTemporaryDir();
	if (!directory.isValid()) {
		return Fail("file chunk lock temporary directory was unavailable");
	}
	const auto context = MakeContext();
	const auto idPath = [](const auto &id) {
		return QString::fromLatin1(QByteArray(
			reinterpret_cast<const char*>(id.bytes.data()),
			id.bytes.size()).toHex());
	};
	const auto target = QDir(directory.path()).filePath(
		idPath(context.conversationId)
		+ QString::fromLatin1("/")
		+ idPath(context.fileId)
		+ QString::fromLatin1("/0.fcl"));
	if (!QDir().mkpath(QFileInfo(target).absolutePath())) {
		return Fail("file chunk lock directory was unavailable");
	}
	auto lock = QLockFile(target + QString::fromLatin1(".lock"));
	if (!lock.tryLock(0)) {
		return Fail("file chunk contention fixture could not lock");
	}
	auto timer = QElapsedTimer();
	timer.start();
	auto store = FileChunkFileStore(directory.path(), protector);
	const auto stored = store.storeIfAbsent(
		context.conversationId,
		context.fileId,
		0,
		{
			.plaintextHash = FilledId<Digest>(11),
			.exactCiphertext = QByteArray("ciphertext"),
		});
	if (stored != FileChunkStoreResult::Error || timer.elapsed() >= 1000) {
		return Fail("file chunk lock contention blocked the caller");
	}
	return 0;
}

[[nodiscard]] int ScenarioChunkStoreReleasesQuotaAfterRemoval() {
	auto localKey = LocalRecordKey();
	localKey.fill(42);
	const auto protector = AesGcmLocalRecordProtector(std::move(localKey));
	auto directory = QTemporaryDir();
	if (!directory.isValid()) {
		return Fail("file chunk removal temporary directory was unavailable");
	}
	const auto context = MakeContext();
	const auto chunk = StoredFileChunk{
		.plaintextHash = FilledId<Digest>(11),
		.exactCiphertext = QByteArray("ciphertext"),
	};
	auto store = FileChunkFileStore(directory.path(), protector, 200);
	if (store.storeIfAbsent(
			context.conversationId,
			context.fileId,
			0,
			chunk) != FileChunkStoreResult::Stored
		|| !store.hasChunk(
			context.conversationId,
			context.fileId,
			0)
		|| store.storeIfAbsent(
			context.conversationId,
			context.fileId,
			1,
			chunk) != FileChunkStoreResult::QuotaExceeded
		|| !store.removeChunk(
			context.conversationId,
			context.fileId,
			0)
		|| store.read(
			context.conversationId,
			context.fileId,
			0).status != FileChunkReadStatus::Missing
		|| store.hasChunk(
			context.conversationId,
			context.fileId,
			0)
		|| store.storeIfAbsent(
			context.conversationId,
			context.fileId,
			1,
			chunk) != FileChunkStoreResult::Stored
		|| !store.removeChunk(
			context.conversationId,
			context.fileId,
			0)) {
		return Fail("removed file chunk did not release cache quota");
	}
	return 0;
}

[[nodiscard]] int ScenarioChunkStoreRemovesAcceptedPrefix() {
	auto localKey = LocalRecordKey();
	localKey.fill(42);
	const auto protector = AesGcmLocalRecordProtector(std::move(localKey));
	auto directory = QTemporaryDir();
	if (!directory.isValid()) {
		return Fail("file chunk prefix temporary directory was unavailable");
	}
	const auto authorization = MakeAuthorization();
	const auto context = authorization.context;
	const auto chunk = StoredFileChunk{
		.plaintextHash = FilledId<Digest>(11),
		.exactCiphertext = QByteArray("ciphertext"),
	};
	auto otherFileId = context.fileId;
	otherFileId.bytes.back() ^= 1;
	auto store = FileChunkFileStore(directory.path(), protector);
	if (store.authorize(authorization) != FileChunkAuthorizeResult::Authorized
		|| store.storeIfAbsent(
			context.conversationId,
			context.fileId,
			0,
			chunk) != FileChunkStoreResult::Stored
		|| store.storeIfAbsent(
			context.conversationId,
			context.fileId,
			1,
			chunk) != FileChunkStoreResult::Stored
		|| store.storeIfAbsent(
			context.conversationId,
			otherFileId,
			0,
			chunk) != FileChunkStoreResult::Stored
		|| !store.removeChunksBefore(
			context.conversationId,
			context.fileId,
			1)
		|| store.hasChunk(
			context.conversationId,
			context.fileId,
			0)
		|| !store.hasChunk(
			context.conversationId,
			context.fileId,
			1)
		|| !store.hasChunk(
			context.conversationId,
			otherFileId,
			0)
		|| store.authorization(
			context.conversationId,
			context.fileId).status
			!= FileChunkAuthorizationReadStatus::Found) {
		return Fail("accepted file chunk prefix was not cleaned precisely");
	}
	return 0;
}

[[nodiscard]] int ScenarioSignedChunkEnvelope() {
	const auto sha256 = OpenSslSha256Provider();
	const auto codec = EnvelopeCodecV1();
	auto identity = GenerateAccountPrivateIdentity();
	const auto accountId = identity
		? DeriveAccountId(identity->credential, sha256)
		: std::nullopt;
	const auto context = MakeContext();
	const auto key = MakeKey();
	const auto ciphertext = AesGcmFileChunkCipher().encrypt(
		key,
		context,
		1,
		FilledBytes(13, 'z'));
	const auto clientId = FilledId<ClientId>(4);
	const auto prepared = (identity && accountId && ciphertext)
		? PrepareFileChunkEnvelope({
			.conversationId = context.conversationId,
			.senderAccountId = *accountId,
			.senderClientId = clientId,
			.telegramPeerIdBinding = 12345,
			.groupGeneration = 7,
			.fileId = context.fileId,
			.chunkIndex = 1,
			.chunkCount = context.chunkCount,
			.senderSigningPrivateKey = &identity->signingPrivateKey,
			.exactCiphertext = *ciphertext,
		}, codec, sha256)
		: std::nullopt;
	const auto decoded = prepared
		? codec.decode(prepared->encoded)
		: std::nullopt;
	const auto verified = (identity && decoded)
		? VerifyFileChunkEnvelope(*decoded, identity->credential, sha256)
		: std::nullopt;
	const auto metadata = decoded
		? DecodeFileChunkEnvelopeMetadata(*decoded)
		: std::nullopt;
	if (!prepared
		|| !decoded
		|| !verified
		|| !metadata
		|| metadata->fileId != context.fileId
		|| metadata->chunkIndex != 1
		|| verified->fileId != context.fileId
		|| verified->chunkIndex != 1
		|| verified->chunkCount != context.chunkCount) {
		return Fail("signed file chunk envelope did not round-trip");
	}
	auto tampered = *decoded;
	tampered.epochOrGeneration++;
	if (VerifyFileChunkEnvelope(tampered, identity->credential, sha256)) {
		return Fail("signed file chunk accepted changed group generation");
	}
	tampered = *decoded;
	tampered.payload[tampered.payload.size() - 1] ^= 1;
	if (VerifyFileChunkEnvelope(tampered, identity->credential, sha256)) {
		return Fail("signed file chunk accepted modified ciphertext");
	}
	tampered = *decoded;
	tampered.authenticationData[42] ^= 1;
	if (VerifyFileChunkEnvelope(tampered, identity->credential, sha256)) {
		return Fail("signed file chunk accepted modified chunk index");
	}
	return 0;
}

[[nodiscard]] int ScenarioProtectedMessageBody() {
	const auto codec = ProtectedMessageBodyCodecV1();
	const auto body = ProtectedMessageBody{
		.unixTime = 1'725'000'000,
		.textUtf8 = QByteArray("hello \xF0\x9F\x94\x92"),
	};
	const auto encoded = codec.encodePlaintext(body);
	const auto decoded = encoded
		? codec.decodePlaintext(*encoded)
		: std::nullopt;
	if (!encoded || !decoded || *decoded != body) {
		return Fail("protected message body did not round-trip");
	}
	auto invalidUtf8 = body;
	invalidUtf8.textUtf8 = QByteArray("\xC0\xAF", 2);
	auto nul = body;
	nul.textUtf8 = QByteArray("a\0b", 3);
	auto overflowingTime = body;
	overflowingTime.unixTime = std::numeric_limits<std::uint64_t>::max();
	auto trailing = *encoded;
	trailing.append('x');
	if (codec.encodePlaintext(invalidUtf8)
		|| codec.encodePlaintext(nul)
		|| codec.encodePlaintext(overflowingTime)
		|| codec.decodePlaintext(trailing)) {
		return Fail("protected message body accepted malformed text");
	}
	auto overflowingEncoded = *encoded;
	std::fill_n(overflowingEncoded.data() + 10, 8, char(0xFF));
	if (codec.decodePlaintext(overflowingEncoded)) {
		return Fail("protected message body decoded overflowing timestamp");
	}
	return 0;
}

} // namespace

int main(int, char *[]) {
	for (const auto scenario : {
		ScenarioMaterialGeneration,
		ScenarioChunkRoundTripAndResume,
		ScenarioChunkBindsContextAndTag,
		ScenarioChunkRejectsInvalidLayout,
		ScenarioEmptyFileLayout,
		ScenarioPrivateManifestRoundTrip,
		ScenarioPrivateManifestRejectsUnsafeName,
		ScenarioIdempotentChunkLedger,
		ScenarioChunkLedgerFailsClosed,
		ScenarioChunkStoreRejectsOversizedRecord,
		ScenarioChunkAuthorizationLedger,
		ScenarioChunkStoreEnforcesQuota,
		ScenarioChunkStoreLockContentionIsNonBlocking,
		ScenarioChunkStoreReleasesQuotaAfterRemoval,
		ScenarioChunkStoreRemovesAcceptedPrefix,
		ScenarioSignedChunkEnvelope,
		ScenarioProtectedMessageBody,
	}) {
		if (const auto result = scenario()) {
			return result;
		}
	}
	return 0;
}

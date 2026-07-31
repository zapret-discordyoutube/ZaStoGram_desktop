/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "e2e_cloud/files/file_chunk_crypto.h"
#include "e2e_cloud/files/idempotent_file_chunk_protector.h"
#include "e2e_cloud/files/private_file_manifest.h"

#include <algorithm>
#include <cstdio>

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
	return 0;
}

[[nodiscard]] PrivateFileManifest MakeManifest() {
	return {
		.context = MakeContext(),
		.key = MakeKey(),
		.plaintextHash = FilledId<Digest>(8),
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
	manifest.filenameUtf8 = QByteArray("safe.bin");
	manifest.mimeTypeUtf8 = QByteArray("text/plain\r\nInjected: yes");
	if (codec.encodePlaintext(manifest)) {
		return Fail("private file manifest accepted header injection metadata");
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
	int storeCalls = 0;
	bool readError = false;
	bool writeError = false;
};

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
		|| store.storeCalls != 1) {
		return Fail("file chunk ledger did not reuse exact ciphertext");
	}
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

} // namespace

int main(int, char *[]) {
	for (const auto scenario : {
		ScenarioMaterialGeneration,
		ScenarioChunkRoundTripAndResume,
		ScenarioChunkBindsContextAndTag,
		ScenarioChunkRejectsInvalidLayout,
		ScenarioPrivateManifestRoundTrip,
		ScenarioPrivateManifestRejectsUnsafeName,
		ScenarioIdempotentChunkLedger,
		ScenarioChunkLedgerFailsClosed,
	}) {
		if (const auto result = scenario()) {
			return result;
		}
	}
	return 0;
}

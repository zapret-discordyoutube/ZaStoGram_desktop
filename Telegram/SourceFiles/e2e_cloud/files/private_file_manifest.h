/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "e2e_cloud/files/file_chunk_crypto.h"

#include <QtCore/QByteArray>

#include <optional>

namespace E2ECloud {

struct PrivateFileManifest {
	FileChunkContext context;
	FileEncryptionKey key;
	Digest plaintextHash;
	std::uint64_t unixTime = 0;
	QByteArray filenameUtf8;
	QByteArray mimeTypeUtf8;
};

class PrivateFileManifestCodecV1 final {
public:
	[[nodiscard]] std::optional<QByteArray> encodePlaintext(
		const PrivateFileManifest &manifest) const;
	[[nodiscard]] std::optional<PrivateFileManifest> decodePlaintext(
		const QByteArray &bytes) const;
};

} // namespace E2ECloud

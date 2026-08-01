/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "e2e_cloud/storage/persistent_conversation_metadata.h"

#include <openssl/crypto.h>

#include <algorithm>
#include <array>

namespace E2ECloud {
namespace {

inline constexpr auto kMagic = std::array<std::uint8_t, 8>{
	'T', 'D', 'E', '2', 'E', 'L', 'M', 'T',
};
inline constexpr auto kEncodedSize = 8 + 2 + 8 + 32 + 8 + 32 + 16;

void AppendUint16(QByteArray &result, std::uint16_t value) {
	result.append(char(value >> 8));
	result.append(char(value));
}

void AppendUint64(QByteArray &result, std::uint64_t value) {
	for (auto shift = 56; shift >= 0; shift -= 8) {
		result.append(char(value >> shift));
	}
}

template <typename Array>
void AppendArray(QByteArray &result, const Array &value) {
	result.append(
		reinterpret_cast<const char*>(value.data()),
		int(value.size()));
}

[[nodiscard]] std::uint16_t ReadUint16(const char *data) {
	const auto bytes = reinterpret_cast<const std::uint8_t*>(data);
	return (std::uint16_t(bytes[0]) << 8) | std::uint16_t(bytes[1]);
}

[[nodiscard]] std::uint64_t ReadUint64(const char *data) {
	const auto bytes = reinterpret_cast<const std::uint8_t*>(data);
	auto result = std::uint64_t();
	for (auto i = 0; i != 8; ++i) {
		result = (result << 8) | bytes[i];
	}
	return result;
}

template <typename Array>
void ReadArray(const char *data, Array &value) {
	std::copy_n(
		reinterpret_cast<const std::uint8_t*>(data),
		value.size(),
		value.data());
}

[[nodiscard]] bool Valid(const ConversationLocalMetadata &metadata) {
	return metadata.conversationId
		&& metadata.telegramPeerIdBinding
		&& metadata.accountId
		&& metadata.clientId;
}

[[nodiscard]] QByteArray Purpose(ConversationId conversationId) {
	auto result = QByteArray("TDE2E/conversation-local-metadata/v1");
	result.append(char(0));
	AppendArray(result, conversationId.bytes);
	return result;
}

[[nodiscard]] QByteArray Encode(
		const ConversationLocalMetadata &metadata,
		std::uint64_t revision) {
	if (!Valid(metadata) || !revision) {
		return {};
	}
	auto result = QByteArray();
	result.reserve(kEncodedSize);
	AppendArray(result, kMagic);
	AppendUint16(result, 1);
	AppendUint64(result, revision);
	AppendArray(result, metadata.conversationId.bytes);
	AppendUint64(result, metadata.telegramPeerIdBinding);
	AppendArray(result, metadata.accountId.bytes);
	AppendArray(result, metadata.clientId.bytes);
	return result;
}

struct Decoded {
	ConversationLocalMetadata metadata;
	std::uint64_t revision = 0;
};

[[nodiscard]] std::optional<Decoded> Decode(const QByteArray &bytes) {
	if (bytes.size() != kEncodedSize) {
		return std::nullopt;
	}
	auto magic = std::array<std::uint8_t, 8>();
	auto result = Decoded();
	auto offset = 0;
	ReadArray(bytes.constData() + offset, magic);
	offset += int(magic.size());
	const auto version = ReadUint16(bytes.constData() + offset);
	offset += 2;
	result.revision = ReadUint64(bytes.constData() + offset);
	offset += 8;
	ReadArray(
		bytes.constData() + offset,
		result.metadata.conversationId.bytes);
	offset += int(result.metadata.conversationId.bytes.size());
	result.metadata.telegramPeerIdBinding = ReadUint64(
		bytes.constData() + offset);
	offset += 8;
	ReadArray(bytes.constData() + offset, result.metadata.accountId.bytes);
	offset += int(result.metadata.accountId.bytes.size());
	ReadArray(bytes.constData() + offset, result.metadata.clientId.bytes);
	return (magic == kMagic
		&& version == 1
		&& result.revision
		&& Valid(result.metadata))
		? std::optional<Decoded>(result)
		: std::nullopt;
}

void Cleanse(QByteArray &bytes) {
	if (!bytes.isEmpty()) {
		OPENSSL_cleanse(bytes.data(), bytes.size());
	}
	bytes.clear();
}

} // namespace

PersistentConversationMetadata::PersistentConversationMetadata(
		AtomicBlobStore &blobStore,
		const LocalRecordProtector &protector)
: _blobStore(blobStore)
, _protector(protector) {
}

ConversationMetadataLoadResult PersistentConversationMetadata::load(
		ConversationId expectedConversationId) {
	reset();
	if (!expectedConversationId) {
		return ConversationMetadataLoadResult::InvalidSnapshot;
	}
	_conversationId = expectedConversationId;
	const auto stored = _blobStore.read();
	if (stored.status == BlobReadStatus::Missing) {
		_loaded = true;
		return ConversationMetadataLoadResult::Missing;
	} else if (stored.status != BlobReadStatus::Found) {
		reset();
		return ConversationMetadataLoadResult::StorageError;
	}
	auto plaintext = _protector.open(Purpose(_conversationId), stored.bytes);
	if (!plaintext) {
		reset();
		return ConversationMetadataLoadResult::AuthenticationFailed;
	}
	const auto decoded = Decode(*plaintext);
	Cleanse(*plaintext);
	if (!decoded
		|| decoded->metadata.conversationId != expectedConversationId) {
		reset();
		return ConversationMetadataLoadResult::InvalidSnapshot;
	}
	_metadata = decoded->metadata;
	_revision = decoded->revision;
	_loaded = true;
	return ConversationMetadataLoadResult::Loaded;
}

ConversationMetadataCommitResult PersistentConversationMetadata::initialize(
		ConversationLocalMetadata metadata) {
	if (!_loaded) {
		return ConversationMetadataCommitResult::NotLoaded;
	} else if (!Valid(metadata)
		|| metadata.conversationId != _conversationId) {
		return ConversationMetadataCommitResult::InvalidMetadata;
	} else if (_metadata) {
		return (*_metadata == metadata)
			? ConversationMetadataCommitResult::AlreadyCommitted
			: ConversationMetadataCommitResult::Conflict;
	} else if (_revision) {
		return ConversationMetadataCommitResult::Conflict;
	} else if (!persist(metadata, 1)) {
		return ConversationMetadataCommitResult::PersistenceFailed;
	}
	_metadata = metadata;
	_revision = 1;
	return ConversationMetadataCommitResult::Committed;
}

bool PersistentConversationMetadata::loaded() const {
	return _loaded;
}

std::uint64_t PersistentConversationMetadata::revision() const {
	return _revision;
}

const ConversationLocalMetadata *PersistentConversationMetadata::metadata()
		const {
	return _metadata ? &*_metadata : nullptr;
}

bool PersistentConversationMetadata::persist(
		const ConversationLocalMetadata &metadata,
		std::uint64_t revision) const {
	auto plaintext = Encode(metadata, revision);
	if (plaintext.isEmpty()) {
		return false;
	}
	const auto protectedBytes = _protector.seal(
		Purpose(_conversationId),
		plaintext);
	Cleanse(plaintext);
	return protectedBytes && _blobStore.writeAtomic(*protectedBytes);
}

void PersistentConversationMetadata::reset() {
	_metadata.reset();
	_conversationId = {};
	_revision = 0;
	_loaded = false;
}

} // namespace E2ECloud

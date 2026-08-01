/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "e2e_cloud/storage/persistent_content_sync_state.h"

#include <openssl/crypto.h>

#include <algorithm>
#include <array>
#include <limits>

namespace E2ECloud {
namespace {

inline constexpr auto kMagic = std::array<std::uint8_t, 8>{
	'T', 'D', 'E', '2', 'E', 'C', 'S', 'Y',
};
inline constexpr auto kEncodedSize = 8 + 2 + 32 + 8 + 8;
inline constexpr auto kPurpose = "e2e-cloud-content-sync-state-v1";

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
	auto result = std::uint64_t();
	for (auto i = 0; i != 8; ++i) {
		result = (result << 8) | std::uint8_t(data[i]);
	}
	return result;
}

void Cleanse(QByteArray &bytes) {
	if (!bytes.isEmpty()) {
		OPENSSL_cleanse(bytes.data(), bytes.size());
	}
	bytes.clear();
}

} // namespace

PersistentContentSyncState::PersistentContentSyncState(
		AtomicBlobStore &blobStore,
		const LocalRecordProtector &protector)
: _blobStore(blobStore)
, _protector(protector) {
}

ContentSyncStateLoadResult PersistentContentSyncState::load(
		ConversationId conversationId) {
	if (!conversationId) {
		return ContentSyncStateLoadResult::InvalidSnapshot;
	}
	const auto stored = _blobStore.read();
	if (stored.status == BlobReadStatus::Missing) {
		_conversationId = conversationId;
		_newestObservedMessageId = 0;
		_revision = 0;
		_loaded = true;
		return ContentSyncStateLoadResult::Missing;
	} else if (stored.status != BlobReadStatus::Found) {
		return ContentSyncStateLoadResult::ReadFailed;
	}
	auto plaintext = _protector.open(QByteArray(kPurpose), stored.bytes);
	if (!plaintext) {
		return ContentSyncStateLoadResult::AuthenticationFailed;
	}
	if (plaintext->size() != kEncodedSize
		|| !std::equal(
			begin(kMagic),
			end(kMagic),
			reinterpret_cast<const std::uint8_t*>(plaintext->constData()))
		|| ReadUint16(plaintext->constData() + 8) != 1) {
		Cleanse(*plaintext);
		return ContentSyncStateLoadResult::InvalidSnapshot;
	}
	auto storedConversationId = ConversationId();
	std::copy_n(
		reinterpret_cast<const std::uint8_t*>(plaintext->constData() + 10),
		storedConversationId.bytes.size(),
		storedConversationId.bytes.begin());
	const auto revision = ReadUint64(plaintext->constData() + 42);
	const auto messageId = ReadUint64(plaintext->constData() + 50);
	Cleanse(*plaintext);
	if (storedConversationId != conversationId
		|| messageId
			> std::uint64_t(std::numeric_limits<std::int64_t>::max())
		|| (messageId && !revision)) {
		return ContentSyncStateLoadResult::InvalidSnapshot;
	}
	_conversationId = conversationId;
	_newestObservedMessageId = std::int64_t(messageId);
	_revision = revision;
	_loaded = true;
	return ContentSyncStateLoadResult::Loaded;
}

ContentSyncStateCommitResult PersistentContentSyncState::advance(
		std::int64_t newestObservedMessageId) {
	if (!_loaded
		|| newestObservedMessageId <= 0
		|| newestObservedMessageId < _newestObservedMessageId) {
		return ContentSyncStateCommitResult::InvalidBoundary;
	} else if (newestObservedMessageId == _newestObservedMessageId) {
		return ContentSyncStateCommitResult::AlreadyCommitted;
	} else if (_revision == std::numeric_limits<std::uint64_t>::max()) {
		return ContentSyncStateCommitResult::PersistenceFailed;
	}
	const auto revision = _revision + 1;
	if (!persist(newestObservedMessageId, revision)) {
		return ContentSyncStateCommitResult::PersistenceFailed;
	}
	_newestObservedMessageId = newestObservedMessageId;
	_revision = revision;
	return ContentSyncStateCommitResult::Committed;
}

std::int64_t PersistentContentSyncState::newestObservedMessageId() const {
	return _newestObservedMessageId;
}

std::uint64_t PersistentContentSyncState::revision() const {
	return _revision;
}

bool PersistentContentSyncState::loaded() const {
	return _loaded;
}

bool PersistentContentSyncState::persist(
		std::int64_t newestObservedMessageId,
		std::uint64_t revision) const {
	if (!_conversationId || newestObservedMessageId <= 0 || !revision) {
		return false;
	}
	auto plaintext = QByteArray();
	plaintext.reserve(kEncodedSize);
	AppendArray(plaintext, kMagic);
	AppendUint16(plaintext, 1);
	AppendArray(plaintext, _conversationId.bytes);
	AppendUint64(plaintext, revision);
	AppendUint64(plaintext, std::uint64_t(newestObservedMessageId));
	const auto protectedBytes = _protector.seal(
		QByteArray(kPurpose),
		plaintext);
	Cleanse(plaintext);
	return protectedBytes && _blobStore.writeAtomic(*protectedBytes);
}

} // namespace E2ECloud

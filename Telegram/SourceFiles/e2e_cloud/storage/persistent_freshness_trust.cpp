/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "e2e_cloud/storage/persistent_freshness_trust.h"

#include <openssl/crypto.h>

#include <algorithm>
#include <array>
#include <limits>

namespace E2ECloud {
namespace {

inline constexpr auto kMagic = std::array<std::uint8_t, 8>{
	'T', 'D', 'E', '2', 'E', 'F', 'T', 'R',
};
inline constexpr auto kEncodedSize = 8 + 2 + 8 + 32 + 1;

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

[[nodiscard]] QByteArray Purpose(ConversationId conversationId) {
	auto result = QByteArray("TDE2E/freshness-trust/v1");
	result.append(char(0));
	AppendArray(result, conversationId.bytes);
	return result;
}

void Cleanse(QByteArray &bytes) {
	if (!bytes.isEmpty()) {
		OPENSSL_cleanse(bytes.data(), bytes.size());
	}
	bytes.clear();
}

} // namespace

PersistentFreshnessTrust::PersistentFreshnessTrust(
		AtomicBlobStore &blobStore,
		const LocalRecordProtector &protector)
: _blobStore(blobStore)
, _protector(protector) {
}

FreshnessTrustLoadResult PersistentFreshnessTrust::load(
		ConversationId conversationId) {
	reset();
	if (!conversationId) {
		return FreshnessTrustLoadResult::InvalidSnapshot;
	}
	_conversationId = conversationId;
	const auto stored = _blobStore.read();
	if (stored.status == BlobReadStatus::Missing) {
		_loaded = true;
		return FreshnessTrustLoadResult::Missing;
	} else if (stored.status != BlobReadStatus::Found) {
		reset();
		return FreshnessTrustLoadResult::StorageError;
	}
	auto opened = _protector.open(Purpose(conversationId), stored.bytes);
	if (!opened) {
		reset();
		return FreshnessTrustLoadResult::AuthenticationFailed;
	}
	auto magic = std::array<std::uint8_t, 8>();
	if (opened->size() != kEncodedSize) {
		Cleanse(*opened);
		reset();
		return FreshnessTrustLoadResult::InvalidSnapshot;
	}
	auto offset = 0;
	ReadArray(opened->constData() + offset, magic);
	offset += int(magic.size());
	const auto version = ReadUint16(opened->constData() + offset);
	offset += 2;
	const auto revision = ReadUint64(opened->constData() + offset);
	offset += 8;
	auto storedConversationId = ConversationId();
	ReadArray(opened->constData() + offset, storedConversationId.bytes);
	offset += int(storedConversationId.bytes.size());
	const auto trusted = std::uint8_t((*opened)[offset]);
	Cleanse(*opened);
	if (magic != kMagic
		|| version != 1
		|| !revision
		|| storedConversationId != conversationId
		|| trusted > 1) {
		reset();
		return FreshnessTrustLoadResult::InvalidSnapshot;
	}
	_revision = revision;
	_trusted = trusted != 0;
	_loaded = true;
	return FreshnessTrustLoadResult::Loaded;
}

FreshnessTrustCommitResult PersistentFreshnessTrust::initialize(bool trusted) {
	if (!_loaded) {
		return FreshnessTrustCommitResult::NotLoaded;
	} else if (_revision) {
		return (_trusted == trusted)
			? FreshnessTrustCommitResult::AlreadyCommitted
			: FreshnessTrustCommitResult::InvalidMutation;
	} else if (!persist(trusted, 1)) {
		return FreshnessTrustCommitResult::PersistenceFailed;
	}
	_revision = 1;
	_trusted = trusted;
	return FreshnessTrustCommitResult::Committed;
}

FreshnessTrustCommitResult PersistentFreshnessTrust::confirm() {
	if (!_loaded || !_revision) {
		return FreshnessTrustCommitResult::NotLoaded;
	} else if (_trusted) {
		return FreshnessTrustCommitResult::AlreadyCommitted;
	} else if (_revision == std::numeric_limits<std::uint64_t>::max()) {
		return FreshnessTrustCommitResult::InvalidMutation;
	} else if (!persist(true, _revision + 1)) {
		return FreshnessTrustCommitResult::PersistenceFailed;
	}
	++_revision;
	_trusted = true;
	return FreshnessTrustCommitResult::Committed;
}

bool PersistentFreshnessTrust::loaded() const {
	return _loaded;
}

bool PersistentFreshnessTrust::trusted() const {
	return _loaded && _trusted;
}

std::uint64_t PersistentFreshnessTrust::revision() const {
	return _revision;
}

bool PersistentFreshnessTrust::persist(
		bool trusted,
		std::uint64_t revision) const {
	if (!_conversationId || !revision) {
		return false;
	}
	auto plaintext = QByteArray();
	plaintext.reserve(kEncodedSize);
	AppendArray(plaintext, kMagic);
	AppendUint16(plaintext, 1);
	AppendUint64(plaintext, revision);
	AppendArray(plaintext, _conversationId.bytes);
	plaintext.append(char(trusted ? 1 : 0));
	const auto sealed = _protector.seal(
		Purpose(_conversationId),
		plaintext);
	Cleanse(plaintext);
	return sealed && _blobStore.writeAtomic(*sealed);
}

void PersistentFreshnessTrust::reset() {
	_conversationId = {};
	_revision = 0;
	_trusted = false;
	_loaded = false;
}

} // namespace E2ECloud

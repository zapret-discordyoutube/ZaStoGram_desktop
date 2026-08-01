/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "e2e_cloud/vault/persistent_cloud_vault_anchor.h"

#include <algorithm>
#include <array>

namespace E2ECloud {
namespace {

inline constexpr auto kMagic = std::array<std::uint8_t, 8>{
	'T', 'D', 'E', '2', 'E', 'V', 'A', 'N',
};
inline constexpr auto kEncodedSize = 8 + 2 + 8 + 8 + 32 + 32;

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

[[nodiscard]] bool Valid(const CloudVaultAnchor &anchor) {
	return anchor.generation && anchor.blobDigest && anchor.accountId;
}

[[nodiscard]] QByteArray Encode(
		std::uint64_t telegramUserIdBinding,
		const CloudVaultAnchor &anchor) {
	if (!telegramUserIdBinding || !Valid(anchor)) {
		return {};
	}
	auto result = QByteArray();
	result.reserve(kEncodedSize);
	AppendArray(result, kMagic);
	AppendUint16(result, 1);
	AppendUint64(result, telegramUserIdBinding);
	AppendUint64(result, anchor.generation);
	AppendArray(result, anchor.blobDigest.bytes);
	AppendArray(result, anchor.accountId.bytes);
	return result;
}

struct Decoded {
	std::uint64_t telegramUserIdBinding = 0;
	CloudVaultAnchor anchor;
};

[[nodiscard]] std::optional<Decoded> Decode(const QByteArray &bytes) {
	if (bytes.size() != kEncodedSize) {
		return std::nullopt;
	}
	auto result = Decoded();
	auto magic = std::array<std::uint8_t, 8>();
	auto offset = 0;
	ReadArray(bytes.constData() + offset, magic);
	offset += int(magic.size());
	const auto version = ReadUint16(bytes.constData() + offset);
	offset += 2;
	result.telegramUserIdBinding = ReadUint64(bytes.constData() + offset);
	offset += 8;
	result.anchor.generation = ReadUint64(bytes.constData() + offset);
	offset += 8;
	ReadArray(bytes.constData() + offset, result.anchor.blobDigest.bytes);
	offset += int(result.anchor.blobDigest.bytes.size());
	ReadArray(bytes.constData() + offset, result.anchor.accountId.bytes);
	return (magic == kMagic && version == 1 && Valid(result.anchor))
		? std::optional<Decoded>(result)
		: std::nullopt;
}

} // namespace

PersistentCloudVaultAnchor::PersistentCloudVaultAnchor(
		AtomicBlobStore &blobStore,
		std::uint64_t telegramUserIdBinding)
: _blobStore(blobStore)
, _telegramUserIdBinding(telegramUserIdBinding) {
}

CloudVaultAnchorLoadResult PersistentCloudVaultAnchor::load() {
	_anchor.reset();
	_loaded = false;
	if (!_telegramUserIdBinding) {
		return CloudVaultAnchorLoadResult::InvalidSnapshot;
	}
	const auto stored = _blobStore.read();
	if (stored.status == BlobReadStatus::Missing) {
		_loaded = true;
		return CloudVaultAnchorLoadResult::Missing;
	} else if (stored.status != BlobReadStatus::Found) {
		return CloudVaultAnchorLoadResult::StorageError;
	}
	const auto decoded = Decode(stored.bytes);
	if (!decoded
		|| decoded->telegramUserIdBinding != _telegramUserIdBinding) {
		return CloudVaultAnchorLoadResult::InvalidSnapshot;
	}
	_anchor = decoded->anchor;
	_loaded = true;
	return CloudVaultAnchorLoadResult::Loaded;
}

CloudVaultAnchorCommitResult PersistentCloudVaultAnchor::commit(
		CloudVaultAnchor anchor) {
	if (!_loaded) {
		return CloudVaultAnchorCommitResult::NotLoaded;
	} else if (!Valid(anchor)) {
		return CloudVaultAnchorCommitResult::InvalidAnchor;
	} else if (_anchor) {
		if (anchor.generation < _anchor->generation
			|| anchor.accountId != _anchor->accountId
			|| (anchor.generation == _anchor->generation
				&& anchor.blobDigest != _anchor->blobDigest)) {
			return CloudVaultAnchorCommitResult::Conflict;
		} else if (anchor.generation == _anchor->generation) {
			return CloudVaultAnchorCommitResult::AlreadyCommitted;
		}
	}
	const auto encoded = Encode(_telegramUserIdBinding, anchor);
	if (encoded.isEmpty() || !_blobStore.writeAtomic(encoded)) {
		return CloudVaultAnchorCommitResult::PersistenceFailed;
	}
	_anchor = anchor;
	return CloudVaultAnchorCommitResult::Committed;
}

bool PersistentCloudVaultAnchor::loaded() const {
	return _loaded;
}

const std::optional<CloudVaultAnchor> &PersistentCloudVaultAnchor::anchor()
		const {
	return _anchor;
}

} // namespace E2ECloud

/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "e2e_cloud/storage/persistent_fork_recovery_ledger.h"

#include <openssl/crypto.h>

#include <algorithm>
#include <array>
#include <limits>
#include <set>
#include <utility>

namespace E2ECloud {
namespace {

inline constexpr auto kMagic = std::array<std::uint8_t, 8>{
	'T', 'D', 'E', '2', 'E', 'F', 'R', 'L',
};
inline constexpr auto kPurpose = "TDE2E/local-fork-recovery-ledger/v1";
inline constexpr auto kMaximumRecords = std::size_t(256);
inline constexpr auto kMaximumSnapshotSize = 4 * 1024 * 1024;

struct Reader {
	const QByteArray &bytes;
	int offset = 0;
};

void AppendUint16(QByteArray &result, std::uint16_t value) {
	result.append(char(value >> 8));
	result.append(char(value));
}

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

template <typename Array>
void AppendArray(QByteArray &result, const Array &value) {
	result.append(
		reinterpret_cast<const char*>(value.data()),
		int(value.size()));
}

[[nodiscard]] bool ReadUint16(Reader &reader, std::uint16_t &value) {
	if (reader.bytes.size() - reader.offset < 2) {
		return false;
	}
	const auto data = reinterpret_cast<const std::uint8_t*>(
		reader.bytes.constData() + reader.offset);
	value = (std::uint16_t(data[0]) << 8) | std::uint16_t(data[1]);
	reader.offset += 2;
	return true;
}

[[nodiscard]] bool ReadUint32(Reader &reader, std::uint32_t &value) {
	if (reader.bytes.size() - reader.offset < 4) {
		return false;
	}
	const auto data = reinterpret_cast<const std::uint8_t*>(
		reader.bytes.constData() + reader.offset);
	value = (std::uint32_t(data[0]) << 24)
		| (std::uint32_t(data[1]) << 16)
		| (std::uint32_t(data[2]) << 8)
		| std::uint32_t(data[3]);
	reader.offset += 4;
	return true;
}

[[nodiscard]] bool ReadUint64(Reader &reader, std::uint64_t &value) {
	if (reader.bytes.size() - reader.offset < 8) {
		return false;
	}
	const auto data = reinterpret_cast<const std::uint8_t*>(
		reader.bytes.constData() + reader.offset);
	value = 0;
	for (auto i = 0; i != 8; ++i) {
		value = (value << 8) | std::uint64_t(data[i]);
	}
	reader.offset += 8;
	return true;
}

template <typename Array>
[[nodiscard]] bool ReadArray(Reader &reader, Array &value) {
	const auto size = int(value.size());
	if (reader.bytes.size() - reader.offset < size) {
		return false;
	}
	std::copy_n(
		reinterpret_cast<const std::uint8_t*>(
			reader.bytes.constData() + reader.offset),
		size,
		value.data());
	reader.offset += size;
	return true;
}

void Cleanse(QByteArray &bytes) {
	if (!bytes.isEmpty()) {
		OPENSSL_cleanse(bytes.data(), bytes.size());
	}
	bytes.clear();
}

[[nodiscard]] QByteArray Purpose(ConversationId conversationId) {
	auto result = QByteArray(kPurpose);
	result.append('/');
	AppendArray(result, conversationId.bytes);
	return result;
}

[[nodiscard]] bool CandidateLess(
		const ForkRecoveryCandidate &a,
		const ForkRecoveryCandidate &b) {
	return (a.transitionId != b.transitionId)
		? a.transitionId < b.transitionId
		: a.transitionPayloadHash < b.transitionPayloadHash;
}

[[nodiscard]] bool ValidRecord(const ForkRecoveryRecord &record) {
	if (!record.commonGeneration
		|| !record.recoveryId
		|| !record.manifestHash
		|| !record.canonicalCandidate.transitionId
		|| !record.canonicalCandidate.transitionPayloadHash
		|| record.candidates.size() < 2
		|| record.candidates.size() > kMaximumForkRecoveryCandidates
		|| !std::is_sorted(
			begin(record.candidates),
			end(record.candidates),
			CandidateLess)
		|| std::adjacent_find(
			begin(record.candidates),
			end(record.candidates),
			[](const auto &a, const auto &b) {
				return a.transitionId == b.transitionId;
			}) != end(record.candidates)
		|| std::any_of(
			begin(record.candidates),
			end(record.candidates),
			[](const auto &candidate) {
				return !candidate.transitionId
					|| !candidate.transitionPayloadHash;
			})) {
		return false;
	}
	return std::find(
		begin(record.candidates),
		end(record.candidates),
		record.canonicalCandidate) != end(record.candidates);
}

} // namespace

PersistentForkRecoveryLedger::PersistentForkRecoveryLedger(
		AtomicBlobStore &blobStore,
		const LocalRecordProtector &protector,
		const Sha256Provider &sha256)
: _blobStore(blobStore)
, _protector(protector)
, _sha256(sha256) {
}

ForkRecoveryLedgerLoadResult PersistentForkRecoveryLedger::load(
		ConversationId conversationId) {
	_conversationId = {};
	_records.clear();
	_revision = 0;
	_loaded = false;
	if (!conversationId) {
		return ForkRecoveryLedgerLoadResult::InvalidSnapshot;
	}
	const auto stored = _blobStore.read();
	if (stored.status == BlobReadStatus::Error) {
		return ForkRecoveryLedgerLoadResult::StorageError;
	} else if (stored.status == BlobReadStatus::Missing) {
		_conversationId = conversationId;
		_loaded = true;
		return ForkRecoveryLedgerLoadResult::Missing;
	}
	auto opened = _protector.open(Purpose(conversationId), stored.bytes);
	if (!opened) {
		return ForkRecoveryLedgerLoadResult::AuthenticationFailed;
	}
	auto reader = Reader{ *opened };
	auto magic = std::array<std::uint8_t, 8>();
	auto version = std::uint16_t();
	auto storedConversationId = ConversationId();
	auto revision = std::uint64_t();
	auto count = std::uint32_t();
	if (!ReadArray(reader, magic)
		|| !ReadUint16(reader, version)
		|| !ReadArray(reader, storedConversationId.bytes)
		|| !ReadUint64(reader, revision)
		|| !ReadUint32(reader, count)
		|| magic != kMagic
		|| version != 1
		|| storedConversationId != conversationId
		|| !revision
		|| count > kMaximumRecords) {
		Cleanse(*opened);
		return ForkRecoveryLedgerLoadResult::InvalidSnapshot;
	}
	auto records = std::vector<ForkRecoveryRecord>();
	records.reserve(count);
	for (auto index = std::uint32_t(); index != count; ++index) {
		auto record = ForkRecoveryRecord();
		auto candidateCount = std::uint16_t();
		if (!ReadUint64(reader, record.commonGeneration)
			|| !ReadArray(reader, record.recoveryId.bytes)
			|| !ReadArray(reader, record.manifestHash.bytes)
			|| !ReadArray(
				reader,
				record.canonicalCandidate.transitionId.bytes)
			|| !ReadArray(
				reader,
				record.canonicalCandidate.transitionPayloadHash.bytes)
			|| !ReadUint16(reader, candidateCount)
			|| candidateCount < 2
			|| candidateCount > kMaximumForkRecoveryCandidates) {
			Cleanse(*opened);
			return ForkRecoveryLedgerLoadResult::InvalidSnapshot;
		}
		record.candidates.reserve(candidateCount);
		for (auto candidateIndex = std::uint16_t();
				candidateIndex != candidateCount;
				++candidateIndex) {
			auto candidate = ForkRecoveryCandidate();
			if (!ReadArray(reader, candidate.transitionId.bytes)
				|| !ReadArray(
					reader,
					candidate.transitionPayloadHash.bytes)) {
				Cleanse(*opened);
				return ForkRecoveryLedgerLoadResult::InvalidSnapshot;
			}
			record.candidates.push_back(candidate);
		}
		if (!ValidRecord(record)
			|| (!records.empty()
				&& records.back().commonGeneration
					>= record.commonGeneration)) {
			Cleanse(*opened);
			return ForkRecoveryLedgerLoadResult::InvalidSnapshot;
		}
		records.push_back(std::move(record));
	}
	const auto complete = reader.offset == reader.bytes.size();
	Cleanse(*opened);
	if (!complete) {
		return ForkRecoveryLedgerLoadResult::InvalidSnapshot;
	}
	_conversationId = conversationId;
	_records = std::move(records);
	_revision = revision;
	_loaded = true;
	return ForkRecoveryLedgerLoadResult::Loaded;
}

ForkRecoveryLedgerCommitResult
PersistentForkRecoveryLedger::commitVerified(
		const SignedForkRecoveryManifest &manifest) {
	if (!_loaded) {
		return ForkRecoveryLedgerCommitResult::NotLoaded;
	}
	const auto encoded = SignedForkRecoveryManifestCodecV1().encode(manifest);
	if (!encoded || manifest.conversationId != _conversationId) {
		return ForkRecoveryLedgerCommitResult::InvalidManifest;
	}
	const auto manifestHash = _sha256.digest(*encoded);
	const auto existing = record(manifest.commonGeneration);
	if (existing) {
		return existing->manifestHash == manifestHash
			? ForkRecoveryLedgerCommitResult::AlreadyCommitted
			: ForkRecoveryLedgerCommitResult::OwnerEquivocation;
	}
	if (_records.size() == kMaximumRecords
		|| _revision == std::numeric_limits<std::uint64_t>::max()) {
		return ForkRecoveryLedgerCommitResult::CapacityExceeded;
	}
	auto candidates = manifest.candidates;
	std::sort(begin(candidates), end(candidates), CandidateLess);
	auto records = _records;
	records.push_back({
		.commonGeneration = manifest.commonGeneration,
		.recoveryId = manifest.recoveryId,
		.manifestHash = manifestHash,
		.canonicalCandidate = {
			.transitionId = manifest.canonicalTransitionId,
			.transitionPayloadHash =
				manifest.canonicalTransitionPayloadHash,
		},
		.candidates = std::move(candidates),
	});
	std::sort(
		begin(records),
		end(records),
		[](const auto &a, const auto &b) {
			return a.commonGeneration < b.commonGeneration;
		});
	const auto revision = _revision + 1;
	if (!persist(records, revision)) {
		return ForkRecoveryLedgerCommitResult::PersistenceFailed;
	}
	_records = std::move(records);
	_revision = revision;
	return ForkRecoveryLedgerCommitResult::Committed;
}

ForkRecoveryCandidateObservation PersistentForkRecoveryLedger::observe(
		std::uint64_t commonGeneration,
		ForkRecoveryCandidate candidate) const {
	if (!_loaded || !commonGeneration || !candidate.transitionId
		|| !candidate.transitionPayloadHash) {
		return ForkRecoveryCandidateObservation::Unavailable;
	}
	const auto resolved = record(commonGeneration);
	if (!resolved) {
		return ForkRecoveryCandidateObservation::Unresolved;
	}
	const auto matchingId = std::find_if(
		begin(resolved->candidates),
		end(resolved->candidates),
		[&](const auto &known) {
			return known.transitionId == candidate.transitionId;
		});
	if (matchingId == end(resolved->candidates)) {
		return ForkRecoveryCandidateObservation::HiddenCandidate;
	}
	return matchingId->transitionPayloadHash == candidate.transitionPayloadHash
		? ForkRecoveryCandidateObservation::Known
		: ForkRecoveryCandidateObservation::ObjectIdConflict;
}

const ForkRecoveryRecord *PersistentForkRecoveryLedger::record(
		std::uint64_t commonGeneration) const {
	const auto i = std::lower_bound(
		begin(_records),
		end(_records),
		commonGeneration,
		[](const ForkRecoveryRecord &record, std::uint64_t generation) {
			return record.commonGeneration < generation;
		});
	return (i != end(_records) && i->commonGeneration == commonGeneration)
		? &*i
		: nullptr;
}

bool PersistentForkRecoveryLedger::loaded() const {
	return _loaded;
}

std::uint64_t PersistentForkRecoveryLedger::revision() const {
	return _revision;
}

const std::vector<ForkRecoveryRecord>
&PersistentForkRecoveryLedger::records() const {
	return _records;
}

bool PersistentForkRecoveryLedger::persist(
		const std::vector<ForkRecoveryRecord> &records,
		std::uint64_t revision) const {
	if (!_conversationId
		|| !revision
		|| records.size() > kMaximumRecords) {
		return false;
	}
	auto plaintext = QByteArray();
	AppendArray(plaintext, kMagic);
	AppendUint16(plaintext, 1);
	AppendArray(plaintext, _conversationId.bytes);
	AppendUint64(plaintext, revision);
	AppendUint32(plaintext, std::uint32_t(records.size()));
	auto previousGeneration = std::uint64_t();
	for (const auto &record : records) {
		if (!ValidRecord(record)
			|| record.commonGeneration <= previousGeneration) {
			Cleanse(plaintext);
			return false;
		}
		previousGeneration = record.commonGeneration;
		AppendUint64(plaintext, record.commonGeneration);
		AppendArray(plaintext, record.recoveryId.bytes);
		AppendArray(plaintext, record.manifestHash.bytes);
		AppendArray(
			plaintext,
			record.canonicalCandidate.transitionId.bytes);
		AppendArray(
			plaintext,
			record.canonicalCandidate.transitionPayloadHash.bytes);
		AppendUint16(
			plaintext,
			std::uint16_t(record.candidates.size()));
		for (const auto &candidate : record.candidates) {
			AppendArray(plaintext, candidate.transitionId.bytes);
			AppendArray(plaintext, candidate.transitionPayloadHash.bytes);
		}
	}
	if (plaintext.size() > kMaximumSnapshotSize) {
		Cleanse(plaintext);
		return false;
	}
	const auto protectedBytes = _protector.seal(
		Purpose(_conversationId),
		plaintext);
	Cleanse(plaintext);
	return protectedBytes && _blobStore.writeAtomic(*protectedBytes);
}

} // namespace E2ECloud

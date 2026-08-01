/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "e2e_cloud/identity/safety_gossip.h"

#include <algorithm>
#include <array>
#include <limits>
#include <set>
#include <utility>

namespace E2ECloud {
namespace {

inline constexpr auto kMagic = std::array<std::uint8_t, 8>{
	'T', 'D', 'E', '2', 'E', 'S', 'G', 'P',
};
inline constexpr auto kFixedBodySize = 8 + 2 + 32 + 32 + 8 + 32
	+ 32 + 16 + 4;
inline constexpr auto kEntrySize = 8 + 32 + 32;
inline constexpr auto kMaximumEncodedSize = kFixedBodySize
	+ kMaximumSafetyGossipEntries * kEntrySize + 64;

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

[[nodiscard]] bool EntryLess(
		const SafetyGossipEntry &a,
		const SafetyGossipEntry &b) {
	return std::tie(a.telegramUserIdBinding, a.accountId)
		< std::tie(b.telegramUserIdBinding, b.accountId);
}

[[nodiscard]] bool ValidEntries(
		const std::vector<SafetyGossipEntry> &entries) {
	if (entries.empty()
		|| entries.size() > kMaximumSafetyGossipEntries
		|| !std::is_sorted(entries.begin(), entries.end(), EntryLess)) {
		return false;
	}
	auto telegramUsers = std::set<std::uint64_t>();
	auto accounts = std::set<AccountId>();
	for (const auto &entry : entries) {
		if (!entry.telegramUserIdBinding
			|| !entry.accountId
			|| !entry.credentialHash
			|| !telegramUsers.emplace(
				entry.telegramUserIdBinding).second
			|| !accounts.emplace(entry.accountId).second) {
			return false;
		}
	}
	return true;
}

[[nodiscard]] bool ValidGossip(const SafetyGossip &gossip) {
	return gossip.conversationId
		&& gossip.gossipId
		&& gossip.checkpoint.conversationId == gossip.conversationId
		&& gossip.checkpoint.generation
		&& gossip.checkpoint.stateHash
		&& gossip.reporterAccountId
		&& gossip.reporterClientId
		&& ValidEntries(gossip.entries)
		&& std::any_of(
			std::begin(gossip.signature),
			std::end(gossip.signature),
			[](std::uint8_t byte) { return byte != 0; });
}

[[nodiscard]] QByteArray EncodeBody(const SafetyGossip &gossip) {
	auto result = QByteArray();
	result.reserve(kFixedBodySize + int(gossip.entries.size()) * kEntrySize);
	AppendArray(result, kMagic);
	AppendUint16(result, 1);
	AppendArray(result, gossip.conversationId.bytes);
	AppendArray(result, gossip.gossipId.bytes);
	AppendUint64(result, gossip.checkpoint.generation);
	AppendArray(result, gossip.checkpoint.stateHash.bytes);
	AppendArray(result, gossip.reporterAccountId.bytes);
	AppendArray(result, gossip.reporterClientId.bytes);
	AppendUint32(result, std::uint32_t(gossip.entries.size()));
	for (const auto &entry : gossip.entries) {
		AppendUint64(result, entry.telegramUserIdBinding);
		AppendArray(result, entry.accountId.bytes);
		AppendArray(result, entry.credentialHash.bytes);
	}
	return result;
}

[[nodiscard]] QByteArray SignatureBytes(
		const AccountSignature &signature) {
	return QByteArray(
		reinterpret_cast<const char*>(signature.data()),
		int(signature.size()));
}

[[nodiscard]] std::optional<std::vector<SafetyGossipEntry>> EntriesForState(
		const ProtectedGroupState &state,
		const PersistentGroupLedger &groupLedger,
		const Sha256Provider &sha256) {
	auto result = std::vector<SafetyGossipEntry>();
	result.reserve(state.members().size());
	for (const auto &member : state.members()) {
		const auto credential = groupLedger.credential(member.accountId);
		const auto encoded = credential
			? AccountCredentialCodecV1().encode(*credential)
			: std::nullopt;
		if (!encoded) {
			return std::nullopt;
		}
		result.push_back({
			.telegramUserIdBinding = member.telegramUserIdBinding,
			.accountId = member.accountId,
			.credentialHash = sha256.digest(*encoded),
		});
	}
	std::sort(result.begin(), result.end(), EntryLess);
	return ValidEntries(result)
		? std::optional<std::vector<SafetyGossipEntry>>(std::move(result))
		: std::nullopt;
}

[[nodiscard]] std::optional<Checkpoint> CheckpointAt(
		const PersistentGroupLedger &groupLedger,
		std::uint64_t generation,
		const Sha256Provider &sha256) {
	if (!generation || generation > groupLedger.events().size()) {
		return std::nullopt;
	}
	const auto &event = groupLedger.events()[generation - 1];
	if (event.generation != generation) {
		return std::nullopt;
	}
	const auto stateHash = event.kind == GroupLedgerEventKind::Genesis
		? sha256.digest(event.bytes)
		: [&]() {
			const auto transition = SignedGroupTransitionCodecV1().decode(
				event.bytes);
			return transition ? transition->resultingStateHash : Digest();
		}();
	return stateHash
		? std::optional<Checkpoint>(Checkpoint{
			.conversationId = groupLedger.state()->conversationId(),
			.generation = generation,
			.stateHash = stateHash,
		})
		: std::nullopt;
}

} // namespace

std::optional<QByteArray> SafetyGossipCodecV1::encode(
		const SafetyGossip &gossip) const {
	if (!ValidGossip(gossip)) {
		return std::nullopt;
	}
	auto result = EncodeBody(gossip);
	AppendArray(result, gossip.signature);
	return result.size() <= kMaximumEncodedSize
		? std::optional<QByteArray>(std::move(result))
		: std::nullopt;
}

std::optional<SafetyGossip> SafetyGossipCodecV1::decode(
		const QByteArray &bytes) const {
	if (bytes.size() < kFixedBodySize + kEntrySize + 64
		|| bytes.size() > kMaximumEncodedSize) {
		return std::nullopt;
	}
	auto reader = Reader{ bytes };
	auto magic = std::array<std::uint8_t, 8>();
	auto version = std::uint16_t();
	auto count = std::uint32_t();
	auto result = SafetyGossip();
	if (!ReadArray(reader, magic)
		|| !ReadUint16(reader, version)
		|| !ReadArray(reader, result.conversationId.bytes)
		|| !ReadArray(reader, result.gossipId.bytes)
		|| !ReadUint64(reader, result.checkpoint.generation)
		|| !ReadArray(reader, result.checkpoint.stateHash.bytes)
		|| !ReadArray(reader, result.reporterAccountId.bytes)
		|| !ReadArray(reader, result.reporterClientId.bytes)
		|| !ReadUint32(reader, count)
		|| magic != kMagic
		|| version != 1
		|| !count
		|| count > kMaximumSafetyGossipEntries
		|| reader.bytes.size() - reader.offset
			!= int(count) * kEntrySize + int(result.signature.size())) {
		return std::nullopt;
	}
	result.checkpoint.conversationId = result.conversationId;
	result.entries.reserve(count);
	for (auto index = std::uint32_t(); index != count; ++index) {
		auto entry = SafetyGossipEntry();
		if (!ReadUint64(reader, entry.telegramUserIdBinding)
			|| !ReadArray(reader, entry.accountId.bytes)
			|| !ReadArray(reader, entry.credentialHash.bytes)) {
			return std::nullopt;
		}
		result.entries.push_back(entry);
	}
	if (!ReadArray(reader, result.signature)
		|| reader.offset != bytes.size()
		|| !ValidGossip(result)) {
		return std::nullopt;
	}
	return result;
}

std::optional<SafetyGossip> CreateSafetyGossip(
		CreateSafetyGossipArgs args,
		const PersistentGroupLedger &groupLedger,
		const Sha256Provider &sha256) {
	if (!args.gossipId
		|| !args.reporterAccountId
		|| !args.reporterClientId
		|| !args.reporterSigningPrivateKey
		|| !args.reporterSigningPrivateKey->valid()
		|| !groupLedger.loaded()
		|| !groupLedger.state()
		|| !groupLedger.state()->memberByClient(args.reporterClientId)
		|| groupLedger.state()->memberByClient(args.reporterClientId)->accountId
			!= args.reporterAccountId) {
		return std::nullopt;
	}
	const auto entries = EntriesForState(
		*groupLedger.state(),
		groupLedger,
		sha256);
	if (!entries) {
		return std::nullopt;
	}
	auto result = SafetyGossip{
		.conversationId = groupLedger.state()->conversationId(),
		.gossipId = args.gossipId,
		.checkpoint = groupLedger.checkpoint(),
		.reporterAccountId = args.reporterAccountId,
		.reporterClientId = args.reporterClientId,
		.entries = *entries,
		.signature = {},
	};
	const auto signature = SignAccountData(
		*args.reporterSigningPrivateKey,
		AccountSignatureDomain::SafetyGossip,
		EncodeBody(result));
	if (!signature) {
		return std::nullopt;
	}
	result.signature = *signature;
	return result;
}

ObjectId DeriveSafetyGossipObjectId(
		Checkpoint checkpoint,
		AccountId reporterAccountId,
		ClientId reporterClientId,
		const Sha256Provider &sha256) {
	if (!checkpoint.conversationId
		|| !checkpoint.generation
		|| !checkpoint.stateHash
		|| !reporterAccountId
		|| !reporterClientId) {
		return {};
	}
	auto input = QByteArray("TDE2E/safety-gossip-id/v1");
	input.append(char(0));
	AppendArray(input, checkpoint.conversationId.bytes);
	AppendUint64(input, checkpoint.generation);
	AppendArray(input, checkpoint.stateHash.bytes);
	AppendArray(input, reporterAccountId.bytes);
	AppendArray(input, reporterClientId.bytes);
	const auto digest = sha256.digest(input);
	auto result = ObjectId();
	result.bytes = digest.bytes;
	return result;
}

std::optional<EncodedEnvelope> PrepareSafetyGossipEnvelope(
		PrepareSafetyGossipEnvelopeArgs args,
		const PersistentGroupLedger &groupLedger,
		const EnvelopeCodec &envelopeCodec,
		const Sha256Provider &sha256) {
	if (!args.gossipId || !args.telegramPeerIdBinding) {
		return std::nullopt;
	}
	const auto gossip = CreateSafetyGossip({
		.gossipId = args.gossipId,
		.reporterAccountId = args.reporterAccountId,
		.reporterClientId = args.reporterClientId,
		.reporterSigningPrivateKey = args.reporterSigningPrivateKey,
	}, groupLedger, sha256);
	const auto payload = gossip
		? SafetyGossipCodecV1().encode(*gossip)
		: std::nullopt;
	return payload ? envelopeCodec.encode({
		.conversationId = gossip->conversationId,
		.objectKind = ObjectKind::SafetyCodeGossip,
		.senderAccountId = gossip->reporterAccountId,
		.senderClientId = gossip->reporterClientId,
		.telegramPeerIdBinding = args.telegramPeerIdBinding,
		.epochOrGeneration = gossip->checkpoint.generation,
		.objectId = gossip->gossipId,
		.payloadHash = sha256.digest(*payload),
		.payload = *payload,
		.authenticationData = SignatureBytes(gossip->signature),
	}) : std::nullopt;
}

SafetyGossipVerifyResult VerifySafetyGossip(
		const SafetyGossip &gossip,
		const PersistentGroupLedger &groupLedger,
		const Sha256Provider &sha256) {
	if (!ValidGossip(gossip)
		|| !groupLedger.loaded()
		|| !groupLedger.state()) {
		return SafetyGossipVerifyResult::InvalidStructure;
	} else if (gossip.conversationId
			!= groupLedger.state()->conversationId()) {
		return SafetyGossipVerifyResult::WrongConversation;
	}
	const auto currentGeneration = groupLedger.state()->generation();
	const auto witnessGeneration = std::min(
		gossip.checkpoint.generation,
		currentGeneration);
	const auto credential = groupLedger.credential(gossip.reporterAccountId);
	if (!credential
		|| !groupLedger.wasClientActiveAt(
			gossip.reporterAccountId,
			gossip.reporterClientId,
			witnessGeneration)) {
		return SafetyGossipVerifyResult::InvalidReporter;
	} else if (!VerifyAccountSignature(
			*credential,
			AccountSignatureDomain::SafetyGossip,
			EncodeBody(gossip),
			gossip.signature)) {
		return SafetyGossipVerifyResult::InvalidSignature;
	} else if (gossip.checkpoint.generation > currentGeneration) {
		return SafetyGossipVerifyResult::FutureCheckpoint;
	}
	const auto checkpoint = CheckpointAt(
		groupLedger,
		gossip.checkpoint.generation,
		sha256);
	if (!checkpoint || *checkpoint != gossip.checkpoint) {
		return SafetyGossipVerifyResult::ForkDetected;
	}
	const auto state = groupLedger.stateAt(gossip.checkpoint.generation);
	const auto expected = state
		? EntriesForState(*state, groupLedger, sha256)
		: std::nullopt;
	return expected && *expected == gossip.entries
		? SafetyGossipVerifyResult::Verified
		: SafetyGossipVerifyResult::IdentityConflict;
}

VerifyObservedSafetyGossipOutcome VerifyObservedSafetyGossip(
		const TelegramTransport::UntrustedObject &object,
		ConversationId expectedConversationId,
		std::uint64_t expectedTelegramPeerIdBinding,
		const EnvelopeCodec &envelopeCodec,
		const PersistentGroupLedger &groupLedger,
		const Sha256Provider &sha256) {
	const auto failure = [](SafetyGossipVerifyResult result) {
		return VerifyObservedSafetyGossipOutcome{
			.result = result,
			.verified = std::nullopt,
		};
	};
	if (!expectedConversationId
		|| !expectedTelegramPeerIdBinding
		|| object.bytes.isEmpty()
		|| object.observedTelegramPeerIdBinding
			!= expectedTelegramPeerIdBinding
		|| !object.observedSenderTelegramUserIdBinding
		|| object.observedMessageId <= 0) {
		return failure(SafetyGossipVerifyResult::InvalidStructure);
	}
	auto envelope = envelopeCodec.decodeUntrusted(object.bytes);
	if (!envelope
		|| ValidateEnvelope(*envelope) != EnvelopeValidationError::None
		|| envelope->objectKind != ObjectKind::SafetyCodeGossip
		|| envelope->conversationId != expectedConversationId
		|| envelope->telegramPeerIdBinding
			!= expectedTelegramPeerIdBinding
		|| envelope->payloadHash != sha256.digest(envelope->payload)) {
		return failure(SafetyGossipVerifyResult::InvalidStructure);
	}
	auto gossip = SafetyGossipCodecV1().decode(envelope->payload);
	if (!gossip
		|| gossip->conversationId != envelope->conversationId
		|| gossip->gossipId != envelope->objectId
		|| gossip->checkpoint.generation != envelope->epochOrGeneration
		|| gossip->reporterAccountId != envelope->senderAccountId
		|| gossip->reporterClientId != envelope->senderClientId
		|| envelope->authenticationData
			!= SignatureBytes(gossip->signature)) {
		return failure(SafetyGossipVerifyResult::InvalidStructure);
	}
	const auto result = VerifySafetyGossip(*gossip, groupLedger, sha256);
	if (result == SafetyGossipVerifyResult::InvalidStructure
		|| result == SafetyGossipVerifyResult::WrongConversation
		|| result == SafetyGossipVerifyResult::InvalidReporter
		|| result == SafetyGossipVerifyResult::InvalidSignature) {
		return failure(result);
	}
	const auto witnessGeneration = std::min(
		gossip->checkpoint.generation,
		groupLedger.checkpoint().generation);
	const auto state = groupLedger.stateAt(witnessGeneration);
	const auto reporter = state
		? state->member(gossip->reporterAccountId)
		: nullptr;
	if (!reporter
		|| reporter->telegramUserIdBinding
			!= object.observedSenderTelegramUserIdBinding) {
		return failure(SafetyGossipVerifyResult::InvalidReporter);
	}
	return {
		.result = result,
		.verified = ObservedSafetyGossip{
			.envelope = std::move(*envelope),
			.gossip = std::move(*gossip),
			.telegramMessageId = object.observedMessageId,
		},
	};
}

} // namespace E2ECloud

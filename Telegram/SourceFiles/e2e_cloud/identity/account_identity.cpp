/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "e2e_cloud/identity/account_identity.h"

#include <algorithm>
#include <array>
#include <limits>

namespace E2ECloud {
namespace {

inline constexpr auto kAccountCredentialMagic = std::array<std::uint8_t, 8>{
	'T', 'D', 'E', '2', 'E', 'A', 'C', 'T',
};
inline constexpr auto kSafetyAlphabet =
	"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

template <typename Array>
[[nodiscard]] bool NonZero(const Array &value) {
	return std::any_of(begin(value), end(value), [](std::uint8_t byte) {
		return byte != 0;
	});
}

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

template <typename Array>
void ReadArray(const char *data, Array &value) {
	std::copy_n(
		reinterpret_cast<const std::uint8_t*>(data),
		value.size(),
		value.data());
}

[[nodiscard]] QByteArray DomainInput(const char *domain) {
	auto result = QByteArray(domain);
	result.append(char(0));
	return result;
}

} // namespace

std::optional<QByteArray> AccountCredentialCodecV1::encode(
		const AccountCredentialPublic &credential) const {
	if (credential.version != 1
		|| credential.mlsCipherSuite != kMlsCipherSuiteV1
		|| !NonZero(credential.signingPublicKey)
		|| !NonZero(credential.archiveHpkePublicKey)) {
		return std::nullopt;
	}
	auto result = QByteArray();
	result.reserve(kAccountCredentialEncodedSize);
	AppendArray(result, kAccountCredentialMagic);
	AppendUint16(result, credential.version);
	AppendUint16(result, credential.mlsCipherSuite);
	AppendArray(result, credential.signingPublicKey);
	AppendArray(result, credential.archiveHpkePublicKey);
	return result;
}

std::optional<AccountCredentialPublic> AccountCredentialCodecV1::decode(
		const QByteArray &bytes) const {
	if (bytes.size() != kAccountCredentialEncodedSize) {
		return std::nullopt;
	}
	auto magic = std::array<std::uint8_t, 8>();
	auto result = AccountCredentialPublic();
	ReadArray(bytes.constData(), magic);
	result.version = ReadUint16(bytes.constData() + 8);
	result.mlsCipherSuite = ReadUint16(bytes.constData() + 10);
	ReadArray(bytes.constData() + 12, result.signingPublicKey);
	ReadArray(bytes.constData() + 44, result.archiveHpkePublicKey);
	return (magic == kAccountCredentialMagic
		&& result.version == 1
		&& result.mlsCipherSuite == kMlsCipherSuiteV1
		&& NonZero(result.signingPublicKey)
		&& NonZero(result.archiveHpkePublicKey))
		? std::optional<AccountCredentialPublic>(result)
		: std::nullopt;
}

std::optional<AccountId> DeriveAccountId(
		const AccountCredentialPublic &credential,
		const Sha256Provider &sha256) {
	const auto encoded = AccountCredentialCodecV1().encode(credential);
	if (!encoded) {
		return std::nullopt;
	}
	auto input = DomainInput("TDE2E/account-id/v1");
	input.append(*encoded);
	const auto digest = sha256.digest(input);
	if (!digest) {
		return std::nullopt;
	}
	auto result = AccountId();
	result.bytes = digest.bytes;
	return result;
}

std::optional<Digest> DerivePairwiseSafetyDigest(
		AccountId first,
		AccountId second,
		const Sha256Provider &sha256) {
	if (!first || !second || first == second) {
		return std::nullopt;
	} else if (second < first) {
		std::swap(first, second);
	}
	auto input = DomainInput("TDE2E/pair-safety/v1");
	AppendArray(input, first.bytes);
	AppendArray(input, second.bytes);
	const auto result = sha256.digest(input);
	return result ? std::optional<Digest>(result) : std::nullopt;
}

std::optional<Digest> DeriveGroupSafetyDigest(
		ConversationId conversationId,
		AccountId ownerAccountId,
		std::vector<AccountId> memberAccountIds,
		const Sha256Provider &sha256) {
	if (!conversationId
		|| !ownerAccountId
		|| memberAccountIds.empty()
		|| memberAccountIds.size()
			> std::numeric_limits<std::uint32_t>::max()) {
		return std::nullopt;
	}
	std::sort(begin(memberAccountIds), end(memberAccountIds));
	if (std::find(
			begin(memberAccountIds),
			end(memberAccountIds),
			ownerAccountId) == end(memberAccountIds)
		|| std::any_of(
			begin(memberAccountIds),
			end(memberAccountIds),
			[](AccountId accountId) { return !accountId; })
		|| std::adjacent_find(
			begin(memberAccountIds),
			end(memberAccountIds)) != end(memberAccountIds)) {
		return std::nullopt;
	}
	auto input = DomainInput("TDE2E/group-safety/v1");
	AppendArray(input, conversationId.bytes);
	AppendArray(input, ownerAccountId.bytes);
	AppendUint32(input, std::uint32_t(memberAccountIds.size()));
	for (const auto accountId : memberAccountIds) {
		AppendArray(input, accountId.bytes);
	}
	const auto result = sha256.digest(input);
	return result ? std::optional<Digest>(result) : std::nullopt;
}

std::optional<QString> FormatSafetyCode(Digest digest) {
	if (!digest) {
		return std::nullopt;
	}
	auto result = QByteArray();
	result.reserve(59);
	auto buffer = std::uint32_t();
	auto bits = 0;
	auto characters = 0;
	for (auto i = 0; i != 30; ++i) {
		buffer = (buffer << 8) | digest.bytes[i];
		bits += 8;
		while (bits >= 5) {
			bits -= 5;
			if (characters && !(characters % 4)) {
				result.append(' ');
			}
			result.append(kSafetyAlphabet[(buffer >> bits) & 31]);
			++characters;
		}
	}
	return QString::fromLatin1(result);
}

} // namespace E2ECloud

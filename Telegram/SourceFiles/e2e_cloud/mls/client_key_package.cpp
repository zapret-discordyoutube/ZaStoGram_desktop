/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "e2e_cloud/mls/client_key_package.h"

#include <algorithm>
#include <array>
#include <limits>
#include <utility>

namespace E2ECloud {
namespace {

inline constexpr auto kMagic = std::array<std::uint8_t, 8>{
	'T', 'D', 'E', '2', 'E', 'K', 'P', 'B',
};
inline constexpr auto kFixedSize = 8 + 2
	+ kAccountCredentialEncodedSize
	+ kClientAuthorizationProofEncodedSize
	+ 4;

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

[[nodiscard]] QByteArray SignatureBytes(
		const AccountSignature &signature) {
	return QByteArray(
		reinterpret_cast<const char*>(signature.data()),
		int(signature.size()));
}

} // namespace

std::optional<QByteArray> ClientKeyPackagePublicationCodecV1::encode(
		const ClientKeyPackagePublication &publication) const {
	const auto credential = AccountCredentialCodecV1().encode(
		publication.accountCredential);
	const auto authorization = ClientAuthorizationProofCodecV1().encode(
		publication.authorization);
	if (!credential
		|| !authorization
		|| publication.keyPackage.isEmpty()
		|| publication.keyPackage.size() > kMaximumClientKeyPackageSize) {
		return std::nullopt;
	}
	auto result = QByteArray();
	result.reserve(kFixedSize + publication.keyPackage.size());
	AppendArray(result, kMagic);
	AppendUint16(result, 1);
	result.append(*credential);
	result.append(*authorization);
	AppendUint32(result, std::uint32_t(publication.keyPackage.size()));
	result.append(publication.keyPackage);
	return result;
}

std::optional<ClientKeyPackagePublication>
ClientKeyPackagePublicationCodecV1::decode(const QByteArray &bytes) const {
	if (bytes.size() <= kFixedSize
		|| bytes.size() > kFixedSize + kMaximumClientKeyPackageSize) {
		return std::nullopt;
	}
	auto reader = Reader{ bytes };
	auto magic = std::array<std::uint8_t, 8>();
	auto version = std::uint16_t();
	auto credentialBytes = QByteArray();
	auto authorizationBytes = QByteArray();
	auto keyPackageSize = std::uint32_t();
	if (!ReadArray(reader, magic)
		|| !ReadUint16(reader, version)
		|| magic != kMagic
		|| version != 1
		|| reader.bytes.size() - reader.offset
			< kAccountCredentialEncodedSize
				+ kClientAuthorizationProofEncodedSize + 4) {
		return std::nullopt;
	}
	credentialBytes = QByteArray(
		reader.bytes.constData() + reader.offset,
		kAccountCredentialEncodedSize);
	reader.offset += kAccountCredentialEncodedSize;
	authorizationBytes = QByteArray(
		reader.bytes.constData() + reader.offset,
		kClientAuthorizationProofEncodedSize);
	reader.offset += kClientAuthorizationProofEncodedSize;
	if (!ReadUint32(reader, keyPackageSize)
		|| !keyPackageSize
		|| keyPackageSize > kMaximumClientKeyPackageSize
		|| keyPackageSize
			> std::uint32_t(std::numeric_limits<int>::max())
		|| reader.bytes.size() - reader.offset != int(keyPackageSize)) {
		return std::nullopt;
	}
	const auto credential = AccountCredentialCodecV1().decode(
		credentialBytes);
	const auto authorization = ClientAuthorizationProofCodecV1().decode(
		authorizationBytes);
	if (!credential || !authorization) {
		return std::nullopt;
	}
	return ClientKeyPackagePublication{
		.accountCredential = *credential,
		.authorization = *authorization,
		.keyPackage = QByteArray(
			reader.bytes.constData() + reader.offset,
			int(keyPackageSize)),
	};
}

VerifyClientKeyPackageEnvelopeOutcome VerifyClientKeyPackageEnvelope(
		const TransportEnvelope &envelope,
		ConversationId expectedConversationId,
		std::uint64_t expectedTelegramPeerIdBinding,
		std::uint64_t expectedGeneration,
		const Sha256Provider &sha256) {
	const auto failure = [](ClientKeyPackageEnvelopeResult result) {
		return VerifyClientKeyPackageEnvelopeOutcome{
			.result = result,
			.publication = std::nullopt,
		};
	};
	if (ValidateEnvelope(envelope) != EnvelopeValidationError::None
		|| envelope.objectKind != ObjectKind::ClientKeyPackage
		|| envelope.payloadHash != sha256.digest(envelope.payload)) {
		return failure(ClientKeyPackageEnvelopeResult::InvalidEnvelope);
	} else if (!expectedConversationId
		|| envelope.conversationId != expectedConversationId) {
		return failure(ClientKeyPackageEnvelopeResult::WrongConversation);
	} else if (!expectedTelegramPeerIdBinding
		|| envelope.telegramPeerIdBinding
			!= expectedTelegramPeerIdBinding) {
		return failure(ClientKeyPackageEnvelopeResult::WrongCarrier);
	} else if (!expectedGeneration
		|| envelope.epochOrGeneration != expectedGeneration) {
		return failure(ClientKeyPackageEnvelopeResult::WrongGeneration);
	}
	auto publication = ClientKeyPackagePublicationCodecV1().decode(
		envelope.payload);
	if (!publication
		|| publication->authorization.authorizationId != envelope.objectId
		|| publication->authorization.accountId
			!= envelope.senderAccountId
		|| publication->authorization.clientId
			!= envelope.senderClientId
		|| publication->authorization.requestedAfterGeneration
			!= envelope.epochOrGeneration
		|| envelope.authenticationData
			!= SignatureBytes(publication->authorization.signature)) {
		return failure(ClientKeyPackageEnvelopeResult::InvalidPublication);
	}
	if (!VerifyClientAuthorizationProof(
		publication->authorization,
		envelope.conversationId,
		envelope.senderAccountId,
		envelope.senderClientId,
		envelope.epochOrGeneration,
		publication->accountCredential,
		publication->keyPackage,
		sha256)) {
		return failure(ClientKeyPackageEnvelopeResult::InvalidAuthorization);
	}
	return {
		.result = ClientKeyPackageEnvelopeResult::Verified,
		.publication = std::move(publication),
	};
}

} // namespace E2ECloud

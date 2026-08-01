/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "e2e_cloud/core/envelope.h"

#include <QtCore/QByteArray>

#include <cstdint>
#include <optional>

namespace E2ECloud {

inline constexpr auto kMlsClientCredentialEncodedSize = 90;
inline constexpr auto kMlsTransportAadFixedSize = 136;
inline constexpr auto kMlsTransportAadMaximumSize = 1024 * 1024;

struct MlsClientCredential {
	ConversationId conversationId;
	AccountId accountId;
	ClientId clientId;

	friend inline bool operator==(
		const MlsClientCredential &,
		const MlsClientCredential &) = default;
};

struct MlsTransportAad {
	ConversationId conversationId;
	ObjectKind objectKind = ObjectKind::MlsApplication;
	AccountId senderAccountId;
	ClientId senderClientId;
	std::uint64_t telegramPeerIdBinding = 0;
	ObjectId objectId;
	QByteArray context;

	friend inline bool operator==(
		const MlsTransportAad &,
		const MlsTransportAad &) = default;
};

class MlsContextCodecV1 final {
public:
	[[nodiscard]] std::optional<QByteArray> encodeCredential(
		const MlsClientCredential &credential) const;
	[[nodiscard]] std::optional<MlsClientCredential> decodeCredential(
		const QByteArray &bytes) const;
	[[nodiscard]] std::optional<QByteArray> encodeAad(
		const MlsTransportAad &aad) const;
	[[nodiscard]] std::optional<MlsTransportAad> decodeAad(
		const QByteArray &bytes) const;

};

} // namespace E2ECloud

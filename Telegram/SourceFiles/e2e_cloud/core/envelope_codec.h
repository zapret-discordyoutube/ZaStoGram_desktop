/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "e2e_cloud/core/interfaces.h"

namespace E2ECloud {

inline constexpr auto kMaxEnvelopePayloadSize = 16 * 1024 * 1024;
inline constexpr auto kMaxEnvelopeAuthenticationDataSize = 1024 * 1024;

class EnvelopeCodecV1 final : public EnvelopeCodec {
public:
	[[nodiscard]] std::optional<EncodedEnvelope> encode(
		const TransportEnvelope &envelope) const override;
	[[nodiscard]] std::optional<TransportEnvelope> decode(
		const EncodedEnvelope &envelope) const override;
	[[nodiscard]] std::optional<TransportEnvelope> decodeUntrusted(
		const QByteArray &bytes) const override;

};

} // namespace E2ECloud

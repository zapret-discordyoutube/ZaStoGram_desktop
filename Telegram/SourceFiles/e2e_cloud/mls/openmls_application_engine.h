/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "e2e_cloud/core/interfaces.h"
#include "e2e_cloud/mls/mls_context_codec.h"
#include "e2e_cloud/protocol/inbound_envelope_processor.h"
#include "e2e_cloud/storage/persistent_mls_state.h"

#include <QtCore/QByteArray>

#include <cstdint>

namespace E2ECloud {

class OpenMlsBridge;
class Sha256Provider;

struct OpenMlsClientContext {
	ConversationId conversationId;
	AccountId accountId;
	ClientId clientId;
	std::uint64_t telegramPeerIdBinding = 0;
};

enum class OpenMlsBootstrapStatus {
	Initialized,
	InvalidContext,
	StoreNotLoaded,
	StoreNotEmpty,
	BridgeIncompatible,
	BridgeFailure,
	PersistenceFailure,
};

struct OpenMlsBootstrapResult {
	OpenMlsBootstrapStatus status = OpenMlsBootstrapStatus::InvalidContext;
	QByteArray roster;
};

[[nodiscard]] QByteArray OpenMlsEngineId();
[[nodiscard]] OpenMlsBootstrapResult InitializeOpenMlsCreator(
	const OpenMlsClientContext &context,
	const OpenMlsBridge &bridge,
	const MlsContextCodecV1 &contextCodec,
	PersistentMlsStateStore &store);

class OpenMlsApplicationEngine final : public OutboundMessageProtector {
public:
	OpenMlsApplicationEngine(
		OpenMlsClientContext context,
		const OpenMlsBridge &bridge,
		const MlsContextCodecV1 &contextCodec,
		const EnvelopeCodec &envelopeCodec,
		const Sha256Provider &sha256,
		PersistentMlsStateStore &store);

	[[nodiscard]] bool ready() const;
	[[nodiscard]] std::optional<EncodedEnvelope> protectIdempotently(
		const MlsSealRequest &request) override;
	[[nodiscard]] bool acknowledgeUploaded(ObjectId objectId);

private:
	[[nodiscard]] bool validContext() const;
	[[nodiscard]] std::optional<Digest> requestHash(
		const MlsSealRequest &request,
		const QByteArray &encodedAad) const;

	OpenMlsClientContext _context;
	const OpenMlsBridge &_bridge;
	const MlsContextCodecV1 &_contextCodec;
	const EnvelopeCodec &_envelopeCodec;
	const Sha256Provider &_sha256;
	PersistentMlsStateStore &_store;

};

class OpenMlsEnvelopeAuthenticator final
	: public InboundEnvelopeAuthenticator {
public:
	OpenMlsEnvelopeAuthenticator(
		const MlsContextCodecV1 &contextCodec,
		const Sha256Provider &sha256);

	[[nodiscard]] bool authenticate(
		const TransportEnvelope &envelope) const override;

private:
	const MlsContextCodecV1 &_contextCodec;
	const Sha256Provider &_sha256;

};

class OpenMlsApplicationInboundApplier final
	: public InboundEnvelopeApplier {
public:
	OpenMlsApplicationInboundApplier(
		OpenMlsClientContext context,
		const OpenMlsBridge &bridge,
		const MlsContextCodecV1 &contextCodec,
		const Sha256Provider &sha256,
		PersistentMlsStateStore &store);

	[[nodiscard]] bool ready() const;
	[[nodiscard]] InboundApplyResult apply(
		const TransportEnvelope &envelope) override;
	[[nodiscard]] InboundRecoveryResult recover(
		const TransportEnvelope &envelope) const override;
	[[nodiscard]] const std::vector<MlsInboundApplication>
		&pendingApplications() const;
	[[nodiscard]] std::optional<MlsInboundApplication> application(
		ObjectId objectId) const;
	[[nodiscard]] bool acknowledgeDelivered(ObjectId objectId);

private:
	[[nodiscard]] bool validContext() const;

	OpenMlsClientContext _context;
	const OpenMlsBridge &_bridge;
	const MlsContextCodecV1 &_contextCodec;
	const Sha256Provider &_sha256;
	PersistentMlsStateStore &_store;

};

} // namespace E2ECloud

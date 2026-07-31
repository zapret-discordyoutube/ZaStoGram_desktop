/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "e2e_cloud/core/interfaces.h"

#include <QtCore/QByteArray>

#include <cstdint>

namespace E2ECloud {

enum class InboundJournalLookup {
	Missing,
	Pending,
	Accepted,
	ObjectIdConflict,
	StorageError,
};

class InboundEnvelopeJournal {
public:
	virtual ~InboundEnvelopeJournal() = default;

	[[nodiscard]] virtual InboundJournalLookup lookup(
		ConversationId conversationId,
		ObjectId objectId,
		Digest payloadHash) const = 0;
	virtual bool begin(const TransportEnvelope &envelope) = 0;
	virtual bool accept(
		ConversationId conversationId,
		ObjectId objectId) = 0;
	virtual bool abort(
		ConversationId conversationId,
		ObjectId objectId) = 0;

};

class InboundEnvelopeAuthenticator {
public:
	virtual ~InboundEnvelopeAuthenticator() = default;

	[[nodiscard]] virtual bool authenticate(
		const TransportEnvelope &envelope) const = 0;

};

enum class InboundApplyResult {
	Applied,
	Deferred,
	Rejected,
	ForkDetected,
};

class InboundEnvelopeApplier {
public:
	virtual ~InboundEnvelopeApplier() = default;

	[[nodiscard]] virtual InboundApplyResult apply(
		const TransportEnvelope &envelope) = 0;

};

enum class InboundProcessResult {
	Accepted,
	Duplicate,
	InvalidEncoding,
	WrongConversation,
	WrongCarrier,
	AuthenticationFailed,
	ObjectIdConflict,
	RecoveryRequired,
	Deferred,
	Rejected,
	ForkDetected,
	JournalFailure,
};

class InboundEnvelopeProcessor final {
public:
	InboundEnvelopeProcessor(
		ConversationId conversationId,
		std::uint64_t telegramPeerId,
		const EnvelopeCodec &codec,
		const InboundEnvelopeAuthenticator &authenticator,
		InboundEnvelopeJournal &journal,
		InboundEnvelopeApplier &applier);

	[[nodiscard]] InboundProcessResult process(const QByteArray &bytes);

private:
	ConversationId _conversationId;
	std::uint64_t _telegramPeerId = 0;
	const EnvelopeCodec &_codec;
	const InboundEnvelopeAuthenticator &_authenticator;
	InboundEnvelopeJournal &_journal;
	InboundEnvelopeApplier &_applier;

};

} // namespace E2ECloud

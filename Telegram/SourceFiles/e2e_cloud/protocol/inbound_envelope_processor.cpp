/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "e2e_cloud/protocol/inbound_envelope_processor.h"

namespace E2ECloud {

InboundEnvelopeProcessor::InboundEnvelopeProcessor(
		ConversationId conversationId,
		std::uint64_t telegramPeerId,
		const EnvelopeCodec &codec,
		const InboundEnvelopeAuthenticator &authenticator,
		InboundEnvelopeJournal &journal,
		InboundEnvelopeApplier &applier)
: _conversationId(conversationId)
, _telegramPeerId(telegramPeerId)
, _codec(codec)
, _authenticator(authenticator)
, _journal(journal)
, _applier(applier) {
}

InboundProcessResult InboundEnvelopeProcessor::process(
		const QByteArray &bytes) {
	const auto envelope = _codec.decodeUntrusted(bytes);
	if (!envelope) {
		return InboundProcessResult::InvalidEncoding;
	} else if (envelope->conversationId != _conversationId) {
		return InboundProcessResult::WrongConversation;
	} else if (envelope->telegramPeerIdBinding != _telegramPeerId) {
		return InboundProcessResult::WrongCarrier;
	} else if (!_authenticator.authenticate(*envelope)) {
		return InboundProcessResult::AuthenticationFailed;
	}
	const auto lookup = _journal.lookup(
		envelope->conversationId,
		envelope->objectId,
		envelope->payloadHash);
	switch (lookup) {
	case InboundJournalLookup::Accepted:
		return InboundProcessResult::Duplicate;
	case InboundJournalLookup::Pending:
		return InboundProcessResult::RecoveryRequired;
	case InboundJournalLookup::ObjectIdConflict:
		return InboundProcessResult::ObjectIdConflict;
	case InboundJournalLookup::StorageError:
		return InboundProcessResult::JournalFailure;
	case InboundJournalLookup::Missing:
		break;
	}
	if (!_journal.begin(*envelope)) {
		return InboundProcessResult::JournalFailure;
	}
	const auto applied = _applier.apply(*envelope);
	switch (applied) {
	case InboundApplyResult::Applied:
		return _journal.accept(
			envelope->conversationId,
			envelope->objectId)
			? InboundProcessResult::Accepted
			: InboundProcessResult::RecoveryRequired;
	case InboundApplyResult::Deferred:
		return _journal.abort(
			envelope->conversationId,
			envelope->objectId)
			? InboundProcessResult::Deferred
			: InboundProcessResult::JournalFailure;
	case InboundApplyResult::Rejected:
		return _journal.abort(
			envelope->conversationId,
			envelope->objectId)
			? InboundProcessResult::Rejected
			: InboundProcessResult::JournalFailure;
	case InboundApplyResult::ForkDetected:
		return _journal.abort(
			envelope->conversationId,
			envelope->objectId)
			? InboundProcessResult::ForkDetected
			: InboundProcessResult::JournalFailure;
	}
	return InboundProcessResult::Rejected;
}

} // namespace E2ECloud

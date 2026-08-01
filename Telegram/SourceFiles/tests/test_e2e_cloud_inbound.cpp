/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "e2e_cloud/core/envelope_codec.h"
#include "e2e_cloud/protocol/inbound_envelope_processor.h"

#include <cstdio>
#include <optional>

namespace {

using namespace E2ECloud;

template <typename Id>
[[nodiscard]] Id FilledId(std::uint8_t value) {
	auto result = Id();
	result.bytes.fill(value);
	return result;
}

[[nodiscard]] int Fail(const char *message) {
	std::fprintf(stderr, "%s\n", message);
	return 1;
}

[[nodiscard]] TransportEnvelope MakeEnvelope() {
	return {
		.conversationId = FilledId<ConversationId>(1),
		.objectKind = ObjectKind::MlsApplication,
		.senderAccountId = FilledId<AccountId>(2),
		.senderClientId = FilledId<ClientId>(3),
		.telegramPeerIdBinding = 42,
		.epochOrGeneration = 7,
		.objectId = FilledId<ObjectId>(4),
		.payloadHash = FilledId<Digest>(5),
		.payload = QByteArray("payload"),
		.authenticationData = QByteArray("authentication"),
	};
}

class TestAuthenticator final : public InboundEnvelopeAuthenticator {
public:
	[[nodiscard]] bool authenticate(
			const TransportEnvelope &) const override {
		++calls;
		return accept;
	}

	mutable int calls = 0;
	bool accept = true;

};

class TestJournal final : public InboundEnvelopeJournal {
public:
	[[nodiscard]] InboundJournalLookup lookup(
			ConversationId conversationId,
			ObjectId objectId,
			Digest payloadHash) const override {
		++lookupCalls;
		if (storageError) {
			return InboundJournalLookup::StorageError;
		} else if (!entry) {
			return InboundJournalLookup::Missing;
		} else if (entry->conversationId != conversationId
			|| entry->objectId != objectId) {
			return InboundJournalLookup::Missing;
		} else if (entry->payloadHash != payloadHash) {
			return InboundJournalLookup::ObjectIdConflict;
		}
		return entry->accepted
			? InboundJournalLookup::Accepted
			: InboundJournalLookup::Pending;
	}

	bool begin(const TransportEnvelope &envelope) override {
		++beginCalls;
		if (failBegin) {
			return false;
		}
		entry = Entry{
			.conversationId = envelope.conversationId,
			.objectId = envelope.objectId,
			.payloadHash = envelope.payloadHash,
			.accepted = false,
		};
		return true;
	}

	bool accept(
			ConversationId conversationId,
			ObjectId objectId) override {
		++acceptCalls;
		if (failAccept
			|| !entry
			|| entry->conversationId != conversationId
			|| entry->objectId != objectId) {
			return false;
		}
		entry->accepted = true;
		return true;
	}

	bool abort(
			ConversationId conversationId,
			ObjectId objectId) override {
		++abortCalls;
		if (failAbort
			|| !entry
			|| entry->conversationId != conversationId
			|| entry->objectId != objectId) {
			return false;
		}
		entry.reset();
		return true;
	}

	struct Entry {
		ConversationId conversationId;
		ObjectId objectId;
		Digest payloadHash;
		bool accepted = false;
	};

	std::optional<Entry> entry;
	mutable int lookupCalls = 0;
	int beginCalls = 0;
	int acceptCalls = 0;
	int abortCalls = 0;
	bool storageError = false;
	bool failBegin = false;
	bool failAccept = false;
	bool failAbort = false;

};

class TestApplier final : public InboundEnvelopeApplier {
public:
	[[nodiscard]] InboundApplyResult apply(
			const TransportEnvelope &envelope) override {
		++calls;
		lastEnvelope = envelope;
		return result;
	}

	[[nodiscard]] InboundRecoveryResult recover(
			const TransportEnvelope &) const override {
		++recoverCalls;
		return recovery;
	}

	InboundApplyResult result = InboundApplyResult::Applied;
	InboundRecoveryResult recovery = InboundRecoveryResult::Unknown;
	int calls = 0;
	mutable int recoverCalls = 0;
	std::optional<TransportEnvelope> lastEnvelope;

};

struct Fixture {
	Fixture()
	: encoded(*codec.encode(envelope))
	, processor(
		envelope.conversationId,
		envelope.telegramPeerIdBinding,
		codec,
		authenticator,
		journal,
		applier) {
	}

	EnvelopeCodecV1 codec;
	TransportEnvelope envelope = MakeEnvelope();
	EncodedEnvelope encoded;
	TestAuthenticator authenticator;
	TestJournal journal;
	TestApplier applier;
	InboundEnvelopeProcessor processor;
};

[[nodiscard]] int ScenarioAcceptedThenDeduplicated() {
	auto fixture = Fixture();
	if (fixture.processor.process(fixture.encoded.bytes)
			!= InboundProcessResult::Accepted
		|| fixture.applier.calls != 1
		|| !fixture.journal.entry
		|| !fixture.journal.entry->accepted
		|| fixture.processor.process(fixture.encoded.bytes)
			!= InboundProcessResult::Duplicate
		|| fixture.applier.calls != 1
		|| fixture.authenticator.calls != 2) {
		return Fail("authenticated inbound object was not deduplicated");
	}
	return 0;
}

[[nodiscard]] int ScenarioRejectsBeforeJournalMutation() {
	auto fixture = Fixture();
	fixture.authenticator.accept = false;
	if (fixture.processor.process(fixture.encoded.bytes)
			!= InboundProcessResult::AuthenticationFailed
		|| fixture.journal.lookupCalls
		|| fixture.journal.beginCalls
		|| fixture.applier.calls) {
		return Fail("unauthenticated inbound object reached the journal");
	}
	auto wrongCarrier = fixture.envelope;
	wrongCarrier.telegramPeerIdBinding = 99;
	const auto encoded = fixture.codec.encode(wrongCarrier);
	if (!encoded
		|| fixture.processor.process(encoded->bytes)
			!= InboundProcessResult::WrongCarrier
		|| fixture.authenticator.calls != 1) {
		return Fail("wrong carrier binding reached authentication");
	}
	return 0;
}

[[nodiscard]] int ScenarioDetectsAuthenticatedObjectIdConflict() {
	auto fixture = Fixture();
	fixture.journal.entry = TestJournal::Entry{
		.conversationId = fixture.envelope.conversationId,
		.objectId = fixture.envelope.objectId,
		.payloadHash = FilledId<Digest>(9),
		.accepted = true,
	};
	if (fixture.processor.process(fixture.encoded.bytes)
			!= InboundProcessResult::ObjectIdConflict
		|| fixture.authenticator.calls != 1
		|| fixture.applier.calls) {
		return Fail("authenticated object identifier conflict was accepted");
	}
	return 0;
}

[[nodiscard]] int ScenarioPendingRequiresRecovery() {
	auto fixture = Fixture();
	fixture.journal.entry = TestJournal::Entry{
		.conversationId = fixture.envelope.conversationId,
		.objectId = fixture.envelope.objectId,
		.payloadHash = fixture.envelope.payloadHash,
		.accepted = false,
	};
	if (fixture.processor.process(fixture.encoded.bytes)
			!= InboundProcessResult::RecoveryRequired
		|| fixture.applier.calls
		|| fixture.applier.recoverCalls != 1) {
		return Fail("uncertain post-crash apply state was replayed blindly");
	}
	return 0;
}

[[nodiscard]] int ScenarioPendingNotAppliedRetriesSafely() {
	auto fixture = Fixture();
	fixture.journal.entry = TestJournal::Entry{
		.conversationId = fixture.envelope.conversationId,
		.objectId = fixture.envelope.objectId,
		.payloadHash = fixture.envelope.payloadHash,
		.accepted = false,
	};
	fixture.applier.recovery = InboundRecoveryResult::NotApplied;
	if (fixture.processor.process(fixture.encoded.bytes)
			!= InboundProcessResult::Accepted
		|| fixture.applier.recoverCalls != 1
		|| fixture.applier.calls != 1
		|| fixture.journal.abortCalls != 1
		|| fixture.journal.beginCalls != 1
		|| fixture.journal.acceptCalls != 1
		|| !fixture.journal.entry
		|| !fixture.journal.entry->accepted) {
		return Fail("known pre-apply crash did not retry the inbound object");
	}
	return 0;
}

[[nodiscard]] int ScenarioPendingAppliedCompletesJournal() {
	auto fixture = Fixture();
	fixture.journal.entry = TestJournal::Entry{
		.conversationId = fixture.envelope.conversationId,
		.objectId = fixture.envelope.objectId,
		.payloadHash = fixture.envelope.payloadHash,
		.accepted = false,
	};
	fixture.applier.recovery = InboundRecoveryResult::Applied;
	if (fixture.processor.process(fixture.encoded.bytes)
			!= InboundProcessResult::Accepted
		|| fixture.applier.recoverCalls != 1
		|| fixture.applier.calls
		|| fixture.journal.acceptCalls != 1
		|| !fixture.journal.entry
		|| !fixture.journal.entry->accepted) {
		return Fail("known post-apply crash replayed the inbound object");
	}
	return 0;
}

[[nodiscard]] int ScenarioDeferredApplyCanRetry() {
	auto fixture = Fixture();
	fixture.applier.result = InboundApplyResult::Deferred;
	if (fixture.processor.process(fixture.encoded.bytes)
			!= InboundProcessResult::Deferred
		|| fixture.journal.entry
		|| fixture.journal.abortCalls != 1) {
		return Fail("deferred inbound object remained permanently pending");
	}
	fixture.applier.result = InboundApplyResult::Applied;
	if (fixture.processor.process(fixture.encoded.bytes)
			!= InboundProcessResult::Accepted) {
		return Fail("deferred inbound object could not be retried");
	}
	return 0;
}

[[nodiscard]] int ScenarioCommitFailureFailsClosed() {
	auto fixture = Fixture();
	fixture.journal.failAccept = true;
	if (fixture.processor.process(fixture.encoded.bytes)
			!= InboundProcessResult::RecoveryRequired
		|| !fixture.journal.entry
		|| fixture.journal.entry->accepted
		|| fixture.applier.calls != 1) {
		return Fail("journal commit failure lost uncertain apply state");
	}
	return 0;
}

} // namespace

int main(int, char *[]) {
	for (const auto scenario : {
		ScenarioAcceptedThenDeduplicated,
		ScenarioRejectsBeforeJournalMutation,
		ScenarioDetectsAuthenticatedObjectIdConflict,
		ScenarioPendingRequiresRecovery,
		ScenarioPendingNotAppliedRetriesSafely,
		ScenarioPendingAppliedCompletesJournal,
		ScenarioDeferredApplyCanRetry,
		ScenarioCommitFailureFailsClosed,
	}) {
		if (const auto result = scenario()) {
			return result;
		}
	}
	return 0;
}

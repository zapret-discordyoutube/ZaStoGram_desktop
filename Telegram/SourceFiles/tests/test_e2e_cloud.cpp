/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "e2e_cloud/core/envelope.h"
#include "e2e_cloud/core/envelope_codec.h"
#include "e2e_cloud/core/freshness_gate.h"
#include "e2e_cloud/core/outbox.h"
#include "e2e_cloud/group/group_state.h"
#include "e2e_cloud/transport/cloud_vault_transport.h"
#include "e2e_cloud/transport/outbox_upload_controller.h"
#include "e2e_cloud/transport/telegram_carrier_transport.h"

#include <algorithm>
#include <cstdio>
#include <optional>
#include <utility>
#include <vector>

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

[[nodiscard]] Checkpoint MakeCheckpoint(
		ConversationId conversationId,
		std::uint64_t generation,
		std::uint8_t hashValue) {
	return {
		.conversationId = conversationId,
		.generation = generation,
		.stateHash = FilledId<Digest>(hashValue),
	};
}

[[nodiscard]] FreshnessResponse MakeResponse(
		const Checkpoint &checkpoint,
		ChallengeNonce nonce,
		Checkpoint challengedCheckpoint = {}) {
	return {
		.conversationId = checkpoint.conversationId,
		.nonce = nonce,
		.challengedCheckpoint = challengedCheckpoint.conversationId
			? challengedCheckpoint
			: checkpoint,
		.checkpoint = checkpoint,
		.witnessAccountId = FilledId<AccountId>(4),
		.witnessClientId = FilledId<ClientId>(5),
		.authenticatedProof = QByteArray("proof"),
	};
}

class TestVerifier final : public FreshnessResponseVerifier {
public:
	[[nodiscard]] bool verify(
			const FreshnessResponse &response) const override {
		++calls;
		return accept && !response.authenticatedProof.isEmpty();
	}

	bool accept = true;
	mutable int calls = 0;

};

class TestOutboxStore final : public ProtectedOutboxStore {
public:
	bool append(PendingMessage message) override {
		if (failAppend) {
			return false;
		}
		for (const auto &item : items) {
			if (item.draft.objectId == message.objectId) {
				return false;
			}
		}
		items.push_back({
			.draft = std::move(message),
			.stage = OutboxItemStage::Draft,
			.sealed = std::nullopt,
		});
		return true;
	}

	bool appendSealed(EncodedEnvelope envelope) override {
		for (const auto &item : items) {
			if (item.draft.objectId == envelope.objectId) {
				return item.stage == OutboxItemStage::Sealed
					&& item.sealed == envelope;
			}
		}
		items.push_back({
			.draft = {
				.conversationId = envelope.conversationId,
				.objectId = envelope.objectId,
				.plaintext = {},
				.authenticatedData = {},
			},
			.stage = OutboxItemStage::Sealed,
			.sealed = std::move(envelope),
		});
		return true;
	}

	bool appendSealedThenDraft(
			EncodedEnvelope envelope,
			PendingMessage message) override {
		if (!appendSealed(std::move(envelope))) {
			return false;
		}
		return append(std::move(message));
	}

	[[nodiscard]] std::optional<OutboxItem> front(
			ConversationId conversationId) const override {
		for (const auto &item : items) {
			if (item.draft.conversationId == conversationId) {
				return item;
			}
		}
		return std::nullopt;
	}

	bool replaceWithSealed(
			ObjectId objectId,
			EncodedEnvelope envelope) override {
		if (failReplace) {
			return false;
		}
		for (auto &item : items) {
			if (item.draft.objectId == objectId) {
				item.stage = OutboxItemStage::Sealed;
				item.sealed = std::move(envelope);
				item.draft.plaintext.clear();
				item.draft.authenticatedData.clear();
				return true;
			}
		}
		return false;
	}

	bool remove(ObjectId objectId) override {
		if (failRemove) {
			return false;
		}
		for (auto i = items.begin(); i != items.end(); ++i) {
			if (i->draft.objectId == objectId) {
				items.erase(i);
				return true;
			}
		}
		return false;
	}

	[[nodiscard]] bool contains(ObjectId objectId) const override {
		return std::any_of(items.begin(), items.end(), [&](const auto &item) {
			return item.draft.objectId == objectId;
		});
	}

	std::vector<OutboxItem> items;
	bool failAppend = false;
	bool failReplace = false;
	bool failRemove = false;

};

class TestProtector final : public OutboundMessageProtector {
public:
	[[nodiscard]] std::optional<EncodedEnvelope> protectIdempotently(
			const MlsSealRequest &request) override {
		++calls;
		if (fail) {
			return std::nullopt;
		}
		return EncodedEnvelope{
			.conversationId = wrongConversation
				? FilledId<ConversationId>(99)
				: request.conversationId,
			.objectId = request.objectId,
			.bytes = QByteArray("sealed:") + request.plaintext,
		};
	}

	int calls = 0;
	bool fail = false;
	bool wrongConversation = false;

};

class TestTransport final : public TelegramTransport {
public:
	void uploadExact(
			EncodedEnvelope envelope,
			UploadCallback callback) override {
		uploads.push_back(std::move(envelope));
		callbacks.push_back(std::move(callback));
	}

	void downloadPage(
			DownloadRequest,
			DownloadCallback callback) override {
		callback({
			.result = UploadResult::Accepted,
			.untrustedObjects = {},
			.nextCursor = {},
			.complete = true,
		});
	}

	void finish(std::size_t index, UploadResult result) {
		callbacks.at(index)(result);
	}

	std::vector<EncodedEnvelope> uploads;
	std::vector<UploadCallback> callbacks;

};

class TestCarrierBackend final : public TelegramCarrierBackend {
public:
	void uploadDocument(
			QByteArray bytes,
			QString filename,
			QString mimeType,
			UploadCallback callback) override {
		uploadedBytes.push_back(std::move(bytes));
		filenames.push_back(std::move(filename));
		mimeTypes.push_back(std::move(mimeType));
		uploadCallbacks.push_back(std::move(callback));
	}

	void sendUploadedDocument(
			std::uint64_t telegramPeerId,
			UploadedCarrierFile file,
			QString filename,
			QString mimeType,
			SendCallback callback) override {
		peerIds.push_back(telegramPeerId);
		tokens.push_back(std::move(file.backendToken));
		filenames.push_back(std::move(filename));
		mimeTypes.push_back(std::move(mimeType));
		sendCallbacks.push_back(std::move(callback));
	}

	void downloadDocuments(
			std::uint64_t telegramPeerId,
			QByteArray cursor,
			int limit,
			DownloadCallback callback) override {
		peerIds.push_back(telegramPeerId);
		cursors.push_back(std::move(cursor));
		limits.push_back(limit);
		downloadCallbacks.push_back(std::move(callback));
	}

	void findDocument(
			std::uint64_t telegramPeerId,
			DiscoveryCallback callback) override {
		peerIds.push_back(telegramPeerId);
		discoveryCallbacks.push_back(std::move(callback));
	}

	std::vector<QByteArray> uploadedBytes;
	std::vector<QString> filenames;
	std::vector<QString> mimeTypes;
	std::vector<std::uint64_t> peerIds;
	std::vector<QByteArray> tokens;
	std::vector<QByteArray> cursors;
	std::vector<int> limits;
	std::vector<UploadCallback> uploadCallbacks;
	std::vector<SendCallback> sendCallbacks;
	std::vector<DownloadCallback> downloadCallbacks;
	std::vector<DiscoveryCallback> discoveryCallbacks;

};

[[nodiscard]] PendingMessage MakeMessage(ConversationId conversationId) {
	return {
		.conversationId = conversationId,
		.objectId = FilledId<ObjectId>(7),
		.plaintext = QByteArray("message"),
		.authenticatedData = QByteArray("metadata"),
	};
}

[[nodiscard]] TransportEnvelope MakeEnvelope() {
	return {
		.conversationId = FilledId<ConversationId>(1),
		.objectKind = ObjectKind::MlsApplication,
		.senderAccountId = FilledId<AccountId>(2),
		.senderClientId = FilledId<ClientId>(3),
		.telegramPeerIdBinding = 42,
		.epochOrGeneration = 8,
		.objectId = FilledId<ObjectId>(4),
		.payloadHash = FilledId<Digest>(5),
		.payload = QByteArray("payload"),
		.authenticationData = QByteArray("authenticated"),
	};
}

[[nodiscard]] int ScenarioEnvelopeValidation() {
	auto envelope = MakeEnvelope();
	if (ValidateEnvelope(envelope) != EnvelopeValidationError::None) {
		return Fail("valid transport envelope was rejected");
	}
	envelope.applicationProtocolVersion = kApplicationProtocolVersion + 1;
	if (ValidateEnvelope(envelope)
			!= EnvelopeValidationError::UnsupportedVersion) {
		return Fail("unsupported transport envelope version was accepted");
	}
	envelope.applicationProtocolVersion = kApplicationProtocolVersion;
	envelope.objectKind = static_cast<ObjectKind>(1000);
	if (ValidateEnvelope(envelope)
			!= EnvelopeValidationError::UnknownObjectKind) {
		return Fail("unknown transport envelope kind was accepted");
	}
	return 0;
}

[[nodiscard]] int ScenarioHistoryAccessBoundary() {
	if (!IsValidHistoryAccess({
			.mode = HistoryAccessMode::None,
			.boundaryEventId = {},
		})
		|| !IsValidHistoryAccess({
			.mode = HistoryAccessMode::FromJoin,
			.boundaryEventId = {},
		})
		|| !IsValidHistoryAccess({
			.mode = HistoryAccessMode::Full,
			.boundaryEventId = {},
		})
		|| IsValidHistoryAccess({
			.mode = HistoryAccessMode::Since,
			.boundaryEventId = {},
		})
		|| !IsValidHistoryAccess({
			.mode = HistoryAccessMode::Since,
			.boundaryEventId = FilledId<ObjectId>(3),
		})) {
		return Fail("history boundary accepted an ambiguous policy");
	}
	return 0;
}

[[nodiscard]] int ScenarioEnvelopeCodec() {
	const auto envelope = MakeEnvelope();
	const auto codec = EnvelopeCodecV1();
	const auto first = codec.encode(envelope);
	const auto second = codec.encode(envelope);
	if (!first
		|| first != second
		|| codec.decode(*first) != envelope
		|| first->bytes.size() != 202
		|| std::uint8_t(first->bytes[11]) != 1
		|| std::uint8_t(first->bytes[45]) != 8
		|| std::uint8_t(first->bytes[101]) != 42
		|| std::uint8_t(first->bytes[109]) != 8
		|| std::uint8_t(first->bytes[177]) != 7
		|| std::uint8_t(first->bytes[188]) != 13) {
		return Fail("version one envelope codec was not deterministic");
	}
	auto trailing = *first;
	trailing.bytes.append('x');
	if (codec.decode(trailing)) {
		return Fail("envelope codec accepted trailing bytes");
	}
	auto mismatched = *first;
	mismatched.objectId = FilledId<ObjectId>(99);
	if (codec.decode(mismatched)) {
		return Fail("envelope codec accepted a mismatched transport identity");
	}
	auto truncated = *first;
	truncated.bytes.chop(1);
	if (codec.decode(truncated)) {
		return Fail("envelope codec accepted truncated authentication data");
	}
	return 0;
}

[[nodiscard]] int ScenarioFreshnessConfirmation() {
	const auto conversationId = FilledId<ConversationId>(1);
	const auto checkpoint = MakeCheckpoint(conversationId, 8, 2);
	const auto nonce = FilledId<ChallengeNonce>(3);
	auto gate = FreshnessGate(checkpoint);
	auto verifier = TestVerifier();
	if (gate.sendingAllowed()
		|| gate.administrationAllowed()
		|| !gate.beginChallenge(nonce)) {
		return Fail("freshness gate opened before witness confirmation");
	}
	auto wrong = MakeResponse(checkpoint, FilledId<ChallengeNonce>(9));
	if (gate.acceptResponse(wrong, verifier)
			!= FreshnessResponseResult::WrongChallenge
		|| verifier.calls
		|| gate.state() != FreshnessState::WaitingForWitness) {
		return Fail("wrong freshness challenge changed gate state");
	}
	const auto response = MakeResponse(checkpoint, nonce);
	if (gate.acceptResponse(response, verifier)
			!= FreshnessResponseResult::Accepted
		|| verifier.calls != 1
		|| !gate.sendingAllowed()
		|| !gate.administrationAllowed()) {
		return Fail("valid freshness witness did not open the gate");
	}
	return 0;
}

[[nodiscard]] int ScenarioFreshnessResynchronization() {
	const auto conversationId = FilledId<ConversationId>(1);
	const auto known = MakeCheckpoint(conversationId, 8, 2);
	const auto current = MakeCheckpoint(conversationId, 10, 4);
	const auto nonce = FilledId<ChallengeNonce>(3);
	auto gate = FreshnessGate(known);
	auto verifier = TestVerifier();
	if (!gate.beginChallenge(nonce)
		|| gate.acceptResponse(MakeResponse(current, nonce, known), verifier)
			!= FreshnessResponseResult::ResynchronizationRequired
		|| gate.sendingAllowed()
		|| gate.administrationAllowed()
		|| gate.resynchronizationTarget() != current
		|| gate.completeResynchronization(known, verifier)) {
		return Fail("newer witness state bypassed required resynchronization");
	}
	verifier.accept = false;
	if (gate.completeResynchronization(current, verifier)
		|| gate.sendingAllowed()
		|| gate.state() != FreshnessState::ResynchronizationRequired) {
		return Fail("untrusted witness survived freshness resynchronization");
	}
	verifier.accept = true;
	if (!gate.completeResynchronization(current, verifier)
		|| !gate.sendingAllowed()
		|| gate.knownCheckpoint() != current
		|| verifier.calls != 3) {
		return Fail("newer witness state bypassed required resynchronization");
	}
	return 0;
}

[[nodiscard]] int ScenarioFreshnessFork() {
	const auto conversationId = FilledId<ConversationId>(1);
	const auto known = MakeCheckpoint(conversationId, 8, 2);
	const auto fork = MakeCheckpoint(conversationId, 8, 9);
	const auto nonce = FilledId<ChallengeNonce>(3);
	auto gate = FreshnessGate(known);
	auto verifier = TestVerifier();
	if (!gate.beginChallenge(nonce)
		|| gate.acceptResponse(MakeResponse(fork, nonce, known), verifier)
			!= FreshnessResponseResult::ForkDetected
		|| gate.state() != FreshnessState::Forked
		|| gate.sendingAllowed()
		|| gate.beginChallenge(FilledId<ChallengeNonce>(8))) {
		return Fail("conflicting checkpoint did not fail closed");
	}
	return 0;
}

[[nodiscard]] int ScenarioOutboxWaitsForFreshness() {
	const auto conversationId = FilledId<ConversationId>(1);
	auto gate = FreshnessGate(MakeCheckpoint(conversationId, 8, 2));
	auto store = TestOutboxStore();
	auto protector = TestProtector();
	auto coordinator = OutboxCoordinator(gate, store, protector);
	const auto queued = coordinator.enqueue(MakeMessage(conversationId));
	const auto dispatch = coordinator.dispatchNext();
	if (queued != EnqueueResult::Queued
		|| dispatch.result != OutboxDispatchResult::AwaitingFreshness
		|| dispatch.envelope
		|| protector.calls
		|| store.items.size() != 1) {
		return Fail("pending outbox content escaped before freshness");
	}
	return 0;
}

[[nodiscard]] int ScenarioOutboxSendsAfterFreshness() {
	const auto conversationId = FilledId<ConversationId>(1);
	const auto checkpoint = MakeCheckpoint(conversationId, 8, 2);
	const auto nonce = FilledId<ChallengeNonce>(3);
	auto gate = FreshnessGate(checkpoint);
	auto verifier = TestVerifier();
	auto store = TestOutboxStore();
	auto protector = TestProtector();
	auto coordinator = OutboxCoordinator(gate, store, protector);
	if (coordinator.enqueue(MakeMessage(conversationId))
			!= EnqueueResult::Queued
		|| !gate.beginChallenge(nonce)
		|| gate.acceptResponse(MakeResponse(checkpoint, nonce), verifier)
			!= FreshnessResponseResult::Accepted
		|| protector.calls) {
		return Fail("confirmed outbox content was not sent exactly once");
	}
	const auto dispatch = coordinator.dispatchNext();
	if (dispatch.result != OutboxDispatchResult::Ready
		|| !dispatch.envelope
		|| protector.calls != 1
		|| coordinator.dispatchNext().result
			!= OutboxDispatchResult::UploadInProgress
		|| !coordinator.acknowledgeUploaded(dispatch.envelope->objectId)
		|| !store.items.empty()
		|| coordinator.dispatchNext().result != OutboxDispatchResult::Empty) {
		return Fail("confirmed outbox content was not acknowledged exactly once");
	}
	return 0;
}

[[nodiscard]] int ScenarioOutboxRetriesExactCiphertext() {
	const auto conversationId = FilledId<ConversationId>(1);
	const auto checkpoint = MakeCheckpoint(conversationId, 8, 2);
	const auto nonce = FilledId<ChallengeNonce>(3);
	auto gate = FreshnessGate(checkpoint);
	auto verifier = TestVerifier();
	auto store = TestOutboxStore();
	auto protector = TestProtector();
	auto coordinator = OutboxCoordinator(gate, store, protector);
	if (coordinator.enqueue(MakeMessage(conversationId))
			!= EnqueueResult::Queued
		|| !gate.beginChallenge(nonce)
		|| gate.acceptResponse(MakeResponse(checkpoint, nonce), verifier)
			!= FreshnessResponseResult::Accepted
		|| protector.calls) {
		return Fail("outbox retry setup failed");
	}
	const auto first = coordinator.dispatchNext();
	if (first.result != OutboxDispatchResult::Ready
		|| !first.envelope
		|| !coordinator.markUploadFailed(first.envelope->objectId)) {
		return Fail("outbox upload failure was not retained for retry");
	}
	const auto second = coordinator.dispatchNext();
	if (second.result != OutboxDispatchResult::Ready
		|| !second.envelope
		|| first.envelope != second.envelope
		|| protector.calls != 1
		|| store.items.size() != 1
		|| store.items.front().stage != OutboxItemStage::Sealed
		|| !store.items.front().draft.plaintext.isEmpty()
		|| !coordinator.acknowledgeUploaded(second.envelope->objectId)
		|| !store.items.empty()) {
		return Fail("outbox retry regenerated or lost sealed ciphertext");
	}
	return 0;
}

[[nodiscard]] int ScenarioOutboxRejectsProtectorMismatch() {
	const auto conversationId = FilledId<ConversationId>(1);
	const auto checkpoint = MakeCheckpoint(conversationId, 8, 2);
	const auto nonce = FilledId<ChallengeNonce>(3);
	auto gate = FreshnessGate(checkpoint);
	auto verifier = TestVerifier();
	auto store = TestOutboxStore();
	auto protector = TestProtector();
	protector.wrongConversation = true;
	auto coordinator = OutboxCoordinator(gate, store, protector);
	if (coordinator.enqueue(MakeMessage(conversationId))
			!= EnqueueResult::Queued
		|| !gate.beginChallenge(nonce)
		|| gate.acceptResponse(MakeResponse(checkpoint, nonce), verifier)
			!= FreshnessResponseResult::Accepted
		|| coordinator.dispatchNext().result
			!= OutboxDispatchResult::InvalidItem
		|| store.items.size() != 1) {
		return Fail("mismatched protected envelope reached transport");
	}
	return 0;
}

[[nodiscard]] int ScenarioUploadControllerAcknowledgesRpcSuccess() {
	const auto conversationId = FilledId<ConversationId>(1);
	const auto checkpoint = MakeCheckpoint(conversationId, 8, 2);
	const auto nonce = FilledId<ChallengeNonce>(3);
	auto gate = FreshnessGate(checkpoint);
	auto verifier = TestVerifier();
	auto store = TestOutboxStore();
	auto protector = TestProtector();
	auto transport = TestTransport();
	auto completions = std::vector<UploadCompletion>();
	auto coordinator = OutboxCoordinator(gate, store, protector);
	auto controller = OutboxUploadController(
		coordinator,
		transport,
		[&](UploadCompletion completion) {
			completions.push_back(completion);
		});
	if (coordinator.enqueue(MakeMessage(conversationId))
			!= EnqueueResult::Queued
		|| !gate.beginChallenge(nonce)
		|| gate.acceptResponse(MakeResponse(checkpoint, nonce), verifier)
			!= FreshnessResponseResult::Accepted
		|| controller.pump() != UploadPumpResult::Started
		|| !controller.uploadInProgress()
		|| controller.pump() != UploadPumpResult::UploadInProgress
		|| transport.uploads.size() != 1
		|| store.items.size() != 1) {
		return Fail("upload controller did not retain an in-flight envelope");
	}
	transport.finish(0, TelegramTransport::UploadResult::Accepted);
	if (controller.uploadInProgress()
		|| !store.items.empty()
		|| completions.size() != 1
		|| completions.front().objectId != transport.uploads.front().objectId
		|| completions.front().transportResult
			!= TelegramTransport::UploadResult::Accepted
		|| !completions.front().outboxUpdated
		|| controller.pump() != UploadPumpResult::Empty) {
		return Fail("successful Telegram RPC did not acknowledge the outbox");
	}
	transport.finish(0, TelegramTransport::UploadResult::Accepted);
	if (completions.size() != 1) {
		return Fail("duplicate upload callback changed the outbox twice");
	}
	return 0;
}

[[nodiscard]] int ScenarioUploadControllerRetriesExactEnvelope() {
	const auto conversationId = FilledId<ConversationId>(1);
	const auto checkpoint = MakeCheckpoint(conversationId, 8, 2);
	const auto nonce = FilledId<ChallengeNonce>(3);
	auto gate = FreshnessGate(checkpoint);
	auto verifier = TestVerifier();
	auto store = TestOutboxStore();
	auto protector = TestProtector();
	auto transport = TestTransport();
	auto coordinator = OutboxCoordinator(gate, store, protector);
	auto controller = OutboxUploadController(
		coordinator,
		transport,
		nullptr);
	if (coordinator.enqueue(MakeMessage(conversationId))
			!= EnqueueResult::Queued
		|| !gate.beginChallenge(nonce)
		|| gate.acceptResponse(MakeResponse(checkpoint, nonce), verifier)
			!= FreshnessResponseResult::Accepted
		|| controller.pump() != UploadPumpResult::Started) {
		return Fail("upload retry setup failed");
	}
	transport.finish(0, TelegramTransport::UploadResult::RetryableError);
	if (controller.uploadInProgress()
		|| store.items.size() != 1
		|| controller.pump() != UploadPumpResult::Started
		|| transport.uploads.size() != 2
		|| transport.uploads[0] != transport.uploads[1]
		|| protector.calls != 1) {
		return Fail("upload controller did not retry exact ciphertext");
	}
	transport.finish(1, TelegramTransport::UploadResult::Accepted);
	if (!store.items.empty()) {
		return Fail("retried upload did not leave the outbox");
	}
	return 0;
}

[[nodiscard]] int ScenarioUploadRetriesAfterAcknowledgeFailure() {
	const auto conversationId = FilledId<ConversationId>(1);
	const auto checkpoint = MakeCheckpoint(conversationId, 8, 2);
	const auto nonce = FilledId<ChallengeNonce>(3);
	auto gate = FreshnessGate(checkpoint);
	auto verifier = TestVerifier();
	auto store = TestOutboxStore();
	auto protector = TestProtector();
	auto transport = TestTransport();
	auto completions = std::vector<UploadCompletion>();
	auto coordinator = OutboxCoordinator(gate, store, protector);
	auto controller = OutboxUploadController(
		coordinator,
		transport,
		[&](UploadCompletion completion) {
			completions.push_back(completion);
		});
	if (coordinator.enqueue(MakeMessage(conversationId))
			!= EnqueueResult::Queued
		|| !gate.beginChallenge(nonce)
		|| gate.acceptResponse(MakeResponse(checkpoint, nonce), verifier)
			!= FreshnessResponseResult::Accepted
		|| controller.pump() != UploadPumpResult::Started) {
		return Fail("acknowledgement failure retry setup failed");
	}
	store.failRemove = true;
	transport.finish(0, TelegramTransport::UploadResult::Accepted);
	store.failRemove = false;
	if (completions.size() != 1
		|| completions.front().outboxUpdated
		|| controller.uploadInProgress()
		|| controller.pump() != UploadPumpResult::Started
		|| transport.uploads.size() != 2
		|| transport.uploads[0] != transport.uploads[1]
		|| protector.calls != 1) {
		return Fail("failed local acknowledgement left upload stuck");
	}
	transport.finish(1, TelegramTransport::UploadResult::Accepted);
	if (completions.size() != 2
		|| !completions.back().outboxUpdated
		|| !store.items.empty()
		|| controller.pump() != UploadPumpResult::Empty) {
		return Fail("acknowledgement retry did not clear the outbox");
	}
	return 0;
}

[[nodiscard]] int ScenarioUploadWaitsForDurablePreAcknowledgement() {
	const auto conversationId = FilledId<ConversationId>(1);
	const auto checkpoint = MakeCheckpoint(conversationId, 8, 2);
	const auto nonce = FilledId<ChallengeNonce>(3);
	auto gate = FreshnessGate(checkpoint);
	auto verifier = TestVerifier();
	auto store = TestOutboxStore();
	auto protector = TestProtector();
	auto transport = TestTransport();
	auto completions = std::vector<UploadCompletion>();
	auto prepared = false;
	auto prepareCalls = 0;
	auto coordinator = OutboxCoordinator(gate, store, protector);
	auto controller = OutboxUploadController(
		coordinator,
		transport,
		[&](ObjectId) {
			++prepareCalls;
			return prepared;
		},
		[&](UploadCompletion completion) {
			completions.push_back(completion);
		});
	if (coordinator.enqueue(MakeMessage(conversationId))
			!= EnqueueResult::Queued
		|| !gate.beginChallenge(nonce)
		|| gate.acceptResponse(MakeResponse(checkpoint, nonce), verifier)
			!= FreshnessResponseResult::Accepted
		|| controller.pump() != UploadPumpResult::Started) {
		return Fail("pre-acknowledgement retry setup failed");
	}
	transport.finish(0, TelegramTransport::UploadResult::Accepted);
	if (prepareCalls != 1
		|| completions.size() != 1
		|| completions.front().outboxUpdated
		|| controller.uploadInProgress()
		|| store.items.size() != 1
		|| controller.pump() != UploadPumpResult::Started
		|| transport.uploads.size() != 2
		|| transport.uploads[0] != transport.uploads[1]
		|| protector.calls != 1) {
		return Fail("failed pre-acknowledgement discarded exact ciphertext");
	}
	prepared = true;
	transport.finish(1, TelegramTransport::UploadResult::Accepted);
	if (prepareCalls != 2
		|| completions.size() != 2
		|| !completions.back().outboxUpdated
		|| !store.items.empty()
		|| controller.pump() != UploadPumpResult::Empty) {
		return Fail("durable pre-acknowledgement did not clear the outbox");
	}
	return 0;
}

[[nodiscard]] int ScenarioUploadCallbackCannotOutliveController() {
	const auto conversationId = FilledId<ConversationId>(1);
	const auto checkpoint = MakeCheckpoint(conversationId, 8, 2);
	const auto nonce = FilledId<ChallengeNonce>(3);
	auto gate = FreshnessGate(checkpoint);
	auto verifier = TestVerifier();
	auto store = TestOutboxStore();
	auto protector = TestProtector();
	auto transport = TestTransport();
	auto coordinator = OutboxCoordinator(gate, store, protector);
	if (coordinator.enqueue(MakeMessage(conversationId))
			!= EnqueueResult::Queued
		|| !gate.beginChallenge(nonce)
		|| gate.acceptResponse(MakeResponse(checkpoint, nonce), verifier)
			!= FreshnessResponseResult::Accepted) {
		return Fail("upload callback lifetime setup failed");
	}
	{
		auto controller = OutboxUploadController(
			coordinator,
			transport,
			nullptr);
		if (controller.pump() != UploadPumpResult::Started) {
			return Fail("upload callback lifetime setup did not start");
		}
	}
	transport.finish(0, TelegramTransport::UploadResult::Accepted);
	if (store.items.size() != 1) {
		return Fail("destroyed upload controller handled a late callback");
	}
	auto replacement = OutboxUploadController(
		coordinator,
		transport,
		nullptr);
	if (replacement.pump() != UploadPumpResult::Started
		|| transport.uploads.size() != 2
		|| transport.uploads[0] != transport.uploads[1]) {
		return Fail("destroyed upload controller left the outbox stuck");
	}
	return 0;
}

[[nodiscard]] int ScenarioCarrierAcknowledgesOnlyAfterSendMedia() {
	const auto conversationId = FilledId<ConversationId>(1);
	auto envelope = MakeEnvelope();
	envelope.conversationId = conversationId;
	const auto encoded = EnvelopeCodecV1().encode(envelope);
	if (!encoded) {
		return Fail("carrier test envelope could not be encoded");
	}
	auto backend = TestCarrierBackend();
	auto results = std::vector<TelegramTransport::UploadResult>();
	auto transport = TelegramCarrierTransport(
		conversationId,
		42,
		backend);
	transport.uploadExact(*encoded, [&](TelegramTransport::UploadResult result) {
		results.push_back(result);
	});
	if (backend.uploadedBytes != std::vector<QByteArray>{
			encoded->bytes }
		|| backend.uploadCallbacks.size() != 1
		|| !backend.sendCallbacks.empty()
		|| !results.empty()
		|| backend.filenames != std::vector<QString>{
			ProtectedContentCarrierFilename() }) {
		return Fail("carrier bypassed the Telegram upload stage");
	}
	backend.uploadCallbacks.front()(
		TelegramTransport::UploadResult::Accepted,
		UploadedCarrierFile{ QByteArray("uploaded token") });
	if (backend.sendCallbacks.size() != 1
		|| backend.peerIds != std::vector<std::uint64_t>{ 42 }
		|| backend.tokens != std::vector<QByteArray>{
			QByteArray("uploaded token") }
		|| !results.empty()) {
		return Fail("carrier acknowledged before messages.sendMedia");
	}
	backend.sendCallbacks.front()(
		TelegramTransport::UploadResult::Accepted);
	if (results != std::vector<TelegramTransport::UploadResult>{
			TelegramTransport::UploadResult::Accepted }
		|| backend.filenames.size() != 2
		|| backend.filenames[0] != backend.filenames[1]
		|| backend.mimeTypes.size() != 2
		|| backend.mimeTypes[0] != backend.mimeTypes[1]) {
		return Fail("carrier did not preserve generic document metadata");
	}
	return 0;
}

[[nodiscard]] int ScenarioCarrierPropagatesUploadFailure() {
	const auto conversationId = FilledId<ConversationId>(1);
	auto envelope = MakeEnvelope();
	envelope.conversationId = conversationId;
	envelope.objectKind = ObjectKind::AccountCredential;
	const auto encoded = EnvelopeCodecV1().encode(envelope);
	if (!encoded) {
		return Fail("carrier control envelope could not be encoded");
	}
	auto backend = TestCarrierBackend();
	auto result = std::optional<TelegramTransport::UploadResult>();
	auto transport = TelegramCarrierTransport(
		conversationId,
		42,
		backend);
	transport.uploadExact(*encoded, [&](TelegramTransport::UploadResult value) {
		result = value;
	});
	if (backend.filenames != std::vector<QString>{
			ProtectedControlCarrierFilename() }) {
		return Fail("carrier did not route control metadata separately");
	}
	backend.uploadCallbacks.front()(
		TelegramTransport::UploadResult::RetryableError,
		UploadedCarrierFile());
	if (result != TelegramTransport::UploadResult::RetryableError
		|| !backend.sendCallbacks.empty()) {
		return Fail("carrier converted an upload failure into a send");
	}
	return 0;
}

[[nodiscard]] int ScenarioCarrierDownloadsOnlyUntrustedBytes() {
	const auto conversationId = FilledId<ConversationId>(1);
	auto backend = TestCarrierBackend();
	auto result = std::optional<TelegramTransport::DownloadResult>();
	auto transport = TelegramCarrierTransport(
		conversationId,
		42,
		backend);
	transport.downloadPage(
		{
			.conversationId = conversationId,
			.cursor = QByteArray("page one"),
			.limit = 37,
		},
		[&](TelegramTransport::DownloadResult value) {
			result = std::move(value);
		});
	if (backend.downloadCallbacks.size() != 1
		|| backend.cursors != std::vector<QByteArray>{
			QByteArray("page one") }
		|| backend.limits != std::vector<int>{ 37 }
		|| result) {
		return Fail("carrier download did not remain asynchronous");
	}
	backend.downloadCallbacks.front()(
		TelegramTransport::UploadResult::Accepted,
		{
			.untrustedObjects = {
				{
					.bytes = QByteArray("untrusted one"),
					.observedTelegramPeerIdBinding = 42,
					.observedSenderTelegramUserIdBinding = 1001,
					.observedMessageId = 7,
				},
				{
					.bytes = QByteArray("untrusted two"),
					.observedTelegramPeerIdBinding = 42,
					.observedSenderTelegramUserIdBinding = 1002,
					.observedMessageId = 8,
				},
			},
			.nextCursor = QByteArray("page two"),
			.complete = false,
		});
	if (!result
		|| result->result != TelegramTransport::UploadResult::Accepted
		|| result->untrustedObjects
			!= std::vector<TelegramTransport::UntrustedObject>{
				{
					.bytes = QByteArray("untrusted one"),
					.observedTelegramPeerIdBinding = 42,
					.observedSenderTelegramUserIdBinding = 1001,
					.observedMessageId = 7,
				},
				{
					.bytes = QByteArray("untrusted two"),
					.observedTelegramPeerIdBinding = 42,
					.observedSenderTelegramUserIdBinding = 1002,
					.observedMessageId = 8,
				} }
		|| result->nextCursor != QByteArray("page two")
		|| result->complete) {
		return Fail("carrier transport interpreted untrusted protocol bytes");
	}
	return 0;
}

[[nodiscard]] int ScenarioCloudVaultUsesSavedMessagesCarrier() {
	auto backend = TestCarrierBackend();
	auto transport = TelegramCloudVaultTransport(777, backend);
	auto uploadResult = std::optional<TelegramTransport::UploadResult>();
	transport.uploadExact(
		QByteArray("password-protected vault"),
		[&](TelegramTransport::UploadResult result) {
			uploadResult = result;
		});
	if (backend.uploadedBytes != std::vector<QByteArray>{
		QByteArray("password-protected vault") }
		|| backend.filenames != std::vector<QString>{
			CloudVaultCarrierFilename() }
		|| backend.mimeTypes != std::vector<QString>{
			CloudVaultCarrierMimeType() }
		|| uploadResult) {
		return Fail("cloud vault bypassed its opaque upload stage");
	}
	backend.uploadCallbacks.front()(
		TelegramTransport::UploadResult::Accepted,
		UploadedCarrierFile{ QByteArray("vault token") });
	if (backend.peerIds != std::vector<std::uint64_t>{ 777 }
		|| backend.sendCallbacks.size() != 1
		|| uploadResult) {
		return Fail("cloud vault was acknowledged before Saved Messages send");
	}
	backend.sendCallbacks.front()(
		TelegramTransport::UploadResult::Accepted);
	if (uploadResult != TelegramTransport::UploadResult::Accepted
		|| backend.filenames.size() != 2
		|| backend.filenames[0] != backend.filenames[1]) {
		return Fail("cloud vault carrier did not complete exact upload");
	}
	auto discovery = std::optional<bool>();
	transport.discover([&](
			TelegramTransport::UploadResult result,
			bool present) {
		if (result == TelegramTransport::UploadResult::Accepted) {
			discovery = present;
		}
	});
	if (backend.discoveryCallbacks.size() != 1
		|| backend.peerIds.back() != 777
		|| discovery) {
		return Fail("cloud vault discovery bypassed its metadata backend");
	}
	backend.discoveryCallbacks.front()(
		TelegramTransport::UploadResult::Accepted,
		true);
	if (discovery != true) {
		return Fail("cloud vault discovery did not return backend presence");
	}
	auto page = std::optional<CarrierDownloadPage>();
	transport.downloadPage(
		QByteArray("cursor"),
		50,
		[&](
				TelegramTransport::UploadResult result,
				CarrierDownloadPage value) {
			if (result == TelegramTransport::UploadResult::Accepted) {
				page = std::move(value);
			}
		});
	backend.downloadCallbacks.front()(
		TelegramTransport::UploadResult::Accepted,
		{
			.untrustedObjects = {
				{ .bytes = QByteArray("untrusted vault") },
			},
			.nextCursor = QByteArray("next"),
			.complete = true,
		});
	if (!page
		|| page->untrustedObjects
			!= std::vector<TelegramTransport::UntrustedObject>{
				{ .bytes = QByteArray("untrusted vault") } }
		|| page->nextCursor != QByteArray("next")
		|| !page->complete) {
		return Fail("cloud vault carrier interpreted remote vault bytes");
	}
	return 0;
}

[[nodiscard]] int ScenarioCarrierMetadataRecognitionIsExact() {
	const auto mime = ProtectedCarrierMimeType();
	const auto fileId = FilledId<FileId>(9);
	const auto fileChunk = ProtectedFileChunkCarrierFilename(fileId);
	if (!IsProtectedGroupCarrierMetadata(
			ProtectedLegacyCarrierFilename(),
			mime)
		|| !IsProtectedGroupCarrierMetadata(
			ProtectedControlCarrierFilename(),
			mime)
		|| !IsProtectedGroupCarrierMetadata(
			ProtectedContentCarrierFilename(),
			mime)
		|| !IsProtectedGroupCarrierMetadata(fileChunk, mime)
		|| ProtectedFileChunkCarrierFileId(fileChunk) != fileId
		|| ProtectedFileChunkCarrierFilename(FileId()).size()
		|| ProtectedFileChunkCarrierFileId(
			fileChunk.toUpper()).has_value()
		|| ProtectedFileChunkCarrierFileId(
			fileChunk + QString::fromLatin1("x")).has_value()
		|| !IsProtectedVaultCarrierMetadata(
			CloudVaultCarrierFilename(),
			mime)
		|| !IsProtectedCarrierMetadata(
			CloudVaultCarrierFilename(),
			mime)
		|| IsProtectedCarrierMetadata(
			QString::fromLatin1("notes.tde2e"),
			mime)
		|| IsProtectedCarrierMetadata(
			ProtectedControlCarrierFilename(),
			QString::fromLatin1("application/pdf"))
		|| IsProtectedGroupCarrierMetadata(
			CloudVaultCarrierFilename(),
			mime)) {
		return Fail("protected carrier metadata recognition was not exact");
	}
	return 0;
}

} // namespace

int main(int, char *[]) {
	for (const auto scenario : {
		ScenarioEnvelopeValidation,
		ScenarioHistoryAccessBoundary,
		ScenarioEnvelopeCodec,
		ScenarioFreshnessConfirmation,
		ScenarioFreshnessResynchronization,
		ScenarioFreshnessFork,
		ScenarioOutboxWaitsForFreshness,
		ScenarioOutboxSendsAfterFreshness,
		ScenarioOutboxRetriesExactCiphertext,
		ScenarioOutboxRejectsProtectorMismatch,
		ScenarioUploadControllerAcknowledgesRpcSuccess,
		ScenarioUploadControllerRetriesExactEnvelope,
		ScenarioUploadRetriesAfterAcknowledgeFailure,
		ScenarioUploadWaitsForDurablePreAcknowledgement,
		ScenarioUploadCallbackCannotOutliveController,
		ScenarioCarrierAcknowledgesOnlyAfterSendMedia,
		ScenarioCarrierPropagatesUploadFailure,
		ScenarioCarrierDownloadsOnlyUntrustedBytes,
		ScenarioCloudVaultUsesSavedMessagesCarrier,
		ScenarioCarrierMetadataRecognitionIsExact,
	}) {
		if (const auto result = scenario()) {
			return result;
		}
	}
	return 0;
}

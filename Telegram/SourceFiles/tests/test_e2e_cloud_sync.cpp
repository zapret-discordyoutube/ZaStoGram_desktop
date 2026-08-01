/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "e2e_cloud/core/envelope_codec.h"
#include "e2e_cloud/transport/carrier_sync_controller.h"
#include "e2e_cloud/transport/observed_content_sync_controller.h"

#include <cstdio>
#include <map>
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

[[nodiscard]] TransportEnvelope MakeEnvelope(std::uint8_t value) {
	const auto payloadByte = char(value);
	return {
		.conversationId = FilledId<ConversationId>(1),
		.objectKind = ObjectKind::MlsApplication,
		.senderAccountId = FilledId<AccountId>(2),
		.senderClientId = FilledId<ClientId>(3),
		.telegramPeerIdBinding = 42,
		.epochOrGeneration = 7,
		.objectId = FilledId<ObjectId>(value),
		.payloadHash = FilledId<Digest>(value),
		.payload = QByteArray(&payloadByte, 1),
		.authenticationData = QByteArray("authentication"),
	};
}

class TestTransport final : public TelegramTransport {
public:
	void uploadExact(EncodedEnvelope, UploadCallback callback) override {
		callback(UploadResult::PermanentError);
	}

	void downloadPage(
			DownloadRequest request,
			DownloadCallback callback) override {
		requests.push_back(std::move(request));
		if (asynchronous) {
			callbacks.push_back(std::move(callback));
		} else if (!pages.empty()) {
			auto result = std::move(pages.front());
			pages.erase(pages.begin());
			callback(std::move(result));
		} else {
			callback({
				.result = UploadResult::PermanentError,
				.untrustedObjects = {},
				.nextCursor = {},
				.complete = false,
			});
		}
	}

	std::vector<DownloadRequest> requests;
	std::vector<DownloadResult> pages;
	std::vector<DownloadCallback> callbacks;
	bool asynchronous = false;
};

class TestAuthenticator final : public InboundEnvelopeAuthenticator {
public:
	[[nodiscard]] bool authenticate(
			const TransportEnvelope &) const override {
		return true;
	}
};

class TestJournal final : public InboundEnvelopeJournal {
public:
	[[nodiscard]] InboundJournalLookup lookup(
			ConversationId,
			ObjectId objectId,
			Digest payloadHash) const override {
		const auto i = entries.find(objectId);
		return (i == entries.end())
			? InboundJournalLookup::Missing
			: (i->second != payloadHash)
			? InboundJournalLookup::ObjectIdConflict
			: InboundJournalLookup::Accepted;
	}

	bool begin(const TransportEnvelope &envelope) override {
		pending = std::pair(envelope.objectId, envelope.payloadHash);
		return true;
	}

	bool accept(ConversationId, ObjectId objectId) override {
		if (!pending || pending->first != objectId) {
			return false;
		}
		entries.emplace(pending->first, pending->second);
		pending.reset();
		return true;
	}

	bool abort(ConversationId, ObjectId objectId) override {
		if (!pending || pending->first != objectId) {
			return false;
		}
		pending.reset();
		return true;
	}

	std::map<ObjectId, Digest> entries;
	std::optional<std::pair<ObjectId, Digest>> pending;
};

class TestApplier final : public InboundEnvelopeApplier {
public:
	[[nodiscard]] InboundApplyResult apply(
			const TransportEnvelope &envelope) override {
		return (forkObject && envelope.objectId == forkObject)
			? InboundApplyResult::ForkDetected
			: InboundApplyResult::Applied;
	}

	ObjectId forkObject;
};

struct Fixture {
	Fixture()
	: processor(
		FilledId<ConversationId>(1),
		42,
		codec,
		authenticator,
		journal,
		applier) {
	}

	[[nodiscard]] QByteArray encoded(std::uint8_t value) const {
		return codec.encode(MakeEnvelope(value))->bytes;
	}

	[[nodiscard]] TelegramTransport::UntrustedObject object(
			std::uint8_t value) const {
		return {
			.bytes = encoded(value),
			.observedTelegramPeerIdBinding = 42,
			.observedSenderTelegramUserIdBinding = 100,
			.observedMessageId = value,
		};
	}

	EnvelopeCodecV1 codec;
	TestTransport transport;
	TestAuthenticator authenticator;
	TestJournal journal;
	TestApplier applier;
	InboundEnvelopeProcessor processor;
};

[[nodiscard]] int ScenarioCompletesPagedBackfill() {
	auto fixture = Fixture();
	fixture.transport.pages = {
		{
			.result = TelegramTransport::UploadResult::Accepted,
			.untrustedObjects = {
				fixture.object(4),
				{ .bytes = QByteArray("not an envelope") },
			},
			.nextCursor = QByteArray("second"),
			.complete = false,
		},
		{
			.result = TelegramTransport::UploadResult::Accepted,
			.untrustedObjects = {
				fixture.object(4),
				fixture.object(5),
			},
			.nextCursor = QByteArray("done"),
			.complete = true,
		},
	};
	auto completion = std::optional<CarrierSyncCompletion>();
	auto controller = CarrierSyncController(
		FilledId<ConversationId>(1),
		fixture.transport,
		fixture.processor,
		[&](CarrierSyncCompletion result) {
			completion = std::move(result);
		});
	if (controller.start() != CarrierSyncStartResult::Started
		|| controller.running()
		|| !completion
		|| completion->reason != CarrierSyncFinishReason::Complete
		|| completion->stats.pages != 2
		|| completion->stats.objects != 4
		|| completion->stats.accepted != 2
		|| completion->stats.duplicates != 1
		|| completion->stats.rejected != 1
		|| completion->stats.nextCursor != QByteArray("done")
		|| fixture.transport.requests.size() != 2
		|| fixture.transport.requests[1].cursor != QByteArray("second")) {
		return Fail("paged carrier backfill was not processed exactly once");
	}
	return 0;
}

[[nodiscard]] int ScenarioRejectsCursorLoop() {
	auto fixture = Fixture();
	fixture.transport.pages = {
		{
			.result = TelegramTransport::UploadResult::Accepted,
			.untrustedObjects = {},
			.nextCursor = QByteArray("loop"),
			.complete = false,
		},
		{
			.result = TelegramTransport::UploadResult::Accepted,
			.untrustedObjects = {},
			.nextCursor = QByteArray("loop"),
			.complete = false,
		},
	};
	auto reason = std::optional<CarrierSyncFinishReason>();
	auto controller = CarrierSyncController(
		FilledId<ConversationId>(1),
		fixture.transport,
		fixture.processor,
		[&](CarrierSyncCompletion result) { reason = result.reason; });
	if (controller.start() != CarrierSyncStartResult::Started
		|| reason != CarrierSyncFinishReason::InvalidPagination
		|| fixture.transport.requests.size() != 2) {
		return Fail("untrusted carrier cursor loop was accepted");
	}
	return 0;
}

[[nodiscard]] int ScenarioStopsOnAuthenticatedFork() {
	auto fixture = Fixture();
	fixture.applier.forkObject = FilledId<ObjectId>(5);
	fixture.transport.pages = {
		{
			.result = TelegramTransport::UploadResult::Accepted,
			.untrustedObjects = {
				fixture.object(4),
				fixture.object(5),
				fixture.object(6),
			},
			.nextCursor = QByteArray("unused"),
			.complete = true,
		},
	};
	auto completion = std::optional<CarrierSyncCompletion>();
	auto controller = CarrierSyncController(
		FilledId<ConversationId>(1),
		fixture.transport,
		fixture.processor,
		[&](CarrierSyncCompletion result) {
			completion = std::move(result);
		});
	if (controller.start() != CarrierSyncStartResult::Started
		|| !completion
		|| completion->reason != CarrierSyncFinishReason::SecurityBlocked
		|| completion->stats.objects != 2
		|| fixture.journal.entries.contains(FilledId<ObjectId>(6))) {
		return Fail("authenticated fork did not stop carrier synchronization");
	}
	return 0;
}

[[nodiscard]] int ScenarioCancellationIgnoresLatePage() {
	auto fixture = Fixture();
	fixture.transport.asynchronous = true;
	auto completions = std::vector<CarrierSyncCompletion>();
	auto controller = CarrierSyncController(
		FilledId<ConversationId>(1),
		fixture.transport,
		fixture.processor,
		[&](CarrierSyncCompletion result) {
			completions.push_back(std::move(result));
		});
	if (controller.start() != CarrierSyncStartResult::Started
		|| !controller.running()
		|| fixture.transport.callbacks.size() != 1) {
		return Fail("asynchronous carrier synchronization did not start");
	}
	controller.cancel();
	fixture.transport.callbacks.front()({
		.result = TelegramTransport::UploadResult::Accepted,
		.untrustedObjects = { fixture.object(4) },
		.nextCursor = {},
		.complete = true,
	});
	if (completions.size() != 1
		|| completions.front().reason != CarrierSyncFinishReason::Cancelled
		|| !fixture.journal.entries.empty()) {
		return Fail("cancelled carrier synchronization accepted a late page");
	}
	return 0;
}

[[nodiscard]] int ScenarioObservedContentStopsAtBoundary() {
	auto fixture = Fixture();
	fixture.transport.pages = {
		{
			.result = TelegramTransport::UploadResult::Accepted,
			.untrustedObjects = {
				fixture.object(9),
				fixture.object(8),
			},
			.nextCursor = QByteArray("next"),
			.complete = false,
		},
		{
			.result = TelegramTransport::UploadResult::Accepted,
			.untrustedObjects = {
				fixture.object(7),
				fixture.object(6),
				fixture.object(5),
			},
			.nextCursor = QByteArray("unused"),
			.complete = false,
		},
	};
	auto retained = std::vector<std::int64_t>();
	auto completion = std::optional<ObservedContentSyncCompletion>();
	auto controller = ObservedContentSyncController(
		FilledId<ConversationId>(1),
		42,
		fixture.transport,
		[&](std::vector<TelegramTransport::UntrustedObject> objects) {
			for (const auto &object : objects) {
				retained.push_back(object.observedMessageId);
			}
			return ObservedContentPageResult::Persisted;
		},
		[&](ObservedContentSyncCompletion result) {
			completion = result;
		});
	if (!controller.start(6)
		|| controller.running()
		|| !completion
		|| completion->status != ObservedContentSyncStatus::Complete
		|| completion->pages != 2
		|| completion->objects != 3
		|| completion->previousBoundaryMessageId != 6
		|| completion->newestObservedMessageId != 9
		|| retained != std::vector<std::int64_t>({ 9, 8, 7 })) {
		return Fail("observed content synchronization crossed its boundary");
	}
	return 0;
}

[[nodiscard]] int ScenarioObservedContentRejectsReordering() {
	auto fixture = Fixture();
	fixture.transport.pages = {
		{
			.result = TelegramTransport::UploadResult::Accepted,
			.untrustedObjects = {
				fixture.object(8),
				fixture.object(9),
			},
			.nextCursor = {},
			.complete = true,
		},
	};
	auto status = std::optional<ObservedContentSyncStatus>();
	auto controller = ObservedContentSyncController(
		FilledId<ConversationId>(1),
		42,
		fixture.transport,
		[](std::vector<TelegramTransport::UntrustedObject>) {
			return ObservedContentPageResult::Persisted;
		},
		[&](ObservedContentSyncCompletion result) {
			status = result.status;
		});
	if (!controller.start()
		|| status != ObservedContentSyncStatus::SecurityBlocked) {
		return Fail("reordered observed Telegram content was accepted");
	}
	return 0;
}

} // namespace

int main(int, char *[]) {
	for (const auto scenario : {
		ScenarioCompletesPagedBackfill,
		ScenarioRejectsCursorLoop,
		ScenarioStopsOnAuthenticatedFork,
		ScenarioCancellationIgnoresLatePage,
		ScenarioObservedContentStopsAtBoundary,
		ScenarioObservedContentRejectsReordering,
	}) {
		if (const auto result = scenario()) {
			return result;
		}
	}
	return 0;
}

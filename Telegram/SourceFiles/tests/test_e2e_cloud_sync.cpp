/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "e2e_cloud/core/envelope_codec.h"
#include "e2e_cloud/identity/openssl_account_crypto.h"
#include "e2e_cloud/transport/carrier_sync_controller.h"
#include "e2e_cloud/transport/observed_content_sync_controller.h"
#include "e2e_cloud/transport/public_bootstrap_sync_controller.h"

#include <algorithm>
#include <cstdio>
#include <map>
#include <memory>
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
	OpenSslSha256Provider sha256;
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
		fixture.sha256,
		[&](std::vector<TelegramTransport::UntrustedObject> objects) {
			std::reverse(begin(objects), end(objects));
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
		|| completion->nextBoundaryMessageId != 6
		|| retained != std::vector<std::int64_t>({ 7, 8, 9 })) {
		return Fail("observed content synchronization crossed its boundary");
	}
	return 0;
}

[[nodiscard]] int ScenarioObservedContentRejectsMissingBoundary() {
	auto fixture = Fixture();
	fixture.transport.pages = {
		{
			.result = TelegramTransport::UploadResult::Accepted,
			.untrustedObjects = {
				fixture.object(9),
				fixture.object(7),
				fixture.object(5),
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
		fixture.sha256,
		[](std::vector<TelegramTransport::UntrustedObject>) {
			return ObservedContentPageResult::Persisted;
		},
		[&](ObservedContentSyncCompletion result) {
			status = result.status;
		});
	if (!controller.start(6)
		|| status != ObservedContentSyncStatus::SecurityBlocked) {
		return Fail("observed content accepted a missing saved boundary");
	}
	return 0;
}

[[nodiscard]] int ScenarioObservedContentKeepsOverlap() {
	auto fixture = Fixture();
	auto objects = std::vector<TelegramTransport::UntrustedObject>();
	for (auto messageId = 100; messageId >= 60; --messageId) {
		objects.push_back(fixture.object(std::uint8_t(messageId)));
	}
	fixture.transport.pages = {
		{
			.result = TelegramTransport::UploadResult::Accepted,
			.untrustedObjects = std::move(objects),
			.nextCursor = {},
			.complete = true,
		},
	};
	auto completion = std::optional<ObservedContentSyncCompletion>();
	auto controller = ObservedContentSyncController(
		FilledId<ConversationId>(1),
		42,
		fixture.transport,
		fixture.sha256,
		[](std::vector<TelegramTransport::UntrustedObject>) {
			return ObservedContentPageResult::Persisted;
		},
		[&](ObservedContentSyncCompletion result) {
			completion = result;
		});
	if (!controller.start()
		|| !completion
		|| completion->status != ObservedContentSyncStatus::Complete
		|| completion->objects != 41
		|| completion->newestObservedMessageId != 100
		|| completion->nextBoundaryMessageId != 68) {
		return Fail("observed content did not retain a boundary overlap");
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
		fixture.sha256,
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

[[nodiscard]] int ScenarioObservedContentReplaysOldestPageFirst() {
	auto fixture = Fixture();
	const auto page = [&](std::uint8_t newest, const QByteArray &next) {
		return TelegramTransport::DownloadResult{
			.result = TelegramTransport::UploadResult::Accepted,
			.untrustedObjects = {
				fixture.object(newest),
				fixture.object(newest - 1),
			},
			.nextCursor = next,
			.complete = next.isEmpty(),
		};
	};
	fixture.transport.pages = {
		page(9, QByteArray("second")),
		page(7, QByteArray("third")),
		page(5, QByteArray()),
		page(5, QByteArray()),
		page(7, QByteArray("third")),
	};
	auto retained = std::vector<std::int64_t>();
	auto completion = std::optional<ObservedContentSyncCompletion>();
	auto controller = ObservedContentSyncController(
		FilledId<ConversationId>(1),
		42,
		fixture.transport,
		fixture.sha256,
		[&](std::vector<TelegramTransport::UntrustedObject> objects) {
			std::reverse(begin(objects), end(objects));
			for (const auto &object : objects) {
				retained.push_back(object.observedMessageId);
			}
			return ObservedContentPageResult::Persisted;
		},
		[&](ObservedContentSyncCompletion result) {
			completion = result;
		});
	if (!controller.start()
		|| controller.running()
		|| !completion
		|| completion->status != ObservedContentSyncStatus::Complete
		|| completion->pages != 3
		|| completion->objects != 6
		|| retained != std::vector<std::int64_t>({ 4, 5, 6, 7, 8, 9 })
		|| fixture.transport.requests.size() != 5
		|| fixture.transport.requests[3].cursor != QByteArray("third")
		|| fixture.transport.requests[4].cursor != QByteArray("second")) {
		return Fail("observed content pages were not replayed oldest first");
	}
	return 0;
}

[[nodiscard]] int ScenarioObservedContentRejectsReplayMutation() {
	auto fixture = Fixture();
	auto changed = fixture.object(7);
	changed.bytes.append(char(1));
	fixture.transport.pages = {
		{
			.result = TelegramTransport::UploadResult::Accepted,
			.untrustedObjects = {
				fixture.object(9),
				fixture.object(8),
			},
			.nextCursor = QByteArray("second"),
			.complete = false,
		},
		{
			.result = TelegramTransport::UploadResult::Accepted,
			.untrustedObjects = {
				fixture.object(7),
				fixture.object(6),
			},
			.nextCursor = {},
			.complete = true,
		},
		{
			.result = TelegramTransport::UploadResult::Accepted,
			.untrustedObjects = {
				std::move(changed),
				fixture.object(6),
			},
			.nextCursor = {},
			.complete = true,
		},
	};
	auto status = std::optional<ObservedContentSyncStatus>();
	auto pageCalled = false;
	auto controller = ObservedContentSyncController(
		FilledId<ConversationId>(1),
		42,
		fixture.transport,
		fixture.sha256,
		[&](std::vector<TelegramTransport::UntrustedObject>) {
			pageCalled = true;
			return ObservedContentPageResult::Persisted;
		},
		[&](ObservedContentSyncCompletion result) {
			status = result.status;
		});
	if (!controller.start()
		|| status != ObservedContentSyncStatus::SecurityBlocked
		|| pageCalled) {
		return Fail("mutated observed content replay was accepted");
	}
	return 0;
}

struct PageCallbackLifetimeState {
	bool insideCallback = false;
	bool activeProbeDestroyed = false;
	std::uint64_t lastProbeId = 0;
	std::uint64_t activeProbeId = 0;
};

class PageCallbackLifetimeProbe final {
public:
	explicit PageCallbackLifetimeProbe(
		std::shared_ptr<PageCallbackLifetimeState> state)
	: _state(std::move(state))
	, _id(_state ? ++_state->lastProbeId : 0) {
	}

	PageCallbackLifetimeProbe(const PageCallbackLifetimeProbe &other)
	: _state(other._state)
	, _id(_state ? ++_state->lastProbeId : 0) {
	}
	PageCallbackLifetimeProbe(PageCallbackLifetimeProbe &&other) noexcept
	= default;
	PageCallbackLifetimeProbe &operator=(
		const PageCallbackLifetimeProbe &) = delete;
	PageCallbackLifetimeProbe &operator=(PageCallbackLifetimeProbe &&) = delete;

	~PageCallbackLifetimeProbe() {
		if (_state
			&& _state->insideCallback
			&& _state->activeProbeId == _id) {
			_state->activeProbeDestroyed = true;
		}
	}

	[[nodiscard]] std::shared_ptr<PageCallbackLifetimeState> state() const {
		return _state;
	}
	[[nodiscard]] std::uint64_t id() const {
		return _id;
	}

private:
	std::shared_ptr<PageCallbackLifetimeState> _state;
	std::uint64_t _id = 0;

};

[[nodiscard]] int ScenarioObservedPageCanDestroyController() {
	auto fixture = Fixture();
	fixture.transport.pages = {
		{
			.result = TelegramTransport::UploadResult::Accepted,
			.untrustedObjects = { fixture.object(9) },
			.nextCursor = {},
			.complete = true,
		},
	};
	auto lifetime = std::make_shared<PageCallbackLifetimeState>();
	auto completionCalled = false;
	auto controller = std::unique_ptr<ObservedContentSyncController>();
	controller = std::make_unique<ObservedContentSyncController>(
		FilledId<ConversationId>(1),
		42,
		fixture.transport,
		fixture.sha256,
		[&, probe = PageCallbackLifetimeProbe(lifetime)](
				std::vector<TelegramTransport::UntrustedObject>) {
			const auto state = probe.state();
			state->activeProbeId = probe.id();
			state->insideCallback = true;
			controller.reset();
			state->insideCallback = false;
			return ObservedContentPageResult::Persisted;
		},
		[&](ObservedContentSyncCompletion) {
			completionCalled = true;
		});
	const auto started = controller->start();
	if (!started
		|| controller
		|| completionCalled
		|| lifetime->activeProbeDestroyed) {
		return Fail("observed page callback was destroyed while executing");
	}
	return 0;
}

[[nodiscard]] int ScenarioControlSyncStopsAtBoundary() {
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
	auto completion = std::optional<PublicBootstrapSyncCompletion>();
	auto controller = PublicBootstrapSyncController(
		FilledId<ConversationId>(1),
		42,
		std::nullopt,
		fixture.transport,
		fixture.codec,
		fixture.sha256,
		[&](PublicBootstrapSyncCompletion result) {
			completion = std::move(result);
		});
	if (!controller.startFromBoundary(6)
		|| controller.running()
		|| !completion
		|| completion->status != PublicBootstrapSyncStatus::Incremental
		|| completion->verified
		|| completion->pages != 2
		|| completion->objects != 3
		|| completion->previousBoundaryMessageId != 6
		|| completion->newestObservedMessageId != 9
		|| completion->untrustedObjects.size() != 3
		|| completion->untrustedObjects[0].observedMessageId != 9
		|| completion->untrustedObjects[1].observedMessageId != 8
		|| completion->untrustedObjects[2].observedMessageId != 7) {
		return Fail("control synchronization crossed its saved boundary");
	}
	return 0;
}

[[nodiscard]] int ScenarioJoinSyncDropsUnboundedControlNoise() {
	auto fixture = Fixture();
	const auto object = [&](ObjectKind kind, std::int64_t messageId) {
		auto envelope = MakeEnvelope(std::uint8_t(messageId));
		envelope.objectKind = kind;
		return TelegramTransport::UntrustedObject{
			.bytes = fixture.codec.encode(envelope)->bytes,
			.observedTelegramPeerIdBinding = 42,
			.observedSenderTelegramUserIdBinding = 100,
			.observedMessageId = messageId,
		};
	};
	fixture.transport.pages = {
		{
			.result = TelegramTransport::UploadResult::Accepted,
			.untrustedObjects = {
				object(ObjectKind::SafetyCodeGossip, 3),
				object(ObjectKind::FreshnessResponse, 2),
				object(ObjectKind::SignedGroupTransition, 1),
			},
			.nextCursor = {},
			.complete = true,
		},
	};
	auto completion = std::optional<PublicBootstrapSyncCompletion>();
	auto controller = PublicBootstrapSyncController(
		FilledId<ConversationId>(1),
		42,
		std::nullopt,
		fixture.transport,
		fixture.codec,
		fixture.sha256,
		[&](PublicBootstrapSyncCompletion result) {
			completion = std::move(result);
		});
	if (!controller.startForJoin()
		|| !completion
		|| completion->status != PublicBootstrapSyncStatus::Missing
		|| completion->objects != 1
		|| completion->untrustedObjects.size() != 1
		|| fixture.codec.decodeUntrusted(
			completion->untrustedObjects.front().bytes)->objectKind
			!= ObjectKind::SignedGroupTransition) {
		return Fail("join synchronization retained unbounded control noise");
	}
	return 0;
}

[[nodiscard]] int ScenarioControlSyncRejectsMissingBoundary() {
	auto fixture = Fixture();
	fixture.transport.pages = {
		{
			.result = TelegramTransport::UploadResult::Accepted,
			.untrustedObjects = {
				fixture.object(9),
				fixture.object(7),
				fixture.object(5),
			},
			.nextCursor = {},
			.complete = true,
		},
	};
	auto status = std::optional<PublicBootstrapSyncStatus>();
	auto controller = PublicBootstrapSyncController(
		FilledId<ConversationId>(1),
		42,
		std::nullopt,
		fixture.transport,
		fixture.codec,
		fixture.sha256,
		[&](PublicBootstrapSyncCompletion result) {
			status = result.status;
		});
	if (!controller.startFromBoundary(6)
		|| status != PublicBootstrapSyncStatus::InvalidPagination) {
		return Fail("control synchronization accepted a missing boundary");
	}
	return 0;
}

[[nodiscard]] int ScenarioControlSyncRejectsReordering() {
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
	auto status = std::optional<PublicBootstrapSyncStatus>();
	auto controller = PublicBootstrapSyncController(
		FilledId<ConversationId>(1),
		42,
		std::nullopt,
		fixture.transport,
		fixture.codec,
		fixture.sha256,
		[&](PublicBootstrapSyncCompletion result) {
			status = result.status;
		});
	if (!controller.startFromBoundary(6)
		|| status != PublicBootstrapSyncStatus::InvalidPagination) {
		return Fail("reordered control carriers were accepted");
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
		ScenarioObservedContentRejectsMissingBoundary,
		ScenarioObservedContentKeepsOverlap,
		ScenarioObservedContentReplaysOldestPageFirst,
		ScenarioObservedContentRejectsReplayMutation,
		ScenarioObservedPageCanDestroyController,
		ScenarioControlSyncStopsAtBoundary,
		ScenarioJoinSyncDropsUnboundedControlNoise,
		ScenarioControlSyncRejectsMissingBoundary,
		ScenarioControlSyncRejectsReordering,
	}) {
		if (const auto result = scenario()) {
			return result;
		}
	}
	return 0;
}

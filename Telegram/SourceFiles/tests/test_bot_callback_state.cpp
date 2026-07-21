/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "api/api_bot_callback_state.h"

#include <algorithm>
#include <cstdio>
#include <random>
#include <utility>

namespace {

using Api::BotCallbackButton;
using Api::BotCallbackButtonType;
using Api::BotCallbackPhase;
using Api::BotCallbackState;

[[nodiscard]] int Fail(const char *message) {
	std::fprintf(stderr, "%s\n", message);
	return 1;
}

[[nodiscard]] FullMsgId MessageId(int peer, int message) {
	return FullMsgId(
		peerFromUser(UserId(uint64(peer))),
		MsgId(message));
}

[[nodiscard]] BotCallbackButton Button(
		FullMsgId messageId,
		uint64 revision,
		int row,
		int column,
		QByteArray data = "data",
		BotCallbackButtonType type = BotCallbackButtonType::Callback) {
	return {
		.messageId = messageId,
		.markupRevision = revision,
		.row = row,
		.column = column,
		.type = type,
		.data = std::move(data),
	};
}

[[nodiscard]] int ScenarioMarkupReplacement() {
	auto state = BotCallbackState();
	const auto messageId = MessageId(1, 10);
	const auto firstRevision = state.nextMarkupRevision(messageId);
	const auto firstButton = Button(messageId, firstRevision, 0, 0);
	const auto first = state.start(
		firstButton,
		BotCallbackPhase::Sending,
		1500);
	const auto secondRevision = state.nextMarkupRevision(messageId);
	const auto operation = state.lookup(first);
	if (!first
		|| secondRevision == firstRevision
		|| !operation
		|| operation->phase != BotCallbackPhase::Detached
		|| state.buttonLoading(firstButton)) {
		return Fail("markup replacement did not detach the old operation");
	}
	return 0;
}

[[nodiscard]] int ScenarioOutOfOrderReplies() {
	auto state = BotCallbackState();
	const auto messageId = MessageId(1, 11);
	const auto firstRevision = state.nextMarkupRevision(messageId);
	const auto firstButton = Button(messageId, firstRevision, 0, 0, "a");
	const auto first = state.start(
		firstButton,
		BotCallbackPhase::Sending,
		1500);
	const auto secondRevision = state.nextMarkupRevision(messageId);
	const auto secondButton = Button(messageId, secondRevision, 0, 0, "b");
	const auto second = state.start(
		secondButton,
		BotCallbackPhase::Sending,
		50);
	const auto secondResult = state.complete(second);
	const auto firstResult = state.complete(first);
	if (!first
		|| !second
		|| !secondResult
		|| secondResult->button != secondButton
		|| state.buttonLoading(secondButton)
		|| !firstResult
		|| firstResult->button != firstButton
		|| state.buttonLoading(secondButton)) {
		return Fail("out-of-order reply changed a newer operation");
	}
	return 0;
}

[[nodiscard]] int ScenarioButtonIdentity() {
	auto state = BotCallbackState();
	const auto firstMessage = MessageId(1, 12);
	const auto secondMessage = MessageId(1, 13);
	const auto firstRevision = state.nextMarkupRevision(firstMessage);
	const auto secondRevision = state.nextMarkupRevision(secondMessage);
	const auto first = Button(firstMessage, firstRevision, 0, 0, "same");
	const auto second = Button(firstMessage, firstRevision, 0, 1, "same");
	const auto third = Button(secondMessage, secondRevision, 0, 0, "same");
	const auto game = Button(
		secondMessage,
		secondRevision,
		0,
		1,
		{},
		BotCallbackButtonType::Game);
	if (!state.start(first, BotCallbackPhase::Sending, 100)
		|| !state.start(second, BotCallbackPhase::Sending, 100)
		|| !state.start(third, BotCallbackPhase::Sending, 100)
		|| !state.start(game, BotCallbackPhase::Sending, 100)
		|| !state.buttonLoading(first)
		|| !state.buttonLoading(second)
		|| !state.buttonLoading(third)
		|| !state.buttonLoading(game)) {
		return Fail("button identity collapsed coordinates or messages");
	}
	return 0;
}

[[nodiscard]] int ScenarioMessageRemoval() {
	auto state = BotCallbackState();
	const auto messageId = MessageId(1, 14);
	const auto revision = state.nextMarkupRevision(messageId);
	const auto button = Button(messageId, revision, 0, 0);
	const auto operationId = state.start(
		button,
		BotCallbackPhase::Sending,
		100);
	if (!operationId
		|| !state.detachMessage(messageId)
		|| state.buttonLoading(button)
		|| !state.complete(operationId)) {
		return Fail("message removal did not preserve safe late completion");
	}
	return 0;
}

[[nodiscard]] int ScenarioIdenticalMarkupReplacement() {
	auto state = BotCallbackState();
	const auto messageId = MessageId(1, 15);
	const auto firstRevision = state.nextMarkupRevision(messageId);
	const auto firstButton = Button(messageId, firstRevision, 0, 0, "same");
	const auto operationId = state.start(
		firstButton,
		BotCallbackPhase::Sending,
		100);
	const auto secondRevision = state.nextMarkupRevision(messageId);
	const auto secondButton = Button(messageId, secondRevision, 0, 0, "same");
	if (!operationId
		|| firstRevision == secondRevision
		|| state.buttonLoading(secondButton)) {
		return Fail("identical replacement reused the markup generation");
	}
	return 0;
}

[[nodiscard]] int ScenarioNetworkAndTimeout() {
	auto state = BotCallbackState();
	const auto messageId = MessageId(1, 16);
	const auto revision = state.nextMarkupRevision(messageId);
	const auto button = Button(messageId, revision, 0, 0);
	const auto first = state.start(
		button,
		BotCallbackPhase::Sending,
		100);
	const auto duplicate = state.start(
		button,
		BotCallbackPhase::Sending,
		100);
	if (!first
		|| duplicate
		|| !state.requestSent(first, 42)
		|| !state.timeout(99).empty()
		|| !state.buttonLoading(button)) {
		return Fail("network pause ended the operation before its deadline");
	}
	const auto timedOut = state.timeout(100);
	const auto second = state.start(
		button,
		BotCallbackPhase::Sending,
		200);
	if (timedOut.size() != 1
		|| state.buttonLoading(button) != bool(second)
		|| !state.complete(first)
		|| !state.buttonLoading(button)
		|| !state.complete(second)) {
		return Fail("late timed-out reply changed the explicit retry");
	}
	return 0;
}

[[nodiscard]] int ScenarioTerminalStates() {
	auto state = BotCallbackState();
	const auto messageId = MessageId(1, 17);
	const auto revision = state.nextMarkupRevision(messageId);
	const auto button = Button(messageId, revision, 0, 0);
	const auto completed = state.start(
		button,
		BotCallbackPhase::Sending,
		100);
	const auto completedResult = state.complete(completed);
	const auto failed = state.start(
		button,
		BotCallbackPhase::Sending,
		100);
	const auto failedResult = state.fail(failed);
	if (!completedResult
		|| completedResult->phase != BotCallbackPhase::Completed
		|| !failedResult
		|| failedResult->phase != BotCallbackPhase::Failed
		|| state.operationCount()) {
		return Fail("done or fail did not finish its exact operation");
	}
	return 0;
}

[[nodiscard]] int ScenarioPasswordPreparation() {
	auto state = BotCallbackState();
	const auto messageId = MessageId(1, 18);
	const auto revision = state.nextMarkupRevision(messageId);
	const auto button = Button(
		messageId,
		revision,
		0,
		0,
		"password",
		BotCallbackButtonType::CallbackWithPassword);
	const auto operationId = state.start(
		button,
		BotCallbackPhase::PreparingPassword,
		100);
	if (!operationId
		|| !state.requestSent(operationId, 50)
		|| !state.requestFinished(operationId)
		|| !state.beginSending(operationId, 200)
		|| !state.requestSent(operationId, 51)) {
		return Fail("password preparation did not transition to sending");
	}
	const auto operation = state.lookup(operationId);
	if (!operation
		|| operation->phase != BotCallbackPhase::Sending
		|| operation->requestId != 51) {
		return Fail("password callback kept an implicit sentinel state");
	}
	return 0;
}

[[nodiscard]] int ScenarioCancellation() {
	auto state = BotCallbackState();
	const auto messageId = MessageId(1, 19);
	const auto revision = state.nextMarkupRevision(messageId);
	const auto button = Button(messageId, revision, 0, 0);
	const auto operationId = state.start(
		button,
		BotCallbackPhase::Sending,
		100);
	if (!operationId
		|| !state.requestSent(operationId, 60)
		|| !state.cancel(operationId)
		|| state.buttonLoading(button)
		|| !state.complete(operationId)) {
		return Fail("cancel did not detach visuals from the pending request");
	}
	return 0;
}

[[nodiscard]] int ScenarioSessionClear() {
	auto state = BotCallbackState();
	const auto firstMessage = MessageId(1, 21);
	const auto secondMessage = MessageId(1, 22);
	const auto first = Button(
		firstMessage,
		state.nextMarkupRevision(firstMessage),
		0,
		0);
	const auto second = Button(
		secondMessage,
		state.nextMarkupRevision(secondMessage),
		0,
		0);
	if (!state.start(first, BotCallbackPhase::Sending, 100)
		|| !state.start(second, BotCallbackPhase::Sending, 100)) {
		return Fail("session clear setup lost an operation");
	}
	const auto repaint = state.clear();
	if (repaint.size() != 2
		|| state.operationCount()
		|| state.buttonLoading(first)
		|| state.buttonLoading(second)) {
		return Fail("session clear did not finish all visual operations");
	}
	return 0;
}

[[nodiscard]] int ScenarioStress() {
	auto state = BotCallbackState();
	const auto messageId = MessageId(1, 20);
	auto operations = std::vector<uint64>();
	operations.reserve(1000);
	auto lastButton = BotCallbackButton();
	for (auto i = 0; i != 1000; ++i) {
		const auto revision = state.nextMarkupRevision(messageId);
		lastButton = Button(
			messageId,
			revision,
			0,
			0,
			QByteArray::number(i));
		const auto operationId = state.start(
			lastButton,
			BotCallbackPhase::Sending,
			1000 + i);
		if (!operationId || !state.requestSent(operationId, i + 1)) {
			return Fail("stress setup lost an operation");
		}
		operations.push_back(operationId);
	}
	auto random = std::mt19937(0xC011BACC);
	std::shuffle(begin(operations), end(operations), random);
	for (const auto operationId : operations) {
		const auto wasLatest = state.buttonLoading(lastButton);
		const auto operation = state.complete(operationId);
		if (!operation) {
			return Fail("stress completion lost operation identity");
		}
		if (operation->button != lastButton
			&& wasLatest != state.buttonLoading(lastButton)) {
			return Fail("old stress reply changed the latest operation");
		}
	}
	if (state.operationCount()) {
		return Fail("stress completion leaked operations");
	}
	return 0;
}

} // namespace

int main(int, char *[]) {
	for (const auto scenario : {
		ScenarioMarkupReplacement,
		ScenarioOutOfOrderReplies,
		ScenarioButtonIdentity,
		ScenarioMessageRemoval,
		ScenarioIdenticalMarkupReplacement,
		ScenarioNetworkAndTimeout,
		ScenarioTerminalStates,
		ScenarioPasswordPreparation,
		ScenarioCancellation,
		ScenarioSessionClear,
		ScenarioStress,
	}) {
		if (const auto result = scenario()) {
			return result;
		}
	}
	return 0;
}

/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "api/api_bot_callback_state.h"

#include <algorithm>

namespace Api {
namespace {

void UniqueMessageIds(std::vector<FullMsgId> &messageIds) {
	std::sort(begin(messageIds), end(messageIds));
	messageIds.erase(
		std::unique(begin(messageIds), end(messageIds)),
		end(messageIds));
}

} // namespace

bool BotCallbackState::Active(BotCallbackPhase phase) {
	return phase == BotCallbackPhase::PreparingPassword
		|| phase == BotCallbackPhase::Sending;
}

bool BotCallbackState::Loading(const BotCallbackOperation &operation) {
	return Active(operation.phase) && operation.visualDeadline > 0;
}

uint64 BotCallbackState::nextMarkupRevision(FullMsgId messageId) {
	[[maybe_unused]] const auto detached = detachMessage(messageId);
	if (!++_lastMarkupRevision) {
		++_lastMarkupRevision;
	}
	return _lastMarkupRevision;
}

uint64 BotCallbackState::start(
		BotCallbackButton button,
		BotCallbackPhase phase,
		crl::time visualDeadline) {
	Expects(Active(phase));

	if (buttonBusy(button)) {
		return 0;
	}
	const auto operationId = nextOperationId();
	_operations.emplace(operationId, BotCallbackOperation{
		.operationId = operationId,
		.button = std::move(button),
		.phase = phase,
		.visualDeadline = visualDeadline,
	});
	return operationId;
}

bool BotCallbackState::requestSent(
		uint64 operationId,
		mtpRequestId requestId) {
	const auto i = _operations.find(operationId);
	if (i == end(_operations)) {
		return false;
	}
	i->second.requestId = requestId;
	return true;
}

bool BotCallbackState::requestFinished(uint64 operationId) {
	const auto i = _operations.find(operationId);
	if (i == end(_operations)) {
		return false;
	}
	i->second.requestId = 0;
	return true;
}

bool BotCallbackState::beginSending(
		uint64 operationId,
		crl::time visualDeadline) {
	const auto i = _operations.find(operationId);
	if (i == end(_operations)
		|| i->second.phase != BotCallbackPhase::PreparingPassword) {
		return false;
	}
	i->second.phase = BotCallbackPhase::Sending;
	i->second.visualDeadline = visualDeadline;
	return true;
}

bool BotCallbackState::buttonBusy(const BotCallbackButton &button) const {
	for (const auto &entry : _operations) {
		const auto &operation = entry.second;
		if (Active(operation.phase) && operation.button == button) {
			return true;
		}
	}
	return false;
}

bool BotCallbackState::buttonLoading(const BotCallbackButton &button) const {
	for (const auto &entry : _operations) {
		const auto &operation = entry.second;
		if (Loading(operation) && operation.button == button) {
			return true;
		}
	}
	return false;
}

bool BotCallbackState::operationActive(uint64 operationId) const {
	const auto operation = lookup(operationId);
	return operation && Active(operation->phase);
}

const BotCallbackOperation *BotCallbackState::lookup(
		uint64 operationId) const {
	const auto i = _operations.find(operationId);
	return (i != end(_operations)) ? &i->second : nullptr;
}

std::optional<BotCallbackOperation> BotCallbackState::complete(
		uint64 operationId) {
	return finish(operationId, BotCallbackPhase::Completed);
}

std::optional<BotCallbackOperation> BotCallbackState::fail(
		uint64 operationId) {
	return finish(operationId, BotCallbackPhase::Failed);
}

bool BotCallbackState::cancel(uint64 operationId) {
	const auto i = _operations.find(operationId);
	if (i == end(_operations)) {
		return false;
	} else if (!i->second.requestId) {
		_operations.erase(i);
	} else {
		i->second.phase = BotCallbackPhase::Detached;
		i->second.visualDeadline = 0;
	}
	return true;
}

bool BotCallbackState::detachMessage(FullMsgId messageId) {
	auto changed = false;
	for (auto &entry : _operations) {
		auto &operation = entry.second;
		if (operation.button.messageId == messageId
			&& Active(operation.phase)) {
			operation.phase = BotCallbackPhase::Detached;
			changed = true;
		}
	}
	return changed;
}

std::vector<FullMsgId> BotCallbackState::timeout(crl::time now) {
	auto result = std::vector<FullMsgId>();
	for (auto &entry : _operations) {
		auto &operation = entry.second;
		if (Loading(operation) && operation.visualDeadline <= now) {
			operation.phase = BotCallbackPhase::TimedOut;
			result.push_back(operation.button.messageId);
		}
	}
	UniqueMessageIds(result);
	return result;
}

std::vector<FullMsgId> BotCallbackState::clear() {
	auto result = std::vector<FullMsgId>();
	result.reserve(_operations.size());
	for (const auto &entry : _operations) {
		const auto &operation = entry.second;
		result.push_back(operation.button.messageId);
	}
	_operations.clear();
	UniqueMessageIds(result);
	return result;
}

std::optional<crl::time> BotCallbackState::nextVisualDeadline() const {
	auto result = std::optional<crl::time>();
	for (const auto &entry : _operations) {
		const auto &operation = entry.second;
		if (Loading(operation)
			&& (!result || operation.visualDeadline < *result)) {
			result = operation.visualDeadline;
		}
	}
	return result;
}

int BotCallbackState::operationCount() const {
	return int(_operations.size());
}

std::optional<BotCallbackOperation> BotCallbackState::finish(
		uint64 operationId,
		BotCallbackPhase phase) {
	const auto i = _operations.find(operationId);
	if (i == end(_operations)) {
		return std::nullopt;
	}
	auto result = std::move(i->second);
	result.phase = phase;
	_operations.erase(i);
	return result;
}

uint64 BotCallbackState::nextOperationId() {
	do {
		if (!++_lastOperationId) {
			++_lastOperationId;
		}
	} while (_operations.find(_lastOperationId) != end(_operations));
	return _lastOperationId;
}

} // namespace Api

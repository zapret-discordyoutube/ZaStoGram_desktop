/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "base/flat_map.h"
#include "data/data_msg_id.h"
#include "mtproto/core_types.h"

#include <crl/crl_time.h>

#include <optional>
#include <vector>

namespace Api {

enum class BotCallbackPhase {
	PreparingPassword,
	Sending,
	Completed,
	Failed,
	TimedOut,
	Detached,
};

enum class BotCallbackButtonType {
	Callback,
	CallbackWithPassword,
	Game,
};

struct BotCallbackButton {
	FullMsgId messageId;
	uint64 markupRevision = 0;
	int row = 0;
	int column = 0;
	BotCallbackButtonType type = BotCallbackButtonType::Callback;
	QByteArray data;
	QByteArray richPageKey;

	friend inline bool operator==(
		const BotCallbackButton &,
		const BotCallbackButton &) = default;
};

struct BotCallbackOperation {
	uint64 operationId = 0;
	mtpRequestId requestId = 0;
	BotCallbackButton button;
	BotCallbackPhase phase = BotCallbackPhase::Sending;
	crl::time visualDeadline = 0;
};

class BotCallbackState final {
public:
	[[nodiscard]] uint64 nextMarkupRevision(FullMsgId messageId);
	[[nodiscard]] uint64 start(
		BotCallbackButton button,
		BotCallbackPhase phase,
		crl::time visualDeadline);

	[[nodiscard]] bool requestSent(
		uint64 operationId,
		mtpRequestId requestId);
	[[nodiscard]] bool requestFinished(uint64 operationId);
	[[nodiscard]] bool beginSending(
		uint64 operationId,
		crl::time visualDeadline);

	[[nodiscard]] bool buttonBusy(const BotCallbackButton &button) const;
	[[nodiscard]] bool buttonLoading(const BotCallbackButton &button) const;
	[[nodiscard]] bool operationActive(uint64 operationId) const;
	[[nodiscard]] const BotCallbackOperation *lookup(
		uint64 operationId) const;

	[[nodiscard]] std::optional<BotCallbackOperation> complete(
		uint64 operationId);
	[[nodiscard]] std::optional<BotCallbackOperation> fail(
		uint64 operationId);
	[[nodiscard]] bool cancel(uint64 operationId);
	[[nodiscard]] bool detachMessage(FullMsgId messageId);
	[[nodiscard]] std::vector<FullMsgId> timeout(crl::time now);
	[[nodiscard]] std::vector<FullMsgId> clear();

	[[nodiscard]] std::optional<crl::time> nextVisualDeadline() const;
	[[nodiscard]] int operationCount() const;

private:
	[[nodiscard]] static bool Active(BotCallbackPhase phase);
	[[nodiscard]] static bool Loading(const BotCallbackOperation &operation);
	[[nodiscard]] std::optional<BotCallbackOperation> finish(
		uint64 operationId,
		BotCallbackPhase phase);
	[[nodiscard]] uint64 nextOperationId();

	base::flat_map<uint64, BotCallbackOperation> _operations;
	uint64 _lastOperationId = 0;
	uint64 _lastMarkupRevision = 0;

};

} // namespace Api

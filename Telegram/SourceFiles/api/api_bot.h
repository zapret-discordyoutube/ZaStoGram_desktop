/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "api/api_bot_callback_state.h"

#include <memory>

struct ClickHandlerContext;
class HistoryItem;
struct HistoryMessageMarkupButton;

namespace Main {
class Session;
} // namespace Main

namespace Window {
class SessionController;
} // namespace Window

namespace Api {

using BotButtonLookup = Fn<const HistoryMessageMarkupButton*()>;

class BotCallbackManager final {
public:
	explicit BotCallbackManager(not_null<Main::Session*> session);
	~BotCallbackManager();

	[[nodiscard]] uint64 markupUpdated(FullMsgId messageId);
	[[nodiscard]] uint64 start(
		BotCallbackButton button,
		BotCallbackPhase phase);
	[[nodiscard]] bool requestSent(
		uint64 operationId,
		mtpRequestId requestId);
	[[nodiscard]] bool requestFinished(uint64 operationId);
	[[nodiscard]] bool beginSending(uint64 operationId);

	[[nodiscard]] bool buttonLoading(
		const BotCallbackButton &button) const;
	[[nodiscard]] bool operationActive(uint64 operationId) const;
	[[nodiscard]] std::optional<BotCallbackOperation> complete(
		uint64 operationId);
	[[nodiscard]] std::optional<BotCallbackOperation> fail(
		uint64 operationId);
	void cancel(uint64 operationId);
	void detachMessage(FullMsgId messageId);
	void finishSession();

private:
	class Private;
	const std::unique_ptr<Private> _private;

};

void SendBotCallbackData(
	not_null<Window::SessionController*> controller,
	not_null<HistoryItem*> item,
	BotButtonLookup lookup);

void SendBotCallbackDataWithPassword(
	not_null<Window::SessionController*> controller,
	not_null<HistoryItem*> item,
	BotButtonLookup lookup);

bool SwitchInlineBotButtonReceived(
	not_null<Window::SessionController*> controller,
	const QByteArray &queryWithPeerTypes,
	UserData *samePeerBot = nullptr,
	MsgId samePeerReplyTo = 0);

void ActivateBotButton(ClickHandlerContext context, BotButtonLookup lookup);
void ActivateBotCommand(ClickHandlerContext context, int row, int column);
void ActivateRichPageBotButton(
	ClickHandlerContext context,
	const HistoryMessageMarkupButton &button);

} // namespace Api

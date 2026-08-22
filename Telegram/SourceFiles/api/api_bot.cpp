/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "api/api_bot.h"

#include "apiwrap.h"
#include "api/api_cloud_password.h"
#include "api/api_send_progress.h"
#include "api/api_suggest_post.h"
#include "base/timer.h"
#include "boxes/peers/choose_peer_box.h"
#include "boxes/peers/create_managed_bot_box.h"
#include "boxes/passcode_box.h"
#include "boxes/share_box.h"
#include "boxes/url_auth_box.h"
#include "lang/lang_keys.h"
#include "chat_helpers/bot_command.h"
#include "core/core_cloud_password.h"
#include "core/click_handler_types.h"
#include "data/components/ephemeral_messages.h"
#include "data/data_changes.h"
#include "data/data_peer.h"
#include "data/data_poll.h"
#include "data/data_user.h"
#include "data/data_session.h"
#include "history/history.h"
#include "history/history_item.h"
#include "history/history_item_components.h"
#include "inline_bots/bot_attach_web_view.h"
#include "payments/payments_checkout_process.h"
#include "payments/payments_non_panel_process.h"
#include "main/main_session.h"
#include "mainwidget.h"
#include "mainwindow.h"
#include "window/window_session_controller.h"
#include "window/window_peer_menu.h"
#include "ui/boxes/confirm_box.h"
#include "ui/toast/toast.h"
#include "ui/layers/generic_box.h"
#include "ui/text/text_utilities.h"
#include "styles/style_chat.h"
#include "styles/style_chat_helpers.h"

#include <QtCore/QDataStream>
#include <QtGui/QGuiApplication>
#include <QtGui/QClipboard>

namespace Api {

class BotCallbackManager::Private final {
public:
	explicit Private(not_null<Main::Session*> session);

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
	static constexpr auto kVisualTimeout = 30 * crl::time(1000);

	void repaint(FullMsgId messageId) const;
	void repaint(const std::vector<FullMsgId> &messageIds) const;
	void scheduleTimeout();
	void timeout();

	const not_null<Main::Session*> _session;
	BotCallbackState _state;
	base::Timer _timer;
	rpl::lifetime _lifetime;

};

BotCallbackManager::Private::Private(not_null<Main::Session*> session)
: _session(session)
, _timer([=] { timeout(); }) {
	_session->data().itemRemoved(
	) | rpl::on_next([=](not_null<const HistoryItem*> item) {
		detachMessage(item->fullId());
	}, _lifetime);
	_session->data().sessionDataAboutToBeCleared(
	) | rpl::on_next([=] {
		finishSession();
	}, _lifetime);
}

uint64 BotCallbackManager::Private::markupUpdated(FullMsgId messageId) {
	const auto result = _state.nextMarkupRevision(messageId);
	repaint(messageId);
	scheduleTimeout();
	return result;
}

uint64 BotCallbackManager::Private::start(
		BotCallbackButton button,
		BotCallbackPhase phase) {
	const auto messageId = button.messageId;
	const auto result = _state.start(
		std::move(button),
		phase,
		crl::now() + kVisualTimeout);
	if (result) {
		repaint(messageId);
		scheduleTimeout();
	}
	return result;
}

bool BotCallbackManager::Private::requestSent(
		uint64 operationId,
		mtpRequestId requestId) {
	return _state.requestSent(operationId, requestId);
}

bool BotCallbackManager::Private::requestFinished(uint64 operationId) {
	return _state.requestFinished(operationId);
}

bool BotCallbackManager::Private::beginSending(uint64 operationId) {
	const auto operation = _state.lookup(operationId);
	if (!operation) {
		return false;
	}
	const auto messageId = operation->button.messageId;
	if (!_state.beginSending(
		operationId,
		crl::now() + kVisualTimeout)) {
		return false;
	}
	repaint(messageId);
	scheduleTimeout();
	return true;
}

bool BotCallbackManager::Private::buttonLoading(
		const BotCallbackButton &button) const {
	return _state.buttonLoading(button);
}

bool BotCallbackManager::Private::operationActive(
		uint64 operationId) const {
	return _state.operationActive(operationId);
}

std::optional<BotCallbackOperation> BotCallbackManager::Private::complete(
		uint64 operationId) {
	const auto result = _state.complete(operationId);
	if (result) {
		repaint(result->button.messageId);
		scheduleTimeout();
	}
	return result;
}

std::optional<BotCallbackOperation> BotCallbackManager::Private::fail(
		uint64 operationId) {
	const auto result = _state.fail(operationId);
	if (result) {
		repaint(result->button.messageId);
		scheduleTimeout();
	}
	return result;
}

void BotCallbackManager::Private::cancel(uint64 operationId) {
	const auto operation = _state.lookup(operationId);
	if (!operation) {
		return;
	}
	const auto messageId = operation->button.messageId;
	if (_state.cancel(operationId)) {
		repaint(messageId);
		scheduleTimeout();
	}
}

void BotCallbackManager::Private::detachMessage(FullMsgId messageId) {
	if (_state.detachMessage(messageId)) {
		repaint(messageId);
		scheduleTimeout();
	}
}

void BotCallbackManager::Private::finishSession() {
	_timer.cancel();
	repaint(_state.clear());
}

void BotCallbackManager::Private::repaint(FullMsgId messageId) const {
	if (const auto item = _session->data().message(messageId)) {
		item->history()->owner().requestItemRepaint(item);
	}
}

void BotCallbackManager::Private::repaint(
		const std::vector<FullMsgId> &messageIds) const {
	for (const auto &messageId : messageIds) {
		repaint(messageId);
	}
}

void BotCallbackManager::Private::scheduleTimeout() {
	_timer.cancel();
	if (const auto deadline = _state.nextVisualDeadline()) {
		_timer.callOnce(std::max(crl::time(0), *deadline - crl::now()));
	}
}

void BotCallbackManager::Private::timeout() {
	repaint(_state.timeout(crl::now()));
	scheduleTimeout();
}

BotCallbackManager::BotCallbackManager(not_null<Main::Session*> session)
: _private(std::make_unique<Private>(session)) {
}

BotCallbackManager::~BotCallbackManager() = default;

uint64 BotCallbackManager::markupUpdated(FullMsgId messageId) {
	return _private->markupUpdated(messageId);
}

uint64 BotCallbackManager::start(
		BotCallbackButton button,
		BotCallbackPhase phase) {
	return _private->start(std::move(button), phase);
}

bool BotCallbackManager::requestSent(
		uint64 operationId,
		mtpRequestId requestId) {
	return _private->requestSent(operationId, requestId);
}

bool BotCallbackManager::requestFinished(uint64 operationId) {
	return _private->requestFinished(operationId);
}

bool BotCallbackManager::beginSending(uint64 operationId) {
	return _private->beginSending(operationId);
}

bool BotCallbackManager::buttonLoading(
		const BotCallbackButton &button) const {
	return _private->buttonLoading(button);
}

bool BotCallbackManager::operationActive(uint64 operationId) const {
	return _private->operationActive(operationId);
}

std::optional<BotCallbackOperation> BotCallbackManager::complete(
		uint64 operationId) {
	return _private->complete(operationId);
}

std::optional<BotCallbackOperation> BotCallbackManager::fail(
		uint64 operationId) {
	return _private->fail(operationId);
}

void BotCallbackManager::cancel(uint64 operationId) {
	_private->cancel(operationId);
}

void BotCallbackManager::detachMessage(FullMsgId messageId) {
	_private->detachMessage(messageId);
}

void BotCallbackManager::finishSession() {
	_private->finishSession();
}

namespace {

[[nodiscard]] std::optional<BotCallbackButtonType> CallbackButtonType(
		HistoryMessageMarkupButton::Type type) {
	using Type = HistoryMessageMarkupButton::Type;
	switch (type) {
	case Type::Callback:
		return BotCallbackButtonType::Callback;
	case Type::CallbackWithPassword:
		return BotCallbackButtonType::CallbackWithPassword;
	case Type::Game:
		return BotCallbackButtonType::Game;
	default:
		return std::nullopt;
	}
}

[[nodiscard]] std::optional<BotCallbackButton> ResolveCallbackButton(
		not_null<HistoryItem*> item,
		const BotButtonLookup &lookup) {
	const auto button = lookup();
	if (!button) {
		return std::nullopt;
	}
	const auto type = CallbackButtonType(button->type);
	if (!type) {
		return std::nullopt;
	}
	const auto markup = item->Get<HistoryMessageReplyMarkup>();
	if (markup) {
		for (auto row = 0; row != markup->data.rows.size(); ++row) {
			const auto &buttons = markup->data.rows[row];
			for (auto column = 0; column != buttons.size(); ++column) {
				if (&buttons[column] == button) {
					return BotCallbackButton{
						.messageId = item->fullId(),
						.markupRevision = markup->markupRevision,
						.row = row,
						.column = column,
						.type = *type,
						.data = button->data,
					};
				}
			}
		}
	}
	const auto owner = &item->history()->owner();
	const auto key = HistoryMessageMarkupButton::RichPageButtonKey(*button);
	if (HistoryMessageMarkupButton::GetRichPageButton(
			owner,
			item->fullId(),
			key) != button) {
		return std::nullopt;
	}
	return BotCallbackButton{
		.messageId = item->fullId(),
		.row = -1,
		.column = -1,
		.type = *type,
		.data = button->data,
		.richPageKey = key,
	};
}

[[nodiscard]] bool CallbackButtonMatches(
		not_null<HistoryItem*> item,
		const BotCallbackButton &button) {
	const auto owner = &item->history()->owner();
	const auto current = ResolveCallbackButton(item, [=] {
		return button.richPageKey.isEmpty()
			? HistoryMessageMarkupButton::Get(
				owner,
				item->fullId(),
				button.row,
				button.column)
			: HistoryMessageMarkupButton::GetRichPageButton(
				owner,
				item->fullId(),
				button.richPageKey);
	});
	return current && *current == button;
}

using BotCallbackErrorHandler = Fn<bool(const QString &)>;

void SendBotCallbackRequest(
		not_null<Window::SessionController*> controller,
		not_null<HistoryItem*> item,
		BotCallbackButton button,
		uint64 operationId,
		std::optional<Core::CloudPasswordResult> password,
		Fn<void()> done = nullptr,
		BotCallbackErrorHandler handleError = nullptr,
		Fn<bool()> operationCurrent = nullptr) {
	const auto session = &item->history()->session();
	const auto callbacks = &session->botCallbacks();
	if (!item->isRegular() && !item->isEphemeral()) {
		[[maybe_unused]] const auto failed = callbacks->fail(operationId);
		return;
	}
	const auto history = item->history();
	const auto owner = &history->owner();
	const auto api = &session->api();
	const auto bot = item->getMessageBot();
	const auto fullId = button.messageId;
	const auto isGame = (button.type == BotCallbackButtonType::Game);

	auto flags = MTPmessages_GetBotCallbackAnswer::Flags(0);
	auto sendData = QByteArray();
	if (isGame) {
		flags |= MTPmessages_GetBotCallbackAnswer::Flag::f_game;
	} else {
		flags |= MTPmessages_GetBotCallbackAnswer::Flag::f_data;
		sendData = button.data;
	}
	const auto withPassword = password.has_value();
	if (withPassword) {
		flags |= MTPmessages_GetBotCallbackAnswer::Flag::f_password;
	}
	const auto ephemeralId = item->isEphemeral()
		? session->ephemeralMessages().lookupId(item)
		: 0;
	if (item->isEphemeral() && (!ephemeralId || isGame || withPassword)) {
		[[maybe_unused]] const auto failed = callbacks->fail(operationId);
		return;
	}
	if (item->isEphemeral()) {
		session->ephemeralMessages().noteCallbackTopic(
			history,
			item->from()->id,
			item->topicRootId());
	}
	const auto weak = base::make_weak(controller);
	const auto show = controller->uiShow();
	const auto handleDone = [=](
			const MTPmessages_BotCallbackAnswer &result) {
		const auto operation = callbacks->complete(operationId);
		if (!operation) {
			return;
		}
		const auto guard = gsl::finally([&] {
			if (done) {
				done();
			}
		});
		const auto item = owner->message(fullId);
		if (!item) {
			return;
		}
		const auto &data = result.data();
		const auto message = data.vmessage()
			? qs(*data.vmessage())
			: QString();
		const auto link = data.vurl() ? qs(*data.vurl()) : QString();
		const auto showAlert = data.is_alert();
		const auto closePassword = withPassword
			&& (!operationCurrent || operationCurrent());

		if (!message.isEmpty()) {
			if (!show->valid()) {
				return;
			} else if (showAlert) {
				show->showBox(Ui::MakeInformBox(message));
			} else {
				if (closePassword) {
					show->hideLayer();
				}
				show->showToast(message);
			}
		} else if (!link.isEmpty()) {
			if (!isGame) {
				UrlClickHandler::Open(link);
				return;
			}
			BotGameUrlClickHandler(bot, link).onClick({
				Qt::LeftButton,
				QVariant::fromValue(ClickHandlerContext{
					.itemId = item->fullId(),
					.sessionWindow = weak,
				}),
			});
			session->sendProgressManager().update(
				history,
				Api::SendProgressType::PlayGame);
		} else if (closePassword) {
			show->hideLayer();
		}
	};
	const auto handleFail = [=](const MTP::Error &error) {
		const auto current = operationCurrent
			? operationCurrent()
			: callbacks->operationActive(operationId);
		if (handleError
			&& current
			&& handleError(error.type())) {
			[[maybe_unused]] const auto finished
				= callbacks->requestFinished(operationId);
			return;
		}
		[[maybe_unused]] const auto failed = callbacks->fail(operationId);
	};
	const auto requestId = ephemeralId
		? api->request(MTPephemeral_GetCallbackAnswer(
			MTP_flags(sendData.isEmpty()
				? MTPephemeral_GetCallbackAnswer::Flag(0)
				: MTPephemeral_GetCallbackAnswer::Flag::f_data),
			history->peer->input(),
			MTP_int(ephemeralId),
			MTP_bytes(sendData)
		)).done(handleDone).fail(handleFail).send()
		: api->request(MTPmessages_GetBotCallbackAnswer(
			MTP_flags(flags),
			history->peer->input(),
			MTP_int(item->id),
			MTP_bytes(sendData),
			password ? password->result : MTP_inputCheckPasswordEmpty()
		)).done(handleDone).fail(handleFail).send();
	[[maybe_unused]] const auto requestStored = callbacks->requestSent(
		operationId,
		requestId);

	session->changes().messageUpdated(
		item,
		Data::MessageUpdate::Flag::BotCallbackSent
	);
}

void HideSingleUseKeyboard(
		not_null<Window::SessionController*> controller,
		not_null<HistoryItem*> item) {
	controller->content()->hideSingleUseKeyboard(item->fullId());
}

} // namespace

void SendBotCallbackData(
		not_null<Window::SessionController*> controller,
		not_null<HistoryItem*> item,
		BotButtonLookup lookup) {
	if (!item->isRegular() && !item->isEphemeral()) {
		return;
	}
	const auto button = ResolveCallbackButton(item, lookup);
	if (!button) {
		return;
	}
	const auto callbacks = &item->history()->session().botCallbacks();
	const auto operationId = callbacks->start(
		*button,
		BotCallbackPhase::Sending);
	if (!operationId) {
		return;
	}
	SendBotCallbackRequest(
		controller,
		item,
		*button,
		operationId,
		std::nullopt);
}

void SendBotCallbackDataWithPassword(
		not_null<Window::SessionController*> controller,
		not_null<HistoryItem*> item,
		BotButtonLookup lookup) {
	if (!item->isRegular()) {
		return;
	}
	const auto history = item->history();
	const auto session = &history->session();
	const auto owner = &history->owner();
	const auto api = &session->api();
	const auto fullId = item->fullId();
	const auto button = ResolveCallbackButton(item, lookup);
	if (!button
		|| button->type != BotCallbackButtonType::CallbackWithPassword) {
		return;
	}
	const auto callbacks = &session->botCallbacks();
	const auto operationId = callbacks->start(
		*button,
		BotCallbackPhase::PreparingPassword);
	if (!operationId) {
		return;
	}
	struct PasswordState {
		BotCallbackButton button;
		uint64 operationId = 0;
		rpl::lifetime cloudStateLifetime;
	};
	const auto state = std::make_shared<PasswordState>();
	state->button = *button;
	state->operationId = operationId;
	api->cloudPassword().reload();
	const auto weak = base::make_weak(controller);
	const auto show = controller->uiShow();
	SendBotCallbackRequest(controller, item, *button, operationId, {}, {}, [=](
			const QString &error) {
		const auto current = owner->message(fullId);
		if (!current
			|| !callbacks->operationActive(state->operationId)
			|| !CallbackButtonMatches(current, state->button)) {
			return false;
		}
		auto box = PrePasswordErrorBox(
			error,
			session,
			tr::lng_bots_password_confirm_check_about(
				tr::now,
				tr::marked));
		if (box) {
			show->showBox(std::move(box), Ui::LayerOption::CloseOther);
			return false;
		} else {
			api->cloudPassword().state(
			) | rpl::take(
				1
			) | rpl::on_next([=](const Core::CloudPasswordState &cloudState) {
				state->cloudStateLifetime.destroy();
				const auto item = owner->message(fullId);
				if (!item
					|| !callbacks->operationActive(state->operationId)
					|| !CallbackButtonMatches(item, state->button)) {
					callbacks->cancel(state->operationId);
					return;
				}
				auto fields = PasscodeBox::CloudFields::From(cloudState);
				fields.customTitle = tr::lng_bots_password_confirm_title();
				fields.customDescription
					= tr::lng_bots_password_confirm_description(tr::now);
				fields.customSubmitButton = tr::lng_passcode_submit();
				fields.customCheckCallback = [=](
						const Core::CloudPasswordResult &result,
						base::weak_qptr<PasscodeBox> box) {
					const auto item = owner->message(fullId);
					if (!item || !CallbackButtonMatches(item, state->button)) {
						callbacks->cancel(state->operationId);
						return;
					}
					auto operationId = state->operationId;
					if (callbacks->operationActive(operationId)) {
						if (!callbacks->beginSending(operationId)) {
							return;
						}
					} else {
						operationId = callbacks->start(
							state->button,
							BotCallbackPhase::Sending);
						if (!operationId) {
							return;
						}
						state->operationId = operationId;
					}
					const auto strongController = weak.get();
					if (!strongController) {
						callbacks->cancel(operationId);
						return;
					}
					SendBotCallbackRequest(
						strongController,
						item,
						state->button,
						operationId,
						result,
						[=] {
							if (box
								&& state->operationId == operationId) {
								box->closeBox();
							}
						},
						[=](const QString &error) {
							if (box) {
								box->handleCustomCheckError(error);
							}
							return false;
						},
						[=] {
							return box
								&& state->operationId == operationId;
						});
				};
				auto object = Box<PasscodeBox>(session, fields);
				const auto passwordBox = object.data();
				passwordBox->boxClosing(
				) | rpl::on_next([=] {
					callbacks->cancel(state->operationId);
				}, passwordBox->lifetime());
				show->showBox(std::move(object), Ui::LayerOption::CloseOther);
			}, state->cloudStateLifetime);
		}
		return true;
	});
}

bool SwitchInlineBotButtonReceived(
		not_null<Window::SessionController*> controller,
		const QByteArray &queryWithPeerTypes,
		UserData *samePeerBot,
		MsgId samePeerReplyTo) {
	return controller->content()->notify_switchInlineBotButtonReceived(
		QString::fromUtf8(queryWithPeerTypes),
		samePeerBot,
		samePeerReplyTo);
}

void ActivateBotButton(ClickHandlerContext context, BotButtonLookup lookup) {
	const auto strong = context.sessionWindow.get();
	if (!strong) {
		return;
	}
	const auto controller = not_null{ strong };
	const auto item = controller->session().data().message(context.itemId);
	if (!item) {
		return;
	}
	const auto button = lookup();
	if (!button) {
		return;
	}

	using ButtonType = HistoryMessageMarkupButton::Type;
	switch (button->type) {
	case ButtonType::Default: {
		// Copy string before passing it to the sending method
		// because the original button can be destroyed inside.
		const auto replyTo = item->isRegular()
			? item->fullId()
			: FullMsgId();
		controller->content()->sendBotCommand({
			.peer = item->history()->peer,
			.command = QString(button->text),
			.context = item->fullId(),
			.replyTo = { replyTo },
		});
	} break;

	case ButtonType::Callback:
	case ButtonType::Game: {
		SendBotCallbackData(controller, item, lookup);
	} break;

	case ButtonType::CallbackWithPassword: {
		SendBotCallbackDataWithPassword(controller, item, lookup);
	} break;

	case ButtonType::Buy: {
		Payments::CheckoutProcess::Start(
			item,
			Payments::Mode::Payment,
			crl::guard(controller, [=](auto) {
				controller->widget()->activate();
			}),
			Payments::ProcessNonPanelPaymentFormFactory(controller, item));
	} break;

	case ButtonType::Url: {
		auto url = QString::fromUtf8(button->data);
		auto skipConfirmation = false;
		if (const auto bot = item->getMessageBot()) {
			if (bot->isVerified()) {
				skipConfirmation = true;
			}
		}
		const auto variant = QVariant::fromValue(context);
		if (skipConfirmation) {
			UrlClickHandler::Open(url, variant);
		} else {
			HiddenUrlClickHandler::Open(url, variant);
		}
	} break;

	case ButtonType::RequestLocation: {
		HideSingleUseKeyboard(controller, item);
		controller->show(
			Ui::MakeInformBox(tr::lng_bot_share_location_unavailable()));
	} break;

	case ButtonType::RequestPhone: {
		HideSingleUseKeyboard(controller, item);
		const auto itemId = item->fullId();
		const auto topicRootId = item->topicRootId();
		const auto history = item->history();
		controller->show(Ui::MakeConfirmBox({
			.text = tr::lng_bot_share_phone(),
			.confirmed = [=] {
				controller->showPeerHistory(
					history,
					Window::SectionShow::Way::Forward,
					ShowAtTheEndMsgId);
				auto action = Api::SendAction(history);
				action.clearDraft = false;
				action.replyTo = {
					.messageId = itemId,
					.topicRootId = topicRootId,
				};
				history->session().api().shareContact(
					history->session().user(),
					action);
			},
			.confirmText = tr::lng_bot_share_phone_confirm(),
		}));
	} break;

	case ButtonType::RequestPoll: {
		HideSingleUseKeyboard(controller, item);
		auto chosen = kDefaultPollCreateFlags;
		auto disabled = PollData::Flags();
		if (!button->data.isEmpty()) {
			disabled |= PollData::Flag::Quiz;
			if (button->data[0]) {
				chosen |= PollData::Flag::Quiz;
			}
		}
		const auto replyTo = FullReplyTo();
		const auto suggest = SuggestOptions();
		Window::PeerMenuCreatePoll(
			controller,
			item->history()->peer,
			replyTo,
			suggest,
			chosen,
			disabled);
	} break;

	case ButtonType::RequestPeer: {
		HideSingleUseKeyboard(controller, item);

		auto query = RequestPeerQuery();
		Assert(button->data.size() == sizeof(query));
		memcpy(&query, button->data.data(), sizeof(query));
		const auto peer = item->history()->peer;
		const auto itemId = item->id;
		const auto id = int32(button->buttonId);
		const auto chosen = [=](std::vector<not_null<PeerData*>> result) {
			using Flag = MTPmessages_SendBotRequestedPeer::Flag;
			peer->session().api().request(MTPmessages_SendBotRequestedPeer(
				MTP_flags(Flag::f_msg_id),
				peer->input(),
				MTP_int(itemId),
				MTPstring(), // request_id
				MTP_int(id),
				MTP_vector_from_range(
					result | ranges::views::transform([](
							not_null<PeerData*> peer) {
						return MTPInputPeer(peer->input());
					}))
			)).done([=](const MTPUpdates &result) {
				peer->session().api().applyUpdates(result);
			}).send();
		};
		if (const auto bot = item->getMessageBot()) {
			ShowChoosePeerBox(controller, bot, query, chosen);
		} else {
			LOG(("API Error: Bot not found for RequestPeer button."));
		}
	} break;

	case ButtonType::SwitchInlineSame:
	case ButtonType::SwitchInline: {
		if (const auto bot = item->getMessageBot()) {
			const auto fastSwitchDone = [&] {
				const auto samePeer = (button->type
					== ButtonType::SwitchInlineSame);
				if (samePeer) {
					SwitchInlineBotButtonReceived(
						controller,
						button->data,
						bot,
						item->id);
					return true;
				} else if (bot->isBot() && bot->botInfo->inlineReturnTo.key) {
					const auto switched = SwitchInlineBotButtonReceived(
						controller,
						button->data);
					if (switched) {
						return true;
					}
				}
				return false;
			}();
			if (!fastSwitchDone) {
				const auto query = QString::fromUtf8(button->data);
				const auto chosen = [=](not_null<Data::Thread*> thread) {
					return controller->switchInlineQuery(
						thread,
						bot,
						query);
				};
				Window::ShowChooseRecipientBox(
					controller,
					chosen,
					tr::lng_inline_switch_choose(),
					nullptr,
					button->peerTypes);
			}
		}
	} break;

	case ButtonType::Auth:
		UrlAuthBox::ActivateButton(controller->uiShow(), item, lookup);
		break;

	case ButtonType::UserProfile: {
		const auto session = &item->history()->session();
		const auto userId = UserId(button->data.toULongLong());
		if (const auto user = session->data().userLoaded(userId)) {
			controller->showPeerInfo(user);
		}
	} break;

	case ButtonType::WebView: {
		if (const auto bot = item->getMessageBot()) {
			bot->session().attachWebView().open({
				.bot = bot,
				.context = { .controller = controller },
				.button = { .text = button->text, .url = button->data },
				.source = InlineBots::WebViewSourceButton{ .simple = false },
			});
		}
	} break;

	case ButtonType::SimpleWebView: {
		if (const auto bot = item->getMessageBot()) {
			bot->session().attachWebView().open({
				.bot = bot,
				.context = { .controller = controller },
				.button = { .text = button->text, .url = button->data },
				.source = InlineBots::WebViewSourceButton{ .simple = true },
			});
		}
	} break;

	case ButtonType::CopyText: {
		const auto text = QString::fromUtf8(button->data);
		if (!text.isEmpty()) {
			QGuiApplication::clipboard()->setText(text);
			controller->showToast({
				.text = { tr::lng_text_copied(tr::now) },
				.iconLottie = u"toast/copy"_q,
				.iconLottieSize = st::toastLottieIconSize,
			});
		}
	} break;

	case ButtonType::Disabled: break;

	case ButtonType::SuggestAccept: {
		Api::AcceptClickHandler(item)->onClick(ClickContext{
			Qt::LeftButton,
			QVariant::fromValue(context),
		});
	} break;

	case ButtonType::SuggestDecline: {
		Api::DeclineClickHandler(item)->onClick(ClickContext{
			Qt::LeftButton,
			QVariant::fromValue(context),
		});
	} break;

	case ButtonType::SuggestChange: {
		Api::SuggestChangesClickHandler(item)->onClick(ClickContext{
			Qt::LeftButton,
			QVariant::fromValue(context),
		});
	} break;

	case ButtonType::CreateBot: {
		HideSingleUseKeyboard(controller, item);

		auto suggestedName = QString();
		auto suggestedUsername = QString();
		{
			auto stream = QDataStream(button->data);
			stream >> suggestedName >> suggestedUsername;
		}
		const auto peer = item->history()->peer;
		const auto itemId = item->id;
		const auto id = int32(button->buttonId);
		const auto bot = item->getMessageBot();
		if (!bot) {
			break;
		}
		ShowCreateManagedBotBox({
			.show = controller->uiShow(),
			.manager = bot,
			.suggestedName = suggestedName,
			.suggestedUsername = suggestedUsername,
			.done = [=](not_null<UserData*> createdBot) {
				using Flag = MTPmessages_SendBotRequestedPeer::Flag;
				peer->session().api().request(
					MTPmessages_SendBotRequestedPeer(
						MTP_flags(Flag::f_msg_id),
						peer->input(),
						MTP_int(itemId),
						MTPstring(),
						MTP_int(id),
						MTP_vector<MTPInputPeer>(
							1,
							createdBot->input()))
				).done([=](const MTPUpdates &result) {
					peer->session().api().applyUpdates(result);
				}).send();
				controller->showPeerHistory(createdBot);
				controller->showToast({
					.title = tr::lng_managed_bot_created_title(
						tr::now,
						lt_name,
						createdBot->name()),
					.text = { tr::lng_managed_bot_created_text(
						tr::now,
						lt_parent_name,
						bot->name()) },
					.icon = &st::toastCheckIcon,
				});
			},
		});
	} break;
	}
}

void ActivateBotCommand(ClickHandlerContext context, int row, int column) {
	const auto strong = context.sessionWindow.get();
	if (!strong) {
		return;
	}
	const auto owner = &strong->session().data();
	const auto itemId = context.itemId;
	ActivateBotButton(context, [=] {
		return HistoryMessageMarkupButton::Get(owner, itemId, row, column);
	});
}

void ActivateRichPageBotButton(
		ClickHandlerContext context,
		const HistoryMessageMarkupButton &button) {
	const auto strong = context.sessionWindow.get();
	if (!strong) {
		return;
	}
	const auto owner = &strong->session().data();
	const auto itemId = context.itemId;
	const auto key = HistoryMessageMarkupButton::RegisterRichPageButton(
		owner,
		itemId,
		button);
	if (key.isEmpty()) {
		return;
	}
	ActivateBotButton(context, [=] {
		return HistoryMessageMarkupButton::GetRichPageButton(
			owner,
			itemId,
			key);
	});
}

} // namespace Api

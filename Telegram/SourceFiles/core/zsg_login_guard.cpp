/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information see the local LEGAL file.
*/
#include "core/zsg_login_guard.h"

#include "api/api_blocked_peers.h"
#include "apiwrap.h"
#include "base/unixtime.h"
#include "data/data_peer.h"
#include "data/data_session.h"
#include "data/data_user.h"
#include "history/history.h"
#include "history/history_item.h"
#include "history/history_item_helpers.h"
#include "inline_bots/bot_attach_web_view.h"
#include "lang/lang_keys.h"
#include "main/main_session.h"
#include "ui/boxes/confirm_box.h"
#include "ui/layers/generic_box.h"
#include "window/window_session_controller.h"

#include <QtCore/QRegularExpression>

#include <cstdlib>
#include <vector>

namespace Core::ZsgLoginGuard {
namespace {

// A login code is useful to a thief for a short while only, an hour is plenty.
constexpr auto kCodeLifetime = TimeId(60 * 60);
// An old message of the service chat that was just loaded is not a new code.
constexpr auto kFreshMessage = TimeId(5 * 60);

struct RememberedCode {
	QString code;
	TimeId when = 0;
};

[[nodiscard]] std::vector<RememberedCode> &Codes() {
	static auto result = std::vector<RememberedCode>();
	return result;
}

[[nodiscard]] QString Pick(const QString &ru, const QString &en) {
	return Lang::Id().startsWith(u"ru"_q) ? ru : en;
}

[[nodiscard]] QString OnlyDigits(const QString &text) {
	auto result = QString();
	result.reserve(text.size());
	for (const auto ch : text) {
		if (ch.isDigit()) {
			result.append(QChar(u'0' + ch.digitValue()));
		} else if (!ch.isSpace()
			&& ch != u'-'
			&& ch != u'.'
			&& ch != u','
			&& ch != u'‐'
			&& ch != u'‑'
			&& ch != u'–') {
			// Any other character breaks the number: "12345 abc 678" is not
			// a code written with separators.
			result.append(QChar(u'|'));
		}
	}
	return result;
}

void BlockAndReport(not_null<UserData*> bot) {
	const auto session = &bot->session();
	session->api().blockedPeers().block(bot);
	session->api().request(MTPmessages_ReportSpam(
		bot->input()
	)).send();
}

void LeaveWarning(not_null<UserData*> bot) {
	const auto history = bot->owner().history(bot);
	const auto text = Pick(
		u"⚠️ ZaStoGram: после запуска этого мини-приложения пришёл код входа в ваш аккаунт, мини-приложение закрыто. Бот, который просит код входа, — мошенник: никому не передавайте такой код."_q,
		u"⚠️ ZaStoGram: a login code for your account arrived while this mini app was open, so it was closed. A bot that asks for a login code is a scammer: never give this code to anyone."_q);
	const auto item = history->makeMessage({
		.id = bot->owner().nextLocalMessageId(),
		.flags = MessageFlag::Local,
		.date = base::unixtime::now(),
	}, PreparedServiceText{ TextWithEntities{ text } });
	history->addNewLocalMessage(item);
}

void AskToBlock(
		not_null<Main::Session*> session,
		std::vector<not_null<UserData*>> bots) {
	const auto controller = session->tryResolveWindow();
	if (!controller) {
		// Nobody to ask: the safe part is already done, the bots stay
		// unblocked, so that a legitimate one is not punished silently.
		return;
	}
	auto names = QStringList();
	for (const auto bot : bots) {
		names.push_back(bot->name());
	}
	const auto list = names.join(u", "_q);
	controller->show(Ui::MakeConfirmBox({
		.text = Pick(
			u"Пока было открыто мини-приложение (%1), пришёл код входа в ваш аккаунт Telegram. Так мошенники угоняют аккаунты: бот просит номер, запускает вход и ждёт код. Мини-приложение закрыто, код никому не отправляйте и не вводите.\n\nЗаблокировать бота и пожаловаться на спам?"_q,
			u"A login code for your Telegram account arrived while a mini app (%1) was open. This is how accounts are stolen: the bot asks for a phone number, starts a login and waits for the code. The mini app has been closed; never send or enter this code anywhere.\n\nBlock the bot and report it as spam?"_q
		).arg(list),
		.confirmed = [=](Fn<void()> close) {
			for (const auto bot : bots) {
				BlockAndReport(bot);
			}
			close();
		},
		.confirmText = Pick(
			u"Заблокировать и пожаловаться"_q,
			u"Block and report"_q),
		.cancelText = Pick(u"Это не мошенник"_q, u"It is not a scam"_q),
		.title = Pick(u"Возможная кража аккаунта"_q, u"Possible account theft"_q),
	}));
}

void HandleNewItem(
		not_null<Main::Session*> session,
		not_null<HistoryItem*> item) {
	if (item->out() || !IsLoginCodeChat(item->history()->peer)) {
		return;
	}
	const auto now = base::unixtime::now();
	if (std::abs(now - item->date()) > kFreshMessage) {
		return;
	}
	const auto codes = FindLoginCodes(item->originalText().text);
	if (codes.isEmpty()) {
		return;
	}
	for (const auto &code : codes) {
		RememberCode(code, now);
	}

	auto &web = session->attachWebView();
	const auto bots = web.openBots();
	if (bots.empty()) {
		return;
	}
	web.closeAll();
	for (const auto bot : bots) {
		LeaveWarning(bot);
	}
	AskToBlock(session, bots);
}

} // namespace

bool IsLoginCodeChat(not_null<const PeerData*> peer) {
	return (peer->id == PeerData::kServiceNotificationsId);
}

bool BlocksForward(not_null<const HistoryItem*> item) {
	return IsLoginCodeChat(item->history()->peer);
}

QStringList FindLoginCodes(const QString &text) {
	// "Login code: 37544." and the same in every language Telegram has.
	static const auto expression = QRegularExpression(
		u"(?<![\\d])(\\d{5,6})(?![\\d])"_q);
	auto result = QStringList();
	auto i = expression.globalMatch(text);
	while (i.hasNext()) {
		result.push_back(i.next().captured(1));
	}
	return result;
}

void RememberCode(const QString &code, TimeId when) {
	auto &list = Codes();
	std::erase_if(list, [&](const RememberedCode &entry) {
		return (entry.when + kCodeLifetime < when)
			|| (entry.code == code);
	});
	list.push_back({ code, when });
}

bool TextHasFreshCode(const QString &text, TimeId now) {
	const auto &list = Codes();
	if (list.empty()) {
		return false;
	}
	const auto digits = OnlyDigits(text);
	for (const auto &entry : list) {
		if (entry.when + kCodeLifetime >= now
			&& digits.contains(entry.code)) {
			return true;
		}
	}
	return false;
}

void ForgetCodes() {
	Codes().clear();
}

bool BlocksOutgoingText(const QString &text) {
	return TextHasFreshCode(text, base::unixtime::now());
}

bool CheckOutgoing(
		not_null<Main::Session*> session,
		const QString &text) {
	if (!BlocksOutgoingText(text)) {
		return false;
	}
	if (const auto controller = session->tryResolveWindow()) {
		controller->show(Ui::MakeInformBox({
			.text = Pick(
				u"В тексте есть ваш код входа в Telegram. Он нужен только для входа в аккаунт, а тому, кто его просит, нужен ваш аккаунт. Сообщение не отправлено."_q,
				u"The text contains your Telegram login code. It is only for logging in, and whoever asks for it wants your account. The message was not sent."_q),
			.title = Pick(u"Код входа не отправляем"_q, u"Login code is not sent"_q),
		}));
	}
	return true;
}

void Watch(not_null<Main::Session*> session) {
	session->data().newItemAdded(
	) | rpl::on_next([=](not_null<HistoryItem*> item) {
		HandleNewItem(session, item);
	}, session->lifetime());
}

} // namespace Core::ZsgLoginGuard

/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/instance/rpc_error_handler.h"

#include <QtCore/QRegularExpression>

namespace MTP::details {
namespace {

[[nodiscard]] DefaultRpcErrorAction Action(
		DefaultRpcErrorAction::Type type,
		bool badGuestDc) {
	return {
		.type = type,
		.badGuestDc = badGuestDc,
	};
}

[[nodiscard]] DefaultRpcErrorAction RetryAction(
		DefaultRpcErrorRetry retry,
		bool badGuestDc) {
	return {
		.type = DefaultRpcErrorAction::Type::Retry,
		.retry = retry,
		.badGuestDc = badGuestDc,
	};
}

} // namespace

DefaultRpcErrorAction ClassifyDefaultRpcError(
		const Error &error,
		bool badGuestDcAlreadyRetried) {
	const auto &type = error.type();
	const auto code = error.code();
	const auto badGuestDc = (code == 400) && (type == u"FILE_ID_INVALID"_q);
	static const auto MigrateRegExp = QRegularExpression(
		"^(FILE|PHONE|NETWORK|USER)_MIGRATE_(\\d+)$");
	static const auto FloodWaitRegExp = QRegularExpression(
		"^FLOOD_WAIT_(\\d+)$");
	static const auto FloodPremiumWaitRegExp = QRegularExpression(
		"^FLOOD_PREMIUM_WAIT_(\\d+)$");
	static const auto SlowmodeWaitRegExp = QRegularExpression(
		"^SLOWMODE_WAIT_(\\d+)$");

	if (const auto migrate = MigrateRegExp.match(type); migrate.hasMatch()) {
		return {
			.type = DefaultRpcErrorAction::Type::Migrate,
			.migrateDcId = migrate.captured(2).toInt(),
			.badGuestDc = badGuestDc,
		};
	} else if (type == u"MSG_WAIT_TIMEOUT"_q
		|| type == u"MSG_WAIT_FAILED"_q) {
		return Action(DefaultRpcErrorAction::Type::MsgWait, badGuestDc);
	}

	if (code < 0 || code >= 500) {
		return RetryAction({ .delay = DefaultRpcErrorRetry::Delay::Backoff },
			badGuestDc);
	} else if (const auto floodWait = FloodWaitRegExp.match(type);
			floodWait.hasMatch()) {
		return RetryAction({
			.delay = DefaultRpcErrorRetry::Delay::Exact,
			.seconds = floodWait.captured(1).toInt(),
		}, badGuestDc);
	} else if (const auto floodPremiumWait = FloodPremiumWaitRegExp.match(type);
			floodPremiumWait.hasMatch()) {
		return RetryAction({
			.delay = DefaultRpcErrorRetry::Delay::NonPremium,
			.seconds = floodPremiumWait.captured(1).toInt(),
		}, badGuestDc);
	} else if (const auto slowmodeWait = SlowmodeWaitRegExp.match(type);
			slowmodeWait.hasMatch()
			&& slowmodeWait.captured(1).toInt() < 3) {
		return RetryAction({
			.delay = DefaultRpcErrorRetry::Delay::Exact,
			.seconds = slowmodeWait.captured(1).toInt(),
		}, badGuestDc);
	} else if ((code == 401 && type != u"AUTH_KEY_PERM_EMPTY"_q)
		|| (badGuestDc && !badGuestDcAlreadyRetried)) {
		return Action(DefaultRpcErrorAction::Type::Unauthorized, badGuestDc);
	} else if (type == u"CONNECTION_NOT_INITED"_q
		|| type == u"CONNECTION_LAYER_INVALID"_q) {
		return Action(DefaultRpcErrorAction::Type::ConnectionInit, badGuestDc);
	} else if (type == u"CONNECTION_LANG_CODE_INVALID"_q) {
		return Action(DefaultRpcErrorAction::Type::ResetLanguage, badGuestDc);
	} else if (type == u"FROZEN_METHOD_INVALID"_q) {
		return Action(DefaultRpcErrorAction::Type::Frozen, badGuestDc);
	} else if (badGuestDc) {
		return Action(DefaultRpcErrorAction::Type::ClearBadGuestDc, badGuestDc);
	}
	return {};
}

} // namespace MTP::details

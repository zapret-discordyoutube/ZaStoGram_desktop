/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "mtproto/core_types.h"

namespace MTP::details {

class SessionPrivate;

class SessionMessageHandler final {
public:
	explicit SessionMessageHandler(not_null<SessionPrivate*> owner);

	void clearOldContainers();
	void handleReceived();
	void resendAll();

private:
	enum class HandleResult {
		Success,
		Ignored,
		RestartConnection,
		ResetSession,
		DestroyTemporaryKey,
		ParseError,
	};
	struct OuterInfo {
		mtpMsgId outerMsgId = 0;
		uint64 serverSalt = 0;
		int32 serverTime = 0;
		bool badTime = false;
	};

	[[nodiscard]] HandleResult handleOneReceived(
		const mtpPrime *from,
		const mtpPrime *end,
		uint64 msgId,
		OuterInfo info);
	[[nodiscard]] HandleResult handleGzipPacked(
		const mtpPrime *from,
		const mtpPrime *end,
		uint64 msgId,
		OuterInfo info);
	[[nodiscard]] HandleResult handleMsgContainer(
		const mtpPrime *from,
		const mtpPrime *end,
		uint64 msgId,
		OuterInfo info);
	[[nodiscard]] HandleResult handleMsgsAck(
		const mtpPrime *from,
		const mtpPrime *end,
		uint64 msgId,
		OuterInfo info);
	[[nodiscard]] HandleResult handleBadMsgNotification(
		const mtpPrime *from,
		const mtpPrime *end,
		uint64 msgId,
		OuterInfo info);
	[[nodiscard]] HandleResult handleBadServerSalt(
		const mtpPrime *from,
		const mtpPrime *end,
		uint64 msgId,
		OuterInfo info);
	[[nodiscard]] HandleResult handleMsgsStateInfo(
		const mtpPrime *from,
		const mtpPrime *end,
		uint64 msgId,
		OuterInfo info);
	[[nodiscard]] HandleResult handleMsgsAllInfo(
		const mtpPrime *from,
		const mtpPrime *end,
		uint64 msgId,
		OuterInfo info);
	[[nodiscard]] HandleResult handleMsgDetailedInfo(
		const mtpPrime *from,
		const mtpPrime *end,
		uint64 msgId,
		OuterInfo info);
	[[nodiscard]] HandleResult handleMsgNewDetailedInfo(
		const mtpPrime *from,
		const mtpPrime *end,
		uint64 msgId,
		OuterInfo info);
	[[nodiscard]] HandleResult handleRpcResult(
		const mtpPrime *from,
		const mtpPrime *end,
		uint64 msgId,
		OuterInfo info);
	[[nodiscard]] HandleResult handleNewSessionCreated(
		const mtpPrime *from,
		const mtpPrime *end,
		uint64 msgId,
		OuterInfo info);
	[[nodiscard]] HandleResult handlePong(
		const mtpPrime *from,
		const mtpPrime *end,
		uint64 msgId,
		OuterInfo info);
	[[nodiscard]] HandleResult handleUpdates(
		const mtpPrime *from,
		const mtpPrime *end,
		uint64 msgId,
		OuterInfo info);
	[[nodiscard]] HandleResult handleBindResponse(
		mtpMsgId requestMsgId,
		const mtpBuffer &response);
	mtpBuffer ungzip(const mtpPrime *from, const mtpPrime *end) const;
	void handleMsgsStates(const QVector<MTPlong> &ids, const QByteArray &states);
	bool requestsFixTimeSalt(const QVector<MTPlong> &ids, const OuterInfo &info);
	void correctUnixtimeByFastRequest(
		const QVector<MTPlong> &ids,
		TimeId serverTime);
	void correctUnixtimeWithBadLocal(TimeId serverTime);
	void requestsAcked(const QVector<MTPlong> &ids, bool byResponse = false);
	void resend(mtpMsgId msgId, crl::time msCanWait = 0);
	void clearSpecialMsgId(mtpMsgId msgId);

	const not_null<SessionPrivate*> _owner;
};

} // namespace MTP::details

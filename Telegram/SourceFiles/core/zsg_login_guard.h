/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information see the local LEGAL file.
*/
#pragma once

#include "base/basic_types.h"

class HistoryItem;
class PeerData;

namespace Main {
class Session;
} // namespace Main

namespace Core::ZsgLoginGuard {

// ZaStoGram: protection against the "bot asks for a phone number, then for
// the login code" account theft. One module, a few one-line hooks elsewhere.
//
// The scheme: a bot (usually inside a mini app) asks for the phone number and
// starts a login of that number, Telegram sends the login code to the service
// chat 777000, and the victim forwards the code, sends it as text or types it
// on a fake keypad inside the mini app. What this module does:
//  - messages of the service chat cannot be forwarded (BlocksForward);
//  - a text that contains a login code received in the last hour is never
//    sent anywhere (BlocksOutgoingText);
//  - a login code that arrives while a mini app is open closes every open
//    mini app, offers to block those bots and report them as spam, and leaves
//    a warning in the chat with each of them (Watch).

// Is it the service chat 777000, where Telegram sends login codes?
[[nodiscard]] bool IsLoginCodeChat(not_null<const PeerData*> peer);

// Forwarding anything from the service chat is forbidden.
[[nodiscard]] bool BlocksForward(not_null<const HistoryItem*> item);

// Does the text to be sent contain a fresh login code? Digits may be
// separated by spaces, dots, commas and dashes.
[[nodiscard]] bool BlocksOutgoingText(const QString &text);

// BlocksOutgoingText plus a warning box. True when the sending is cancelled.
[[nodiscard]] bool CheckOutgoing(
	not_null<Main::Session*> session,
	const QString &text);

// Subscribes to new messages of the session: remembers login codes and reacts
// to a code that arrives while a mini app is open.
void Watch(not_null<Main::Session*> session);

// The pure parts, exposed for tests and for tools/guards.
[[nodiscard]] QStringList FindLoginCodes(const QString &text);
void RememberCode(const QString &code, TimeId when);
[[nodiscard]] bool TextHasFreshCode(const QString &text, TimeId now);
void ForgetCodes();

} // namespace Core::ZsgLoginGuard

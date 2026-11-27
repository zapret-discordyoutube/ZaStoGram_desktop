/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "ui/text/text_entity.h"

namespace Zsg::Naive {

// A NaiveProxy link, naive+https://user:pass@host:port#name, is not a link
// to the generic text parser: it does not know the '+' of the scheme and
// takes the host after user:pass@ for an e-mail domain. This finds such
// links in a message text and makes each one a single Url entity (replacing
// whatever the server or the parser made of its pieces), so it is clickable;
// Core::TryConvertUrlToLocal turns the click into the proxy confirmation box.
void MarkNaiveLinks(TextWithEntities &text);

} // namespace Zsg::Naive

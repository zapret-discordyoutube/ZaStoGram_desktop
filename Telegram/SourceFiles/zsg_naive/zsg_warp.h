/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include <QtNetwork/QNetworkProxy>

#include <optional>

namespace Zsg::Warp {

// Cloudflare WARP as an optional ENTRY hop: with the setting on, the first hop
// of every connection (direct MTProto, MTProxy, WSS, Naive, the update check)
// goes through a loopback SOCKS5 listener of the zsgnaive library, whose bytes
// travel through a WireGuard tunnel to WARP. It is never an exit and never an
// entry in the proxy list. Off by default; a dead tunnel falls back to a direct
// first hop. State lives in tdata/zsg/warp.json.

// Reads the saved setting and starts the tunnel when it is on. Main thread,
// once, after the working directory is known.
void Init();

[[nodiscard]] bool Enabled();
// Saves the setting; turning it on registers an account on first use.
void SetEnabled(bool enabled);

// The SOCKS5 proxy of the running tunnel, or nothing (setting off, tunnel not
// up yet, library without WARP). Any thread.
[[nodiscard]] std::optional<QNetworkProxy> EntryProxy();

} // namespace Zsg::Warp

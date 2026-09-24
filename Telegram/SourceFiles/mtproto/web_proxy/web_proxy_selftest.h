/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "mtproto/proxy/data.h"

#include <optional>

// A throughput and latency self-test of the WEB proxy data path, for a
// test relay whose backend is a sink / source / echo server instead of an
// MTProxy (see the stand next to the relay sources). It is enabled only by
//
//   TDESKTOP_WEB_PROXY_SELFTEST=host:secret[:up=MB][:down=MB][:ul=N][:dl=N]
//                                [:ctl=PATH:net=A|B|...]
//
// With ctl and net the whole run is repeated once per network condition:
// before each round the condition string is written to the ctl file, for
// the stand's WAN emulator to pick up (e.g. "100 400000 4000000" for a
// 100 ms round trip, 400 KB/s up and 4 MB/s down).
//
// and then selects that proxy for this run, waits for the carrier and drives
// synthetic streams through the real Transport, WebView bridge and relay:
// idle pings, upload, download, both at once, pinging an interactive echo
// stream every 100 ms the whole time. Results go to the main log with the
// "Web Proxy SelfTest" prefix.

namespace MTP::WebProxy {

[[nodiscard]] std::optional<ProxyData> SelfTestProxy();

// Main thread, after the proxy is active.
void StartSelfTest();

} // namespace MTP::WebProxy

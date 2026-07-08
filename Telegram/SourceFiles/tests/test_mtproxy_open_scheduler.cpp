/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/proxy/mtproxy/open_scheduler.h"

#include <QtCore/QString>

#include <algorithm>
#include <cstdio>

namespace {

[[nodiscard]] int Fail(const char *message) {
	std::fprintf(stderr, "%s\n", message);
	return 1;
}

struct FakeAsync {
	crl::time time = crl::time(1000);
	int jitter = 7;

	[[nodiscard]] MTP::RuntimeAsyncGateway gateway() {
		const auto fixedTime = time;
		const auto fixedJitter = jitter;
		return {
			.now = [fixedTime] {
				return fixedTime;
			},
			.randomIndex = [fixedJitter](int limit) {
				return std::clamp(fixedJitter, 0, limit - 1);
			},
			.singleShot = [](
					crl::time,
					QObject*,
					Fn<void()> callback) {
				callback();
			},
			.makeTimer = [](
					not_null<QThread*>,
					Fn<void()> callback) {
				return MTP::RuntimeTimer(
					[callback = std::move(callback)](crl::time) mutable {
						callback();
					},
					[](crl::time) {
					},
					[] {
					},
					[] {
						return false;
					});
			},
		};
	}
};

[[nodiscard]] MTP::details::MtProxy::EndpointId Endpoint() {
	return {
		.canonical = {
			.type = MTP::ProxyData::Type::Mtproto,
			.originalHost = QString::fromLatin1("scheduler.test"),
			.port = 443,
			.secretHash = QString::fromLatin1("secret"),
			.proxyKind = MTP::ProxyData::Type::Mtproto,
		},
		.route = {
			.address = QString::fromLatin1("203.0.113.10"),
			.port = 443,
			.addressFamily = MTP::details::MtProxy::RouteAddressFamily::IPv4,
			.transport = MTP::ProxyTransport::Tcp,
		},
	};
}

} // namespace

int main(int, char *[]) {
	auto fake = FakeAsync();
	auto scheduler = MTP::details::MtProxy::OpenScheduler(fake.gateway());
	const auto endpoint = Endpoint();

	const auto first = scheduler.ReserveOpenSlot(
		endpoint,
		MTP::ProxyConnectionPattern::Soft);
	if (first != 0) {
		return Fail("first open should start immediately");
	}

	const auto second = scheduler.ReserveOpenSlot(
		endpoint,
		MTP::ProxyConnectionPattern::Soft);
	if (second != crl::time(1107)) {
		return Fail("second open should use fake time and fake jitter");
	}
	return 0;
}

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
#include <vector>

namespace {

using OpenSlotReservation = MTP::details::MtProxy::OpenSlotReservation;

[[nodiscard]] int Fail(const char *message) {
	std::fprintf(stderr, "%s\n", message);
	return 1;
}

struct FakeAsync {
	crl::time time = crl::time(1000);
	int jitter = 7;

	[[nodiscard]] MTP::RuntimeAsyncGateway gateway() {
		return {
			.now = [this] {
				return time;
			},
			.randomIndex = [this](int limit) {
				return std::clamp(jitter, 0, limit - 1);
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
	const auto emptyEndpoint = MTP::details::MtProxy::EndpointId();
	const auto emptyDelay = scheduler.ReserveOpenSlot(
		emptyEndpoint,
		MTP::ProxyConnectionPattern::Off,
		crl::time(250));
	if (emptyDelay.delay() != crl::time(250)) {
		return Fail("empty endpoint should preserve the requested delay");
	}

	auto first = scheduler.ReserveOpenSlot(
		endpoint,
		MTP::ProxyConnectionPattern::Soft);
	if (first.delay() != 0) {
		return Fail("first open should start immediately");
	}
	first.commit();

	auto second = scheduler.ReserveOpenSlot(
		endpoint,
		MTP::ProxyConnectionPattern::Soft);
	if (second.delay() != crl::time(1107)) {
		return Fail("second open should use fake time and fake jitter");
	}
	second.commit();

	auto coldScheduler = MTP::details::MtProxy::OpenScheduler(fake.gateway());
	auto coldFirst = coldScheduler.ReserveOpenSlot(
		endpoint,
		MTP::ProxyConnectionPattern::Off);
	auto coldSecond = coldScheduler.ReserveOpenSlot(
		endpoint,
		MTP::ProxyConnectionPattern::Off);
	auto coldThird = coldScheduler.ReserveOpenSlot(
		endpoint,
		MTP::ProxyConnectionPattern::Off);
	if (coldFirst.delay() != 0
		|| coldSecond.delay() != crl::time(507)
		|| coldThird.delay() != crl::time(1014)) {
		return Fail("cold endpoint opens should use steady spacing");
	}
	coldFirst.commit();
	coldSecond.commit();
	coldThird.commit();
	auto coldFourth = coldScheduler.ReserveOpenSlot(
		endpoint,
		MTP::ProxyConnectionPattern::Off);
	if (coldFourth.delay() != crl::time(1521)) {
		return Fail("cold endpoint should keep steady spacing after commits");
	}
	coldFourth.cancel();
	auto coldReplacement = coldScheduler.ReserveOpenSlot(
		endpoint,
		MTP::ProxyConnectionPattern::Off);
	if (coldReplacement.delay() != crl::time(1521)) {
		return Fail("cancelling a pending slot should preserve real opens");
	}
	coldReplacement.cancel();
	fake.time = crl::time(2522);
	auto afterWindow = coldScheduler.ReserveOpenSlot(
		endpoint,
		MTP::ProxyConnectionPattern::Off);
	if (afterWindow.delay() != 0) {
		return Fail("expired real opens should release steady spacing");
	}
	afterWindow.cancel();

	auto cancelledScheduler = MTP::details::MtProxy::OpenScheduler(
		fake.gateway());
	auto cancelled = std::vector<OpenSlotReservation>();
	for (auto i = 0; i != 7; ++i) {
		cancelled.push_back(cancelledScheduler.ReserveOpenSlot(
			endpoint,
			MTP::ProxyConnectionPattern::Off));
	}
	for (auto &reservation : cancelled) {
		reservation.cancel();
	}
	auto retry = cancelledScheduler.ReserveOpenSlot(
		endpoint,
		MTP::ProxyConnectionPattern::Off);
	if (retry.delay() != 0) {
		return Fail("cancelled future slots should not delay a retry");
	}
	retry.cancel();

	auto abandonedScheduler = MTP::details::MtProxy::OpenScheduler(
		fake.gateway());
	{
		auto abandoned = std::vector<OpenSlotReservation>();
		for (auto i = 0; i != 7; ++i) {
			abandoned.push_back(abandonedScheduler.ReserveOpenSlot(
				endpoint,
				MTP::ProxyConnectionPattern::Off));
		}
	}
	auto afterAbandon = abandonedScheduler.ReserveOpenSlot(
		endpoint,
		MTP::ProxyConnectionPattern::Off);
	if (afterAbandon.delay() != 0) {
		return Fail("destroyed reservations should release future slots");
	}
	return 0;
}

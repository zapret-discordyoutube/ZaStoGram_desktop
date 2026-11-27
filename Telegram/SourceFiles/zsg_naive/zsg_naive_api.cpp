/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "zsg_naive/zsg_naive_api.h"

#include "logs.h"

#include <QtCore/QCoreApplication>
#include <QtCore/QLibrary>
#include <QtNetwork/QSslCertificate>
#include <QtNetwork/QSslConfiguration>

#include <type_traits>

namespace Zsg::Naive {
namespace {

// ISRG Root X1 (Let's Encrypt), SHA-256 96BCEC06...BDDF08C6.
constexpr auto kIsrgRootX1 = R"PEM(-----BEGIN CERTIFICATE-----
MIIFazCCA1OgAwIBAgIRAIIQz7DSQONZRGPgu2OCiwAwDQYJKoZIhvcNAQELBQAw
TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh
cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMTUwNjA0MTEwNDM4
WhcNMzUwNjA0MTEwNDM4WjBPMQswCQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJu
ZXQgU2VjdXJpdHkgUmVzZWFyY2ggR3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBY
MTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAK3oJHP0FDfzm54rVygc
h77ct984kIxuPOZXoHj3dcKi/vVqbvYATyjb3miGbESTtrFj/RQSa78f0uoxmyF+
0TM8ukj13Xnfs7j/EvEhmkvBioZxaUpmZmyPfjxwv60pIgbz5MDmgK7iS4+3mX6U
A5/TR5d8mUgjU+g4rk8Kb4Mu0UlXjIB0ttov0DiNewNwIRt18jA8+o+u3dpjq+sW
T8KOEUt+zwvo/7V3LvSye0rgTBIlDHCNAymg4VMk7BPZ7hm/ELNKjD+Jo2FR3qyH
B5T0Y3HsLuJvW5iB4YlcNHlsdu87kGJ55tukmi8mxdAQ4Q7e2RCOFvu396j3x+UC
B5iPNgiV5+I3lg02dZ77DnKxHZu8A/lJBdiB3QW0KtZB6awBdpUKD9jf1b0SHzUv
KBds0pjBqAlkd25HN7rOrFleaJ1/ctaJxQZBKT5ZPt0m9STJEadao0xAH0ahmbWn
OlFuhjuefXKnEgV4We0+UXgVCwOPjdAvBbI+e0ocS3MFEvzG6uBQE3xDk3SzynTn
jh8BCNAw1FtxNrQHusEwMFxIt4I7mKZ9YIqioymCzLq9gwQbooMDQaHWBfEbwrbw
qHyGO0aoSCqI3Haadr8faqU9GY/rOPNk3sgrDQoo//fb4hVC1CLQJ13hef4Y53CI
rU7m2Ys6xt0nUW7/vGT1M0NPAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNV
HRMBAf8EBTADAQH/MB0GA1UdDgQWBBR5tFnme7bl5AFzgAiIyBpY9umbbjANBgkq
hkiG9w0BAQsFAAOCAgEAVR9YqbyyqFDQDLHYGmkgJykIrGF1XIpu+ILlaS/V9lZL
ubhzEFnTIZd+50xx+7LSYK05qAvqFyFWhfFQDlnrzuBZ6brJFe+GnY+EgPbk6ZGQ
3BebYhtF8GaV0nxvwuo77x/Py9auJ/GpsMiu/X1+mvoiBOv/2X/qkSsisRcOj/KK
NFtY2PwByVS5uCbMiogziUwthDyC3+6WVwW6LLv3xLfHTjuCvjHIInNzktHCgKQ5
ORAzI4JMPJ+GslWYHb4phowim57iaztXOoJwTdwJx4nLCgdNbOhdjsnvzqvHu7Ur
TkXWStAmzOVyyghqpZXjFaH3pO3JLF+l+/+sKAIuvtd7u+Nxe5AW0wdeRlN8NwdC
jNPElpzVmbUq4JUagEiuTDkHzsxHpFKVK7q4+63SM1N95R1NbdWhscdCb+ZAJzVc
oyi3B43njTOQ5yOf+1CceWxG1bQVs5ZufpsMljq4Ui0/1lvh+wjChP4kqKOJ2qxq
4RgqsahDYVvTH9w7jXbyLeiNdd8XM2w9U/t7y0Ff/9yi0GE44Za4rF2LN9d11TPA
mRGunUHBcnWEvgJBQl9nJEiU0Zsnvgc/ubhPgXRR4Xq37Z0j4r7g1SgEEzwxA57d
emyPxgcYxn/eR44/KJ4EBs+lVDR3veyJm+kXQ99b21/+jh5Xos1AnX5iItreGCc=
-----END CERTIFICATE-----
)PEM";

struct Loaded {
	Api api = {};
	bool ok = false;
	QString error;
};

[[nodiscard]] Loaded Load() {
	auto result = Loaded();
	static QLibrary library;
	library.setFileName(
		QCoreApplication::applicationDirPath() + u"/zsgnaive"_q);
	if (!library.load()) {
		result.error = u"zsgnaive library is not available: "_q
			+ library.errorString();
		return result;
	}
	auto missing = QString();
	const auto resolve = [&](auto &slot, const char *name) {
		slot = reinterpret_cast<std::remove_reference_t<decltype(slot)>>(
			library.resolve(name));
		if (!slot) {
			missing += QString::fromLatin1(name) + u' ';
		}
	};
	auto &api = result.api;
	resolve(api.naiveNew, "zsg_naive_new");
	resolve(api.naiveFree, "zsg_naive_free");
	resolve(api.naiveState, "zsg_naive_state");
	resolve(api.naiveError, "zsg_naive_error");
	resolve(api.naiveFeedNetwork, "zsg_naive_feed_network");
	resolve(api.naiveTakeNetwork, "zsg_naive_take_network");
	resolve(api.naiveOpenTunnel, "zsg_naive_open_tunnel");
	resolve(api.naiveTunnelState, "zsg_naive_tunnel_state");
	resolve(api.naiveTunnelHttpStatus, "zsg_naive_tunnel_http_status");
	resolve(api.naiveTunnelWrite, "zsg_naive_tunnel_write");
	resolve(api.naiveTunnelRead, "zsg_naive_tunnel_read");
	resolve(api.naiveTunnelEof, "zsg_naive_tunnel_eof");
	resolve(api.naiveCloseTunnel, "zsg_naive_close_tunnel");
	resolve(api.wsNew, "zsg_ws_new");
	resolve(api.wsFree, "zsg_ws_free");
	resolve(api.wsState, "zsg_ws_state");
	resolve(api.wsError, "zsg_ws_error");
	resolve(api.wsUpgradeStatus, "zsg_ws_upgrade_status");
	resolve(api.wsUpgradeRetryable, "zsg_ws_upgrade_retryable");
	resolve(api.wsRetryUpgrade, "zsg_ws_retry_upgrade");
	resolve(api.wsFeedNetwork, "zsg_ws_feed_network");
	resolve(api.wsTakeNetwork, "zsg_ws_take_network");
	resolve(api.wsSend, "zsg_ws_send");
	resolve(api.wsNextMessageSize, "zsg_ws_next_message_size");
	resolve(api.wsPopMessage, "zsg_ws_pop_message");
	resolve(api.wsClose, "zsg_ws_close");
	resolve(api.wsDeflateNegotiated, "zsg_ws_deflate_negotiated");
	resolve(api.profileVersion, "zsg_naive_profile_version");
	if (!missing.isEmpty()) {
		result.error = u"zsgnaive library lacks: "_q + missing;
		return result;
	}
	result.ok = true;
	LOG(("Naive: library loaded, Chrome profile %1.").arg(
		QString::fromLatin1(api.profileVersion())));
	return result;
}

} // namespace

const Api *LoadApi(QString *error) {
	static const auto loaded = Load();
	if (!loaded.ok && error) {
		*error = loaded.error;
	}
	return loaded.ok ? &loaded.api : nullptr;
}

const Trust &SystemTrust() {
	static const auto trust = [] {
		auto result = Trust();
		const auto system = QSslConfiguration::systemCaCertificates();
		for (const auto &certificate : system) {
			auto der = certificate.toDer();
			if (!der.isEmpty()) {
				result.der.push_back(std::move(der));
			}
		}
		for (const auto &der : result.der) {
			result.certs.push_back({
				reinterpret_cast<const uint8_t*>(der.constData()),
				size_t(der.size()),
			});
		}
		result.pem = QByteArray(kIsrgRootX1);
		LOG(("Naive: %1 system roots + ISRG Root X1.").arg(
			result.der.size()));
		return result;
	}();
	return trust;
}

const Identity &BrowserIdentity() {
#if defined Q_OS_WIN
	static const auto result = Identity{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
		"(KHTML, like Gecko) Chrome/158.0.0.0 Safari/537.36",
		"\"Chromium\";v=\"158\", \"Not.A/Brand\";v=\"24\", "
		"\"Google Chrome\";v=\"158\"",
		"?0",
		"\"Windows\"",
	};
#elif defined Q_OS_MAC
	static const auto result = Identity{
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
		"(KHTML, like Gecko) Chrome/158.0.0.0 Safari/537.36",
		"\"Chromium\";v=\"158\", \"Not.A/Brand\";v=\"24\", "
		"\"Google Chrome\";v=\"158\"",
		"?0",
		"\"macOS\"",
	};
#else
	static const auto result = Identity{
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
		"(KHTML, like Gecko) Chrome/158.0.0.0 Safari/537.36",
		"\"Chromium\";v=\"158\", \"Not.A/Brand\";v=\"24\", "
		"\"Google Chrome\";v=\"158\"",
		"?0",
		"\"Linux\"",
	};
#endif
	return result;
}

} // namespace Zsg::Naive

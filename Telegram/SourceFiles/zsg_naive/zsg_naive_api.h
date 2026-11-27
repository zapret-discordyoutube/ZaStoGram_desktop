/*
ZaStoGram Naive module (fork-only, kept in this folder so upstream merges never touch it).

The TLS / HTTP/2 / Naive / WebSocket logic lives in the separate library zsgnaive (own BoringSSL, Chrome 158
handshake) and is reached only through its C API, declared here and resolved at run time. The library is shipped
next to the executable; when it is missing every user of this module fails closed with a logged reason instead of
the application failing to start.
*/
#pragma once

#include <QtCore/QByteArray>
#include <QtCore/QString>

#include <cstddef>
#include <cstdint>
#include <vector>

namespace Zsg::Naive {

// Layouts mirror zsg_naive.h of the library (C ABI).
struct DerCert {
	const uint8_t *data;
	size_t size;
};

struct NaiveConfig {
	const char *host;
	uint16_t port;
	const char *user;
	const char *password;
	const char *ca_file;
	const char *ca_dir;
	int insecure_skip_verify;
	const char *extra_roots_pem;
	const DerCert *extra_roots_der;
	size_t extra_roots_der_count;
	const char *user_agent;
	const char *sec_ch_ua;
	const char *sec_ch_ua_mobile;
	const char *sec_ch_ua_platform;
	int send_preamble;
};

struct WsConfig {
	const char *host;
	uint16_t port;
	const char *path;
	const char *origin;
	const char *user_agent;
	const char *subprotocol;
	const char *accept_language;
	const char *ca_file;
	const char *ca_dir;
	int insecure_skip_verify;
	const char *extra_roots_pem;
	const DerCert *extra_roots_der;
	size_t extra_roots_der_count;
	int offer_deflate;
	// Appended to the core's zsg_ws_config: TLS server name when it must
	// differ from host (NULL = host), and 1 for ws:// without TLS.
	const char *sni;
	int plain;
};

struct WarpConfigC {
	const char *private_key;
	const char *peer_public_key;
	const char *reserved;
	const char *address;
	const char *endpoint_host;
	uint16_t endpoint_port;
	int junk_count;
};
struct WarpMasqueConfigC {
	const char *private_key;
	const char *server_key_pem;
	const char *address;
	const char *edges;
	int first;
};
struct WarpHandle;
enum WarpState {
	WarpConnecting = 0,
	WarpUp = 1,
	WarpFailed = 2,
};

enum NaiveState {
	NaiveHandshaking = 0,
	NaivePreamble = 1,
	NaiveReady = 2,
	NaiveFailed = 3,
	NaiveClosed = 4,
};
enum TunnelState {
	TunnelConnecting = 0,
	TunnelOpen = 1,
	TunnelFailed = 2,
	TunnelClosed = 3,
};
enum WsState {
	WsHandshaking = 0,
	WsUpgrading = 1,
	WsOpen = 2,
	WsRefused = 3,
	WsFailed = 4,
	WsClosed = 5,
};

struct NaiveHandle;
struct WsHandle;

struct Api {
	NaiveHandle *(*naiveNew)(const NaiveConfig *, char *, size_t);
	void (*naiveFree)(NaiveHandle *);
	int (*naiveState)(const NaiveHandle *);
	const char *(*naiveError)(const NaiveHandle *);
	void (*naiveFeedNetwork)(NaiveHandle *, const uint8_t *, size_t);
	size_t (*naiveTakeNetwork)(NaiveHandle *, uint8_t *, size_t);
	int (*naiveOpenTunnel)(NaiveHandle *, const char *, uint16_t);
	int (*naiveTunnelState)(const NaiveHandle *, int);
	int (*naiveTunnelHttpStatus)(const NaiveHandle *, int);
	size_t (*naiveTunnelWrite)(NaiveHandle *, int, const uint8_t *, size_t);
	size_t (*naiveTunnelRead)(NaiveHandle *, int, uint8_t *, size_t);
	int (*naiveTunnelEof)(const NaiveHandle *, int);
	void (*naiveCloseTunnel)(NaiveHandle *, int);

	WsHandle *(*wsNew)(const WsConfig *, char *, size_t);
	void (*wsFree)(WsHandle *);
	int (*wsState)(const WsHandle *);
	const char *(*wsError)(const WsHandle *);
	int (*wsUpgradeStatus)(const WsHandle *);
	int (*wsUpgradeRetryable)(const WsHandle *);
	int (*wsRetryUpgrade)(WsHandle *);
	void (*wsFeedNetwork)(WsHandle *, const uint8_t *, size_t);
	size_t (*wsTakeNetwork)(WsHandle *, uint8_t *, size_t);
	int (*wsSend)(WsHandle *, const uint8_t *, size_t);
	size_t (*wsNextMessageSize)(WsHandle *);
	size_t (*wsPopMessage)(WsHandle *, uint8_t *, size_t);
	void (*wsClose)(WsHandle *);
	int (*wsDeflateNegotiated)(const WsHandle *);

	// WARP entry hop: absent (nullptr) in a library older than the feature.
	WarpHandle *(*warpStart)(const WarpConfigC *, uint16_t *, char *, size_t);
	int (*warpState)(const WarpHandle *);
	void (*warpStop)(WarpHandle *);
	size_t (*warpStats)(WarpHandle *, char *, size_t);
	int (*warpKeypair)(char *, char *, size_t);
	// The MASQUE fallback (HTTP/2 over TCP 443): absent in a library older than it.
	WarpHandle *(*warpStart2)(const WarpConfigC *, const WarpMasqueConfigC *, uint16_t *, char *, size_t);
	int (*warpMasqueKeypair)(char *, char *, size_t);
	int (*warpTransport)(const WarpHandle *);

	const char *(*profileVersion)();
};

// The resolved library, or nullptr (|error| then says why). Loaded once per
// process, safe from any thread.
[[nodiscard]] const Api *LoadApi(QString *error = nullptr);

// Trusted roots handed to the library: the system store of the platform
// (through Qt) plus the ISRG Root X1 that many Cloudflare front domains chain
// to and an old Windows store may still lack. Built once, lives for the
// process.
struct Trust {
	QByteArray pem;
	std::vector<QByteArray> der;
	std::vector<DerCert> certs;
};
[[nodiscard]] const Trust &SystemTrust();

// Browser identity of the current OS; must match the Chrome 158 TLS profile
// of the library.
struct Identity {
	const char *userAgent;
	const char *secChUa;
	const char *secChUaMobile;
	const char *secChUaPlatform;
};
[[nodiscard]] const Identity &BrowserIdentity();

} // namespace Zsg::Naive

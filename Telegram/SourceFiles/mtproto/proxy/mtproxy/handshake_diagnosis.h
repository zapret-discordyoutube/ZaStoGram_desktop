/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "mtproto/proxy/mtproxy/tls_socket_utils.h"

#include <QtCore/QByteArray>
#include <QtCore/QString>

namespace MTP::details::MtProxy {

// The single most misread FakeTLS failure is "ClientHello sent, no
// ServerHello": on the wire a silent DPI drop, an overloaded proxy, and a
// ClientHello the server actively rejected all end the same way - a stall.
// The evidence to tell them apart already exists but was scattered across a
// dozen diagnostics fields, so every investigation re-derived the verdict by
// eye (and defaulted to "must be DPI"). This module folds that evidence into
// one report so a human - or a future auto-heuristic - reads a single field.
//
// It is deliberately dependency-light (raw ints/bytes in, strings out) so it
// is unit-testable without a live socket, and it is the ONLY place this
// classification lives.

// Where the failure most likely originates. This is the field worth reading
// first when "works on Android, not here" comes up.
enum class BlockAttribution {
	None,    // not the no-ServerHello case; nothing to say
	Client,  // our side - a different client would likely succeed
	Network, // something on the path acted; a client change will not help
	Unclear, // indistinguishable from the client alone (pure silence)
};

struct HandshakeBlockEvidence {
	bool isNoServerHelloStall = false; // caller already matched the reason
	int clientHelloBytes = 0;          // total we intended to send
	qint64 clientHelloAcceptedBytes = 0; // accepted by the local socket
	qint64 rxAfterClientHello = 0;     // bytes seen after ClientHello
	QByteArray responsePrefix;         // first bytes of whatever came back
	bool peerClosed = false;           // peer sent FIN/RST (not our timeout)
};

struct HandshakeBlockReport {
	QString verdict;                 // machine-readable slug
	BlockAttribution attribution = BlockAttribution::None;

	[[nodiscard]] bool empty() const {
		return verdict.isEmpty();
	}
};

[[nodiscard]] inline QString BlockAttributionSlug(BlockAttribution value) {
	switch (value) {
	case BlockAttribution::Client: return u"client"_q;
	case BlockAttribution::Network: return u"network"_q;
	case BlockAttribution::Unclear: return u"unclear"_q;
	case BlockAttribution::None: break;
	}
	return QString();
}

[[nodiscard]] inline HandshakeBlockReport AnalyzeHandshakeBlock(
		const HandshakeBlockEvidence &e) {
	if (!e.isNoServerHelloStall) {
		return {};
	}
	if (e.clientHelloBytes > 0
		&& e.clientHelloAcceptedBytes < e.clientHelloBytes) {
		// The local socket never accepted the whole ClientHello, so nothing
		// downstream could have answered - this is us (or local congestion),
		// not the network dropping a packet that left the machine.
		return { u"local_write_incomplete"_q, BlockAttribution::Client };
	}
	if (!e.rxAfterClientHello) {
		return e.peerClosed
			// Zero bytes then a remote close/reset right after our
			// ClientHello is the classic on-path RST-injection signature.
			? HandshakeBlockReport{
				u"peer_reset_after_hello"_q,
				BlockAttribution::Network }
			// Pure silence: a dropped packet and an overloaded proxy are
			// indistinguishable from here. Do NOT call this DPI.
			: HandshakeBlockReport{
				u"silent_no_reply"_q,
				BlockAttribution::Unclear };
	}
	const auto cls = FakeTlsResponseClass(
		e.responsePrefix,
		e.rxAfterClientHello);
	if (cls == u"tls_alert"_q) {
		// The server read our ClientHello and answered with a TLS alert - it
		// reached a real TLS endpoint that rejected our specific handshake.
		// The strongest "it is our fingerprint, not DPI" signal there is.
		return { u"server_tls_alert"_q, BlockAttribution::Client };
	}
	if (cls == u"http_like"_q || cls == u"non_tls"_q) {
		// Something that is not the FakeTLS proxy answered (captive portal,
		// injector, wrong host) - not a handshake our client could fix.
		return { u"unexpected_reply"_q, BlockAttribution::Network };
	}
	if (cls == u"partial_tls_header"_q || cls == u"partial_tls_record"_q) {
		// A ServerHello started arriving but never completed in the budget:
		// a slow/half relay or an over-strict parser on our side.
		return { u"truncated_server_hello"_q, BlockAttribution::Unclear };
	}
	return { u"unexpected_reply"_q, BlockAttribution::Network };
}

// One compact log token, greppable by verdict and by attribution:
//   block=server_tls_alert:client
[[nodiscard]] inline QString HandshakeBlockToken(
		const HandshakeBlockReport &report) {
	if (report.empty()) {
		return QString();
	}
	return report.verdict + ':' + BlockAttributionSlug(report.attribution);
}

} // namespace MTP::details::MtProxy

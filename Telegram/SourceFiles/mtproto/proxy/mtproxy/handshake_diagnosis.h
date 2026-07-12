/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "mtproto/proxy/mtproxy/tls_socket_utils.h"
#include "mtproto/runtime/connection_status_types.h"

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

struct HandshakeBlockEvidence {
	bool isNoServerHelloStall = false; // caller already matched the reason
	int clientHelloBytes = 0;          // total we intended to send
	qint64 clientHelloAcceptedBytes = 0; // accepted by the local socket
	qint64 rxAfterClientHello = 0;     // bytes seen after ClientHello
	QByteArray responsePrefix;         // first bytes of whatever came back
	ProxyCloseOrigin closeOrigin = ProxyCloseOrigin::None;
	ProxyConnectionError error = ProxyConnectionError::None;
};

struct HandshakeBlockReport {
	QString verdict;                 // machine-readable slug
	ProxyFailureAttribution attribution = ProxyFailureAttribution::None;

	[[nodiscard]] bool empty() const {
		return verdict.isEmpty();
	}
};

[[nodiscard]] inline QString BlockAttributionSlug(
		ProxyFailureAttribution value) {
	switch (value) {
	case ProxyFailureAttribution::Local: return u"local"_q;
	case ProxyFailureAttribution::Client: return u"client"_q;
	case ProxyFailureAttribution::Peer: return u"peer"_q;
	case ProxyFailureAttribution::Network: return u"network"_q;
	case ProxyFailureAttribution::Unclear: return u"unclear"_q;
	case ProxyFailureAttribution::None: break;
	}
	return QString();
}

[[nodiscard]] inline QString DiagnosticBlockAttributionSlug(
		const HandshakeBlockReport &report) {
	if (report.verdict == u"local_write_incomplete"_q
		|| report.verdict == u"server_tls_alert"_q) {
		return u"client"_q;
	} else if (report.verdict == u"peer_reset_after_hello"_q
		|| report.verdict == u"unexpected_reply"_q) {
		return u"network"_q;
	}
	return BlockAttributionSlug(report.attribution);
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
		return {
			u"local_write_incomplete"_q,
			ProxyFailureAttribution::Local,
		};
	}
	if (!e.rxAfterClientHello) {
		if (e.closeOrigin == ProxyCloseOrigin::PeerClosed) {
			return {
				u"peer_reset_after_hello"_q,
				ProxyFailureAttribution::Peer,
			};
		} else if (e.closeOrigin == ProxyCloseOrigin::NetworkError) {
			const auto network = (e.error == ProxyConnectionError::Network)
				|| (e.error == ProxyConnectionError::ConnectionRefused)
				|| (e.error == ProxyConnectionError::HostNotFound);
			return {
				u"peer_reset_after_hello"_q,
				network
					? ProxyFailureAttribution::Network
					: ProxyFailureAttribution::Unclear,
			};
		}
		return {
			u"silent_no_reply"_q,
			ProxyFailureAttribution::Unclear,
		};
	}
	const auto cls = FakeTlsResponseClass(
		e.responsePrefix,
		e.rxAfterClientHello);
	if (cls == u"tls_alert"_q) {
		// The server read our ClientHello and answered with a TLS alert - it
		// reached a real TLS endpoint that rejected our specific handshake.
		// The strongest "it is our fingerprint, not DPI" signal there is.
		return {
			u"server_tls_alert"_q,
			ProxyFailureAttribution::Client,
		};
	}
	if (cls == u"http_like"_q || cls == u"non_tls"_q) {
		// Something that is not the FakeTLS proxy answered (captive portal,
		// injector, wrong host) - not a handshake our client could fix.
		return {
			u"unexpected_reply"_q,
			ProxyFailureAttribution::Peer,
		};
	}
	if (cls == u"partial_tls_header"_q || cls == u"partial_tls_record"_q) {
		// A ServerHello started arriving but never completed in the budget:
		// a slow/half relay or an over-strict parser on our side.
		return {
			u"truncated_server_hello"_q,
			ProxyFailureAttribution::Unclear,
		};
	}
	return {
		u"unexpected_reply"_q,
		ProxyFailureAttribution::Peer,
	};
}

// One compact, self-justifying log token: the verdict carries the exact
// evidence that produced it, so an investigator reads a single field
// instead of cross-referencing ten raw columns (which stay as backup).
// No spaces, so whitespace tokenizers keep seeing one field; greppable by
// verdict (block=server_tls_alert) and by attribution (:client):
//   block=silent_no_reply:unclear;ch=517/517;rx=0;end=timeout
//   block=server_tls_alert:client;ch=517/517;rx=7;rec=tls_alert;end=peer
[[nodiscard]] inline QString HandshakeBlockToken(
		const HandshakeBlockReport &report,
		const HandshakeBlockEvidence &e) {
	if (report.empty()) {
		return QString();
	}
	auto token = report.verdict + ':' + DiagnosticBlockAttributionSlug(report);
	// ch=<accepted>/<intended>: unequal means we never flushed it locally.
	if (e.clientHelloBytes > 0) {
		token += u";ch=%1/%2"_q
			.arg(e.clientHelloAcceptedBytes)
			.arg(e.clientHelloBytes);
	}
	token += u";rx=%1"_q.arg(e.rxAfterClientHello);
	// What the peer actually answered (only meaningful when bytes came back).
	if (e.rxAfterClientHello > 0) {
		token += u";rec=%1"_q.arg(
			FakeTlsResponseClass(e.responsePrefix, e.rxAfterClientHello));
	}
	// How the attempt ended: an active peer close/reset vs our own timeout
	// on silence - the line between an on-path reset and a dropped packet.
	token += (e.closeOrigin == ProxyCloseOrigin::PeerClosed
		|| e.closeOrigin == ProxyCloseOrigin::NetworkError)
		? u";end=peer"_q
		: u";end=timeout"_q;
	return token;
}

} // namespace MTP::details::MtProxy

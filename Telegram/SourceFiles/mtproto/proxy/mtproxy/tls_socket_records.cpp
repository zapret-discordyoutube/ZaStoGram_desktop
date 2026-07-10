/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/proxy/mtproxy/tls_socket.h"

#include "mtproto/proxy/mtproxy/client_hello_constants.h"
#include "mtproto/proxy/mtproxy/tls_socket_psk.h"
#include "mtproto/proxy/mtproxy/tls_socket_utils.h"
#include "mtproto/proxy/diagnostics.h"
#include "mtproto/proxy/proxy_services.h"
#include "mtproto/runtime/runtime_environment.h"
#include "base/invoke_queued.h"
#include "base/random.h"

#include <QtCore/QtEndian>

#include <algorithm>
#include <iterator>

namespace MTP::details {
namespace {

const auto kServerHeader = qstr("\x17\x03\x03");
constexpr auto kClientPartSize = 2878;
const auto kClientPrefix = qstr("\x14\x03\x03\x00\x01\x01");
const auto kClientHeader = qstr("\x17\x03\x03");
constexpr auto kStartupCoverSoftWindow = crl::time(12000);
constexpr auto kStartupCoverStrictWindow = crl::time(20000);
constexpr auto kStartupCoverSoftFrames = 8;
constexpr auto kStartupCoverStrictFrames = 14;
constexpr auto kRecordSizeMin = 256;
constexpr auto kMaxPacedFrames = 24;

} // namespace

void TlsSocket::readData() {
	if (!isConnected()) {
		return;
	}
	const auto received = _transport->readAll();
	noteIncoming(received);
	_incoming.append(received);
	if (!checkNextPacket()) {
		handleError();
	} else if (hasBytesAvailable()) {
		_readyRead.fire({});
	}
}

bool TlsSocket::checkNextPacket() {
	auto offset = 0;
	const auto incoming = bytes::make_span(_incoming);
	while (!_incomingGoodDataLimit) {
		const auto fullHeader = kServerHeader.size() + kTlsLengthFieldSize;
		if (incoming.size() <= offset + fullHeader) {
			return true;
		}
		if (!CheckPart(incoming.subspan(offset), kServerHeader)) {
			logError(888, "Bad packet header.");
			return false;
		}
		const auto length = ReadPartLength(
			incoming,
			offset + kServerHeader.size());
		if (length > 0) {
			if (offset > 0) {
				shiftIncomingBy(offset);
			}
			_incomingGoodDataOffset = fullHeader;
			_incomingGoodDataLimit = length;
			if (!_firstAppDataReceived) {
				_firstAppDataReceived = true;
				_firstAppDataAt = crl::now();
				_phase = HandshakePhase::FirstDataReceived;
				connectionProgress(_phase);
				reportTransportEvent(
					ProxyDiagnosticsPhase::Connected,
					ProxyDiagnosticsSeverity::Info,
					u"mtproxy first tls appdata received"_q);
				_runtime->proxyServices().control().reportMtproxySuccess({
					.endpoint = _endpointId,
					.use = _endpointUse,
					.runtimeId = _mtproxyAttempt.runtimeId,
					.stealth = _stealth,
					.sentProfile = _sentTlsProfile,
					.proxyGeneration = _mtproxyAttempt.proxyGeneration,
					.attemptId = _mtproxyAttempt.attemptId,
					.proxyEpoch = _mtproxyAttempt.proxyEpoch,
					.successEpoch = _mtproxyAttempt.successEpoch,
					.attemptStartedAt = _mtproxyAttemptStartedAt,
					.scope = MtProxy::SuccessScope::FakeTlsAppData,
				});
				if (!IsProxyCheck(_endpointUse)) {
					_runtime->proxyServices().syntheticPsks().noteDataPathSuccess(
						MtProxy::EndpointKey(_endpointId.canonical),
						domainFromSecret(),
						_sentTlsProfile);
				}
			}
		} else {
			offset += kServerHeader.size() + kTlsLengthFieldSize + length;
		}
	}
	return true;
}

void TlsSocket::shiftIncomingBy(int amount) {
	Expects(_incomingGoodDataOffset == 0);
	Expects(_incomingGoodDataLimit == 0);

	const auto incoming = bytes::make_detached_span(_incoming);
	if (incoming.size() > amount) {
		bytes::move(incoming, incoming.subspan(amount));
		_incoming.chop(amount);
	} else {
		_incoming.clear();
	}
}

bool TlsSocket::hasBytesAvailable() {
	return (_incomingGoodDataLimit > 0)
		&& (_incomingGoodDataOffset < _incoming.size());
}

int64 TlsSocket::read(bytes::span buffer) {
	auto written = int64(0);
	while (_incomingGoodDataLimit) {
		const auto available = std::min(
			_incomingGoodDataLimit,
			int(_incoming.size()) - _incomingGoodDataOffset);
		if (available <= 0) {
			return written;
		}
		const auto write = std::min(std::size_t(available), buffer.size());
		if (write <= 0) {
			return written;
		}
		bytes::copy(
			buffer,
			bytes::make_span(_incoming).subspan(
				_incomingGoodDataOffset,
				write));
		written += write;
		buffer = buffer.subspan(write);
		_incomingGoodDataLimit -= write;
		_incomingGoodDataOffset += write;
		if (_incomingGoodDataLimit) {
			return written;
		}
		shiftIncomingBy(base::take(_incomingGoodDataOffset));
		if (!checkNextPacket()) {
			_state = State::Error;
			InvokeQueued(this, [=] { handleError(); });
			return written;
		}
	}
	return written;
}

TlsSocket::RecordSizing TlsSocket::effectiveRecordSizing() {
	if (!startupCoverActive()) {
		return _recordSizing;
	} else if (_startupCover == StartupCover::Strict) {
		return RecordSizing::Varied;
	}
	return (_recordSizing == RecordSizing::Off)
		? RecordSizing::Conservative
		: _recordSizing;
}

bool TlsSocket::startupCoverActive() {
	if (_startupCover == StartupCover::Off || !_startupCoverStartedAt) {
		return false;
	}
	const auto strict = (_startupCover == StartupCover::Strict);
	const auto window = strict
		? kStartupCoverStrictWindow
		: kStartupCoverSoftWindow;
	const auto maxFrames = strict
		? kStartupCoverStrictFrames
		: kStartupCoverSoftFrames;
	if (crl::now() - _startupCoverStartedAt > window
		|| _startupCoverFrames >= maxFrames) {
		_startupCoverStartedAt = 0;
		return false;
	}
	return true;
}

int TlsSocket::nextRecordPayloadSize() {
	const auto mode = effectiveRecordSizing();
	auto cap = int(kClientPartSize);
	if (mode == RecordSizing::Conservative) {
		static constexpr int kCaps[] = {
			1440, 1728, 2016, 2304, 2580, 2878,
		};
		cap = kCaps[base::RandomIndex(int(std::size(kCaps)))];
	} else if (mode == RecordSizing::Varied) {
		const auto minCap = _firstAppDataSent ? 768 : 1200;
		const auto maxCap = _firstAppDataSent ? 2878 : 2016;
		cap = minCap + base::RandomIndex(maxCap - minCap + 1);
	}
	return std::clamp(cap, kRecordSizeMin, int(kClientPartSize));
}

void TlsSocket::write(bytes::const_span prefix, bytes::const_span buffer) {
	Expects(!buffer.empty());

	if (!isConnected()) {
		return;
	}
	if (_timing == ProxyTiming::Off) {
		if (!prefix.empty()) {
			_transport->write(kClientPrefix.data(), kClientPrefix.size());
		}
		while (!buffer.empty()) {
			const auto cap = nextRecordPayloadSize();
			const auto write = std::min(
				cap - int(prefix.size()),
				int(buffer.size()));
			_transport->write(kClientHeader.data(), kClientHeader.size());
			const auto size = qToBigEndian(uint16(prefix.size() + write));
			_transport->write(
				reinterpret_cast<const char*>(&size),
				sizeof(size));
			if (!prefix.empty()) {
				_transport->write(
					reinterpret_cast<const char*>(prefix.data()),
					prefix.size());
				prefix = bytes::const_span();
			}
			_transport->write(
				reinterpret_cast<const char*>(buffer.data()),
				write);
			buffer = buffer.subspan(write);
			_firstAppDataSent = true;
			++_startupCoverFrames;
		}
		return;
	}
	if (!prefix.empty() && !_clientPrefixSent) {
		_transport->write(kClientPrefix.data(), kClientPrefix.size());
		_clientPrefixSent = true;
	}
	if (!prefix.empty()) {
		_outgoing.append(
			reinterpret_cast<const char*>(prefix.data()),
			prefix.size());
	}
	_outgoing.append(
		reinterpret_cast<const char*>(buffer.data()),
		buffer.size());
	if (!_pacingTimer.isActive()) {
		sendOutgoing();
	}
}

void TlsSocket::sendOutgoing() {
	while (_outgoingOffset < _outgoing.size()) {
		const auto cap = nextRecordPayloadSize();
		const auto available = int(_outgoing.size()) - _outgoingOffset;
		const auto take = std::min(cap, available);
		_transport->write(kClientHeader.data(), kClientHeader.size());
		const auto size = qToBigEndian(uint16(take));
		_transport->write(
			reinterpret_cast<const char*>(&size),
			sizeof(size));
		_transport->write(_outgoing.constData() + _outgoingOffset, take);
		_outgoingOffset += take;
		_firstAppDataSent = true;
		++_startupCoverFrames;
		if (_outgoingOffset < _outgoing.size()) {
			const auto delay = recordPacingDelay();
			if (delay > 0) {
				_transport->flush();
				_pacingTimer.callOnce(delay);
				return;
			}
		}
	}
	_outgoing.clear();
	_outgoingOffset = 0;
}

crl::time TlsSocket::recordPacingDelay() {
	if (_startupCoverFrames > kMaxPacedFrames) {
		return 0;
	}
	if (_timing == ProxyTiming::Gentle) {
		return 8 + base::RandomIndex(14) + base::RandomIndex(25);
	} else if (_timing == ProxyTiming::Balanced) {
		return 20 + base::RandomIndex(28) + base::RandomIndex(54);
	}
	return 0;
}

} // namespace MTP::details

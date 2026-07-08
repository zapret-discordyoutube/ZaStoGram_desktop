/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/session/private/proxy_port.h"

namespace MTP::details {

SessionProxyTicket::Impl::~Impl() = default;

SessionProxyTicket::SessionProxyTicket(std::unique_ptr<Impl> impl)
: _impl(std::move(impl)) {
}

SessionProxyTicket::SessionProxyTicket(SessionProxyTicket &&other) noexcept
: _impl(std::move(other._impl)) {
}

SessionProxyTicket &SessionProxyTicket::operator=(
		SessionProxyTicket &&other) noexcept {
	if (this != &other) {
		cancel();
		_impl = std::move(other._impl);
	}
	return *this;
}

SessionProxyTicket::~SessionProxyTicket() {
	cancel();
}

void SessionProxyTicket::cancel() {
	if (_impl) {
		_impl->cancel();
		_impl = nullptr;
	}
}

SessionProxyTicketId SessionProxyTicket::id() const {
	return _impl ? _impl->id() : 0;
}

SessionProxyTicket::operator bool() const {
	return id() != 0;
}

SessionProxyPort::~SessionProxyPort() = default;

bool EmptySessionProxyAttempt(const SessionProxyAttempt &attempt) {
	return MtProxy::EndpointEmpty(attempt.endpoint);
}

} // namespace MTP::details

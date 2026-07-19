/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/session/private/proxy_port.h"

namespace MTP::details {

SessionProxyLease::Impl::~Impl() = default;

SessionProxyLease::SessionProxyLease(std::unique_ptr<Impl> impl)
: _impl(std::move(impl)) {
}

SessionProxyLease::SessionProxyLease(SessionProxyLease &&other) noexcept
: _impl(std::move(other._impl)) {
}

SessionProxyLease &SessionProxyLease::operator=(
		SessionProxyLease &&other) noexcept {
	if (this != &other) {
		release();
		_impl = std::move(other._impl);
	}
	return *this;
}

SessionProxyLease::~SessionProxyLease() {
	release();
}

void SessionProxyLease::release() {
	if (_impl) {
		_impl->release();
	}
}

void SessionProxyLease::transportReady() {
	if (_impl) {
		_impl->transportReady();
	}
}

bool SessionProxyLease::active() const {
	return _impl ? _impl->active() : false;
}

MtProxy::LiveSlotKey SessionProxyLease::slotKey() const {
	return _impl ? _impl->slotKey() : MtProxy::LiveSlotKey();
}

uint64 SessionProxyLease::attemptId() const {
	return _impl ? _impl->attemptId() : 0;
}

uint64 SessionProxyLease::proxyGeneration() const {
	return _impl ? _impl->proxyGeneration() : 0;
}

uint64 SessionProxyLease::proxyEpoch() const {
	return _impl ? _impl->proxyEpoch() : 0;
}

uint64 SessionProxyLease::successEpoch() const {
	return _impl ? _impl->successEpoch() : 0;
}

crl::time SessionProxyLease::startedAt() const {
	return _impl ? _impl->startedAt() : 0;
}

SessionProxyLease::Impl *SessionProxyLease::impl() const {
	return _impl.get();
}

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

void SessionProxyTicket::reevaluate() {
	if (_impl) {
		_impl->reevaluate();
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
	return EmptySessionProxyEndpoint(attempt.endpoint);
}

bool EmptySessionProxyEndpoint(const MtProxy::EndpointId &endpoint) {
	return endpoint.canonical.type == ProxyData::Type::None;
}

} // namespace MTP::details

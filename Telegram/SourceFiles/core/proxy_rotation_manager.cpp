/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "core/proxy_rotation_manager.h"

#include "core/application.h"
#include "core/core_settings.h"
#include "main/main_account.h"
#include "main/main_domain.h"
#include "mtproto/facade.h"

#include <crl/crl_on_main.h>

#include <algorithm>

namespace Core {
namespace {

constexpr auto kProxyRotationCheckInterval = 2 * crl::time(1000);
constexpr auto kProxyRotationCheckLifetime = 20 * crl::time(1000);
constexpr auto kProxyRotationMaxActiveChecks = 2;

// When the selected proxy degrades, keep the rotation window open at
// least this long regardless of how short the per-failure cooldown is.
// A proxy that flaps under DPI (connects, dies, connects again within
// seconds) otherwise keeps returning to ConnectedState and resetting
// rotation before it can probe a stable candidate and switch to it.
constexpr auto kSelectedDegradedObserveWindow = 25 * crl::time(1000);

} // namespace

ProxyRotationManager::ProxyRotationManager()
: _checkTimer([=] { runChecks(); })
, _switchTimer([=] { switchTimerDone(); }) {
	App().domain().accountsChanges(
	) | rpl::on_next([=] {
		stopChecking();
		reevaluate();
	}, _lifetime);
	MTP::details::MtProxy::EndpointHealth::Instance().changes(
	) | rpl::on_next([=](MTP::details::MtProxy::EndpointEvent event) {
		// Health events fire from session/network threads, while the
		// manager works with App() settings and accounts - marshal.
		crl::on_main(base::make_weak(this), [=] {
			handleEndpointHealthChanged(event);
		});
	}, _lifetime);
}

void ProxyRotationManager::settingsChanged() {
	stopChecking();
	pruneRemovedEntries();
	reevaluate();
}

void ProxyRotationManager::handleConnectionStateChanged(
		not_null<Main::Account*> account,
		int32 state) {
	(void)account;
	(void)state;
	reevaluate();
}

bool ProxyRotationManager::shouldObserve() const {
	const auto &settings = App().settings().proxy();
	return settings.isEnabled()
		&& settings.selected()
		&& settings.proxyRotationEnabled()
		&& (settings.list().size() > 1);
}

std::vector<not_null<Main::Account*>> ProxyRotationManager::productionAccounts() const {
	auto result = std::vector<not_null<Main::Account*>>();
	for (const auto &entry : App().domain().accounts()) {
		const auto account = entry.account.get();
		if (!account->sessionExists() || account->mtp().isTestMode()) {
			continue;
		}
		result.push_back(account);
	}
	return result;
}

not_null<Main::Account*> ProxyRotationManager::accountForChecks() const {
	if (App().someSessionExists()
		&& App().activeAccount().sessionExists()
		&& !App().activeAccount().mtp().isTestMode()) {
		return &App().activeAccount();
	}
	const auto accounts = productionAccounts();
	Expects(!accounts.empty());
	return accounts.front();
}

auto ProxyRotationManager::find(
		const MTP::ProxyData &proxy) -> Entry* {
	const auto i = ranges::find(
		_entries,
		proxy,
		[](const Entry &entry) { return entry.proxy; });
	return (i == end(_entries)) ? nullptr : &*i;
}

auto ProxyRotationManager::ensure(
		const MTP::ProxyData &proxy) -> Entry& {
	if (const auto entry = find(proxy)) {
		return *entry;
	}
	_entries.push_back({ .proxy = proxy });
	return _entries.back();
}

void ProxyRotationManager::reevaluate() {
	if (!shouldObserve()) {
		stopChecking();
		return;
	}
	const auto accounts = productionAccounts();
	if (accounts.empty()) {
		stopChecking();
		return;
	}
	const auto stateProj = [](not_null<Main::Account*> account) {
		return account->mtp().dcstate();
	};
	if (!hasActiveHealthRotationRequest()
		&& ranges::contains(accounts, MTP::ConnectedState, stateProj)) {
		stopChecking();
		return;
	}
	startChecking();
}

void ProxyRotationManager::handleEndpointHealthChanged(
		MTP::details::MtProxy::EndpointEvent event) {
	if (!event.rotationAllowed || event.terminalUntil <= crl::now()) {
		return;
	}
	// Admission starvation fires for every endpoint going through the
	// broker, including candidates we are probing ourselves - only the
	// selected proxy may request rotation, otherwise a starving candidate
	// would keep extending the health window and pin checking forever.
	if (!isSelectedProxyEndpoint(event.endpoint)) {
		return;
	}
	// Hold the observation window open long enough to probe a candidate
	// and switch, decoupled from the (possibly very short) per-failure
	// cooldown: a flapping proxy must not reset rotation on every brief
	// recovery before a stable alternative has been found.
	accumulate_max(
		_healthRotationRequestedUntil,
		std::max(
			event.terminalUntil,
			crl::now() + kSelectedDegradedObserveWindow));
	const auto wasChecking = _checking;
	reevaluate();
	if (!wasChecking || !_checking || _waitingToSwitch) {
		return;
	}
	// Checks were already running, so startChecking() won't re-arm the
	// switch timer. The selected proxy has been starving for a while now,
	// switch right away if some candidate already passed its probe. With
	// no verified candidate (e.g. a total network outage) this changes
	// nothing - the switch timer and checkDone() keep their normal flow.
	if (shouldSwitchToAvailable()) {
		(void)switchToAvailable();
	}
}

bool ProxyRotationManager::isSelectedProxyEndpoint(
		const MTP::details::MtProxy::EndpointId &endpoint) const {
	const auto &settings = App().settings().proxy();
	if (!settings.isEnabled()) {
		return false;
	}
	const auto selected = MTP::details::MtProxy::EndpointIdFromProxy(
		settings.selected(),
		App().settings().proxyStealthOptions());
	const auto key = MTP::details::MtProxy::EndpointKey(selected);
	return !key.isEmpty()
		&& (key == MTP::details::MtProxy::EndpointKey(endpoint));
}

bool ProxyRotationManager::hasActiveHealthRotationRequest() const {
	return _healthRotationRequestedUntil > crl::now();
}

void ProxyRotationManager::startChecking() {
	if (_checking) {
		return;
	}
	_checking = true;
	_waitingToSwitch = false;
	_switchStartedAt = crl::now();
	updateProbeOrder();
	runChecks();
	const auto timeout = App().settings().proxy().proxyRotationTimeout();
	_switchTimer.callOnce(timeout * crl::time(1000));
}

void ProxyRotationManager::stopChecking() {
	_checkTimer.cancel();
	_switchTimer.cancel();
	_checking = false;
	_waitingToSwitch = false;
	_switchStartedAt = 0;
	_healthRotationRequestedUntil = 0;
	_probeOrder.clear();
	_nextCheckIndex = 0;
	clearPendingChecks();
}

void ProxyRotationManager::pruneRemovedEntries() {
	const auto &settings = App().settings().proxy();
	_entries.erase(
		std::remove_if(begin(_entries), end(_entries), [&](const Entry &entry) {
			return (settings.indexInList(entry.proxy) < 0);
		}),
		end(_entries));
}

void ProxyRotationManager::updateProbeOrder() {
	const auto &settings = App().settings().proxy();
	const auto currentIndex = settings.indexInList(settings.selected());
	_probeOrder.clear();
	_probeOrder.reserve(settings.list().size());
	for (const auto index : settings.proxyRotationPreferredIndices()) {
		if (index == currentIndex) {
			continue;
		}
		_probeOrder.push_back(index);
	}
	for (auto i = 0, count = int(settings.list().size()); i != count; ++i) {
		if (i == currentIndex || ranges::contains(_probeOrder, i)) {
			continue;
		}
		_probeOrder.push_back(i);
	}
	_nextCheckIndex = 0;
}

void ProxyRotationManager::continueChecking(crl::time delay) {
	if (!_checking) {
		return;
	}
	if (_checkTimer.isActive()) {
		_checkTimer.cancel();
	}
	_checkTimer.callOnce(delay);
}

void ProxyRotationManager::runChecks() {
	if (!_checking) {
		return;
	}
	if (!shouldObserve()) {
		stopChecking();
		return;
	}
	const auto accounts = productionAccounts();
	if (accounts.empty()
		|| (!hasActiveHealthRotationRequest()
			&& ranges::contains(
			accounts,
			MTP::ConnectedState,
			[](not_null<Main::Account*> account) {
				return account->mtp().dcstate();
			}))) {
		stopChecking();
		return;
	}
	pruneExpiredChecks();
	startNextCheck();
	continueChecking(kProxyRotationCheckInterval);
}

void ProxyRotationManager::pruneExpiredChecks() {
	const auto now = crl::now();
	for (auto &entry : _entries) {
		if (!entry.checking
			|| (now - entry.startedAt < kProxyRotationCheckLifetime)) {
			continue;
		}
		MTP::ResetProxyCheckers(entry.v4, entry.v6);
		entry.checking = false;
		entry.startedAt = 0;
	}
}

void ProxyRotationManager::startNextCheck() {
	if (_probeOrder.empty()) {
		return;
	}
	if (ranges::count(_entries, true, &Entry::checking)
		>= kProxyRotationMaxActiveChecks) {
		return;
	}
	const auto &settings = App().settings().proxy();
	auto attemptsLeft = int(_probeOrder.size());
	while (attemptsLeft-- > 0) {
		if (_nextCheckIndex >= int(_probeOrder.size())) {
			_nextCheckIndex = 0;
		}
		const auto listIndex = _probeOrder[_nextCheckIndex++];
		if (listIndex < 0 || listIndex >= int(settings.list().size())) {
			continue;
		}
		const auto &proxy = settings.list()[listIndex];
		auto &entry = ensure(proxy);
		if (entry.checking) {
			continue;
		}
		entry.checking = true;
		entry.startedAt = crl::now();
		MTP::StartProxyCheck(
			&accountForChecks()->mtp(),
			proxy,
			settings.tryIPv6(),
			App().settings().proxyStealthOptions(),
			entry.v4,
			entry.v6,
			[=](MTP::details::AbstractConnection *raw, int ping) {
				checkDone(proxy, raw, ping);
			},
			[=](MTP::details::AbstractConnection *raw) {
				checkFailed(proxy, raw);
			});
		break;
	}
}

void ProxyRotationManager::switchTimerDone() {
	if (!_checking || !shouldSwitchToAvailable()) {
		return;
	}
	_waitingToSwitch = !switchToAvailable();
}

void ProxyRotationManager::clearPendingChecks() {
	for (auto &entry : _entries) {
		MTP::ResetProxyCheckers(entry.v4, entry.v6);
		entry.checking = false;
		entry.startedAt = 0;
	}
}

void ProxyRotationManager::checkDone(
		const MTP::ProxyData &proxy,
		not_null<MTP::details::AbstractConnection*> raw,
		int ping) {
	const auto entry = find(proxy);
	if (!entry
		|| !entry->checking
		|| ((entry->v4.get() != raw) && (entry->v6.get() != raw))) {
		return;
	}
	MTP::DropProxyChecker(entry->v4, entry->v6, raw);
	MTP::ResetProxyCheckers(entry->v4, entry->v6);
	entry->checking = false;
	entry->startedAt = 0;
	entry->availableAt = crl::now();
	const auto proxySettings = &App().settings().proxy();
	if (const auto index = proxySettings->indexInList(proxy); index >= 0) {
		if (proxySettings->promoteProxyRotationPreferredIndex(index)) {
			App().saveSettingsDelayed();
		}
	}
	updateProbeOrder();
	if (_waitingToSwitch && shouldSwitchToAvailable()) {
		_waitingToSwitch = !switchToAvailable();
	}
}

void ProxyRotationManager::checkFailed(
		const MTP::ProxyData &proxy,
		not_null<MTP::details::AbstractConnection*> raw) {
	const auto entry = find(proxy);
	if (!entry
		|| !entry->checking
		|| ((entry->v4.get() != raw) && (entry->v6.get() != raw))) {
		return;
	}
	MTP::DropProxyChecker(entry->v4, entry->v6, raw);
	if (MTP::HasProxyCheckers(entry->v4, entry->v6)) {
		return;
	}
	entry->checking = false;
	entry->startedAt = 0;
}

bool ProxyRotationManager::switchToAvailable() {
	if (!_checking) {
		return false;
	}
	const auto &settings = App().settings().proxy();
	for (const auto index : _probeOrder) {
		if (index < 0 || index >= int(settings.list().size())) {
			continue;
		}
		const auto &proxy = settings.list()[index];
		const auto entry = find(proxy);
		if (!entry || entry->checking || !entry->availableAt) {
			continue;
		}
		if (entry->availableAt < _switchStartedAt) {
			continue;
		}
		_waitingToSwitch = false;
		App().setCurrentProxy(proxy, MTP::ProxyData::Settings::Enabled);
		App().saveSettingsDelayed();
		return true;
	}
	return false;
}

bool ProxyRotationManager::shouldSwitchToAvailable() const {
	if (!_checking || !shouldObserve()) {
		return false;
	}
	const auto accounts = productionAccounts();
	return !accounts.empty()
		&& (hasActiveHealthRotationRequest()
			|| !ranges::contains(
			accounts,
			MTP::ConnectedState,
			[](not_null<Main::Account*> account) {
				return account->mtp().dcstate();
			}));
}

} // namespace Core

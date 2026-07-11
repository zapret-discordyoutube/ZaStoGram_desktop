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
#include "mtproto/proxy/diagnostics.h"
#include "mtproto/proxy/proxy_services.h"
#include "mtproto/instance/mtp_instance.h"
#include "mtproto/runtime/runtime_environment.h"
#include "mtproto/session/session_state.h"

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

// After a switch the freshly selected proxy needs time to actually bring
// the main session to ConnectedState: every switch restarts all sessions
// of every account, and through an mtproxy that takes seconds. Without
// this grace period the next probe success (they complete about every
// check interval) sees "still nobody connected" and switches again -
// observed as the selection ping-ponging across the whole proxy list
// every ~2 seconds with a full session-restart storm on each hop.
constexpr auto kAfterSwitchGracePeriod = 15 * crl::time(1000);

} // namespace

ProxyRotationManager::ProxyRotationManager()
: _checkTimer([=] { runChecks(); })
, _switchTimer([=] { switchTimerDone(); }) {
	App().domain().accountsChanges(
	) | rpl::on_next([=] {
		stopChecking();
		reevaluate();
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
		clearEndpointHealthSubscription();
		stopChecking();
		return;
	}
	const auto accounts = productionAccounts();
	if (accounts.empty()) {
		clearEndpointHealthSubscription();
		stopChecking();
		return;
	}
	subscribeEndpointHealth();
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

void ProxyRotationManager::subscribeEndpointHealth() {
	auto &runtime = accountForChecks()->mtp().runtimeEnvironment();
	if (_endpointHealthRuntime == &runtime) {
		return;
	}
	_endpointHealthRuntime = &runtime;
	_endpointHealthLifetime.destroy();
	accountForChecks()->mtp().runtimeEnvironment().proxyServices().control().mtproxyEndpointChanges(
	) | rpl::on_next([=](MTP::details::MtProxy::EndpointEvent event) {
		handleEndpointHealthChanged(std::move(event));
	}, _endpointHealthLifetime);
}

void ProxyRotationManager::clearEndpointHealthSubscription() {
	_endpointHealthRuntime = nullptr;
	_endpointHealthLifetime.destroy();
}

void ProxyRotationManager::handleEndpointHealthChanged(
		MTP::details::MtProxy::EndpointEvent event) {
	if (!event.rotationAllowed || event.terminalUntil <= crl::now()) {
		return;
	}
	if (_lastSwitchAt
		&& (crl::now() - _lastSwitchAt < kAfterSwitchGracePeriod)) {
		// Right after a switch every session of every account reconnects
		// through the new proxy at once; the transient admission pressure
		// of that warm-up degrades endpoints for a moment and must not
		// immediately re-open the rotation window for the next hop.
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
			&accountForChecks()->mtp().runtimeEnvironment(),
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
	// A bare ProxyCheck probe bypasses the cooldown ladder and proves only
	// the FakeTLS handshake, so a relay-blocked proxy (the log's
	// server_hello_ok_no_appdata / client_hello_sent_no_server_hello
	// flappers) can still pass its check. Do not let such a proxy jump to
	// the front of the probe order and become the first pick - that is the
	// "check passes -> switch to it -> main-use dies -> switch again"
	// ping-pong. It stays available as a last resort, just not preferred.
	if (const auto index = proxySettings->indexInList(proxy); index >= 0) {
		if (proxyRelayHealthy(proxy)
			&& proxySettings->promoteProxyRotationPreferredIndex(index)) {
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
	if (_lastSwitchAt
		&& (crl::now() - _lastSwitchAt < kAfterSwitchGracePeriod)) {
		return false;
	}
	const auto &settings = App().settings().proxy();
	const auto was = settings.selected();
	const auto eligible = [&](int index) {
		if (index < 0 || index >= int(settings.list().size())) {
			return false;
		}
		const auto entry = find(settings.list()[index]);
		return entry
			&& !entry->checking
			&& entry->availableAt
			&& (entry->availableAt >= _switchStartedAt);
	};
	// Prefer a candidate that main-use health has not marked relay-blocked
	// (a ProxyCheck pass alone does not prove the relay). Fall back to any
	// available candidate so rotation never gets stuck when every proxy is
	// degraded - staying on a dead proxy is strictly worse than a probe.
	auto chosen = -1;
	auto fallback = -1;
	for (const auto index : _probeOrder) {
		if (!eligible(index)) {
			continue;
		}
		if (fallback < 0) {
			fallback = index;
		}
		if (proxyRelayHealthy(settings.list()[index])) {
			chosen = index;
			break;
		}
	}
	if (chosen < 0) {
		chosen = fallback;
	}
	if (chosen < 0) {
		return false;
	}
	const auto &proxy = settings.list()[chosen];
	_waitingToSwitch = false;
	_lastSwitchAt = crl::now();
	_switchStartedAt = _lastSwitchAt;
	_healthRotationRequestedUntil = 0;
	auto &runtime = accountForChecks()->mtp().runtimeEnvironment();
	MTP::WriteProxyDiagnosticsLine(not_null{ &runtime }, {
		.source = MTP::ProxyDiagnosticsSource::MTProxy,
		.phase = MTP::ProxyDiagnosticsPhase::RotationSwitched,
		.severity = MTP::ProxyDiagnosticsSeverity::Warning,
		.proxy = proxy,
		.message = u"proxy rotation switched from %1"_q.arg(
			MTP::ProxyDiagnosticsEndpointText(was.host, was.port)),
	});
	App().setCurrentProxy(
		proxy,
		MTP::ProxyData::Settings::Enabled,
		/*manual=*/false);
	App().saveSettingsDelayed();
	return true;
}

bool ProxyRotationManager::proxyRelayHealthy(
		const MTP::ProxyData &proxy) const {
	if (proxy.type != MTP::ProxyData::Type::Mtproto) {
		return true;
	}
	// accountForChecks() asserts a production account exists; checkDone can
	// reach here from an in-flight check after the last account went away,
	// so mirror its precondition and treat "no account to consult" as
	// healthy (don't block) rather than aborting.
	const auto activeUsable = App().someSessionExists()
		&& App().activeAccount().sessionExists()
		&& !App().activeAccount().mtp().isTestMode();
	if (!activeUsable && productionAccounts().empty()) {
		return true;
	}
	const auto endpoint = MTP::details::MtProxy::EndpointIdFromProxy(
		proxy,
		App().settings().proxyStealthOptions());
	const auto snapshot = accountForChecks()->mtp().runtimeEnvironment()
		.proxyServices().control().mtproxyEndpointSnapshot(endpoint);
	// Block only an endpoint that is ACTIVELY in cooldown right now. This is
	// self-healing: once the cooldown expires the proxy is eligible again,
	// so a genuinely recovered proxy is not deprioritized forever (halfOpen
	// persists until a fresh main-use success, so it is deliberately not
	// used here). A never-used proxy has terminalUntil==0 and stays
	// selectable.
	return snapshot.terminalUntil <= crl::now();
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

/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "e2e_cloud/desktop/protected_groups_box.h"

#include "boxes/add_contact_box.h"
#include "e2e_cloud/desktop/desktop_service.h"
#include "e2e_cloud/desktop/protected_conversation_box.h"
#include "e2e_cloud/identity/account_identity.h"
#include "lang/lang_keys.h"
#include "main/main_session.h"
#include "ui/widgets/fields/password_input.h"
#include "ui/widgets/labels.h"
#include "ui/widgets/buttons.h"
#include "ui/layers/generic_box.h"
#include "window/window_session_controller.h"
#include "styles/style_layers.h"
#include "styles/style_settings.h"
#include "styles/style_widgets.h"

#include <utility>

namespace E2ECloud {
namespace {

inline constexpr auto kMinimumPasswordCharacters = 12;

[[nodiscard]] bool HasMinimumPasswordLength(const QString &password) {
	auto count = 0;
	for (auto i = 0; i != password.size();) {
		const auto first = password.at(i++);
		if (first.isHighSurrogate()
			&& i != password.size()
			&& password.at(i).isLowSurrogate()) {
			++i;
		}
		if (++count >= kMinimumPasswordCharacters) {
			return true;
		}
	}
	return false;
}

void ClearPassword(QString &password) {
	password.fill(QChar());
	password.clear();
}

[[nodiscard]] QString VaultReadyText(const UnlockedCloudVault &vault) {
	const auto accountId = DeriveAccountId(
		vault.identity.credential,
		OpenSslSha256Provider());
	auto fingerprint = QString();
	if (accountId) {
		auto digest = Digest();
		digest.bytes = accountId->bytes;
		fingerprint = FormatSafetyCode(digest).value_or(QString());
	}
	return tr::lng_e2e_cloud_ready(
		tr::now,
		lt_chat_count,
		QString::number(vault.conversations.size()),
		lt_code,
		fingerprint);
}

} // namespace

ProtectedGroupsBox::ProtectedGroupsBox(
	QWidget*,
	not_null<Window::SessionController*> controller)
: _controller(controller)
, _status(this, QString(), st::boxLabel)
, _password(
	this,
	st::defaultInputField,
	tr::lng_e2e_cloud_password())
, _confirm(
	this,
	st::defaultInputField,
	tr::lng_e2e_cloud_password_confirm()) {
}

void ProtectedGroupsBox::prepare() {
	setTitle(tr::lng_e2e_cloud_title());
	_controller->session().e2eCloud().vaultStateValue(
	) | rpl::on_next([=](DesktopVaultState) {
		refresh();
	}, lifetime());
	_controller->session().e2eCloud().groupCreationStateValue(
	) | rpl::on_next([=](DesktopGroupCreationState) {
		refresh();
	}, lifetime());
	connect(_password, &Ui::MaskedInputField::submitted, [=] {
		if (!_confirm->isHidden() && !_confirm->hasFocus()) {
			_confirm->setFocusFast();
		} else {
			submit();
		}
	});
	connect(_confirm, &Ui::MaskedInputField::submitted, [=] {
		submit();
	});
	_controller->session().e2eCloud().ensureVaultDiscovery();
	refresh();
}

void ProtectedGroupsBox::setInnerFocus() {
	if (!_password->isHidden()) {
		_password->setFocusFast();
	}
}

void ProtectedGroupsBox::resizeEvent(QResizeEvent *event) {
	BoxContent::resizeEvent(event);
	updateControlsGeometry();
}

void ProtectedGroupsBox::updateControlsGeometry() {
	const auto available = width()
		- st::boxPadding.left()
		- st::boxPadding.right();
	auto top = st::boxPadding.top();
	_status->moveToLeft(st::boxPadding.left(), top);
	_status->resizeToWidth(available);
	top += _status->height() + st::boxMediumSkip;
	if (!_password->isHidden()) {
		_password->resize(available, _password->height());
		_password->moveToLeft(st::boxPadding.left(), top);
		top += _password->height() + st::boxMediumSkip;
	}
	if (!_confirm->isHidden()) {
		_confirm->resize(available, _confirm->height());
		_confirm->moveToLeft(st::boxPadding.left(), top);
		top += _confirm->height() + st::boxMediumSkip;
	}
	setDimensions(st::boxWidth, top + st::boxPadding.bottom());
}

void ProtectedGroupsBox::refresh() {
	const auto &service = _controller->session().e2eCloud();
	const auto state = service.vaultState();
	const auto passwordVisible = state == DesktopVaultState::Locked
		|| state == DesktopVaultState::Missing
		|| state == DesktopVaultState::WrongPasswordOrDamaged
		|| state == DesktopVaultState::RetryableTransportError;
	const auto confirmVisible = state == DesktopVaultState::Missing;
	_password->setVisible(passwordVisible);
	_confirm->setVisible(confirmVisible);
	_password->setDisabled(
		state == DesktopVaultState::Loading
		|| state == DesktopVaultState::Creating);
	_confirm->setDisabled(state == DesktopVaultState::Creating);
	clearButtons();
	switch (state) {
	case DesktopVaultState::Uninitialized:
	case DesktopVaultState::Discovering:
		_status->setText(tr::lng_e2e_cloud_discovering(tr::now));
		break;
	case DesktopVaultState::Locked:
		_status->setText(tr::lng_e2e_cloud_locked(tr::now));
		addButton(tr::lng_e2e_cloud_unlock(), [=] { submit(); });
		break;
	case DesktopVaultState::Loading:
		_status->setText(tr::lng_e2e_cloud_loading(tr::now));
		break;
	case DesktopVaultState::Missing:
		_status->setText(tr::lng_e2e_cloud_missing(tr::now));
		addButton(tr::lng_e2e_cloud_create(), [=] { submit(); });
		break;
	case DesktopVaultState::Creating:
		_status->setText(tr::lng_e2e_cloud_creating(tr::now));
		break;
	case DesktopVaultState::Ready: {
		_password->setText(QString());
		_confirm->setText(QString());
		const auto vault = service.vault();
		_status->setText(vault
			? VaultReadyText(*vault)
			: tr::lng_e2e_cloud_damaged(tr::now));
		const auto creation = service.groupCreationState();
		if (creation == DesktopGroupCreationState::RetryableTransportError) {
			addButton(tr::lng_e2e_cloud_retry(), [=] {
				(void)_controller->session().e2eCloud()
					.retryProtectedGroupCreation();
			});
		} else if (creation == DesktopGroupCreationState::Preparing
			|| creation == DesktopGroupCreationState::UpdatingVault
			|| creation == DesktopGroupCreationState::AwaitingAdmission
			|| creation == DesktopGroupCreationState::AwaitingFreshness
			|| creation
				== DesktopGroupCreationState::PublishingBootstrap) {
			_status->setText(tr::lng_e2e_cloud_group_publishing(tr::now));
		} else if (creation == DesktopGroupCreationState::LocalFailure
			|| creation
				== DesktopGroupCreationState::PermanentTransportError) {
			_status->setText(tr::lng_e2e_cloud_group_failed(tr::now));
		} else {
			if (!service.protectedGroups().empty()) {
				addButton(tr::lng_e2e_cloud_open_chats(), [=] {
					ShowProtectedGroupList(_controller);
				});
			}
			addButton(tr::lng_e2e_cloud_new_group(), [=] {
				showGroupCreation();
			});
		}
		addButton(tr::lng_e2e_cloud_lock(), [=] {
			_controller->session().e2eCloud().lock();
		});
		break;
	}
	case DesktopVaultState::WrongPasswordOrDamaged:
		_status->setText(tr::lng_e2e_cloud_damaged(tr::now));
		addButton(tr::lng_e2e_cloud_unlock(), [=] { submit(); });
		break;
	case DesktopVaultState::RetryableTransportError:
		_status->setText(tr::lng_e2e_cloud_network_error(tr::now));
		addButton(tr::lng_e2e_cloud_retry(), [=] {
			if (!_controller->session().e2eCloud().retryCreateVault()) {
				submit();
			}
		});
		break;
	case DesktopVaultState::PermanentTransportError:
		_status->setText(tr::lng_e2e_cloud_transport_error(tr::now));
		break;
	case DesktopVaultState::DiscoveryRetryableError:
		_status->setText(
			tr::lng_e2e_cloud_discovery_network_error(tr::now));
		addButton(tr::lng_e2e_cloud_retry(), [=] {
			_controller->session().e2eCloud().ensureVaultDiscovery();
		});
		break;
	case DesktopVaultState::DiscoveryPermanentError:
		_status->setText(
			tr::lng_e2e_cloud_discovery_transport_error(tr::now));
		break;
	case DesktopVaultState::SecurityBlocked:
		_status->setText(tr::lng_e2e_cloud_security_blocked(tr::now));
		break;
	}
	addButton(tr::lng_close(), [=] { closeBox(); });
	updateControlsGeometry();
	if (passwordVisible
		&& !_password->hasFocus()
		&& !_confirm->hasFocus()) {
		_password->setFocusFast();
	}
}

void ProtectedGroupsBox::submit() {
	auto &service = _controller->session().e2eCloud();
	auto password = _password->getLastText();
	if (password.isEmpty()) {
		_password->setFocusFast();
		_password->showError();
		return;
	}
	const auto creating = service.vaultState() == DesktopVaultState::Missing;
	if (creating && !HasMinimumPasswordLength(password)) {
		_status->setText(
			tr::lng_e2e_cloud_password_requirements(tr::now));
		_password->setFocusFast();
		_password->showError();
		ClearPassword(password);
		return;
	}
	auto passwordBytes = password.toUtf8();
	auto started = false;
	if (creating) {
		auto confirmation = _confirm->getLastText();
		if (confirmation.isEmpty() || confirmation != password) {
			_confirm->setFocusFast();
			_confirm->showError();
			passwordBytes.fill('\0');
			ClearPassword(password);
			ClearPassword(confirmation);
			return;
		}
		ClearPassword(confirmation);
		started = service.createVault(passwordBytes);
	} else {
		started = service.unlock(passwordBytes);
	}
	passwordBytes.fill('\0');
	ClearPassword(password);
	if (started) {
		_password->setText(QString());
		_confirm->setText(QString());
	}
}

void ProtectedGroupsBox::showGroupCreation() {
	const auto controller = _controller;
	uiShow()->showBox(Box([=](not_null<Ui::GenericBox*> box) {
		box->setTitle(tr::lng_e2e_cloud_history_policy());
		const auto addPolicy = [=](
				rpl::producer<QString> label,
				HistoryAccessMode mode) {
			const auto button = box->addRow(
				object_ptr<Ui::SettingsButton>(
					box,
					std::move(label),
					st::settingsButton),
				style::al_top);
			button->setClickedCallback([=] {
				box->closeBox();
				controller->uiShow()->showBox(
					Box<GroupInfoBox>(
						controller,
						GroupInfoBox::Type::Megagroup,
						QString(),
						Fn<void(not_null<PeerData*>)>([
								controller,
								mode](not_null<PeerData*> peer) {
							const auto started = controller->session()
								.e2eCloud().createProtectedGroup(peer, {
									.mode = mode,
									.boundaryEventId = {},
								});
							controller->uiShow()->showToast(started
								? tr::lng_e2e_cloud_group_publishing(
									tr::now)
								: tr::lng_e2e_cloud_group_failed(tr::now));
						})),
					Ui::LayerOption::KeepOther);
			});
		};
		addPolicy(
			tr::lng_e2e_cloud_history_none(),
			HistoryAccessMode::None);
		addPolicy(
			tr::lng_e2e_cloud_history_from_join(),
			HistoryAccessMode::FromJoin);
		addPolicy(
			tr::lng_e2e_cloud_history_full(),
			HistoryAccessMode::Full);
		box->addButton(tr::lng_cancel(), [=] { box->closeBox(); });
	}));
}

} // namespace E2ECloud

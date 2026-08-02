/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "e2e_cloud/desktop/protected_conversation_box.h"

#include "e2e_cloud/desktop/desktop_service.h"
#include "e2e_cloud/files/private_file_manifest.h"
#include "core/application.h"
#include "core/file_utilities.h"
#include "data/data_document.h"
#include "lang/lang_keys.h"
#include "main/main_session.h"
#include "ui/boxes/confirm_box.h"
#include "ui/layers/generic_box.h"
#include "ui/toast/toast.h"
#include "ui/widgets/buttons.h"
#include "ui/widgets/labels.h"
#include "window/window_session_controller.h"
#include "styles/style_layers.h"
#include "styles/style_settings.h"
#include "styles/style_widgets.h"

#include <openssl/crypto.h>

#include <QtCore/QScopeGuard>

#include <algorithm>
#include <utility>

namespace E2ECloud {
namespace {

void CleanseRecords(std::vector<ProtectedContentRecord> &records) {
	for (auto &record : records) {
		if (!record.plaintext.isEmpty()) {
			OPENSSL_cleanse(
				record.plaintext.data(),
				record.plaintext.size());
			record.plaintext.clear();
		}
	}
}

template <typename Id>
[[nodiscard]] std::optional<Id> DecodeProtectedHistoryId(
		const QByteArray &bytes) {
	auto result = Id();
	if (bytes.size() != int(result.bytes.size())) {
		return std::nullopt;
	}
	std::copy_n(
		reinterpret_cast<const std::uint8_t*>(bytes.constData()),
		result.bytes.size(),
		result.bytes.begin());
	return result ? std::optional<Id>(result) : std::nullopt;
}

void CloseWhenVaultUnavailable(
		not_null<Ui::GenericBox*> box,
		not_null<DesktopService*> service) {
	service->vaultStateValue() | rpl::on_next([=](DesktopVaultState state) {
		if (state != DesktopVaultState::Ready) {
			box->closeBox();
		}
	}, box->lifetime());
}

void CloseWhenSecurityChanges(
		not_null<Ui::GenericBox*> box,
		not_null<DesktopService*> service) {
	service->securityRevisionValue(
	) | rpl::skip(1) | rpl::on_next([=](std::uint64_t) {
		box->closeBox();
	}, box->lifetime());
}

void SaveProtectedRecord(
		not_null<DesktopService*> service,
		ConversationId conversationId,
		ObjectId eventObjectId,
		QString filename,
		QWidget *guard) {
	FileDialog::GetWritePath(
		Core::App().getFileDialogParent(),
		tr::lng_e2e_cloud_save_file(tr::now),
		FileDialog::AllFilesFilter(),
		std::move(filename),
		crl::guard(guard, [=](QString &&path) {
			if (!path.isEmpty()) {
				(void)service->saveProtectedFile(
					conversationId,
					eventObjectId,
					std::move(path),
					crl::guard(guard, [](ProtectedFileSaveResult result) {
						const auto text = (result
								== ProtectedFileSaveResult::Saved)
							? tr::lng_e2e_cloud_file_saved(tr::now)
							: (result == ProtectedFileSaveResult::Busy)
							? tr::lng_e2e_cloud_file_busy(tr::now)
							: tr::lng_e2e_cloud_file_save_failed(tr::now);
						Ui::Toast::Show({ .text = text });
					}));
			}
		}));
}

void RebuildProtectedFiles(
		not_null<Ui::VerticalLayout*> container,
		DesktopService &service,
		ConversationId conversationId,
		not_null<std::size_t*> visibleLimit) {
	container->clear();
	const auto kind = ObjectKind::EncryptedFileManifest;
	const auto total = service.protectedContentCount(conversationId, kind);
	if (!total) {
		container->add(
			object_ptr<Ui::FlatLabel>(
				container,
				tr::lng_e2e_cloud_content_empty(),
				st::boxLabel),
			st::boxRowPadding);
		return;
	}
	constexpr auto kVisiblePageSize = std::size_t(200);
	const auto visible = std::min(*visibleLimit, total);
	const auto first = total - visible;
	if (first) {
		const auto count = std::min(kVisiblePageSize, first);
		const auto button = container->add(
			object_ptr<Ui::SettingsButton>(
				container,
				tr::lng_e2e_cloud_show_older(
					lt_count,
					rpl::single(int(count)) | tr::to_count()),
				st::settingsButton),
			st::boxRowPadding,
			style::al_top);
		button->setClickedCallback([=, service = &service] {
			*visibleLimit += count;
			crl::on_main(container, [=] {
				RebuildProtectedFiles(
					container,
					*service,
					conversationId,
					visibleLimit);
			});
		});
	}
	auto records = service.protectedContent(
		conversationId,
		first,
		visible,
		kind);
	const auto recordsGuard = qScopeGuard([&] {
		CleanseRecords(records);
	});
	if (records.size() != visible) {
		container->add(
			object_ptr<Ui::FlatLabel>(
				container,
				tr::lng_e2e_cloud_content_failed(),
				st::boxLabel),
			st::boxRowPadding);
		return;
	}
	for (const auto &record : records) {
		const auto manifest = PrivateFileManifestCodecV1()
			.decodePlaintext(record.plaintext);
		if (!manifest) {
			continue;
		}
		const auto title = tr::lng_e2e_cloud_file(
			tr::now,
			lt_name,
			QString::fromUtf8(manifest->filenameUtf8),
			lt_size,
			QString::number(manifest->context.plaintextSize));
		const auto button = container->add(
			object_ptr<Ui::SettingsButton>(
				container,
				rpl::single(title),
				st::settingsButton),
			st::boxRowPadding,
			style::al_top);
		const auto eventObjectId = record.eventObjectId;
		const auto filename = QString::fromUtf8(manifest->filenameUtf8);
		button->setClickedCallback([=, service = &service] {
			SaveProtectedRecord(
				service,
				conversationId,
				eventObjectId,
				filename,
				container.get());
		});
	}
}

[[nodiscard]] QString ContentStatusText(
		const DesktopService &service,
		ConversationId conversationId) {
	const auto groups = service.protectedGroups();
	const auto group = std::find_if(
		begin(groups),
		end(groups),
		[&](const auto &value) {
			return value.conversationId == conversationId;
		});
	if (group != end(groups) && group->removed) {
		return tr::lng_e2e_cloud_content_removed(tr::now);
	}
	switch (service.contentState(conversationId)) {
	case DesktopContentState::Idle:
	case DesktopContentState::Ready:
		return tr::lng_e2e_cloud_content_ready(tr::now);
	case DesktopContentState::Synchronizing:
		return tr::lng_e2e_cloud_content_syncing(tr::now);
	case DesktopContentState::AwaitingFreshness:
		return tr::lng_e2e_cloud_content_freshness(tr::now);
	case DesktopContentState::RetryableTransportError:
		return tr::lng_e2e_cloud_network_error(tr::now);
	case DesktopContentState::PermanentTransportError:
	case DesktopContentState::LocalFailure:
		return tr::lng_e2e_cloud_content_failed(tr::now);
	case DesktopContentState::SecurityBlocked:
		return tr::lng_e2e_cloud_security_blocked(tr::now);
	}
	return tr::lng_e2e_cloud_content_failed(tr::now);
}

[[nodiscard]] QString RoleText(GroupRole role) {
	switch (role) {
	case GroupRole::Owner:
		return tr::lng_e2e_cloud_role_owner(tr::now);
	case GroupRole::Administrator:
		return tr::lng_e2e_cloud_role_admin(tr::now);
	case GroupRole::Member:
		return tr::lng_e2e_cloud_role_member(tr::now);
	}
	return tr::lng_e2e_cloud_role_member(tr::now);
}

[[nodiscard]] QString HistoryAccessText(HistoryAccess historyAccess) {
	switch (historyAccess.mode) {
	case HistoryAccessMode::None:
		return tr::lng_e2e_cloud_history_none(tr::now);
	case HistoryAccessMode::FromJoin:
		return tr::lng_e2e_cloud_history_from_join(tr::now);
	case HistoryAccessMode::Since:
		return tr::lng_e2e_cloud_history_since(tr::now);
	case HistoryAccessMode::Full:
		return tr::lng_e2e_cloud_history_full(tr::now);
	}
	return tr::lng_e2e_cloud_history_from_join(tr::now);
}

[[nodiscard]] QString MemberSecurityText(
		const DesktopProtectedMember &member) {
	auto text = tr::lng_e2e_cloud_member_security(
		tr::now,
		lt_user,
		member.local
			? tr::lng_e2e_cloud_you(tr::now)
			: QString::number(member.telegramUserIdBinding),
		lt_role,
		RoleText(member.role),
		lt_devices,
		QString::number(member.clientCount),
		lt_history,
		HistoryAccessText(member.historyAccess),
		lt_code,
		member.accountSafetyCode);
	if (!member.pairwiseSafetyCode.isEmpty()) {
		text += u"\n"_q + tr::lng_e2e_cloud_pair_code(
			tr::now,
			lt_pair_code,
			member.pairwiseSafetyCode);
	}
	return text;
}

[[nodiscard]] QString SecurityText(
		const DesktopService &service,
		ConversationId conversationId) {
	const auto security = service.protectedSecurity(conversationId);
	if (!security) {
		return tr::lng_e2e_cloud_content_failed(tr::now);
	}
	auto sections = QStringList{
		tr::lng_e2e_cloud_group_code(
			tr::now,
			lt_code,
			security->groupSafetyCode),
		tr::lng_e2e_cloud_witnesses(
			tr::now,
			lt_confirmed,
			QString::number(security->witnessCount),
			lt_total,
			QString::number(security->memberCount)),
		tr::lng_e2e_cloud_verify_hint(tr::now),
		tr::lng_e2e_cloud_default_history_current(
			tr::now,
			lt_history,
			HistoryAccessText(security->defaultHistoryAccess)),
	};
	for (const auto &member : security->members) {
		sections.push_back(MemberSecurityText(member));
	}
	return sections.join(u"\n\n"_q);
}

template <typename Callback>
void AddSecurityAction(
		not_null<Ui::GenericBox*> box,
		QString title,
		Callback &&callback) {
	const auto button = box->addRow(
		object_ptr<Ui::SettingsButton>(
			box,
			rpl::single(std::move(title)),
			st::settingsButton),
		style::al_top);
	button->setClickedCallback(std::forward<Callback>(callback));
}

void ShowProtectedMemberSecurity(
		not_null<Window::SessionController*> controller,
		ConversationId conversationId,
		AccountId accountId) {
	controller->uiShow()->showBox(Box([=](not_null<Ui::GenericBox*> box) {
		const auto service = &controller->session().e2eCloud();
		CloseWhenVaultUnavailable(box, service);
		CloseWhenSecurityChanges(box, service);
		const auto security = service->protectedSecurity(conversationId);
		const auto member = security
			? std::find_if(
				begin(security->members),
				end(security->members),
				[&](const auto &value) {
					return value.accountId == accountId;
				})
			: std::vector<DesktopProtectedMember>::const_iterator();
		if (!security || member == end(security->members)) {
			box->setTitle(tr::lng_e2e_cloud_security());
			box->addRow(object_ptr<Ui::FlatLabel>(
				box,
				tr::lng_e2e_cloud_content_failed(),
				st::boxLabel));
			box->addButton(tr::lng_close(), [=] { box->closeBox(); });
			return;
		}
		box->setTitle(tr::lng_e2e_cloud_manage_member(
			lt_user,
			rpl::single(QString::number(member->telegramUserIdBinding))));
		box->addRow(object_ptr<Ui::FlatLabel>(
			box,
			MemberSecurityText(*member),
			st::boxLabel));
		const auto apply = [=](auto callback) {
			if (callback()) {
				box->closeBox();
			}
		};
		if (!member->local && security->canGrantHistory) {
			AddSecurityAction(
				box,
				tr::lng_e2e_cloud_set_member_history(
					tr::now,
					lt_history,
					tr::lng_e2e_cloud_history_none(tr::now)),
				[=] {
					apply([=] {
						return service->setProtectedMemberHistory(
							conversationId,
							accountId,
							{ .mode = HistoryAccessMode::None });
					});
				});
			AddSecurityAction(
				box,
				tr::lng_e2e_cloud_set_member_history(
					tr::now,
					lt_history,
					tr::lng_e2e_cloud_history_from_join(tr::now)),
				[=] {
					apply([=] {
						return service->setProtectedMemberHistory(
							conversationId,
							accountId,
							{ .mode = HistoryAccessMode::FromJoin });
					});
				});
		}
		if (!member->local && security->canGrantFullHistory) {
			AddSecurityAction(
				box,
				tr::lng_e2e_cloud_set_member_history(
					tr::now,
					lt_history,
					tr::lng_e2e_cloud_history_full(tr::now)),
				[=] {
					apply([=] {
						return service->setProtectedMemberHistory(
							conversationId,
							accountId,
							{ .mode = HistoryAccessMode::Full });
					});
				});
		}
		if (!member->local
			&& member->role != GroupRole::Owner
			&& security->canSetRoles) {
			const auto promote = member->role == GroupRole::Member;
			AddSecurityAction(
				box,
				promote
					? tr::lng_e2e_cloud_promote_admin(tr::now)
					: tr::lng_e2e_cloud_demote_member(tr::now),
				[=] {
					apply([=] {
						return service->setProtectedMemberRole(
							conversationId,
							accountId,
							promote
								? GroupRole::Administrator
								: GroupRole::Member);
					});
				});
		}
		if (!member->local
			&& member->role != GroupRole::Owner
			&& security->canRemoveMembers
			&& (member->role != GroupRole::Administrator
				|| security->canSetRoles)) {
			AddSecurityAction(
				box,
				tr::lng_e2e_cloud_remove_member(tr::now),
				[=] {
					apply([=] {
						return service->removeProtectedMember(
							conversationId,
							accountId);
					});
				});
		}
		box->addButton(tr::lng_close(), [=] { box->closeBox(); });
	}));
}

void ShowProtectedSecurity(
		not_null<Window::SessionController*> controller,
		ConversationId conversationId) {
	controller->uiShow()->showBox(Box([=](not_null<Ui::GenericBox*> box) {
		const auto service = &controller->session().e2eCloud();
		CloseWhenVaultUnavailable(box, service);
		CloseWhenSecurityChanges(box, service);
		box->setTitle(tr::lng_e2e_cloud_security());
		const auto text = box->addRow(object_ptr<Ui::FlatLabel>(
			box,
			QString(),
			st::boxLabel));
		const auto refresh = [=] {
			text->setText(SecurityText(*service, conversationId));
		};
		const auto security = service->protectedSecurity(conversationId);
		if (security && security->canChangeDefaultHistory) {
			const auto addDefault = [=](
					HistoryAccessMode mode,
					QString title) {
				AddSecurityAction(box, std::move(title), [=] {
					if (service->setProtectedDefaultHistory(
							conversationId,
							{ .mode = mode })) {
						box->closeBox();
					}
				});
			};
			addDefault(
				HistoryAccessMode::None,
				tr::lng_e2e_cloud_set_default_history(
					tr::now,
					lt_history,
					tr::lng_e2e_cloud_history_none(tr::now)));
			addDefault(
				HistoryAccessMode::FromJoin,
				tr::lng_e2e_cloud_set_default_history(
					tr::now,
					lt_history,
					tr::lng_e2e_cloud_history_from_join(tr::now)));
			if (security->canGrantFullHistory) {
				addDefault(
					HistoryAccessMode::Full,
					tr::lng_e2e_cloud_set_default_history(
						tr::now,
						lt_history,
						tr::lng_e2e_cloud_history_full(tr::now)));
			}
		}
		const auto canManage = security
			&& (security->canSetRoles
				|| security->canRemoveMembers
				|| security->canGrantHistory);
		if (canManage) {
			for (const auto &member : security->members) {
				if (member.local) {
					continue;
				}
				AddSecurityAction(
					box,
					tr::lng_e2e_cloud_manage_member(
						tr::now,
						lt_user,
						QString::number(member.telegramUserIdBinding)),
					[=] {
						ShowProtectedMemberSecurity(
							controller,
							conversationId,
							member.accountId);
					});
			}
		} else {
			box->addRow(object_ptr<Ui::FlatLabel>(
				box,
				tr::lng_e2e_cloud_admin_freshness(),
				st::boxLabel));
		}
		box->addButton(tr::lng_close(), [=] { box->closeBox(); });
		refresh();
	}));
}

void ShowProtectedFiles(
		not_null<Window::SessionController*> controller,
		ConversationId conversationId) {
	controller->uiShow()->showBox(Box([=](not_null<Ui::GenericBox*> box) {
		const auto service = &controller->session().e2eCloud();
		CloseWhenVaultUnavailable(box, service);
		box->setTitle(tr::lng_e2e_cloud_files());
		const auto files = box->addRow(
			object_ptr<Ui::VerticalLayout>(box),
			style::margins());
		const auto visible = box->lifetime().make_state<std::size_t>(200);
		service->contentRevisionValue(
		) | rpl::on_next([=](std::uint64_t) {
			RebuildProtectedFiles(
				files,
				*service,
				conversationId,
				visible);
		}, box->lifetime());
		box->addButton(tr::lng_close(), [=] { box->closeBox(); });
	}));
}

} // namespace

void OpenProtectedHistoryFile(
		not_null<Window::SessionController*> controller,
		not_null<DocumentData*> document,
		FullMsgId context,
		bool showInMediaView,
		const QByteArray &conversationIdBytes,
		const QByteArray &eventObjectIdBytes) {
	const auto conversationId = DecodeProtectedHistoryId<ConversationId>(
		conversationIdBytes);
	const auto eventObjectId = DecodeProtectedHistoryId<ObjectId>(
		eventObjectIdBytes);
	if (!conversationId || !eventObjectId) {
		Ui::Toast::Show({
			.text = tr::lng_e2e_cloud_file_save_failed(tr::now),
		});
		return;
	}
	FileDialog::GetWritePath(
		Core::App().getFileDialogParent(),
		tr::lng_e2e_cloud_save_file(tr::now),
		FileDialog::AllFilesFilter(),
		document->filename(),
		crl::guard(controller, [=](QString &&path) {
			if (path.isEmpty()) {
				return;
			}
			const auto savedPath = path;
			(void)controller->session().e2eCloud().saveProtectedFile(
					*conversationId,
					*eventObjectId,
					std::move(path),
					crl::guard(controller, [=](
							ProtectedFileSaveResult result) {
						const auto saved
							= (result == ProtectedFileSaveResult::Saved);
						Ui::Toast::Show({
							.text = saved
								? tr::lng_e2e_cloud_file_saved(tr::now)
								: (result == ProtectedFileSaveResult::Busy)
								? tr::lng_e2e_cloud_file_busy(tr::now)
								: tr::lng_e2e_cloud_file_save_failed(
									tr::now),
						});
						if (saved) {
							document->setLocation(Core::FileLocation(savedPath));
							controller->openDocument(
								document,
								showInMediaView,
								{ .id = context });
						}
					}));
		}));
}

void ShowProtectedGroupList(
		not_null<Window::SessionController*> controller) {
	controller->uiShow()->showBox(Box([=](not_null<Ui::GenericBox*> box) {
		const auto service = &controller->session().e2eCloud();
		CloseWhenVaultUnavailable(box, service);
		box->setTitle(tr::lng_e2e_cloud_title());
		const auto groups = service->protectedGroups();
		if (groups.empty()) {
			box->addRow(object_ptr<Ui::FlatLabel>(
				box,
				tr::lng_e2e_cloud_chats_empty(),
				st::boxLabel));
		}
		for (const auto &group : groups) {
			const auto title = group.title
				+ u" · "_q
				+ QString::number(group.contentCount)
				+ u" · #"_q
				+ QString::number(group.generation);
			const auto button = box->addRow(
				object_ptr<Ui::SettingsButton>(
					box,
					rpl::single(title),
					st::settingsButton),
				style::al_top);
			button->setClickedCallback([=] {
				box->closeBox();
				ShowProtectedConversation(
					controller,
					group.conversationId);
			});
		}
		box->addButton(tr::lng_close(), [=] { box->closeBox(); });
	}));
}

void ShowProtectedConversation(
		not_null<Window::SessionController*> controller,
		ConversationId conversationId) {
	controller->uiShow()->showBox(Box([=](not_null<Ui::GenericBox*> box) {
		const auto service = &controller->session().e2eCloud();
		CloseWhenVaultUnavailable(box, service);
		const auto groups = service->protectedGroups();
		const auto group = std::find_if(
			begin(groups),
			end(groups),
			[&](const auto &value) {
				return value.conversationId == conversationId;
			});
		box->setTitle((group != end(groups))
			? group->title
			: tr::lng_e2e_cloud_title(tr::now));
		const auto status = box->addRow(object_ptr<Ui::FlatLabel>(
			box,
			QString(),
			st::boxLabel));
		const auto refreshStatus = [=] {
			status->setText(ContentStatusText(*service, conversationId));
		};
		service->contentStateValue(
		) | rpl::on_next([=](DesktopContentState) {
			refreshStatus();
		}, box->lifetime());
		service->securityRevisionValue(
		) | rpl::on_next([=](std::uint64_t) {
			refreshStatus();
		}, box->lifetime());
		const auto cancelFile = box->addButton(
			tr::lng_e2e_cloud_cancel_file(),
			[=] {
				box->uiShow()->showBox(Ui::MakeConfirmBox({
					.text = tr::lng_e2e_cloud_cancel_file_sure(),
					.confirmed = [=] {
						const auto cancelled
							= service->cancelProtectedFileTransfer(
								conversationId);
						Ui::Toast::Show({
							.text = cancelled
								? tr::lng_e2e_cloud_file_cancelled(tr::now)
								: tr::lng_e2e_cloud_file_cancel_failed(
									tr::now),
						});
					},
					.confirmText = tr::lng_e2e_cloud_cancel_file(),
				}));
			});
		const auto updateCancelFile = [=] {
			const auto current = service->protectedGroups();
			const auto found = std::find_if(
				begin(current),
				end(current),
				[&](const auto &value) {
					return value.conversationId == conversationId;
				});
			cancelFile->setDisabled(
				found == end(current)
				|| !found->active
				|| !found->fileTransferPending);
		};
		service->contentStateValue(
		) | rpl::on_next([=](DesktopContentState) {
			updateCancelFile();
		}, cancelFile->lifetime());
		service->fileTransferRevisionValue(
		) | rpl::on_next([=](std::uint64_t) {
			refreshStatus();
			updateCancelFile();
		}, cancelFile->lifetime());
		updateCancelFile();
		box->addButton(tr::lng_e2e_cloud_files(), [=] {
			ShowProtectedFiles(controller, conversationId);
		});
		box->addButton(tr::lng_e2e_cloud_security(), [=] {
			ShowProtectedSecurity(controller, conversationId);
		});
		box->addButton(tr::lng_e2e_cloud_sync(), [=] {
			service->synchronizeProtectedContent(conversationId);
		});
		box->addButton(tr::lng_close(), [=] { box->closeBox(); });
		service->synchronizeProtectedContent(conversationId);
		refreshStatus();
	}));
}

} // namespace E2ECloud

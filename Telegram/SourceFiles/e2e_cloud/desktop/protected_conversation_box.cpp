/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "e2e_cloud/desktop/protected_conversation_box.h"

#include "e2e_cloud/content/protected_message_body.h"
#include "e2e_cloud/desktop/desktop_service.h"
#include "e2e_cloud/files/private_file_manifest.h"
#include "e2e_cloud/identity/account_identity.h"
#include "core/application.h"
#include "core/file_utilities.h"
#include "lang/lang_keys.h"
#include "main/main_session.h"
#include "ui/layers/generic_box.h"
#include "ui/widgets/buttons.h"
#include "ui/widgets/fields/input_field.h"
#include "ui/widgets/labels.h"
#include "window/window_session_controller.h"
#include "styles/style_layers.h"
#include "styles/style_settings.h"
#include "styles/style_widgets.h"

#include <QtCore/QDateTime>
#include <QtCore/QLocale>
#include <QtCore/QStringList>

#include <algorithm>
#include <utility>

namespace E2ECloud {
namespace {

[[nodiscard]] QString ShortAccountCode(AccountId accountId) {
	auto digest = Digest();
	digest.bytes = accountId.bytes;
	const auto code = FormatSafetyCode(digest);
	return code ? code->left(11) : QString();
}

[[nodiscard]] QString AuthorText(
		const DesktopService &service,
		AccountId senderAccountId) {
	const auto vault = service.vault();
	const auto localAccountId = vault
		? DeriveAccountId(vault->identity.credential, OpenSslSha256Provider())
		: std::nullopt;
	return (localAccountId && *localAccountId == senderAccountId)
		? tr::lng_e2e_cloud_you(tr::now)
		: tr::lng_e2e_cloud_participant(
			tr::now,
			lt_code,
			ShortAccountCode(senderAccountId));
}

[[nodiscard]] QString ContentText(
		const ProtectedContentRecord &record) {
	if (record.objectKind == ObjectKind::EncryptedMessageBody) {
		const auto body = ProtectedMessageBodyCodecV1().decodePlaintext(
			record.plaintext);
		return body ? QString::fromUtf8(body->textUtf8) : QString();
	}
	const auto manifest = PrivateFileManifestCodecV1().decodePlaintext(
		record.plaintext);
	return manifest
		? tr::lng_e2e_cloud_file(
			tr::now,
			lt_name,
			QString::fromUtf8(manifest->filenameUtf8),
			lt_size,
			QString::number(manifest->context.plaintextSize))
		: QString();
}

[[nodiscard]] QString ConversationText(
		const DesktopService &service,
		ConversationId conversationId) {
	const auto records = service.protectedContent(conversationId);
	if (records.empty()) {
		return tr::lng_e2e_cloud_content_empty(tr::now);
	}
	constexpr auto kMaximumVisibleRecords = std::size_t(500);
	const auto first = (records.size() > kMaximumVisibleRecords)
		? records.size() - kMaximumVisibleRecords
		: 0;
	auto lines = QStringList();
	lines.reserve(int(records.size() - first));
	for (auto index = first; index != records.size(); ++index) {
		const auto &record = records[index];
		const auto content = ContentText(record);
		if (content.isEmpty()) {
			continue;
		}
		const auto time = QLocale().toString(
			QDateTime::fromSecsSinceEpoch(qint64(record.unixTime)),
			QLocale::ShortFormat);
		lines.push_back(
			time
			+ u"  "_q
			+ AuthorText(service, record.senderAccountId)
			+ u"\n"_q
			+ content);
	}
	return lines.join(u"\n\n"_q);
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
		box->setTitle(tr::lng_e2e_cloud_security());
		const auto text = box->addRow(object_ptr<Ui::FlatLabel>(
			box,
			QString(),
			st::boxLabel));
		const auto refresh = [=] {
			text->setText(SecurityText(*service, conversationId));
		};
		service->securityRevisionValue(
		) | rpl::on_next([=](std::uint64_t) {
			refresh();
		}, box->lifetime());
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
		box->setTitle(tr::lng_e2e_cloud_files());
		const auto records = service->protectedContent(conversationId);
		auto found = false;
		for (const auto &record : records) {
			if (record.objectKind != ObjectKind::EncryptedFileManifest) {
				continue;
			}
			const auto manifest = PrivateFileManifestCodecV1()
				.decodePlaintext(record.plaintext);
			if (!manifest) {
				continue;
			}
			found = true;
			const auto title = tr::lng_e2e_cloud_file(
				tr::now,
				lt_name,
				QString::fromUtf8(manifest->filenameUtf8),
				lt_size,
				QString::number(manifest->context.plaintextSize));
			const auto button = box->addRow(
				object_ptr<Ui::SettingsButton>(
					box,
					rpl::single(title),
					st::settingsButton),
				style::al_top);
			const auto eventObjectId = record.eventObjectId;
			const auto filename = QString::fromUtf8(
				manifest->filenameUtf8);
			button->setClickedCallback([=] {
				FileDialog::GetWritePath(
					Core::App().getFileDialogParent(),
					tr::lng_e2e_cloud_save_file(tr::now),
					FileDialog::AllFilesFilter(),
					filename,
					crl::guard(box, [=](QString &&path) {
						if (!path.isEmpty()) {
							(void)service->saveProtectedFile(
								conversationId,
								eventObjectId,
								std::move(path));
						}
					}));
			});
		}
		if (!found) {
			box->addRow(object_ptr<Ui::FlatLabel>(
				box,
				tr::lng_e2e_cloud_content_empty(),
				st::boxLabel));
		}
		box->addButton(tr::lng_close(), [=] { box->closeBox(); });
	}));
}

} // namespace

void ShowProtectedGroupList(
		not_null<Window::SessionController*> controller) {
	controller->uiShow()->showBox(Box([=](not_null<Ui::GenericBox*> box) {
		box->setTitle(tr::lng_e2e_cloud_title());
		const auto groups = controller->session().e2eCloud()
			.protectedGroups();
		if (groups.empty()) {
			box->addRow(object_ptr<Ui::FlatLabel>(
				box,
				tr::lng_e2e_cloud_chats_empty(),
				st::boxLabel));
		}
		for (const auto &group : groups) {
			const auto title = group.title
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
		const auto messages = box->addRow(object_ptr<Ui::FlatLabel>(
			box,
			QString(),
			st::boxLabel));
		const auto field = box->addRow(object_ptr<Ui::InputField>(
			box,
			st::defaultInputField,
			tr::lng_e2e_cloud_message()));
		const auto refresh = [=] {
			status->setText(ContentStatusText(*service, conversationId));
			messages->setText(ConversationText(*service, conversationId));
			const auto current = service->protectedGroups();
			const auto found = std::find_if(
				begin(current),
				end(current),
				[&](const auto &value) {
					return value.conversationId == conversationId;
				});
			field->setDisabled(
				found == end(current) || found->removed || !found->active);
		};
		service->contentRevisionValue(
		) | rpl::on_next([=](std::uint64_t) {
			refresh();
		}, box->lifetime());
		service->contentStateValue(
		) | rpl::on_next([=](DesktopContentState) {
			refresh();
		}, box->lifetime());
		box->setFocusCallback([=] { field->setFocusFast(); });
		box->addButton(tr::lng_e2e_cloud_send(), [=] {
			const auto text = field->getLastText();
			if (text.isEmpty()) {
				field->showError();
				return;
			}
			if (service->sendProtectedText(conversationId, text)) {
				field->setText(QString());
			} else {
				field->showError();
			}
		});
		box->addButton(tr::lng_e2e_cloud_send_file(), [=] {
			FileDialog::GetOpenPath(
				Core::App().getFileDialogParent(),
				tr::lng_choose_file(tr::now),
				FileDialog::AllFilesFilter(),
				crl::guard(box, [=](FileDialog::OpenResult &&result) {
					if (!result.paths.empty()) {
						(void)service->sendProtectedFile(
							conversationId,
							result.paths.front());
					}
				}));
		});
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
		refresh();
	}));
}

} // namespace E2ECloud

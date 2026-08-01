/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "e2e_cloud/archive/persistent_archive_state.h"
#include "e2e_cloud/group/persistent_group_ledger.h"

#include <cstdint>
#include <optional>

namespace E2ECloud {

class OpenMlsBridge;

enum class HistoryGrantServiceStatus {
	Created,
	Accepted,
	AlreadyAccepted,
	StateUnavailable,
	WrongConversation,
	WrongCarrier,
	InvalidGrant,
	IssuerNotAuthorized,
	RecipientNotAuthorized,
	PolicyMismatch,
	ArchiveBoundaryUnavailable,
	CryptoFailure,
	ArchiveConflict,
	PersistenceFailure,
};

struct CreateAuthorizedHistoryGrantArgs {
	ConversationId conversationId;
	ObjectId grantId;
	AccountId issuerAccountId;
	ClientId issuerClientId;
	AccountId recipientAccountId;
	std::uint64_t telegramPeerIdBinding = 0;
	std::uint64_t groupGeneration = 0;
	HistoryAccess historyAccess;
	const SecureKey32 *issuerSigningPrivateKey = nullptr;
};

struct CreateAuthorizedHistoryGrantOutcome {
	HistoryGrantServiceStatus status
		= HistoryGrantServiceStatus::InvalidGrant;
	std::optional<EncryptedHistoryGrant> grant;
};

struct CreateAdmissionHistoryGrantArgs {
	CreateAuthorizedHistoryGrantArgs grant;
	const SignedGroupTransition *signedTransition = nullptr;
	const AppliedSignedGroupTransition *applied = nullptr;
	const AccountCredentialPublic *admittedCredential = nullptr;
	const ArchiveEpochSecret *archiveEpoch = nullptr;
};

struct AcceptAuthorizedHistoryGrantArgs {
	ConversationId conversationId;
	std::uint64_t telegramPeerIdBinding = 0;
	AccountId recipientAccountId;
	const SecureKey32 *recipientArchivePrivateKey = nullptr;
	const EncryptedHistoryGrant *grant = nullptr;
};

[[nodiscard]] CreateAuthorizedHistoryGrantOutcome
CreateAuthorizedHistoryGrant(
		CreateAuthorizedHistoryGrantArgs args,
		const PersistentGroupLedger &groupLedger,
		const PersistentArchiveState &archiveState,
		const OpenMlsBridge &bridge);

[[nodiscard]] HistoryGrantServiceStatus AcceptAuthorizedHistoryGrant(
	AcceptAuthorizedHistoryGrantArgs args,
	const PersistentGroupLedger &groupLedger,
	PersistentArchiveState &archiveState,
	const Sha256Provider &sha256,
	const OpenMlsBridge &bridge);

[[nodiscard]] CreateAuthorizedHistoryGrantOutcome
	CreateAdmissionHistoryGrant(
		CreateAdmissionHistoryGrantArgs args,
		const PersistentGroupLedger &groupLedger,
		const PersistentArchiveState &archiveState,
		const Sha256Provider &sha256,
		const OpenMlsBridge &bridge);

} // namespace E2ECloud

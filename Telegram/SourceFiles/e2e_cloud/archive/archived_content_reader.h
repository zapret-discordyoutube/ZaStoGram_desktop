/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "e2e_cloud/archive/archived_content_crypto.h"

#include <QtCore/QByteArray>

#include <cstdint>
#include <optional>

namespace E2ECloud {

class PersistentArchiveState;
class PersistentGroupLedger;

struct AuthenticatedArchivedContentDescriptor {
	ConversationId conversationId;
	ObjectId eventObjectId;
	AccountId senderAccountId;
	ClientId senderClientId;
	QByteArray plaintext;
};

enum class ArchivedContentOpenStatus {
	Opened,
	StateUnavailable,
	WrongConversation,
	WrongCarrier,
	InvalidEnvelope,
	InvalidDescriptor,
	ObjectMismatch,
	SenderNotAuthorized,
	ArchiveEpochUnavailable,
	ArchiveEpochMismatch,
	AuthenticationFailed,
};

struct OpenedArchivedContent {
	ObjectId eventObjectId;
	ObjectId contentObjectId;
	ObjectKind objectKind = ObjectKind::EncryptedMessageBody;
	std::uint64_t groupGeneration = 0;
	AccountId senderAccountId;
	ClientId senderClientId;
	QByteArray plaintext;
};

struct ArchivedContentOpenOutcome {
	ArchivedContentOpenStatus status
		= ArchivedContentOpenStatus::InvalidEnvelope;
	std::optional<OpenedArchivedContent> content;
};

[[nodiscard]] ArchivedContentOpenOutcome OpenLiveArchivedContent(
	ConversationId conversationId,
	std::uint64_t telegramPeerIdBinding,
	const AuthenticatedArchivedContentDescriptor &source,
	const TransportEnvelope &contentEnvelope,
	const PersistentGroupLedger &groupLedger,
	const EncryptedArchivedContentCodecV1 &contentCodec,
	const ArchivedContentDescriptorCodecV1 &descriptorCodec,
	const Sha256Provider &sha256);

[[nodiscard]] ArchivedContentOpenOutcome OpenStoredArchivedContent(
	ConversationId conversationId,
	std::uint64_t telegramPeerIdBinding,
	const TransportEnvelope &contentEnvelope,
	const PersistentGroupLedger &groupLedger,
	const PersistentArchiveState &archiveState,
	const EncryptedArchivedContentCodecV1 &contentCodec,
	const Sha256Provider &sha256,
	const ArchiveEpochCrypto &archiveCrypto);

} // namespace E2ECloud

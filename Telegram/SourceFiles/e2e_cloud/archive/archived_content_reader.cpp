/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "e2e_cloud/archive/archived_content_reader.h"

#include "e2e_cloud/archive/persistent_archive_state.h"
#include "e2e_cloud/core/interfaces.h"
#include "e2e_cloud/group/persistent_group_ledger.h"

#include <utility>

namespace E2ECloud {
namespace {

struct ValidatedContent {
	EncryptedArchivedContent encrypted;
	const AccountCredentialPublic *senderCredential = nullptr;
};

[[nodiscard]] ArchivedContentOpenOutcome Failure(
		ArchivedContentOpenStatus status) {
	return {
		.status = status,
		.content = std::nullopt,
	};
}

[[nodiscard]] bool ValidContentKind(ObjectKind kind) {
	return kind == ObjectKind::EncryptedMessageBody
		|| kind == ObjectKind::EncryptedFileManifest;
}

[[nodiscard]] std::optional<ValidatedContent> ValidateContent(
		ConversationId conversationId,
		std::uint64_t telegramPeerIdBinding,
		const TransportEnvelope &envelope,
		const PersistentGroupLedger &groupLedger,
		const EncryptedArchivedContentCodecV1 &contentCodec,
		const Sha256Provider &sha256,
		ArchivedContentOpenStatus &failure) {
	if (!groupLedger.loaded() || !groupLedger.state()) {
		failure = ArchivedContentOpenStatus::StateUnavailable;
		return std::nullopt;
	} else if (envelope.conversationId != conversationId
		|| groupLedger.state()->conversationId() != conversationId) {
		failure = ArchivedContentOpenStatus::WrongConversation;
		return std::nullopt;
	} else if (envelope.telegramPeerIdBinding != telegramPeerIdBinding) {
		failure = ArchivedContentOpenStatus::WrongCarrier;
		return std::nullopt;
	} else if (ValidateEnvelope(envelope) != EnvelopeValidationError::None
		|| !ValidContentKind(envelope.objectKind)
		|| envelope.payloadHash != sha256.digest(envelope.payload)) {
		failure = ArchivedContentOpenStatus::InvalidEnvelope;
		return std::nullopt;
	}
	const auto decoded = contentCodec.decode(envelope.payload);
	if (!decoded) {
		failure = ArchivedContentOpenStatus::InvalidEnvelope;
		return std::nullopt;
	}
	const auto signature = QByteArray(
		reinterpret_cast<const char*>(decoded->signature.data()),
		decoded->signature.size());
	if (decoded->conversationId != envelope.conversationId
		|| decoded->contentObjectId != envelope.objectId
		|| decoded->objectKind != envelope.objectKind
		|| decoded->senderAccountId != envelope.senderAccountId
		|| decoded->senderClientId != envelope.senderClientId
		|| decoded->groupGeneration != envelope.epochOrGeneration
		|| signature != envelope.authenticationData) {
		failure = ArchivedContentOpenStatus::ObjectMismatch;
		return std::nullopt;
	}
	if (!groupLedger.wasClientActiveAt(
			decoded->senderAccountId,
			decoded->senderClientId,
			decoded->groupGeneration)) {
		failure = ArchivedContentOpenStatus::SenderNotAuthorized;
		return std::nullopt;
	}
	const auto credential = groupLedger.credential(decoded->senderAccountId);
	if (!credential) {
		failure = ArchivedContentOpenStatus::SenderNotAuthorized;
		return std::nullopt;
	}
	return ValidatedContent{
		.encrypted = std::move(*decoded),
		.senderCredential = credential,
	};
}

[[nodiscard]] ArchivedContentOpenOutcome Success(
		EncryptedArchivedContent encrypted,
		QByteArray plaintext) {
	return {
		.status = ArchivedContentOpenStatus::Opened,
		.content = OpenedArchivedContent{
			.eventObjectId = encrypted.eventObjectId,
			.contentObjectId = encrypted.contentObjectId,
			.objectKind = encrypted.objectKind,
			.groupGeneration = encrypted.groupGeneration,
			.senderAccountId = encrypted.senderAccountId,
			.senderClientId = encrypted.senderClientId,
			.plaintext = std::move(plaintext),
		},
	};
}

} // namespace

ArchivedContentOpenOutcome OpenLiveArchivedContent(
		ConversationId conversationId,
		std::uint64_t telegramPeerIdBinding,
		const AuthenticatedArchivedContentDescriptor &source,
		const TransportEnvelope &contentEnvelope,
		const PersistentGroupLedger &groupLedger,
		const EncryptedArchivedContentCodecV1 &contentCodec,
		const ArchivedContentDescriptorCodecV1 &descriptorCodec,
		const Sha256Provider &sha256) {
	auto failure = ArchivedContentOpenStatus::InvalidEnvelope;
	auto validated = ValidateContent(
		conversationId,
		telegramPeerIdBinding,
		contentEnvelope,
		groupLedger,
		contentCodec,
		sha256,
		failure);
	if (!validated) {
		return Failure(failure);
	}
	const auto descriptor = descriptorCodec.decodePlaintext(source.plaintext);
	if (!descriptor) {
		return Failure(ArchivedContentOpenStatus::InvalidDescriptor);
	} else if (source.conversationId != conversationId
		|| descriptor->conversationId != conversationId) {
		return Failure(ArchivedContentOpenStatus::WrongConversation);
	} else if (source.eventObjectId != descriptor->eventObjectId
		|| source.senderAccountId != validated->encrypted.senderAccountId
		|| source.senderClientId != validated->encrypted.senderClientId
		|| descriptor->eventObjectId != validated->encrypted.eventObjectId
		|| descriptor->contentObjectId
			!= validated->encrypted.contentObjectId
		|| descriptor->objectKind != validated->encrypted.objectKind
		|| descriptor->groupGeneration
			!= validated->encrypted.groupGeneration
		|| descriptor->archiveEpochGeneration
			!= validated->encrypted.wrappedContentKey.epochGeneration
		|| descriptor->encodedContentHash != contentEnvelope.payloadHash) {
		return Failure(ArchivedContentOpenStatus::ObjectMismatch);
	}
	auto plaintext = OpenArchivedContentWithContentKey(
		validated->encrypted,
		descriptor->contentKey,
		*validated->senderCredential,
		sha256);
	return plaintext
		? Success(std::move(validated->encrypted), std::move(*plaintext))
		: Failure(ArchivedContentOpenStatus::AuthenticationFailed);
}

ArchivedContentOpenOutcome OpenStoredArchivedContent(
		ConversationId conversationId,
		std::uint64_t telegramPeerIdBinding,
		const TransportEnvelope &contentEnvelope,
		const PersistentGroupLedger &groupLedger,
		const PersistentArchiveState &archiveState,
		const EncryptedArchivedContentCodecV1 &contentCodec,
		const Sha256Provider &sha256,
		const ArchiveEpochCrypto &archiveCrypto) {
	auto failure = ArchivedContentOpenStatus::InvalidEnvelope;
	auto validated = ValidateContent(
		conversationId,
		telegramPeerIdBinding,
		contentEnvelope,
		groupLedger,
		contentCodec,
		sha256,
		failure);
	if (!validated) {
		return Failure(failure);
	} else if (!archiveState.loaded()) {
		return Failure(ArchivedContentOpenStatus::StateUnavailable);
	} else if (archiveState.conversationId() != conversationId) {
		return Failure(ArchivedContentOpenStatus::WrongConversation);
	}
	const auto generation = validated->encrypted.wrappedContentKey
		.epochGeneration;
	const auto epoch = archiveState.epoch(generation);
	if (!epoch) {
		return Failure(ArchivedContentOpenStatus::ArchiveEpochUnavailable);
	} else if (!archiveState.epochWasActiveAt(
			generation,
			validated->encrypted.groupGeneration)) {
		return Failure(ArchivedContentOpenStatus::ArchiveEpochMismatch);
	}
	auto plaintext = OpenArchivedContentWithEpochKey(
		validated->encrypted,
		epoch->key,
		*validated->senderCredential,
		sha256,
		archiveCrypto);
	return plaintext
		? Success(std::move(validated->encrypted), std::move(*plaintext))
		: Failure(ArchivedContentOpenStatus::AuthenticationFailed);
}

} // namespace E2ECloud

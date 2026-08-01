/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "e2e_cloud/archive/archived_content_outbox.h"

#include "e2e_cloud/core/interfaces.h"
#include "e2e_cloud/identity/account_identity.h"

#include <openssl/crypto.h>

#include <utility>

namespace E2ECloud {

ArchivedContentQueueResult QueueArchivedContent(
		QueueArchivedContentArgs args,
		const ArchiveEpochCrypto &archiveCrypto,
		const EncryptedArchivedContentCodecV1 &contentCodec,
		const ArchivedContentDescriptorCodecV1 &descriptorCodec,
		const EnvelopeCodec &envelopeCodec,
		const Sha256Provider &sha256,
		OutboxCoordinator &outbox) {
	if (!args.conversationId
		|| !args.eventObjectId
		|| !args.contentObjectId
		|| args.eventObjectId == args.contentObjectId
		|| !args.senderAccountId
		|| !args.senderClientId
		|| !args.telegramPeerIdBinding
		|| !args.groupGeneration
		|| !args.archiveEpochGeneration) {
		return ArchivedContentQueueResult::InvalidArguments;
	}
	auto prepared = PrepareArchivedContent({
		.conversationId = args.conversationId,
		.eventObjectId = args.eventObjectId,
		.contentObjectId = args.contentObjectId,
		.objectKind = args.objectKind,
		.groupGeneration = args.groupGeneration,
		.senderAccountId = args.senderAccountId,
		.senderClientId = args.senderClientId,
		.archiveEpochGeneration = args.archiveEpochGeneration,
		.archiveEpochKey = args.archiveEpochKey,
		.senderSigningPrivateKey = args.senderSigningPrivateKey,
		.plaintext = std::move(args.plaintext),
	}, archiveCrypto);
	if (!prepared) {
		return ArchivedContentQueueResult::ProtectionFailed;
	}
	const auto contentBytes = contentCodec.encode(prepared->encrypted);
	if (!contentBytes) {
		return ArchivedContentQueueResult::EncodingFailed;
	}
	const auto contentHash = sha256.digest(*contentBytes);
	if (!contentHash) {
		return ArchivedContentQueueResult::ProtectionFailed;
	}
	auto signature = QByteArray(
		reinterpret_cast<const char*>(prepared->encrypted.signature.data()),
		prepared->encrypted.signature.size());
	const auto contentEnvelope = envelopeCodec.encode({
		.conversationId = args.conversationId,
		.objectKind = args.objectKind,
		.senderAccountId = args.senderAccountId,
		.senderClientId = args.senderClientId,
		.telegramPeerIdBinding = args.telegramPeerIdBinding,
		.epochOrGeneration = args.groupGeneration,
		.objectId = args.contentObjectId,
		.payloadHash = contentHash,
		.payload = *contentBytes,
		.authenticationData = std::move(signature),
	});
	if (!contentEnvelope) {
		return ArchivedContentQueueResult::EncodingFailed;
	}
	auto contentKey = prepared->contentKey.bytes();
	auto descriptor = ArchivedContentDescriptor{
		.conversationId = args.conversationId,
		.eventObjectId = args.eventObjectId,
		.contentObjectId = args.contentObjectId,
		.objectKind = args.objectKind,
		.groupGeneration = args.groupGeneration,
		.archiveEpochGeneration = args.archiveEpochGeneration,
		.encodedContentHash = contentHash,
		.contentKey = ArchiveKey32(std::move(contentKey)),
	};
	auto descriptorBytes = descriptorCodec.encodePlaintext(descriptor);
	if (!descriptorBytes) {
		return ArchivedContentQueueResult::EncodingFailed;
	}
	const auto queued = outbox.enqueueSealedThenDraft(
		*contentEnvelope,
		{
			.conversationId = args.conversationId,
			.objectId = args.eventObjectId,
			.plaintext = *descriptorBytes,
			.authenticatedData = std::move(args.mlsContext),
		});
	OPENSSL_cleanse(descriptorBytes->data(), descriptorBytes->size());
	return (queued == EnqueueResult::Queued)
		? ArchivedContentQueueResult::Queued
		: (queued == EnqueueResult::InvalidMessage)
		? ArchivedContentQueueResult::InvalidArguments
		: ArchivedContentQueueResult::PersistenceFailed;
}

} // namespace E2ECloud

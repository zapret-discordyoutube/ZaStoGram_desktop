/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "e2e_cloud/archive/archived_content_crypto.h"
#include "e2e_cloud/core/outbox.h"

#include <QtCore/QByteArray>

#include <cstdint>

namespace E2ECloud {

class EnvelopeCodec;
class Sha256Provider;

enum class ArchivedContentQueueResult {
	Queued,
	InvalidArguments,
	ProtectionFailed,
	EncodingFailed,
	PersistenceFailed,
};

struct QueueArchivedContentArgs {
	ConversationId conversationId;
	ObjectId eventObjectId;
	ObjectId contentObjectId;
	ObjectKind objectKind = ObjectKind::EncryptedMessageBody;
	AccountId senderAccountId;
	ClientId senderClientId;
	std::uint64_t telegramPeerIdBinding = 0;
	std::uint64_t groupGeneration = 0;
	std::uint64_t archiveEpochGeneration = 0;
	const ArchiveKey32 *archiveEpochKey = nullptr;
	const SecureKey32 *senderSigningPrivateKey = nullptr;
	QByteArray plaintext;
	QByteArray mlsContext;
};

[[nodiscard]] ArchivedContentQueueResult QueueArchivedContent(
	QueueArchivedContentArgs args,
	const ArchiveEpochCrypto &archiveCrypto,
	const EncryptedArchivedContentCodecV1 &contentCodec,
	const ArchivedContentDescriptorCodecV1 &descriptorCodec,
	const EnvelopeCodec &envelopeCodec,
	const Sha256Provider &sha256,
	OutboxCoordinator &outbox);

} // namespace E2ECloud

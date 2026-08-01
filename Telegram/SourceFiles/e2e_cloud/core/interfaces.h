/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "e2e_cloud/core/envelope.h"

#include <QtCore/QByteArray>

#include <functional>
#include <optional>
#include <vector>

namespace E2ECloud {

struct EncodedEnvelope {
	ConversationId conversationId;
	ObjectId objectId;
	QByteArray bytes;

	friend inline bool operator==(
		const EncodedEnvelope &,
		const EncodedEnvelope &) = default;
};

struct MlsSealRequest {
	ConversationId conversationId;
	ObjectId objectId;
	QByteArray plaintext;
	QByteArray authenticatedData;
};

struct MlsSealedApplication {
	std::uint64_t epoch = 0;
	QByteArray wireMessage;
	QByteArray authenticationData;
};

class MlsEngine {
public:
	virtual ~MlsEngine() = default;

	[[nodiscard]] virtual std::optional<Checkpoint> currentCheckpoint(
		ConversationId conversationId) const = 0;
	[[nodiscard]] virtual std::optional<MlsSealedApplication>
		sealApplicationIdempotently(const MlsSealRequest &request) = 0;
	virtual bool applyProtocolEnvelope(
		const TransportEnvelope &envelope) = 0;

};

class EnvelopeCodec {
public:
	virtual ~EnvelopeCodec() = default;

	[[nodiscard]] virtual std::optional<EncodedEnvelope> encode(
		const TransportEnvelope &envelope) const = 0;
	[[nodiscard]] virtual std::optional<TransportEnvelope> decode(
		const EncodedEnvelope &envelope) const = 0;
	[[nodiscard]] virtual std::optional<TransportEnvelope> decodeUntrusted(
		const QByteArray &bytes) const = 0;

};

class AccountVault {
public:
	virtual ~AccountVault() = default;

	[[nodiscard]] virtual bool unlocked() const = 0;
	[[nodiscard]] virtual AccountId accountId() const = 0;
	[[nodiscard]] virtual std::optional<QByteArray> loadProtectedRecord(
		const QByteArray &name) const = 0;
	virtual bool storeProtectedRecord(
		const QByteArray &name,
		const QByteArray &value) = 0;

};

class ArchiveService {
public:
	virtual ~ArchiveService() = default;

	virtual bool ingest(const TransportEnvelope &envelope) = 0;
	[[nodiscard]] virtual std::vector<EncodedEnvelope> history(
		ConversationId conversationId,
		HistoryAccess access) const = 0;

};

class FileStorage {
public:
	virtual ~FileStorage() = default;

	virtual bool ingestManifest(const TransportEnvelope &envelope) = 0;
	virtual bool ingestChunk(const TransportEnvelope &envelope) = 0;

};

class TelegramTransport {
public:
	enum class UploadResult {
		Accepted,
		RetryableError,
		PermanentError,
	};

	using UploadCallback = std::function<void(UploadResult)>;
	struct UntrustedObject {
		QByteArray bytes;
		std::uint64_t observedTelegramPeerIdBinding = 0;
		std::uint64_t observedSenderTelegramUserIdBinding = 0;
		std::int64_t observedMessageId = 0;

		friend inline bool operator==(
			const UntrustedObject &,
			const UntrustedObject &) = default;
	};
	struct DownloadRequest {
		ConversationId conversationId;
		QByteArray cursor;
		int limit = 50;
	};
	struct DownloadResult {
		UploadResult result = UploadResult::RetryableError;
		std::vector<UntrustedObject> untrustedObjects;
		QByteArray nextCursor;
		bool complete = false;
	};
	using DownloadCallback = std::function<void(DownloadResult)>;

	virtual ~TelegramTransport() = default;

	virtual void uploadExact(
		EncodedEnvelope envelope,
		UploadCallback callback) = 0;
	virtual void downloadPage(
		DownloadRequest request,
		DownloadCallback callback) = 0;

};

class OutboundMessageProtector {
public:
	virtual ~OutboundMessageProtector() = default;

	[[nodiscard]] virtual std::optional<EncodedEnvelope>
		protectIdempotently(const MlsSealRequest &request) = 0;

};

} // namespace E2ECloud

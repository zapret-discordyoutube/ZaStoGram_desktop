/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "e2e_cloud/protocol/observed_content_processor.h"

#include "e2e_cloud/archive/archived_content_reader.h"
#include "e2e_cloud/archive/persistent_archive_state.h"
#include "e2e_cloud/content/protected_message_body.h"
#include "e2e_cloud/files/file_chunk_envelope.h"
#include "e2e_cloud/files/idempotent_file_chunk_protector.h"
#include "e2e_cloud/files/private_file_manifest.h"
#include "e2e_cloud/group/persistent_group_ledger.h"
#include "e2e_cloud/mls/mls_outbox_reconciler.h"
#include "e2e_cloud/mls/openmls_bridge.h"
#include "e2e_cloud/protocol/inbound_envelope_processor.h"
#include "e2e_cloud/storage/persistent_content_store.h"
#include "e2e_cloud/storage/persistent_inbound_journal.h"
#include "e2e_cloud/storage/persistent_mls_state.h"

#include <openssl/crypto.h>

#include <QtCore/QScopeGuard>

#include <algorithm>
#include <limits>
#include <utility>

namespace E2ECloud {
namespace {

[[nodiscard]] const GroupMember *ObservedSender(
		const TelegramTransport::UntrustedObject &object,
		const TransportEnvelope &envelope,
		std::uint64_t groupGeneration,
		const PersistentGroupLedger &groupLedger) {
	const auto state = groupLedger.stateAt(groupGeneration);
	const auto member = state
		? state->member(envelope.senderAccountId)
		: nullptr;
	return (member
		&& member->telegramUserIdBinding
			== object.observedSenderTelegramUserIdBinding
		&& std::find(
			begin(member->clients),
			end(member->clients),
			envelope.senderClientId) != end(member->clients))
		? member
		: nullptr;
}

[[nodiscard]] bool ObservedCarrierMatches(
		const TelegramTransport::UntrustedObject &object,
		const TransportEnvelope &envelope,
		const OpenMlsClientContext &local) {
	return object.observedMessageId > 0
		&& object.observedTelegramPeerIdBinding
			== local.telegramPeerIdBinding
		&& envelope.conversationId == local.conversationId
		&& envelope.telegramPeerIdBinding == local.telegramPeerIdBinding;
}

void Cleanse(QByteArray &bytes) {
	if (!bytes.isEmpty()) {
		OPENSSL_cleanse(bytes.data(), bytes.size());
	}
	bytes.clear();
}

[[nodiscard]] ObservedContentProcessStatus ProcessObservedManifest(
		const TelegramTransport::UntrustedObject &object,
		const TransportEnvelope &envelope,
		const OpenMlsClientContext &local,
		const Sha256Provider &sha256,
		PersistentArchiveState &archiveState,
		PersistentGroupLedger &groupLedger,
		PersistentContentStore &contentStore,
		FileChunkCiphertextStore &chunkStore,
		ObservedContentProcessStats &stats) {
	auto opened = OpenStoredArchivedContent(
		local.conversationId,
		local.telegramPeerIdBinding,
		envelope,
		groupLedger,
		archiveState,
		EncryptedArchivedContentCodecV1(),
		sha256,
		ArchiveEpochCrypto());
	if (opened.status == ArchivedContentOpenStatus::ArchiveEpochUnavailable
		|| !opened.content) {
		++stats.ignored;
		return ObservedContentProcessStatus::Processed;
	} else if (!ObservedSender(
			object,
			envelope,
			opened.content->groupGeneration,
			groupLedger)) {
		return ObservedContentProcessStatus::SecurityBlocked;
	}
	auto openedContent = std::move(*opened.content);
	const auto plaintextGuard = qScopeGuard([&] {
		Cleanse(openedContent.plaintext);
	});
	auto manifest = PrivateFileManifestCodecV1().decodePlaintext(
		openedContent.plaintext);
	const auto manifestGuard = qScopeGuard([&] {
		if (manifest) {
			Cleanse(manifest->filenameUtf8);
			Cleanse(manifest->mimeTypeUtf8);
		}
	});
	if (!manifest
		|| manifest->context.conversationId != local.conversationId) {
		++stats.ignored;
		return ObservedContentProcessStatus::Processed;
	}
	const auto authorization = FileChunkAuthorization{
		.context = manifest->context,
		.senderAccountId = openedContent.senderAccountId,
		.senderClientId = openedContent.senderClientId,
		.manifestEventObjectId = openedContent.eventObjectId,
		.manifestDigest = sha256.digest(openedContent.plaintext),
		.groupGeneration = openedContent.groupGeneration,
	};
	if (!authorization.manifestDigest) {
		return ObservedContentProcessStatus::PersistenceFailed;
	}
	const auto existingAuthorization = chunkStore.authorization(
		local.conversationId,
		manifest->context.fileId);
	if (existingAuthorization.status
			== FileChunkAuthorizationReadStatus::Error) {
		return ObservedContentProcessStatus::PersistenceFailed;
	} else if (existingAuthorization.status
			== FileChunkAuthorizationReadStatus::Found
		&& !IsSameFileChunkAuthorization(
			existingAuthorization.authorization,
			authorization)) {
		++stats.ignored;
		return ObservedContentProcessStatus::Processed;
	}
	const auto stored = contentStore.append({
		.conversationId = local.conversationId,
		.eventObjectId = openedContent.eventObjectId,
		.contentObjectId = openedContent.contentObjectId,
		.objectKind = openedContent.objectKind,
		.groupGeneration = openedContent.groupGeneration,
		.senderAccountId = openedContent.senderAccountId,
		.senderClientId = openedContent.senderClientId,
		.unixTime = manifest->unixTime,
		.observedTelegramMessageId = object.observedMessageId,
		.plaintext = std::move(openedContent.plaintext),
	});
	if (stored == ContentStoreAppendResult::Conflict) {
		return ObservedContentProcessStatus::SecurityBlocked;
	} else if (stored == ContentStoreAppendResult::InvalidRecord
		|| stored == ContentStoreAppendResult::PersistenceFailed) {
		return ObservedContentProcessStatus::PersistenceFailed;
	} else if (stored == ContentStoreAppendResult::Stored) {
		++stats.manifestsStored;
	}
	const auto authorized = chunkStore.authorize(authorization);
	if (authorized == FileChunkAuthorizeResult::Conflict) {
		++stats.ignored;
		return ObservedContentProcessStatus::Processed;
	} else if (authorized == FileChunkAuthorizeResult::Error) {
		return ObservedContentProcessStatus::PersistenceFailed;
	}
	return ObservedContentProcessStatus::Processed;
}

enum class FileChunkAdmissionStatus {
	Admitted,
	Ignored,
	PersistenceFailed,
};

[[nodiscard]] FileChunkAdmissionStatus AdmitObservedFileChunk(
		const TransportEnvelope &envelope,
		const VerifiedFileChunkEnvelope &verified,
		const Sha256Provider &sha256,
		PersistentContentStore &contentStore,
		FileChunkCiphertextStore &chunkStore) {
	const auto storedAuthorization = chunkStore.authorization(
		envelope.conversationId,
		verified.fileId);
	if (storedAuthorization.status
			== FileChunkAuthorizationReadStatus::Missing) {
		return FileChunkAdmissionStatus::Ignored;
	} else if (storedAuthorization.status
			!= FileChunkAuthorizationReadStatus::Found) {
		return FileChunkAdmissionStatus::PersistenceFailed;
	}
	const auto &authorization = storedAuthorization.authorization;
	if (authorization.context.fileId != verified.fileId
		|| authorization.context.chunkCount != verified.chunkCount
		|| authorization.senderAccountId != envelope.senderAccountId
		|| authorization.senderClientId != envelope.senderClientId
		|| authorization.groupGeneration != envelope.epochOrGeneration) {
		return FileChunkAdmissionStatus::Ignored;
	}
	auto record = contentStore.record(authorization.manifestEventObjectId);
	const auto recordGuard = qScopeGuard([&] {
		if (record) {
			Cleanse(record->plaintext);
		}
	});
	if (!record
		|| record->objectKind != ObjectKind::EncryptedFileManifest
		|| record->senderAccountId != authorization.senderAccountId
		|| record->senderClientId != authorization.senderClientId
		|| record->groupGeneration != authorization.groupGeneration
		|| sha256.digest(record->plaintext)
			!= authorization.manifestDigest) {
		return FileChunkAdmissionStatus::PersistenceFailed;
	}
	auto manifest = PrivateFileManifestCodecV1().decodePlaintext(
		record->plaintext);
	const auto manifestGuard = qScopeGuard([&] {
		if (manifest) {
			Cleanse(manifest->filenameUtf8);
			Cleanse(manifest->mimeTypeUtf8);
		}
	});
	if (!manifest
		|| !IsSameFileChunkAuthorization(authorization, {
			.context = manifest->context,
			.senderAccountId = record->senderAccountId,
			.senderClientId = record->senderClientId,
			.manifestEventObjectId = record->eventObjectId,
			.manifestDigest = authorization.manifestDigest,
			.groupGeneration = record->groupGeneration,
		})) {
		return FileChunkAdmissionStatus::PersistenceFailed;
	}
	auto plaintext = AesGcmFileChunkCipher().decrypt(
		manifest->key,
		manifest->context,
		verified.chunkIndex,
		envelope.payload);
	if (!plaintext) {
		return FileChunkAdmissionStatus::Ignored;
	}
	Cleanse(*plaintext);
	return FileChunkAdmissionStatus::Admitted;
}

} // namespace

ObservedContentProcessOutcome ProcessObservedFileManifestPreview(
		const std::vector<TelegramTransport::UntrustedObject> &objects,
		std::size_t objectLimit,
		OpenMlsClientContext local,
		const EnvelopeCodec &envelopeCodec,
		const Sha256Provider &sha256,
		PersistentArchiveState &archiveState,
		PersistentGroupLedger &groupLedger,
		PersistentContentStore &contentStore,
		FileChunkCiphertextStore &chunkStore) {
	auto outcome = ObservedContentProcessOutcome{
		.status = ObservedContentProcessStatus::Processed,
		.stats = {},
	};
	if (!local.conversationId
		|| !local.accountId
		|| !local.clientId
		|| !local.telegramPeerIdBinding
		|| !archiveState.loaded()
		|| !groupLedger.loaded()
		|| !groupLedger.state()
		|| !contentStore.loaded()
		|| objectLimit > objects.size()) {
		outcome.status = ObservedContentProcessStatus::InvalidState;
		return outcome;
	}
	for (auto index = std::size_t(); index != objectLimit; ++index) {
		const auto &object = objects[index];
		const auto envelope = envelopeCodec.decodeUntrusted(object.bytes);
		if (!envelope
			|| !ObservedCarrierMatches(object, *envelope, local)
			|| envelope->objectKind
				!= ObjectKind::EncryptedFileManifest) {
			continue;
		}
		outcome.status = ProcessObservedManifest(
			object,
			*envelope,
			local,
			sha256,
			archiveState,
			groupLedger,
			contentStore,
			chunkStore,
			outcome.stats);
		if (outcome.status != ObservedContentProcessStatus::Processed) {
			return outcome;
		}
	}
	return outcome;
}

ObservedFileChunkProcessOutcome ProcessObservedFileChunkPage(
		const std::vector<TelegramTransport::UntrustedObject> &objects,
		FileId expectedFileId,
		OpenMlsClientContext local,
		const EnvelopeCodec &envelopeCodec,
		const Sha256Provider &sha256,
		PersistentGroupLedger &groupLedger,
		PersistentContentStore &contentStore,
		FileChunkCiphertextStore &chunkStore) {
	auto outcome = ObservedFileChunkProcessOutcome{
		.status = ObservedContentProcessStatus::Processed,
		.stats = {},
		.availableChunkIndices = {},
	};
	if (!expectedFileId
		|| !local.conversationId
		|| !local.accountId
		|| !local.clientId
		|| !local.telegramPeerIdBinding
		|| !groupLedger.loaded()
		|| !groupLedger.state()
		|| !contentStore.loaded()) {
		outcome.status = ObservedContentProcessStatus::InvalidState;
		return outcome;
	}
	for (const auto &object : objects) {
		const auto envelope = envelopeCodec.decodeUntrusted(object.bytes);
		if (!envelope
			|| !ObservedCarrierMatches(object, *envelope, local)
			|| envelope->objectKind != ObjectKind::EncryptedFileChunk) {
			++outcome.stats.ignored;
			continue;
		}
		const auto metadata = DecodeFileChunkEnvelopeMetadata(*envelope);
		if (!metadata || metadata->fileId != expectedFileId) {
			++outcome.stats.ignored;
			continue;
		}
		const auto credential = groupLedger.credential(
			envelope->senderAccountId);
		const auto verified = credential
			? VerifyFileChunkEnvelope(*envelope, *credential, sha256)
			: std::nullopt;
		if (!verified || verified->fileId != expectedFileId) {
			++outcome.stats.ignored;
			continue;
		} else if (!ObservedSender(
				object,
				*envelope,
				envelope->epochOrGeneration,
				groupLedger)) {
			outcome.status = ObservedContentProcessStatus::SecurityBlocked;
			return outcome;
		}
		const auto admission = AdmitObservedFileChunk(
			*envelope,
			*verified,
			sha256,
			contentStore,
			chunkStore);
		if (admission == FileChunkAdmissionStatus::Ignored) {
			++outcome.stats.ignored;
			continue;
		} else if (admission
				== FileChunkAdmissionStatus::PersistenceFailed) {
			outcome.status = ObservedContentProcessStatus::PersistenceFailed;
			return outcome;
		}
		const auto stored = chunkStore.storeIfAbsent(
			local.conversationId,
			verified->fileId,
			verified->chunkIndex,
			{
				.plaintextHash = envelope->payloadHash,
				.exactCiphertext = envelope->payload,
			});
		if (stored == FileChunkStoreResult::QuotaExceeded) {
			++outcome.stats.ignored;
			continue;
		} else if (stored == FileChunkStoreResult::Error) {
			outcome.status = ObservedContentProcessStatus::PersistenceFailed;
			return outcome;
		} else if (stored == FileChunkStoreResult::AlreadyExists
			&& !HasExactFileChunkCiphertext(
				chunkStore.read(
					local.conversationId,
					verified->fileId,
					verified->chunkIndex),
				envelope->payload)) {
			++outcome.stats.ignored;
			continue;
		}
		if (stored == FileChunkStoreResult::Stored) {
			++outcome.stats.chunksStored;
		}
		outcome.availableChunkIndices.push_back(verified->chunkIndex);
	}
	return outcome;
}

ObservedContentProcessOutcome ProcessObservedContentPage(
		const std::vector<TelegramTransport::UntrustedObject> &objects,
		OpenMlsClientContext local,
		std::uint64_t localTelegramUserIdBinding,
		const EnvelopeCodec &envelopeCodec,
		const OpenMlsBridge &bridge,
		const MlsContextCodecV1 &contextCodec,
		const Sha256Provider &sha256,
		PersistentMlsStateStore &mlsState,
		PersistentArchiveState &archiveState,
		PersistentGroupLedger &groupLedger,
		PersistentInboundJournal &inboundJournal,
		PersistentContentStore &contentStore,
		FileChunkCiphertextStore &chunkStore) {
	auto outcome = ObservedContentProcessOutcome{
		.status = ObservedContentProcessStatus::Processed,
		.stats = {},
	};
	if (!local.conversationId
		|| !local.accountId
		|| !local.clientId
		|| !local.telegramPeerIdBinding
		|| !localTelegramUserIdBinding
		|| !mlsState.loaded()
		|| !archiveState.loaded()
		|| !groupLedger.loaded()
		|| !groupLedger.state()
		|| !contentStore.loaded()) {
		outcome.status = ObservedContentProcessStatus::InvalidState;
		return outcome;
	}
	auto applications = std::vector<std::pair<
		const TelegramTransport::UntrustedObject*,
		TransportEnvelope>>();
	for (const auto &object : objects) {
		const auto envelope = envelopeCodec.decodeUntrusted(object.bytes);
		if (!envelope || !ObservedCarrierMatches(object, *envelope, local)) {
			++outcome.stats.ignored;
			continue;
		}
		if (envelope->objectKind == ObjectKind::MlsApplication) {
			applications.emplace_back(&object, *envelope);
			continue;
		} else if (envelope->objectKind == ObjectKind::EncryptedFileChunk) {
			const auto credential = groupLedger.credential(
				envelope->senderAccountId);
			const auto verified = credential
				? VerifyFileChunkEnvelope(*envelope, *credential, sha256)
				: std::nullopt;
			if (!verified) {
				++outcome.stats.ignored;
				continue;
			} else if (!ObservedSender(
					object,
					*envelope,
					envelope->epochOrGeneration,
					groupLedger)) {
				outcome.status = ObservedContentProcessStatus::SecurityBlocked;
				return outcome;
			}
			const auto admission = AdmitObservedFileChunk(
				*envelope,
				*verified,
				sha256,
				contentStore,
				chunkStore);
			if (admission == FileChunkAdmissionStatus::Ignored) {
				++outcome.stats.ignored;
				continue;
			} else if (admission
					== FileChunkAdmissionStatus::PersistenceFailed) {
				outcome.status
					= ObservedContentProcessStatus::PersistenceFailed;
				return outcome;
			}
			const auto stored = chunkStore.storeIfAbsent(
				local.conversationId,
				verified->fileId,
				verified->chunkIndex,
				{
					.plaintextHash = envelope->payloadHash,
					.exactCiphertext = envelope->payload,
				});
			if (stored == FileChunkStoreResult::QuotaExceeded) {
				++outcome.stats.ignored;
				continue;
			} else if (stored == FileChunkStoreResult::Error) {
				outcome.status = ObservedContentProcessStatus::PersistenceFailed;
				return outcome;
			} else if (stored == FileChunkStoreResult::AlreadyExists
				&& !HasExactFileChunkCiphertext(
					chunkStore.read(
						local.conversationId,
						verified->fileId,
						verified->chunkIndex),
					envelope->payload)) {
				++outcome.stats.ignored;
			} else if (stored == FileChunkStoreResult::Stored) {
				++outcome.stats.chunksStored;
			}
			continue;
		} else if (envelope->objectKind
				== ObjectKind::EncryptedFileManifest) {
			outcome.status = ProcessObservedManifest(
				object,
				*envelope,
				local,
				sha256,
				archiveState,
				groupLedger,
				contentStore,
				chunkStore,
				outcome.stats);
			if (outcome.status != ObservedContentProcessStatus::Processed) {
				return outcome;
			}
			continue;
		} else if (envelope->objectKind
				!= ObjectKind::EncryptedMessageBody) {
			++outcome.stats.ignored;
			continue;
		}
		auto opened = OpenStoredArchivedContent(
			local.conversationId,
			local.telegramPeerIdBinding,
			*envelope,
			groupLedger,
			archiveState,
			EncryptedArchivedContentCodecV1(),
			sha256,
			ArchiveEpochCrypto());
		if (opened.status == ArchivedContentOpenStatus::ArchiveEpochUnavailable) {
			++outcome.stats.ignored;
			continue;
		} else if (!opened.content) {
			++outcome.stats.ignored;
			continue;
		} else if (!ObservedSender(
				object,
				*envelope,
				opened.content->groupGeneration,
				groupLedger)) {
			outcome.status = ObservedContentProcessStatus::SecurityBlocked;
			return outcome;
		}
		auto openedContent = std::move(*opened.content);
		auto record = ProtectedContentRecord{
			.conversationId = local.conversationId,
			.eventObjectId = openedContent.eventObjectId,
			.contentObjectId = openedContent.contentObjectId,
			.objectKind = openedContent.objectKind,
			.groupGeneration = openedContent.groupGeneration,
			.senderAccountId = openedContent.senderAccountId,
			.senderClientId = openedContent.senderClientId,
			.unixTime = 0,
			.observedTelegramMessageId = object.observedMessageId,
			.plaintext = std::move(openedContent.plaintext),
		};
		auto body = ProtectedMessageBodyCodecV1().decodePlaintext(
			record.plaintext);
		const auto unixTime = body ? body->unixTime : 0;
		if (body) {
			Cleanse(body->textUtf8);
		}
		if (!unixTime) {
			Cleanse(record.plaintext);
			++outcome.stats.ignored;
			continue;
		}
		record.unixTime = unixTime;
		const auto stored = contentStore.append(std::move(record));
		if (stored == ContentStoreAppendResult::Conflict) {
			outcome.status = ObservedContentProcessStatus::SecurityBlocked;
			return outcome;
		} else if (stored == ContentStoreAppendResult::InvalidRecord
			|| stored == ContentStoreAppendResult::PersistenceFailed) {
			outcome.status = ObservedContentProcessStatus::PersistenceFailed;
			return outcome;
		} else if (stored == ContentStoreAppendResult::Stored) {
			++outcome.stats.messagesStored;
		}
	}
	std::sort(
		begin(applications),
		end(applications),
		[](const auto &a, const auto &b) {
			return a.first->observedMessageId < b.first->observedMessageId;
		});
	auto applier = OpenMlsApplicationInboundApplier(
		local,
		bridge,
		contextCodec,
		sha256,
		mlsState);
	auto authenticator = OpenMlsEnvelopeAuthenticator(contextCodec, sha256);
	auto processor = InboundEnvelopeProcessor(
		local.conversationId,
		local.telegramPeerIdBinding,
		envelopeCodec,
		authenticator,
		inboundJournal,
		applier);
	for (const auto &[object, envelope] : applications) {
		if (envelope.epochOrGeneration
				== std::numeric_limits<std::uint64_t>::max()
			|| !ObservedSender(
				*object,
				envelope,
				envelope.epochOrGeneration + 1,
				groupLedger)) {
			outcome.status = ObservedContentProcessStatus::SecurityBlocked;
			return outcome;
		}
		const auto lookup = inboundJournal.lookup(
			envelope.conversationId,
			envelope.objectId,
			envelope.payloadHash);
		if (lookup == InboundJournalLookup::ObjectIdConflict) {
			outcome.status = ObservedContentProcessStatus::SecurityBlocked;
			return outcome;
		} else if (lookup == InboundJournalLookup::StorageError) {
			outcome.status = ObservedContentProcessStatus::PersistenceFailed;
			return outcome;
		}
		const auto localEnvelope = envelope.senderAccountId == local.accountId
			&& envelope.senderClientId == local.clientId
			&& object->observedSenderTelegramUserIdBinding
				== localTelegramUserIdBinding;
		const auto receipt = localEnvelope
			? mlsState.receipt(envelope.objectId)
			: std::nullopt;
		if (receipt) {
			const auto reconciled = ReconcileObservedMlsReceipt(
				envelope,
				envelopeCodec,
				mlsState,
				inboundJournal);
			if (reconciled
					== ObservedMlsReceiptReconcileResult::ObjectIdConflict) {
				outcome.status = ObservedContentProcessStatus::SecurityBlocked;
				return outcome;
			} else if (reconciled
					!= ObservedMlsReceiptReconcileResult::Reconciled) {
				outcome.status = ObservedContentProcessStatus::PersistenceFailed;
				return outcome;
			}
			continue;
		}
		if (lookup == InboundJournalLookup::Accepted) {
			continue;
		}
		const auto processed = processor.process(object->bytes);
		switch (processed) {
		case InboundProcessResult::Accepted:
			if (!applier.acknowledgeDelivered(envelope.objectId)) {
				outcome.status = ObservedContentProcessStatus::PersistenceFailed;
				return outcome;
			}
			++outcome.stats.applicationsProcessed;
			break;
		case InboundProcessResult::Duplicate:
		case InboundProcessResult::InvalidEncoding:
		case InboundProcessResult::WrongConversation:
		case InboundProcessResult::WrongCarrier:
		case InboundProcessResult::AuthenticationFailed:
		case InboundProcessResult::Rejected:
			++outcome.stats.ignored;
			break;
		case InboundProcessResult::Deferred:
			outcome.status = ObservedContentProcessStatus::RetryRequired;
			return outcome;
		case InboundProcessResult::ObjectIdConflict:
		case InboundProcessResult::ForkDetected:
			outcome.status = ObservedContentProcessStatus::SecurityBlocked;
			return outcome;
		case InboundProcessResult::RecoveryRequired:
		case InboundProcessResult::JournalFailure:
			outcome.status = ObservedContentProcessStatus::PersistenceFailed;
			return outcome;
		}
	}
	return outcome;
}

} // namespace E2ECloud

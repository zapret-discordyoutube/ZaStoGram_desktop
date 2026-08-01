/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "e2e_cloud/mls/key_package_lifecycle.h"

#include "e2e_cloud/mls/openmls_bridge.h"

#include <limits>
#include <utility>

namespace E2ECloud {
namespace {

[[nodiscard]] QByteArray IdBytes(ConversationId id) {
	return QByteArray(
		reinterpret_cast<const char*>(id.bytes.data()),
		int(id.bytes.size()));
}

[[nodiscard]] QByteArray SignatureBytes(
		const AccountSignature &signature) {
	return QByteArray(
		reinterpret_cast<const char*>(signature.data()),
		int(signature.size()));
}

} // namespace

PrepareClientKeyPackageOutcome PrepareClientKeyPackage(
		PrepareClientKeyPackageArgs args,
		const OpenMlsBridge &bridge,
		const MlsContextCodecV1 &contextCodec,
		const ClientKeyPackagePublicationCodecV1 &publicationCodec,
		const EnvelopeCodec &envelopeCodec,
		const Sha256Provider &sha256) {
	const auto failure = [](PrepareClientKeyPackageStatus status) {
		return PrepareClientKeyPackageOutcome{
			.status = status,
			.entry = std::nullopt,
		};
	};
	if (!args.client.conversationId
		|| !args.client.accountId
		|| !args.client.clientId
		|| !args.client.telegramPeerIdBinding
		|| !args.currentGeneration
		|| !args.publicationObjectId
		|| !args.createdAt
		|| args.createdAt
			> std::numeric_limits<std::uint64_t>::max()
				- kOpenMlsKeyPackageLifetimeSeconds
		|| !args.accountCredential
		|| !args.accountSigningPrivateKey
		|| !args.accountSigningPrivateKey->valid()) {
		return failure(PrepareClientKeyPackageStatus::InvalidArguments);
	} else if (!bridge.compatible()) {
		return failure(PrepareClientKeyPackageStatus::BridgeIncompatible);
	}
	const auto identity = contextCodec.encodeCredential({
		.conversationId = args.client.conversationId,
		.accountId = args.client.accountId,
		.clientId = args.client.clientId,
	});
	if (!identity) {
		return failure(PrepareClientKeyPackageStatus::EncodingFailure);
	}
	auto generated = bridge.createKeyPackage(
		*identity,
		IdBytes(args.client.conversationId));
	if (generated.status != OpenMlsBridgeStatus::Ok
		|| generated.state.isEmpty()
		|| generated.keyPackage.isEmpty()
		|| !bridge.isKeyPackageState(generated.state)) {
		return failure(PrepareClientKeyPackageStatus::MlsFailure);
	}
	const auto authorization = CreateClientAuthorizationProof({
		.conversationId = args.client.conversationId,
		.authorizationId = args.publicationObjectId,
		.accountId = args.client.accountId,
		.clientId = args.client.clientId,
		.requestedAfterGeneration = args.currentGeneration,
		.createdAt = args.createdAt,
		.accountCredential = args.accountCredential,
		.accountSigningPrivateKey = args.accountSigningPrivateKey,
		.keyPackage = generated.keyPackage,
	}, sha256);
	if (!authorization) {
		return failure(PrepareClientKeyPackageStatus::SignatureFailure);
	}
	const auto payload = publicationCodec.encode({
		.accountCredential = *args.accountCredential,
		.authorization = *authorization,
		.keyPackage = generated.keyPackage,
	});
	if (!payload) {
		return failure(PrepareClientKeyPackageStatus::EncodingFailure);
	}
	const auto encodedEnvelope = envelopeCodec.encode({
		.conversationId = args.client.conversationId,
		.objectKind = ObjectKind::ClientKeyPackage,
		.senderAccountId = args.client.accountId,
		.senderClientId = args.client.clientId,
		.telegramPeerIdBinding = args.client.telegramPeerIdBinding,
		.epochOrGeneration = args.currentGeneration,
		.objectId = args.publicationObjectId,
		.payloadHash = sha256.digest(*payload),
		.payload = *payload,
		.authenticationData = SignatureBytes(authorization->signature),
	});
	if (!encodedEnvelope) {
		return failure(PrepareClientKeyPackageStatus::EncodingFailure);
	}
	return {
		.status = PrepareClientKeyPackageStatus::Prepared,
		.entry = StoredClientKeyPackage{
			.keyPackageHash = sha256.digest(generated.keyPackage),
			.createdAt = args.createdAt,
			.expiresAt = args.createdAt
				+ kOpenMlsKeyPackageLifetimeSeconds,
			.privateEngineState = std::move(generated.state),
			.publicationEnvelope = std::move(*encodedEnvelope),
			.queued = false,
		},
	};
}

InstallClientKeyPackageStatus InstallClientKeyPackageForWelcome(
		const QByteArray &targetKeyPackage,
		std::uint64_t currentTime,
		const OpenMlsBridge &bridge,
		const Sha256Provider &sha256,
		PersistentKeyPackagePool &pool,
		PersistentMlsStateStore &mlsState) {
	if (targetKeyPackage.isEmpty()
		|| !currentTime
		|| !bridge.compatible()
		|| !pool.loaded()
		|| !mlsState.loaded()) {
		return InstallClientKeyPackageStatus::InvalidArguments;
	}
	const auto keyPackageHash = sha256.digest(targetKeyPackage);
	const auto candidate = pool.find(keyPackageHash, currentTime);
	if (!candidate) {
		return InstallClientKeyPackageStatus::PackageUnavailable;
	}
	if (!bridge.isKeyPackageState(candidate->privateEngineState)) {
		return InstallClientKeyPackageStatus::InvalidPrivateState;
	}
	if (!mlsState.revision()) {
		return (mlsState.initialize(
			OpenMlsEngineId(),
			candidate->privateEngineState)
			== MlsStateCommitResult::Committed)
			? InstallClientKeyPackageStatus::Installed
			: InstallClientKeyPackageStatus::PersistenceFailure;
	} else if (mlsState.engineId() != OpenMlsEngineId()) {
		return InstallClientKeyPackageStatus::InvalidPrivateState;
	} else if (mlsState.engineState() == candidate->privateEngineState) {
		return InstallClientKeyPackageStatus::AlreadyInstalled;
	} else if (mlsState.removed()) {
		return (mlsState.replaceRemovedWithKeyPackage(
			mlsState.revision(),
			candidate->privateEngineState)
			== MlsStateCommitResult::Committed)
			? InstallClientKeyPackageStatus::Installed
			: InstallClientKeyPackageStatus::PersistenceFailure;
	} else if (!bridge.isKeyPackageState(mlsState.engineState())) {
		return InstallClientKeyPackageStatus::ActiveGroupState;
	}
	return (mlsState.replacePendingKeyPackage(
		mlsState.revision(),
		candidate->privateEngineState)
		== MlsStateCommitResult::Committed)
		? InstallClientKeyPackageStatus::Installed
		: InstallClientKeyPackageStatus::PersistenceFailure;
}

FinalizeClientKeyPackageStatus FinalizeClientKeyPackageWelcome(
		const QByteArray &targetKeyPackage,
		const OpenMlsBridge &bridge,
		const Sha256Provider &sha256,
		PersistentKeyPackagePool &pool,
		const PersistentMlsStateStore &mlsState) {
	if (targetKeyPackage.isEmpty()
		|| !bridge.compatible()
		|| !pool.loaded()
		|| !mlsState.loaded()) {
		return FinalizeClientKeyPackageStatus::InvalidArguments;
	} else if (mlsState.removed()
		|| mlsState.engineId() != OpenMlsEngineId()
		|| bridge.inspectGroup(mlsState.engineState()).status
			!= OpenMlsBridgeStatus::Ok) {
		return FinalizeClientKeyPackageStatus::GroupStateUnavailable;
	}
	const auto hash = sha256.digest(targetKeyPackage);
	if (pool.entries().empty()) {
		return FinalizeClientKeyPackageStatus::AlreadyFinalized;
	}
	return (pool.consume(hash) == KeyPackagePoolMutationResult::Committed)
		? FinalizeClientKeyPackageStatus::Finalized
		: FinalizeClientKeyPackageStatus::PersistenceFailure;
}

} // namespace E2ECloud

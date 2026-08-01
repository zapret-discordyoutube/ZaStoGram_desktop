/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "e2e_cloud/mls/openmls_application_engine.h"
#include "e2e_cloud/storage/persistent_key_package_pool.h"

#include <cstdint>
#include <optional>

namespace E2ECloud {

class OpenMlsBridge;

enum class PrepareClientKeyPackageStatus {
	Prepared,
	InvalidArguments,
	BridgeIncompatible,
	EncodingFailure,
	MlsFailure,
	SignatureFailure,
};

struct PrepareClientKeyPackageArgs {
	OpenMlsClientContext client;
	std::uint64_t currentGeneration = 0;
	ObjectId publicationObjectId;
	std::uint64_t createdAt = 0;
	const AccountCredentialPublic *accountCredential = nullptr;
	const SecureKey32 *accountSigningPrivateKey = nullptr;
};

struct PrepareClientKeyPackageOutcome {
	PrepareClientKeyPackageStatus status
		= PrepareClientKeyPackageStatus::InvalidArguments;
	std::optional<StoredClientKeyPackage> entry;
};

[[nodiscard]] PrepareClientKeyPackageOutcome PrepareClientKeyPackage(
	PrepareClientKeyPackageArgs args,
	const OpenMlsBridge &bridge,
	const MlsContextCodecV1 &contextCodec,
	const ClientKeyPackagePublicationCodecV1 &publicationCodec,
	const EnvelopeCodec &envelopeCodec,
	const Sha256Provider &sha256);

enum class InstallClientKeyPackageStatus {
	Installed,
	AlreadyInstalled,
	InvalidArguments,
	PackageUnavailable,
	InvalidPrivateState,
	ActiveGroupState,
	PersistenceFailure,
};

[[nodiscard]] InstallClientKeyPackageStatus InstallClientKeyPackageForWelcome(
	const QByteArray &targetKeyPackage,
	std::uint64_t currentTime,
	const OpenMlsBridge &bridge,
	const Sha256Provider &sha256,
	PersistentKeyPackagePool &pool,
	PersistentMlsStateStore &mlsState);

enum class FinalizeClientKeyPackageStatus {
	Finalized,
	AlreadyFinalized,
	InvalidArguments,
	GroupStateUnavailable,
	PersistenceFailure,
};

[[nodiscard]] FinalizeClientKeyPackageStatus FinalizeClientKeyPackageWelcome(
	const QByteArray &targetKeyPackage,
	const OpenMlsBridge &bridge,
	const Sha256Provider &sha256,
	PersistentKeyPackagePool &pool,
	const PersistentMlsStateStore &mlsState);

} // namespace E2ECloud

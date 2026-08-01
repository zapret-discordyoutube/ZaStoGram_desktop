/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "e2e_cloud/protocol/group_bootstrap.h"

#include "e2e_cloud/archive/history_grant_crypto.h"

#include <algorithm>
#include <utility>

namespace E2ECloud {
namespace {

[[nodiscard]] QByteArray Bytes(ConversationId id) {
	return QByteArray(
		reinterpret_cast<const char*>(id.bytes.data()),
		id.bytes.size());
}

[[nodiscard]] QByteArray SignatureBytes(
		const AccountSignature &signature) {
	return QByteArray(
		reinterpret_cast<const char*>(signature.data()),
		signature.size());
}

[[nodiscard]] bool DistinctObjectIds(
		const ProtectedGroupBootstrapArgs &args) {
	const auto ids = std::array{
		args.genesisObjectId,
		args.ownerCredentialObjectId,
		args.initialMlsPublicObjectId,
		args.archiveActivationEventId,
		args.ownerHistoryGrantObjectId,
	};
	for (auto i = std::size_t(0); i != ids.size(); ++i) {
		if (!ids[i]
			|| std::find(ids.begin() + i + 1, ids.end(), ids[i])
				!= ids.end()) {
			return false;
		}
	}
	return true;
}

} // namespace

ProtectedGroupBootstrapOutcome PrepareProtectedGroupBootstrap(
		ProtectedGroupBootstrapArgs args,
		const OpenMlsBridge &bridge,
		const MlsContextCodecV1 &contextCodec,
		const MlsRosterCodecV1 &rosterCodec,
		const EnvelopeCodecV1 &envelopeCodec,
		const Sha256Provider &sha256) {
	if (!args.conversationId
		|| !args.telegramPeerIdBinding
		|| !args.ownerTelegramUserIdBinding
		|| !args.ownerClientId
		|| !IsValidHistoryAccess(args.policy.defaultHistoryAccess)
		|| !DistinctObjectIds(args)
		|| !args.ownerIdentity
		|| !ValidateAccountPrivateIdentity(*args.ownerIdentity)
		|| !args.initialArchiveKey
		|| !args.initialArchiveKey->valid()) {
		return {
			.status = ProtectedGroupBootstrapStatus::InvalidArgument,
			.prepared = std::nullopt,
		};
	}
	const auto ownerAccountId = DeriveAccountId(
		args.ownerIdentity->credential,
		sha256);
	const auto ownerCredentialBytes = AccountCredentialCodecV1().encode(
		args.ownerIdentity->credential);
	if (!ownerAccountId || !ownerCredentialBytes) {
		return {
			.status = ProtectedGroupBootstrapStatus::IdentityFailure,
			.prepared = std::nullopt,
		};
	}
	const auto mlsCredential = contextCodec.encodeCredential({
		.conversationId = args.conversationId,
		.accountId = *ownerAccountId,
		.clientId = args.ownerClientId,
	});
	const auto groupId = Bytes(args.conversationId);
	auto created = mlsCredential
		? bridge.createGroup(*mlsCredential, groupId)
		: OpenMlsStateOutput();
	if (created.status != OpenMlsBridgeStatus::Ok
		|| created.epoch != 0
		|| created.state.isEmpty()
		|| created.roster.isEmpty()) {
		return {
			.status = ProtectedGroupBootstrapStatus::OpenMlsFailure,
			.prepared = std::nullopt,
		};
	}
	const auto roster = rosterCodec.decode(created.roster, contextCodec);
	if (!roster
		|| roster->conversationId != args.conversationId
		|| roster->epoch != 0
		|| roster->members.size() != 1
		|| roster->members.front().credential.conversationId
			!= args.conversationId
		|| roster->members.front().credential.accountId != *ownerAccountId
		|| roster->members.front().credential.clientId != args.ownerClientId) {
		return {
			.status = ProtectedGroupBootstrapStatus::RosterMismatch,
			.prepared = std::nullopt,
		};
	}
	const auto genesis = CreateSignedGroupGenesis({
		.conversationId = args.conversationId,
		.genesisObjectId = args.genesisObjectId,
		.telegramPeerIdBinding = args.telegramPeerIdBinding,
		.ownerAccountId = *ownerAccountId,
		.ownerClientId = args.ownerClientId,
		.ownerTelegramUserIdBinding = args.ownerTelegramUserIdBinding,
		.policy = args.policy,
		.mlsGroupId = sha256.digest(groupId),
		.initialMlsPublicObjectId = args.initialMlsPublicObjectId,
		.archiveActivationEventId = args.archiveActivationEventId,
		.initialArchiveKey = args.initialArchiveKey,
		.ownerCredential = &args.ownerIdentity->credential,
		.ownerSigningPrivateKey = &args.ownerIdentity->signingPrivateKey,
		.initialMlsPublicObject = created.roster,
	}, sha256);
	const auto verified = genesis
		? VerifySignedGroupGenesis({
			.genesis = &*genesis,
			.ownerCredential = &args.ownerIdentity->credential,
			.genesisObjectId = args.genesisObjectId,
			.initialMlsPublicObjectId = args.initialMlsPublicObjectId,
			.initialMlsPublicObject = created.roster,
			.initialArchiveKey = args.initialArchiveKey,
		}, sha256)
		: VerifySignedGroupGenesisOutcome();
	const auto encodedGenesis = genesis
		? SignedGroupGenesisCodecV1().encode(*genesis)
		: std::nullopt;
	if (!genesis || !verified.verified || !encodedGenesis) {
		return {
			.status = ProtectedGroupBootstrapStatus::GenesisFailure,
			.prepared = std::nullopt,
		};
	}
	auto initialEpochs = std::vector<ArchiveEpochSecret>();
	initialEpochs.push_back({
		.generation = 1,
		.activationGroupGeneration = 1,
		.activationEventId = args.archiveActivationEventId,
		.key = args.initialArchiveKey->clone(),
	});
	const auto ownerHistoryGrant = CreateHistoryGrant({
		.conversationId = args.conversationId,
		.grantId = args.ownerHistoryGrantObjectId,
		.issuerAccountId = *ownerAccountId,
		.issuerClientId = args.ownerClientId,
		.recipientAccountId = *ownerAccountId,
		.telegramPeerIdBinding = args.telegramPeerIdBinding,
		.groupGeneration = 1,
		.historyAccess = {
			.mode = HistoryAccessMode::Full,
			.boundaryEventId = {},
		},
		.recipientArchivePublicKey =
			args.ownerIdentity->credential.archiveHpkePublicKey,
		.issuerSigningPrivateKey =
			&args.ownerIdentity->signingPrivateKey,
		.epochs = &initialEpochs,
	}, bridge);
	const auto encodedOwnerHistoryGrant = ownerHistoryGrant
		? EncryptedHistoryGrantCodecV1().encode(*ownerHistoryGrant)
		: std::nullopt;
	if (!ownerHistoryGrant || !encodedOwnerHistoryGrant) {
		return {
			.status = ProtectedGroupBootstrapStatus::HistoryGrantFailure,
			.prepared = std::nullopt,
		};
	}
	const auto authenticationData = SignatureBytes(genesis->ownerSignature);
	const auto envelopes = std::array{
		TransportEnvelope{
			.conversationId = args.conversationId,
			.objectKind = ObjectKind::AccountCredential,
			.senderAccountId = *ownerAccountId,
			.senderClientId = args.ownerClientId,
			.telegramPeerIdBinding = args.telegramPeerIdBinding,
			.epochOrGeneration = 1,
			.objectId = args.ownerCredentialObjectId,
			.payloadHash = sha256.digest(*ownerCredentialBytes),
			.payload = *ownerCredentialBytes,
			.authenticationData = authenticationData,
		},
		TransportEnvelope{
			.conversationId = args.conversationId,
			.objectKind = ObjectKind::MlsGroupInfo,
			.senderAccountId = *ownerAccountId,
			.senderClientId = args.ownerClientId,
			.telegramPeerIdBinding = args.telegramPeerIdBinding,
			.epochOrGeneration = 0,
			.objectId = args.initialMlsPublicObjectId,
			.payloadHash = sha256.digest(created.roster),
			.payload = created.roster,
			.authenticationData = authenticationData,
		},
		TransportEnvelope{
			.conversationId = args.conversationId,
			.objectKind = ObjectKind::InitialGroupState,
			.senderAccountId = *ownerAccountId,
			.senderClientId = args.ownerClientId,
			.telegramPeerIdBinding = args.telegramPeerIdBinding,
			.epochOrGeneration = 1,
			.objectId = args.genesisObjectId,
			.payloadHash = sha256.digest(*encodedGenesis),
			.payload = *encodedGenesis,
			.authenticationData = authenticationData,
		},
		TransportEnvelope{
			.conversationId = args.conversationId,
			.objectKind = ObjectKind::HistoryGrant,
			.senderAccountId = *ownerAccountId,
			.senderClientId = args.ownerClientId,
			.telegramPeerIdBinding = args.telegramPeerIdBinding,
			.epochOrGeneration = 1,
			.objectId = args.ownerHistoryGrantObjectId,
			.payloadHash = sha256.digest(*encodedOwnerHistoryGrant),
			.payload = *encodedOwnerHistoryGrant,
			.authenticationData = SignatureBytes(
				ownerHistoryGrant->signature),
		},
	};
	auto encodedEnvelopes = std::vector<EncodedEnvelope>();
	for (const auto &envelope : envelopes) {
		const auto encoded = envelopeCodec.encode(envelope);
		if (!encoded) {
			return {
				.status = ProtectedGroupBootstrapStatus::EncodingFailure,
				.prepared = std::nullopt,
			};
		}
		encodedEnvelopes.push_back(*encoded);
	}
	return {
		.status = ProtectedGroupBootstrapStatus::Prepared,
		.prepared = PreparedProtectedGroupBootstrap{
			.conversationId = args.conversationId,
			.ownerAccountId = *ownerAccountId,
			.ownerClientId = args.ownerClientId,
			.genesis = *genesis,
			.groupState = std::move(verified.verified->state),
			.checkpoint = verified.verified->checkpoint,
			.archiveEpoch = {
				.generation = 1,
				.activationGroupGeneration = 1,
				.activationEventId = args.archiveActivationEventId,
				.key = args.initialArchiveKey->clone(),
			},
			.mlsEngineState = std::move(created.state),
			.initialMlsPublicObject = std::move(created.roster),
			.outboxEnvelopes = std::move(encodedEnvelopes),
		},
	};
}

} // namespace E2ECloud

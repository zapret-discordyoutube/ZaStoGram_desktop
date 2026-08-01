/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "e2e_cloud/core/envelope.h"

namespace E2ECloud {

bool IsKnownObjectKind(ObjectKind kind) {
	switch (kind) {
	case ObjectKind::InitialGroupState:
	case ObjectKind::AccountCredential:
	case ObjectKind::ClientKeyPackage:
	case ObjectKind::JoinRequest:
	case ObjectKind::MlsProposal:
	case ObjectKind::MlsCommit:
	case ObjectKind::MlsWelcome:
	case ObjectKind::MlsApplication:
	case ObjectKind::EncryptedMessageBody:
	case ObjectKind::EncryptedFileManifest:
	case ObjectKind::EncryptedFileChunk:
	case ObjectKind::ArchiveEpoch:
	case ObjectKind::HistoryPolicy:
	case ObjectKind::HistoryGrant:
	case ObjectKind::RoleUpdate:
	case ObjectKind::SafetyCodeGossip:
	case ObjectKind::FreshnessChallenge:
	case ObjectKind::FreshnessResponse:
	case ObjectKind::ResynchronizationRequest:
	case ObjectKind::SignedGroupTransition:
	case ObjectKind::ForkRecoveryManifest:
	case ObjectKind::MlsGroupInfo:
		return true;
	}
	return false;
}

EnvelopeValidationError ValidateEnvelope(const TransportEnvelope &envelope) {
	if (envelope.magic != kEnvelopeMagic) {
		return EnvelopeValidationError::InvalidMagic;
	} else if (envelope.applicationProtocolVersion
			!= kApplicationProtocolVersion) {
		return EnvelopeValidationError::UnsupportedVersion;
	} else if (!IsKnownObjectKind(envelope.objectKind)) {
		return EnvelopeValidationError::UnknownObjectKind;
	} else if (!envelope.conversationId) {
		return EnvelopeValidationError::MissingConversationId;
	} else if (!envelope.senderAccountId) {
		return EnvelopeValidationError::MissingSenderAccountId;
	} else if (!envelope.senderClientId) {
		return EnvelopeValidationError::MissingSenderClientId;
	} else if (!envelope.telegramPeerIdBinding) {
		return EnvelopeValidationError::MissingTelegramPeerBinding;
	} else if (!envelope.objectId) {
		return EnvelopeValidationError::MissingObjectId;
	} else if (!envelope.payloadHash) {
		return EnvelopeValidationError::MissingPayloadHash;
	} else if (envelope.payload.isEmpty()) {
		return EnvelopeValidationError::MissingPayload;
	} else if (envelope.authenticationData.isEmpty()) {
		return EnvelopeValidationError::MissingAuthenticationData;
	}
	return EnvelopeValidationError::None;
}

} // namespace E2ECloud

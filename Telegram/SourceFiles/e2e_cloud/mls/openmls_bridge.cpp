/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "e2e_cloud/mls/openmls_bridge.h"

#include "e2e_cloud/mls/td_e2e_openmls.h"

#include <algorithm>
#include <limits>
#include <utility>

namespace E2ECloud {
namespace {

inline constexpr auto kMaximumBridgeRosterSize = std::size_t(4096);
inline constexpr auto kMaximumBridgeKeyPackageSize = 1024 * 1024;
inline constexpr auto kMaximumBridgeKeyPackageListSize = 16 * 1024 * 1024;

struct TakenBuffer {
	QByteArray bytes;
	bool valid = false;
};

[[nodiscard]] TdE2EOpenMlsBytes View(const QByteArray &value) {
	return {
		.data = reinterpret_cast<const std::uint8_t*>(value.constData()),
		.size = std::size_t(value.size()),
	};
}

[[nodiscard]] OpenMlsBridgeStatus Status(std::uint32_t value) {
	switch (value) {
	case TD_E2E_OPENMLS_STATUS_OK:
		return OpenMlsBridgeStatus::Ok;
	case TD_E2E_OPENMLS_STATUS_INVALID_ARGUMENT:
		return OpenMlsBridgeStatus::InvalidArgument;
	case TD_E2E_OPENMLS_STATUS_INVALID_STATE:
		return OpenMlsBridgeStatus::InvalidState;
	case TD_E2E_OPENMLS_STATUS_CODEC_ERROR:
		return OpenMlsBridgeStatus::CodecError;
	case TD_E2E_OPENMLS_STATUS_CRYPTO_ERROR:
		return OpenMlsBridgeStatus::CryptoError;
	case TD_E2E_OPENMLS_STATUS_UNSUPPORTED:
		return OpenMlsBridgeStatus::Unsupported;
	case TD_E2E_OPENMLS_STATUS_PANIC:
		return OpenMlsBridgeStatus::Panic;
	}
	return OpenMlsBridgeStatus::InvalidState;
}

[[nodiscard]] OpenMlsContentKind ContentKind(std::uint32_t value) {
	switch (value) {
	case TD_E2E_OPENMLS_CONTENT_NONE:
		return OpenMlsContentKind::None;
	case TD_E2E_OPENMLS_CONTENT_APPLICATION:
		return OpenMlsContentKind::Application;
	case TD_E2E_OPENMLS_CONTENT_PROPOSAL:
		return OpenMlsContentKind::Proposal;
	case TD_E2E_OPENMLS_CONTENT_COMMIT:
		return OpenMlsContentKind::Commit;
	}
	return OpenMlsContentKind::None;
}

[[nodiscard]] TakenBuffer Take(TdE2EOpenMlsBuffer buffer) {
	const auto structurallyValid = (buffer.data == nullptr) == (buffer.size == 0)
		&& buffer.size <= std::size_t(std::numeric_limits<int>::max());
	auto result = QByteArray();
	if (structurallyValid && buffer.size) {
		result = QByteArray(
			reinterpret_cast<const char*>(buffer.data),
			int(buffer.size));
	}
	td_e2e_openmls_buffer_free(buffer);
	return {
		.bytes = std::move(result),
		.valid = structurallyValid,
	};
}

template <typename... Buffers>
[[nodiscard]] bool AllValid(const Buffers &...buffers) {
	return (buffers.valid && ...);
}

[[nodiscard]] OpenMlsBridgeStatus ValidatedStatus(
		std::uint32_t status,
		bool buffersValid) {
	return buffersValid ? Status(status) : OpenMlsBridgeStatus::InvalidState;
}

} // namespace

bool OpenMlsBridge::compatible() const {
	return td_e2e_openmls_abi_version() == TD_E2E_OPENMLS_ABI_VERSION;
}

OpenMlsStateOutput OpenMlsBridge::createGroup(
		const QByteArray &identity,
		const QByteArray &groupId) const {
	const auto raw = td_e2e_openmls_create_group(
		View(identity),
		View(groupId));
	auto state = Take(raw.state);
	auto roster = Take(raw.roster);
	return {
		.status = ValidatedStatus(raw.status, AllValid(state, roster)),
		.epoch = raw.epoch,
		.state = std::move(state.bytes),
		.roster = std::move(roster.bytes),
	};
}

OpenMlsStateOutput OpenMlsBridge::inspectGroup(
		const QByteArray &stateBytes) const {
	const auto raw = td_e2e_openmls_inspect_group(View(stateBytes));
	auto state = Take(raw.state);
	auto roster = Take(raw.roster);
	return {
		.status = ValidatedStatus(raw.status, AllValid(state, roster)),
		.epoch = raw.epoch,
		.state = std::move(state.bytes),
		.roster = std::move(roster.bytes),
	};
}

OpenMlsKeyPackageOutput OpenMlsBridge::createKeyPackage(
		const QByteArray &identity,
		const QByteArray &expectedGroupId) const {
	const auto raw = td_e2e_openmls_create_key_package(
		View(identity),
		View(expectedGroupId));
	auto state = Take(raw.state);
	auto keyPackage = Take(raw.key_package);
	return {
		.status = ValidatedStatus(raw.status, AllValid(state, keyPackage)),
		.state = std::move(state.bytes),
		.keyPackage = std::move(keyPackage.bytes),
	};
}

bool OpenMlsBridge::isKeyPackageState(const QByteArray &state) const {
	return td_e2e_openmls_inspect_key_package_state(View(state))
		== TD_E2E_OPENMLS_STATUS_OK;
}

OpenMlsCommitOutput OpenMlsBridge::addMember(
		const QByteArray &stateBytes,
		const QByteArray &keyPackageBytes,
		const QByteArray &authenticatedData) const {
	const auto raw = td_e2e_openmls_add_member(
		View(stateBytes),
		View(keyPackageBytes),
		View(authenticatedData));
	auto state = Take(raw.state);
	auto commit = Take(raw.commit);
	auto welcome = Take(raw.welcome);
	auto roster = Take(raw.roster);
	return {
		.status = ValidatedStatus(
			raw.status,
			AllValid(state, commit, welcome, roster)),
		.epoch = raw.epoch,
		.state = std::move(state.bytes),
		.commit = std::move(commit.bytes),
		.welcome = std::move(welcome.bytes),
		.roster = std::move(roster.bytes),
	};
}

OpenMlsCommitOutput OpenMlsBridge::updateGroup(
		const QByteArray &stateBytes,
		const QByteArray &authenticatedData) const {
	const auto raw = td_e2e_openmls_update_group(
		View(stateBytes),
		View(authenticatedData));
	auto state = Take(raw.state);
	auto commit = Take(raw.commit);
	auto welcome = Take(raw.welcome);
	auto roster = Take(raw.roster);
	return {
		.status = ValidatedStatus(
			raw.status,
			AllValid(state, commit, welcome, roster)),
		.epoch = raw.epoch,
		.state = std::move(state.bytes),
		.commit = std::move(commit.bytes),
		.welcome = std::move(welcome.bytes),
		.roster = std::move(roster.bytes),
	};
}

OpenMlsCommitOutput OpenMlsBridge::removeMember(
		const QByteArray &stateBytes,
		std::uint32_t leafIndex,
		const QByteArray &authenticatedData) const {
	const auto raw = td_e2e_openmls_remove_member(
		View(stateBytes),
		leafIndex,
		View(authenticatedData));
	auto state = Take(raw.state);
	auto commit = Take(raw.commit);
	auto welcome = Take(raw.welcome);
	auto roster = Take(raw.roster);
	return {
		.status = ValidatedStatus(
			raw.status,
			AllValid(state, commit, welcome, roster)),
		.epoch = raw.epoch,
		.state = std::move(state.bytes),
		.commit = std::move(commit.bytes),
		.welcome = std::move(welcome.bytes),
		.roster = std::move(roster.bytes),
	};
}

OpenMlsCommitOutput OpenMlsBridge::removeMembers(
		const QByteArray &stateBytes,
		const std::vector<std::uint32_t> &leafIndices,
		const QByteArray &authenticatedData) const {
	auto encodedIndices = QByteArray();
	encodedIndices.reserve(int(leafIndices.size()) * 4);
	for (const auto index : leafIndices) {
		encodedIndices.append(char(index >> 24));
		encodedIndices.append(char(index >> 16));
		encodedIndices.append(char(index >> 8));
		encodedIndices.append(char(index));
	}
	const auto raw = td_e2e_openmls_remove_members(
		View(stateBytes),
		View(encodedIndices),
		View(authenticatedData));
	auto state = Take(raw.state);
	auto commit = Take(raw.commit);
	auto welcome = Take(raw.welcome);
	auto roster = Take(raw.roster);
	return {
		.status = ValidatedStatus(
			raw.status,
			AllValid(state, commit, welcome, roster)),
		.epoch = raw.epoch,
		.state = std::move(state.bytes),
		.commit = std::move(commit.bytes),
		.welcome = std::move(welcome.bytes),
		.roster = std::move(roster.bytes),
	};
}

OpenMlsCommitOutput OpenMlsBridge::recoverFork(
		const QByteArray &stateBytes,
		const std::vector<std::uint32_t> &ownPartitionLeafIndices,
		const std::vector<QByteArray> &replacementKeyPackages,
		const QByteArray &authenticatedData) const {
	if (ownPartitionLeafIndices.empty()
		|| ownPartitionLeafIndices.size() > kMaximumBridgeRosterSize
		|| replacementKeyPackages.empty()
		|| replacementKeyPackages.size() > kMaximumBridgeRosterSize) {
		return {
			.status = OpenMlsBridgeStatus::InvalidArgument,
			.epoch = 0,
			.state = {},
			.commit = {},
			.welcome = {},
			.roster = {},
		};
	}
	auto encodedSize = std::size_t(4);
	for (const auto &keyPackage : replacementKeyPackages) {
		if (keyPackage.isEmpty()
			|| keyPackage.size() > kMaximumBridgeKeyPackageSize
			|| encodedSize > kMaximumBridgeKeyPackageListSize
				- 4 - std::size_t(keyPackage.size())) {
			return {
				.status = OpenMlsBridgeStatus::InvalidArgument,
				.epoch = 0,
				.state = {},
				.commit = {},
				.welcome = {},
				.roster = {},
			};
		}
		encodedSize += 4 + std::size_t(keyPackage.size());
	}
	auto encodedIndices = QByteArray();
	encodedIndices.reserve(int(ownPartitionLeafIndices.size()) * 4);
	for (const auto index : ownPartitionLeafIndices) {
		encodedIndices.append(char(index >> 24));
		encodedIndices.append(char(index >> 16));
		encodedIndices.append(char(index >> 8));
		encodedIndices.append(char(index));
	}
	auto encodedPackages = QByteArray();
	encodedPackages.reserve(int(encodedSize));
	const auto appendUint32 = [&](std::uint32_t value) {
		encodedPackages.append(char(value >> 24));
		encodedPackages.append(char(value >> 16));
		encodedPackages.append(char(value >> 8));
		encodedPackages.append(char(value));
	};
	appendUint32(std::uint32_t(replacementKeyPackages.size()));
	for (const auto &keyPackage : replacementKeyPackages) {
		appendUint32(std::uint32_t(keyPackage.size()));
		encodedPackages.append(keyPackage);
	}
	const auto raw = td_e2e_openmls_recover_fork(
		View(stateBytes),
		View(encodedIndices),
		View(encodedPackages),
		View(authenticatedData));
	auto state = Take(raw.state);
	auto commit = Take(raw.commit);
	auto welcome = Take(raw.welcome);
	auto roster = Take(raw.roster);
	return {
		.status = ValidatedStatus(
			raw.status,
			AllValid(state, commit, welcome, roster)),
		.epoch = raw.epoch,
		.state = std::move(state.bytes),
		.commit = std::move(commit.bytes),
		.welcome = std::move(welcome.bytes),
		.roster = std::move(roster.bytes),
	};
}

OpenMlsStateOutput OpenMlsBridge::join(
		const QByteArray &stateBytes,
		const QByteArray &welcomeBytes) const {
	const auto raw = td_e2e_openmls_join(
		View(stateBytes),
		View(welcomeBytes));
	auto state = Take(raw.state);
	auto roster = Take(raw.roster);
	return {
		.status = ValidatedStatus(raw.status, AllValid(state, roster)),
		.epoch = raw.epoch,
		.state = std::move(state.bytes),
		.roster = std::move(roster.bytes),
	};
}

OpenMlsSealOutput OpenMlsBridge::seal(
		const QByteArray &stateBytes,
		const QByteArray &authenticatedData,
		const QByteArray &plaintext) const {
	const auto raw = td_e2e_openmls_seal(
		View(stateBytes),
		View(authenticatedData),
		View(plaintext));
	auto state = Take(raw.state);
	auto message = Take(raw.message);
	return {
		.status = ValidatedStatus(raw.status, AllValid(state, message)),
		.epoch = raw.epoch,
		.state = std::move(state.bytes),
		.message = std::move(message.bytes),
	};
}

OpenMlsProcessOutput OpenMlsBridge::process(
		const QByteArray &stateBytes,
		const QByteArray &messageBytes) const {
	const auto raw = td_e2e_openmls_process(
		View(stateBytes),
		View(messageBytes));
	auto state = Take(raw.state);
	auto plaintext = Take(raw.plaintext);
	auto authenticatedData = Take(raw.authenticated_data);
	auto senderCredential = Take(raw.sender_credential);
	auto roster = Take(raw.roster);
	return {
		.status = ValidatedStatus(
			raw.status,
			AllValid(
				state,
				plaintext,
				authenticatedData,
				senderCredential,
				roster)),
		.kind = ContentKind(raw.kind),
		.senderIndex = raw.sender_index,
		.epoch = raw.epoch,
		.state = std::move(state.bytes),
		.plaintext = std::move(plaintext.bytes),
		.authenticatedData = std::move(authenticatedData.bytes),
		.senderCredential = std::move(senderCredential.bytes),
		.roster = std::move(roster.bytes),
	};
}

HpkeSealOutput OpenMlsBridge::hpkeSeal(
		const QByteArray &recipientPublicKey,
		const QByteArray &info,
		const QByteArray &authenticatedData,
		const QByteArray &plaintext) const {
	const auto raw = td_e2e_hpke_seal(
		View(recipientPublicKey),
		View(info),
		View(authenticatedData),
		View(plaintext));
	auto encapsulatedKey = Take(raw.encapsulated_key);
	auto ciphertext = Take(raw.ciphertext);
	return {
		.status = ValidatedStatus(
			raw.status,
			AllValid(encapsulatedKey, ciphertext)),
		.encapsulatedKey = std::move(encapsulatedKey.bytes),
		.ciphertext = std::move(ciphertext.bytes),
	};
}

HpkeOpenOutput OpenMlsBridge::hpkeOpen(
		const QByteArray &recipientPrivateKey,
		const QByteArray &encapsulatedKey,
		const QByteArray &info,
		const QByteArray &authenticatedData,
		const QByteArray &ciphertext) const {
	const auto raw = td_e2e_hpke_open(
		View(recipientPrivateKey),
		View(encapsulatedKey),
		View(info),
		View(authenticatedData),
		View(ciphertext));
	auto plaintext = Take(raw.plaintext);
	return {
		.status = ValidatedStatus(raw.status, AllValid(plaintext)),
		.plaintext = std::move(plaintext.bytes),
	};
}

} // namespace E2ECloud

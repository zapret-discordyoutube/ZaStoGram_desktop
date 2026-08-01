/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include <QtCore/QByteArray>

#include <cstdint>
#include <vector>

namespace E2ECloud {

enum class OpenMlsBridgeStatus : std::uint32_t {
	Ok = 0,
	InvalidArgument = 1,
	InvalidState = 2,
	CodecError = 3,
	CryptoError = 4,
	Unsupported = 5,
	Panic = 255,
};

enum class OpenMlsContentKind : std::uint32_t {
	None = 0,
	Application = 1,
	Proposal = 2,
	Commit = 3,
};

inline constexpr auto kOpenMlsNonMemberSender = std::uint32_t(-1);

struct OpenMlsStateOutput {
	OpenMlsBridgeStatus status = OpenMlsBridgeStatus::InvalidState;
	std::uint64_t epoch = 0;
	QByteArray state;
	QByteArray roster;
};

struct OpenMlsKeyPackageOutput {
	OpenMlsBridgeStatus status = OpenMlsBridgeStatus::InvalidState;
	QByteArray state;
	QByteArray keyPackage;
};

struct OpenMlsCommitOutput {
	OpenMlsBridgeStatus status = OpenMlsBridgeStatus::InvalidState;
	std::uint64_t epoch = 0;
	QByteArray state;
	QByteArray commit;
	QByteArray welcome;
	QByteArray roster;
};

struct OpenMlsSealOutput {
	OpenMlsBridgeStatus status = OpenMlsBridgeStatus::InvalidState;
	std::uint64_t epoch = 0;
	QByteArray state;
	QByteArray message;
};

struct OpenMlsProcessOutput {
	OpenMlsBridgeStatus status = OpenMlsBridgeStatus::InvalidState;
	OpenMlsContentKind kind = OpenMlsContentKind::None;
	std::uint32_t senderIndex = kOpenMlsNonMemberSender;
	std::uint64_t epoch = 0;
	QByteArray state;
	QByteArray plaintext;
	QByteArray authenticatedData;
	QByteArray senderCredential;
	QByteArray roster;
};

struct HpkeSealOutput {
	OpenMlsBridgeStatus status = OpenMlsBridgeStatus::InvalidState;
	QByteArray encapsulatedKey;
	QByteArray ciphertext;
};

struct HpkeOpenOutput {
	OpenMlsBridgeStatus status = OpenMlsBridgeStatus::InvalidState;
	QByteArray plaintext;
};

class OpenMlsBridge final {
public:
	[[nodiscard]] bool compatible() const;
	[[nodiscard]] OpenMlsStateOutput createGroup(
		const QByteArray &identity,
		const QByteArray &groupId) const;
	[[nodiscard]] OpenMlsStateOutput inspectGroup(
		const QByteArray &state) const;
	[[nodiscard]] OpenMlsKeyPackageOutput createKeyPackage(
		const QByteArray &identity,
		const QByteArray &expectedGroupId) const;
	[[nodiscard]] bool isKeyPackageState(const QByteArray &state) const;
	[[nodiscard]] OpenMlsCommitOutput addMember(
		const QByteArray &state,
		const QByteArray &keyPackage,
		const QByteArray &authenticatedData) const;
	[[nodiscard]] OpenMlsCommitOutput updateGroup(
		const QByteArray &state,
		const QByteArray &authenticatedData) const;
	[[nodiscard]] OpenMlsCommitOutput removeMember(
		const QByteArray &state,
		std::uint32_t leafIndex,
		const QByteArray &authenticatedData) const;
	[[nodiscard]] OpenMlsCommitOutput removeMembers(
		const QByteArray &state,
		const std::vector<std::uint32_t> &leafIndices,
		const QByteArray &authenticatedData) const;
	[[nodiscard]] OpenMlsCommitOutput recoverFork(
		const QByteArray &state,
		const std::vector<std::uint32_t> &ownPartitionLeafIndices,
		const std::vector<QByteArray> &replacementKeyPackages,
		const QByteArray &authenticatedData) const;
	[[nodiscard]] OpenMlsStateOutput join(
		const QByteArray &state,
		const QByteArray &welcome) const;
	[[nodiscard]] OpenMlsSealOutput seal(
		const QByteArray &state,
		const QByteArray &authenticatedData,
		const QByteArray &plaintext) const;
	[[nodiscard]] OpenMlsProcessOutput process(
		const QByteArray &state,
		const QByteArray &message) const;
	[[nodiscard]] HpkeSealOutput hpkeSeal(
		const QByteArray &recipientPublicKey,
		const QByteArray &info,
		const QByteArray &authenticatedData,
		const QByteArray &plaintext) const;
	[[nodiscard]] HpkeOpenOutput hpkeOpen(
		const QByteArray &recipientPrivateKey,
		const QByteArray &encapsulatedKey,
		const QByteArray &info,
		const QByteArray &authenticatedData,
		const QByteArray &ciphertext) const;

};

} // namespace E2ECloud

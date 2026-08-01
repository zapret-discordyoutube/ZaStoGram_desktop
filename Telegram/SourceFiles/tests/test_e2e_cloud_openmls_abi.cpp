/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "e2e_cloud/mls/td_e2e_openmls.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <string_view>
#include <utility>
#include <vector>

namespace {

[[nodiscard]] int Fail(const char *message) {
	std::fprintf(stderr, "%s\n", message);
	return 1;
}

[[nodiscard]] TdE2EOpenMlsBytes View(const std::vector<std::uint8_t> &value) {
	return {
		.data = value.data(),
		.size = value.size(),
	};
}

[[nodiscard]] TdE2EOpenMlsBytes View(std::string_view value) {
	return {
		.data = reinterpret_cast<const std::uint8_t*>(value.data()),
		.size = value.size(),
	};
}

template <std::size_t Size>
[[nodiscard]] TdE2EOpenMlsBytes View(
		const std::array<std::uint8_t, Size> &value) {
	return {
		.data = value.data(),
		.size = value.size(),
	};
}

[[nodiscard]] std::vector<std::uint8_t> Take(TdE2EOpenMlsBuffer buffer) {
	auto result = std::vector<std::uint8_t>(
		buffer.data,
		buffer.data + buffer.size);
	td_e2e_openmls_buffer_free(buffer);
	return result;
}

void Free(TdE2EOpenMlsBuffer buffer) {
	td_e2e_openmls_buffer_free(buffer);
}

[[nodiscard]] bool Equals(
		const std::vector<std::uint8_t> &value,
		std::string_view expected) {
	return value.size() == expected.size()
		&& std::equal(value.begin(), value.end(), expected.begin());
}

void AppendUint32(std::vector<std::uint8_t> &result, std::uint32_t value) {
	result.push_back(std::uint8_t(value >> 24));
	result.push_back(std::uint8_t(value >> 16));
	result.push_back(std::uint8_t(value >> 8));
	result.push_back(std::uint8_t(value));
}

[[nodiscard]] bool InspectMatches(
		const std::vector<std::uint8_t> &state,
		const std::vector<std::uint8_t> &roster,
		std::uint64_t epoch) {
	auto inspected = td_e2e_openmls_inspect_group(View(state));
	if (inspected.status != TD_E2E_OPENMLS_STATUS_OK
		|| inspected.epoch != epoch) {
		Free(inspected.state);
		Free(inspected.roster);
		return false;
	}
	return Take(inspected.state) == state
		&& Take(inspected.roster) == roster;
}

[[nodiscard]] std::uint32_t RosterMemberCount(
		const std::vector<std::uint8_t> &roster) {
	constexpr auto kCountOffset = std::size_t(8 + 2 + 32 + 8);
	if (roster.size() < kCountOffset + 4) {
		return 0;
	}
	return (std::uint32_t(roster[kCountOffset]) << 24)
		| (std::uint32_t(roster[kCountOffset + 1]) << 16)
		| (std::uint32_t(roster[kCountOffset + 2]) << 8)
		| std::uint32_t(roster[kCountOffset + 3]);
}

} // namespace

int main(int, char *[]) {
	if (td_e2e_openmls_abi_version() != TD_E2E_OPENMLS_ABI_VERSION) {
		return Fail("unexpected OpenMLS bridge ABI version");
	}
	auto groupId = std::array<std::uint8_t, 32>();
	groupId.fill(23);
	auto alice = td_e2e_openmls_create_group(
		View("alice-client"),
		View(groupId));
	if (alice.status != TD_E2E_OPENMLS_STATUS_OK
		|| alice.epoch
		|| !alice.state.size
		|| !alice.roster.size) {
		return Fail("C ABI could not create an MLS group");
	}
	auto aliceState = Take(alice.state);
	auto aliceRoster = Take(alice.roster);
	if (aliceRoster.empty() || !InspectMatches(aliceState, aliceRoster, 0)) {
		return Fail("C ABI could not inspect the creator group");
	}
	auto bobPackage = td_e2e_openmls_create_key_package(
		View("bob-client"),
		View(groupId));
	if (bobPackage.status != TD_E2E_OPENMLS_STATUS_OK
		|| !bobPackage.state.size
		|| !bobPackage.key_package.size) {
		return Fail("C ABI could not create a KeyPackage");
	}
	auto bobState = Take(bobPackage.state);
	auto keyPackage = Take(bobPackage.key_package);
	if (td_e2e_openmls_inspect_key_package_state(View(bobState))
			!= TD_E2E_OPENMLS_STATUS_OK
		|| td_e2e_openmls_inspect_key_package_state(View(aliceState))
			== TD_E2E_OPENMLS_STATUS_OK) {
		return Fail("C ABI confused KeyPackage and active group state");
	}
	auto added = td_e2e_openmls_add_member(
		View(aliceState),
		View(keyPackage),
		View("authenticated-add-transition"));
	if (added.status != TD_E2E_OPENMLS_STATUS_OK
		|| added.epoch != 1
		|| !added.state.size
		|| !added.commit.size
		|| !added.welcome.size
		|| !added.roster.size) {
		return Fail("C ABI could not add an MLS member");
	}
	aliceState = Take(added.state);
	auto commit = Take(added.commit);
	auto welcome = Take(added.welcome);
	auto addedRoster = Take(added.roster);
	if (commit.empty() || addedRoster == aliceRoster) {
		return Fail("C ABI did not advance the MLS roster");
	}
	if (!InspectMatches(aliceState, addedRoster, 1)) {
		return Fail("C ABI could not inspect the admitted group");
	}
	auto joined = td_e2e_openmls_join(View(bobState), View(welcome));
	if (joined.status != TD_E2E_OPENMLS_STATUS_OK
		|| joined.epoch != 1
		|| !joined.state.size) {
		return Fail("C ABI could not process an MLS Welcome");
	}
	bobState = Take(joined.state);
	auto joinedRoster = Take(joined.roster);
	if (joinedRoster != addedRoster) {
		return Fail("C ABI members disagreed on the joined roster");
	}
	auto sealed = td_e2e_openmls_seal(
		View(aliceState),
		View("bound-application-metadata"),
		View("content-key"));
	if (sealed.status != TD_E2E_OPENMLS_STATUS_OK
		|| sealed.epoch != 1
		|| !sealed.message.size) {
		return Fail("C ABI could not seal an MLS application message");
	}
	aliceState = Take(sealed.state);
	auto message = Take(sealed.message);
	auto opened = td_e2e_openmls_process(View(bobState), View(message));
	if (opened.status != TD_E2E_OPENMLS_STATUS_OK
		|| opened.kind != TD_E2E_OPENMLS_CONTENT_APPLICATION
		|| opened.sender_index != 0
		|| opened.epoch != 1) {
		return Fail("C ABI could not authenticate an MLS application message");
	}
	bobState = Take(opened.state);
	const auto plaintext = Take(opened.plaintext);
	const auto aad = Take(opened.authenticated_data);
	const auto credential = Take(opened.sender_credential);
	Free(opened.roster);
	if (!Equals(plaintext, "content-key")
		|| !Equals(aad, "bound-application-metadata")
		|| !Equals(credential, "alice-client")) {
		return Fail("C ABI lost authenticated MLS output fields");
	}
	auto replay = td_e2e_openmls_process(View(bobState), View(message));
	Free(replay.state);
	Free(replay.plaintext);
	Free(replay.authenticated_data);
	Free(replay.sender_credential);
	Free(replay.roster);
	if (replay.status == TD_E2E_OPENMLS_STATUS_OK) {
		return Fail("C ABI accepted an MLS replay");
	}
	auto updated = td_e2e_openmls_update_group(
		View(aliceState),
		View("authenticated-policy-transition"));
	if (updated.status != TD_E2E_OPENMLS_STATUS_OK
		|| updated.epoch != 2
		|| !updated.state.size
		|| !updated.commit.size
		|| updated.welcome.size
		|| !updated.roster.size) {
		return Fail("C ABI could not create an MLS update commit");
	}
	aliceState = Take(updated.state);
	auto updateCommit = Take(updated.commit);
	Free(updated.welcome);
	auto updatedRoster = Take(updated.roster);
	auto processedUpdate = td_e2e_openmls_process(
		View(bobState),
		View(updateCommit));
	if (processedUpdate.status != TD_E2E_OPENMLS_STATUS_OK
		|| processedUpdate.kind != TD_E2E_OPENMLS_CONTENT_COMMIT
		|| processedUpdate.sender_index != 0
		|| processedUpdate.epoch != 1
		|| !processedUpdate.state.size
		|| processedUpdate.plaintext.size
		|| !processedUpdate.authenticated_data.size
		|| !processedUpdate.sender_credential.size
		|| !processedUpdate.roster.size) {
		return Fail("C ABI could not process an MLS update commit");
	}
	bobState = Take(processedUpdate.state);
	Free(processedUpdate.plaintext);
	Free(processedUpdate.authenticated_data);
	Free(processedUpdate.sender_credential);
	if (Take(processedUpdate.roster) != updatedRoster
		|| RosterMemberCount(updatedRoster) != 2
		|| !InspectMatches(aliceState, updatedRoster, 2)) {
		return Fail("C ABI members disagreed after an MLS update");
	}
	const auto bobLeafIndex = std::array<std::uint8_t, 4>{ 0, 0, 0, 1 };
	auto removed = td_e2e_openmls_remove_members(
		View(aliceState),
		View(bobLeafIndex),
		View("authenticated-remove-transition"));
	if (removed.status != TD_E2E_OPENMLS_STATUS_OK
		|| removed.epoch != 3
		|| !removed.state.size
		|| !removed.commit.size
		|| removed.welcome.size
		|| !removed.roster.size) {
		return Fail("C ABI could not batch-remove an MLS member");
	}
	aliceState = Take(removed.state);
	auto removalCommit = Take(removed.commit);
	Free(removed.welcome);
	auto removedRoster = Take(removed.roster);
	if (removalCommit.empty()
		|| removedRoster == addedRoster
		|| RosterMemberCount(removedRoster) != 1
		|| !InspectMatches(aliceState, removedRoster, 3)) {
		return Fail("C ABI did not persist the removed roster");
	}
	auto processedRemoval = td_e2e_openmls_process(
		View(bobState),
		View(removalCommit));
	if (processedRemoval.status != TD_E2E_OPENMLS_STATUS_OK
		|| processedRemoval.kind != TD_E2E_OPENMLS_CONTENT_COMMIT
		|| processedRemoval.sender_index != 0
		|| processedRemoval.epoch != 2
		|| !processedRemoval.state.size
		|| processedRemoval.plaintext.size
		|| !processedRemoval.authenticated_data.size
		|| !processedRemoval.sender_credential.size
		|| !processedRemoval.roster.size) {
		return Fail("C ABI could not process a removal commit");
	}
	bobState = Take(processedRemoval.state);
	Free(processedRemoval.plaintext);
	Free(processedRemoval.authenticated_data);
	Free(processedRemoval.sender_credential);
	auto targetRemovedRoster = Take(processedRemoval.roster);
	if (RosterMemberCount(targetRemovedRoster) != 1) {
		return Fail("C ABI retained the removed client in its local roster");
	}
	auto recoveryGroupId = std::array<std::uint8_t, 32>();
	recoveryGroupId.fill(24);
	auto recoveryOwner = td_e2e_openmls_create_group(
		View("recovery-owner"),
		View(recoveryGroupId));
	auto recoveryMember = td_e2e_openmls_create_key_package(
		View("recovery-member"),
		View(recoveryGroupId));
	auto recoveryOwnerState = Take(recoveryOwner.state);
	Free(recoveryOwner.roster);
	auto recoveryMemberState = Take(recoveryMember.state);
	auto recoveryMemberPackage = Take(recoveryMember.key_package);
	auto recoveryAdded = td_e2e_openmls_add_member(
		View(recoveryOwnerState),
		View(recoveryMemberPackage),
		View("recovery setup"));
	recoveryOwnerState = Take(recoveryAdded.state);
	Free(recoveryAdded.commit);
	Free(recoveryAdded.welcome);
	Free(recoveryAdded.roster);
	auto replacement = td_e2e_openmls_create_key_package(
		View("recovery-member"),
		View(recoveryGroupId));
	auto replacementState = Take(replacement.state);
	auto replacementPackage = Take(replacement.key_package);
	auto packageList = std::vector<std::uint8_t>();
	AppendUint32(packageList, 1);
	AppendUint32(packageList, std::uint32_t(replacementPackage.size()));
	packageList.insert(
		end(packageList),
		begin(replacementPackage),
		end(replacementPackage));
	const auto ownerPartition = std::array<std::uint8_t, 4>{ 0, 0, 0, 0 };
	auto recovered = td_e2e_openmls_recover_fork(
		View(recoveryOwnerState),
		View(ownerPartition),
		View(packageList),
		View("signed complete fork resolution"));
	auto recoveredRoster = Take(recovered.roster);
	if (recovered.status != TD_E2E_OPENMLS_STATUS_OK
		|| recovered.epoch != 2
		|| !recovered.state.size
		|| !recovered.commit.size
		|| !recovered.welcome.size
		|| RosterMemberCount(recoveredRoster) != 2) {
		Free(recovered.state);
		Free(recovered.commit);
		Free(recovered.welcome);
		return Fail("C ABI could not re-add a fork complement partition");
	}
	recoveryOwnerState = Take(recovered.state);
	Free(recovered.commit);
	auto recoveryWelcome = Take(recovered.welcome);
	auto replacementJoined = td_e2e_openmls_join(
		View(replacementState),
		View(recoveryWelcome));
	auto replacementRoster = Take(replacementJoined.roster);
	if (replacementJoined.status != TD_E2E_OPENMLS_STATUS_OK
		|| replacementJoined.epoch != 2
		|| replacementRoster != recoveredRoster
		|| !InspectMatches(recoveryOwnerState, recoveredRoster, 2)) {
		Free(replacementJoined.state);
		return Fail("fork complement could not consume its replacement Welcome");
	}
	Free(replacementJoined.state);
	std::fill(
		begin(recoveryMemberState),
		end(recoveryMemberState),
		std::uint8_t(0));
	const auto recipientPrivateKey = std::array<std::uint8_t, 32>{
		0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d,
		0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
		0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a,
		0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a,
	};
	const auto recipientPublicKey = std::array<std::uint8_t, 32>{
		0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54,
		0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e, 0xf7, 0x5a,
		0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4,
		0xeb, 0xa4, 0xa9, 0x8e, 0xaa, 0x9b, 0x4e, 0x6a,
	};
	auto hpkeSealed = td_e2e_hpke_seal(
		View(recipientPublicKey),
		View("TDE2E/archive-grant/v1"),
		View("authenticated grant fields"),
		View("archive epoch keys"));
	if (hpkeSealed.status != TD_E2E_OPENMLS_STATUS_OK
		|| hpkeSealed.encapsulated_key.size != 32
		|| hpkeSealed.ciphertext.size != 18 + 16) {
		return Fail("C ABI could not HPKE-seal archive keys");
	}
	auto encapsulatedKey = Take(hpkeSealed.encapsulated_key);
	auto hpkeCiphertext = Take(hpkeSealed.ciphertext);
	auto hpkeOpened = td_e2e_hpke_open(
		View(recipientPrivateKey),
		View(encapsulatedKey),
		View("TDE2E/archive-grant/v1"),
		View("authenticated grant fields"),
		View(hpkeCiphertext));
	if (hpkeOpened.status != TD_E2E_OPENMLS_STATUS_OK
		|| !Equals(Take(hpkeOpened.plaintext), "archive epoch keys")) {
		return Fail("C ABI could not HPKE-open archive keys");
	}
	auto hpkeWrongAad = td_e2e_hpke_open(
		View(recipientPrivateKey),
		View(encapsulatedKey),
		View("TDE2E/archive-grant/v1"),
		View("modified grant fields"),
		View(hpkeCiphertext));
	Free(hpkeWrongAad.plaintext);
	if (hpkeWrongAad.status == TD_E2E_OPENMLS_STATUS_OK) {
		return Fail("C ABI HPKE accepted modified authenticated fields");
	}
	return 0;
}

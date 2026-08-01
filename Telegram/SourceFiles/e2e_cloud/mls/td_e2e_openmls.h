/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include <stddef.h>
#include <stdint.h>

#define TD_E2E_OPENMLS_ABI_VERSION 0x00010006u
#define TD_E2E_OPENMLS_STATUS_OK 0u
#define TD_E2E_OPENMLS_STATUS_INVALID_ARGUMENT 1u
#define TD_E2E_OPENMLS_STATUS_INVALID_STATE 2u
#define TD_E2E_OPENMLS_STATUS_CODEC_ERROR 3u
#define TD_E2E_OPENMLS_STATUS_CRYPTO_ERROR 4u
#define TD_E2E_OPENMLS_STATUS_UNSUPPORTED 5u
#define TD_E2E_OPENMLS_STATUS_PANIC 255u
#define TD_E2E_OPENMLS_CONTENT_NONE 0u
#define TD_E2E_OPENMLS_CONTENT_APPLICATION 1u
#define TD_E2E_OPENMLS_CONTENT_PROPOSAL 2u
#define TD_E2E_OPENMLS_CONTENT_COMMIT 3u
#define TD_E2E_OPENMLS_NON_MEMBER_SENDER UINT32_MAX

#ifdef __cplusplus
extern "C" {
#endif

typedef struct TdE2EOpenMlsBytes {
	const uint8_t *data;
	size_t size;
} TdE2EOpenMlsBytes;

typedef struct TdE2EOpenMlsBuffer {
	uint8_t *data;
	size_t size;
} TdE2EOpenMlsBuffer;

typedef struct TdE2EOpenMlsStateResult {
	uint32_t status;
	uint64_t epoch;
	TdE2EOpenMlsBuffer state;
	TdE2EOpenMlsBuffer roster;
} TdE2EOpenMlsStateResult;

typedef struct TdE2EOpenMlsKeyPackageResult {
	uint32_t status;
	TdE2EOpenMlsBuffer state;
	TdE2EOpenMlsBuffer key_package;
} TdE2EOpenMlsKeyPackageResult;

typedef struct TdE2EOpenMlsCommitResult {
	uint32_t status;
	uint64_t epoch;
	TdE2EOpenMlsBuffer state;
	TdE2EOpenMlsBuffer commit;
	TdE2EOpenMlsBuffer welcome;
	TdE2EOpenMlsBuffer roster;
} TdE2EOpenMlsCommitResult;

typedef struct TdE2EOpenMlsSealResult {
	uint32_t status;
	uint64_t epoch;
	TdE2EOpenMlsBuffer state;
	TdE2EOpenMlsBuffer message;
} TdE2EOpenMlsSealResult;

typedef struct TdE2EOpenMlsProcessResult {
	uint32_t status;
	uint32_t kind;
	uint32_t sender_index;
	uint64_t epoch;
	TdE2EOpenMlsBuffer state;
	TdE2EOpenMlsBuffer plaintext;
	TdE2EOpenMlsBuffer authenticated_data;
	TdE2EOpenMlsBuffer sender_credential;
	TdE2EOpenMlsBuffer roster;
} TdE2EOpenMlsProcessResult;

typedef struct TdE2EHpkeSealResult {
	uint32_t status;
	TdE2EOpenMlsBuffer encapsulated_key;
	TdE2EOpenMlsBuffer ciphertext;
} TdE2EHpkeSealResult;

typedef struct TdE2EHpkeOpenResult {
	uint32_t status;
	TdE2EOpenMlsBuffer plaintext;
} TdE2EHpkeOpenResult;

uint32_t td_e2e_openmls_abi_version(void);
void td_e2e_openmls_buffer_free(TdE2EOpenMlsBuffer buffer);

TdE2EOpenMlsStateResult td_e2e_openmls_create_group(
	TdE2EOpenMlsBytes identity,
	TdE2EOpenMlsBytes group_id);

TdE2EOpenMlsStateResult td_e2e_openmls_inspect_group(
	TdE2EOpenMlsBytes state);

TdE2EOpenMlsKeyPackageResult td_e2e_openmls_create_key_package(
	TdE2EOpenMlsBytes identity,
	TdE2EOpenMlsBytes expected_group_id);

uint32_t td_e2e_openmls_inspect_key_package_state(
	TdE2EOpenMlsBytes state);

TdE2EOpenMlsCommitResult td_e2e_openmls_add_member(
	TdE2EOpenMlsBytes state,
	TdE2EOpenMlsBytes key_package,
	TdE2EOpenMlsBytes authenticated_data);

TdE2EOpenMlsCommitResult td_e2e_openmls_update_group(
	TdE2EOpenMlsBytes state,
	TdE2EOpenMlsBytes authenticated_data);

TdE2EOpenMlsCommitResult td_e2e_openmls_remove_member(
	TdE2EOpenMlsBytes state,
	uint32_t leaf_index,
	TdE2EOpenMlsBytes authenticated_data);

TdE2EOpenMlsCommitResult td_e2e_openmls_remove_members(
	TdE2EOpenMlsBytes state,
	TdE2EOpenMlsBytes leaf_indices_be,
	TdE2EOpenMlsBytes authenticated_data);

TdE2EOpenMlsCommitResult td_e2e_openmls_recover_fork(
	TdE2EOpenMlsBytes state,
	TdE2EOpenMlsBytes own_partition_leaf_indices_be,
	TdE2EOpenMlsBytes replacement_key_packages,
	TdE2EOpenMlsBytes authenticated_data);

TdE2EOpenMlsStateResult td_e2e_openmls_join(
	TdE2EOpenMlsBytes state,
	TdE2EOpenMlsBytes welcome);

TdE2EOpenMlsSealResult td_e2e_openmls_seal(
	TdE2EOpenMlsBytes state,
	TdE2EOpenMlsBytes authenticated_data,
	TdE2EOpenMlsBytes plaintext);

TdE2EOpenMlsProcessResult td_e2e_openmls_process(
	TdE2EOpenMlsBytes state,
	TdE2EOpenMlsBytes message);

TdE2EHpkeSealResult td_e2e_hpke_seal(
	TdE2EOpenMlsBytes recipient_public_key,
	TdE2EOpenMlsBytes info,
	TdE2EOpenMlsBytes authenticated_data,
	TdE2EOpenMlsBytes plaintext);

TdE2EHpkeOpenResult td_e2e_hpke_open(
	TdE2EOpenMlsBytes recipient_private_key,
	TdE2EOpenMlsBytes encapsulated_key,
	TdE2EOpenMlsBytes info,
	TdE2EOpenMlsBytes authenticated_data,
	TdE2EOpenMlsBytes ciphertext);

#ifdef __cplusplus
}
#endif

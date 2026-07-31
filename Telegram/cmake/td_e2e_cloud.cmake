# This file is part of Telegram Desktop,
# the official desktop application for the Telegram messaging service.
#
# For license and copyright information please follow this link:
# https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL

add_library(td_e2e_cloud OBJECT)
init_non_host_target(td_e2e_cloud)
add_library(tdesktop::td_e2e_cloud ALIAS td_e2e_cloud)

nice_target_sources(td_e2e_cloud ${src_loc}
PRIVATE
    e2e_cloud/core/envelope.cpp
    e2e_cloud/core/envelope.h
    e2e_cloud/core/envelope_codec.cpp
    e2e_cloud/core/envelope_codec.h
    e2e_cloud/core/freshness_gate.cpp
    e2e_cloud/core/freshness_gate.h
    e2e_cloud/core/interfaces.h
    e2e_cloud/core/outbox.cpp
    e2e_cloud/core/outbox.h
    e2e_cloud/core/types.cpp
    e2e_cloud/core/types.h
    e2e_cloud/files/file_chunk_crypto.cpp
    e2e_cloud/files/file_chunk_crypto.h
    e2e_cloud/files/file_chunk_file_store.cpp
    e2e_cloud/files/file_chunk_file_store.h
    e2e_cloud/files/idempotent_file_chunk_protector.cpp
    e2e_cloud/files/idempotent_file_chunk_protector.h
    e2e_cloud/files/private_file_manifest.cpp
    e2e_cloud/files/private_file_manifest.h
    e2e_cloud/group/group_state.cpp
    e2e_cloud/group/group_state.h
    e2e_cloud/group/group_transition_codec.cpp
    e2e_cloud/group/group_transition_codec.h
    e2e_cloud/identity/account_identity.cpp
    e2e_cloud/identity/account_identity.h
    e2e_cloud/identity/openssl_account_crypto.cpp
    e2e_cloud/identity/openssl_account_crypto.h
    e2e_cloud/protocol/inbound_envelope_processor.cpp
    e2e_cloud/protocol/inbound_envelope_processor.h
    e2e_cloud/storage/aes_gcm_local_record_protector.cpp
    e2e_cloud/storage/aes_gcm_local_record_protector.h
    e2e_cloud/storage/file_atomic_blob_store.cpp
    e2e_cloud/storage/file_atomic_blob_store.h
    e2e_cloud/storage/local_storage.h
    e2e_cloud/storage/persistent_inbound_journal.cpp
    e2e_cloud/storage/persistent_inbound_journal.h
    e2e_cloud/storage/persistent_outbox.cpp
    e2e_cloud/storage/persistent_outbox.h
    e2e_cloud/transport/outbox_upload_controller.cpp
    e2e_cloud/transport/outbox_upload_controller.h
    e2e_cloud/transport/telegram_carrier_transport.cpp
    e2e_cloud/transport/telegram_carrier_transport.h
    e2e_cloud/vault/password_kdf.cpp
    e2e_cloud/vault/password_kdf.h
    e2e_cloud/vault/argon2id_password_kdf.cpp
    e2e_cloud/vault/argon2id_password_kdf.h
    e2e_cloud/vault/password_vault.cpp
    e2e_cloud/vault/password_vault.h
)

target_include_directories(td_e2e_cloud
PUBLIC
    ${src_loc}
)

target_link_libraries(td_e2e_cloud
PUBLIC
    desktop-app::external_qt
PRIVATE
    tdesktop::lib_argon2
    desktop-app::external_openssl
)

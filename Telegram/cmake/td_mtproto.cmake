# This file is part of Telegram Desktop,
# the official desktop application for the Telegram messaging service.
#
# For license and copyright information please follow this link:
# https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL

add_library(td_mtproto OBJECT)
init_non_host_target(td_mtproto)
add_library(tdesktop::td_mtproto ALIAS td_mtproto)

target_precompile_headers(td_mtproto PRIVATE ${src_loc}/mtproto/mtproto_pch.h)
nice_target_sources(td_mtproto ${src_loc}
PRIVATE
    mtproto/transport/details/mtproto_abstract_socket.cpp
    mtproto/transport/details/mtproto_abstract_socket.h
    mtproto/protocol/mtproto_binary.h
    mtproto/auth/mtproto_bound_key_creator.cpp
    mtproto/auth/mtproto_bound_key_creator.h
    mtproto/auth/mtproto_dc_key_binder.cpp
    mtproto/auth/mtproto_dc_key_binder.h
    mtproto/auth/mtproto_dc_key_crypto.cpp
    mtproto/auth/mtproto_dc_key_crypto.h
    mtproto/auth/mtproto_dc_key_creator.cpp
    mtproto/auth/mtproto_dc_key_creator.h
    mtproto/details/mtproto_dcenter.cpp
    mtproto/details/mtproto_dcenter.h
    mtproto/details/mtproto_domain_resolver.cpp
    mtproto/details/mtproto_domain_resolver.h
    mtproto/protocol/mtproto_dump_to_text.cpp
    mtproto/protocol/mtproto_dump_to_text.h
    mtproto/details/mtproto_received_ids_manager.cpp
    mtproto/details/mtproto_received_ids_manager.h
    mtproto/details/mtproto_rsa_public_key.cpp
    mtproto/details/mtproto_rsa_public_key.h
    mtproto/protocol/mtproto_serialized_request.cpp
    mtproto/protocol/mtproto_serialized_request.h
    mtproto/transport/details/mtproto_tcp_socket.cpp
    mtproto/transport/details/mtproto_tcp_socket.h
    mtproto/auth/mtproto_auth_key.cpp
    mtproto/auth/mtproto_auth_key.h
    mtproto/instance/mtproto_concurrent_sender.cpp
    mtproto/instance/mtproto_concurrent_sender.h
    mtproto/config/mtproto_config.cpp
    mtproto/config/mtproto_config.h
    mtproto/config/mtproto_dc_options.cpp
    mtproto/config/mtproto_dc_options.h
    mtproto/auth/mtproto_dh_utils.cpp
    mtproto/auth/mtproto_dh_utils.h
    mtproto/mtproto_pch.h
    mtproto/protocol/mtproto_response.cpp
    mtproto/protocol/mtproto_response.h
)

target_include_directories(td_mtproto
PUBLIC
    ${src_loc}
)

target_link_libraries(td_mtproto
PUBLIC
    tdesktop::td_scheme
PRIVATE
    desktop-app::external_zlib
)

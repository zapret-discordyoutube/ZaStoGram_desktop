# This file is part of Telegram Desktop,
# the official desktop application for the Telegram messaging service.
#
# For license and copyright information please follow this link:
# https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL

add_executable(test_text WIN32)
init_target(test_text "(tests)")

target_include_directories(test_text PRIVATE ${src_loc})

nice_target_sources(test_text ${src_loc}
PRIVATE
    tests/test_main.cpp
    tests/test_main.h
    tests/test_text.cpp
)

nice_target_sources(test_text ${res_loc}
PRIVATE
    qrc/emoji_1.qrc
    qrc/emoji_2.qrc
    qrc/emoji_3.qrc
    qrc/emoji_4.qrc
    qrc/emoji_5.qrc
    qrc/emoji_6.qrc
    qrc/emoji_7.qrc
    qrc/emoji_8.qrc
)

target_link_libraries(test_text
PRIVATE
    desktop-app::lib_base
    desktop-app::lib_crl
    desktop-app::lib_ui
    desktop-app::external_qt
    desktop-app::external_qt_static_plugins
)

set_target_properties(test_text PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

add_dependencies(Telegram test_text)

target_prepare_qrc(test_text)

add_executable(test_bot_callback_state WIN32)
init_target(test_bot_callback_state "(tests)")

target_include_directories(test_bot_callback_state PRIVATE ${src_loc})

nice_target_sources(test_bot_callback_state ${src_loc}
PRIVATE
    api/api_bot_callback_state.cpp
    api/api_bot_callback_state.h
    tests/test_bot_callback_state.cpp
)

target_link_libraries(test_bot_callback_state
PRIVATE
    tdesktop::td_scheme
    desktop-app::lib_base
    desktop-app::lib_crl
    desktop-app::lib_ui
    desktop-app::external_qt
)

set_target_properties(
    test_bot_callback_state
    PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

add_dependencies(Telegram test_bot_callback_state)

add_executable(test_mtproxy_client_hello WIN32)
init_target(test_mtproxy_client_hello "(tests)")

target_include_directories(test_mtproxy_client_hello PRIVATE ${src_loc})

nice_target_sources(test_mtproxy_client_hello ${src_loc}
PRIVATE
    mtproto/proxy/mtproxy/client_hello_builder.cpp
    mtproto/proxy/mtproxy/client_hello_builder.h
    mtproto/proxy/mtproxy/client_hello_constants.h
    mtproto/proxy/mtproxy/client_hello_fragmentation.cpp
    mtproto/proxy/mtproxy/client_hello_facts.cpp
    mtproto/proxy/mtproxy/client_hello_facts.h
    mtproto/proxy/mtproxy/client_hello_profile.cpp
    mtproto/proxy/mtproxy/client_hello_profile.h
    mtproto/proxy/mtproxy/client_hello_rules.cpp
    tests/test_mtproxy_client_hello.cpp
)

target_link_libraries(test_mtproxy_client_hello
PRIVATE
    tdesktop::td_scheme
    desktop-app::lib_base
    desktop-app::lib_crl
    desktop-app::external_qt
    desktop-app::external_openssl
)

set_target_properties(
    test_mtproxy_client_hello
    PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

add_dependencies(Telegram test_mtproxy_client_hello)

add_executable(test_mtproxy_open_scheduler WIN32)
init_target(test_mtproxy_open_scheduler "(tests)")

target_include_directories(test_mtproxy_open_scheduler PRIVATE ${src_loc})

nice_target_sources(test_mtproxy_open_scheduler ${src_loc}
PRIVATE
    mtproto/proxy/mtproxy/endpoint_identity.cpp
    mtproto/proxy/mtproxy/endpoint_identity.h
    mtproto/proxy/mtproxy/open_scheduler.cpp
    mtproto/proxy/mtproxy/open_scheduler.h
    mtproto/proxy/proxy_endpoint_context.cpp
    mtproto/proxy/proxy_endpoint_context.h
    mtproto/proxy/proxy_endpoint_context_p.h
    tests/test_mtproxy_open_scheduler.cpp
)

target_link_libraries(test_mtproxy_open_scheduler
PRIVATE
    desktop-app::lib_base
    desktop-app::lib_crl
    desktop-app::external_qt
)

set_target_properties(
    test_mtproxy_open_scheduler
    PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

add_dependencies(Telegram test_mtproxy_open_scheduler)

add_executable(test_mtproxy_endpoint_context WIN32)
init_target(test_mtproxy_endpoint_context "(tests)")

target_include_directories(test_mtproxy_endpoint_context PRIVATE ${src_loc})

nice_target_sources(test_mtproxy_endpoint_context ${src_loc}
PRIVATE
    mtproto/proxy/mtproxy/endpoint_health_state.h
    mtproto/proxy/proxy_endpoint_context.cpp
    mtproto/proxy/proxy_endpoint_context.h
    mtproto/proxy/proxy_endpoint_context_p.h
    tests/test_mtproxy_endpoint_context.cpp
)

target_link_libraries(test_mtproxy_endpoint_context
PRIVATE
    desktop-app::lib_base
    desktop-app::lib_crl
    desktop-app::external_qt
)

set_target_properties(
    test_mtproxy_endpoint_context
    PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

add_dependencies(Telegram test_mtproxy_endpoint_context)

add_executable(test_mtproxy_tls_socket WIN32)
init_target(test_mtproxy_tls_socket "(tests)")

target_include_directories(test_mtproxy_tls_socket PRIVATE ${src_loc})

nice_target_sources(test_mtproxy_tls_socket ${src_loc}
PRIVATE
    mtproto/proxy/mtproxy/adaptive_policy.cpp
    mtproto/proxy/mtproxy/adaptive_policy.h
    mtproto/proxy/mtproxy/client_hello_builder.cpp
    mtproto/proxy/mtproxy/client_hello_builder.h
    mtproto/proxy/mtproxy/client_hello_constants.h
    mtproto/proxy/mtproxy/client_hello_fragmentation.cpp
    mtproto/proxy/mtproxy/client_hello_facts.cpp
    mtproto/proxy/mtproxy/client_hello_facts.h
    mtproto/proxy/mtproxy/client_hello_profile.cpp
    mtproto/proxy/mtproxy/client_hello_profile.h
    mtproto/proxy/mtproxy/client_hello_rules.cpp
    mtproto/proxy/mtproxy/endpoint_identity.cpp
    mtproto/proxy/mtproxy/endpoint_identity.h
    mtproto/proxy/mtproxy/tls_socket.cpp
    mtproto/proxy/mtproxy/tls_socket_diagnostics.cpp
    mtproto/proxy/mtproxy/tls_socket.h
    mtproto/proxy/mtproxy/tls_socket_handshake.cpp
    mtproto/proxy/mtproxy/tls_socket_psk.cpp
    mtproto/proxy/mtproxy/tls_socket_psk.h
    mtproto/proxy/mtproxy/tls_socket_records.cpp
    mtproto/proxy/mtproxy/tls_socket_transport.cpp
    mtproto/proxy/mtproxy/tls_socket_transport.h
    mtproto/proxy/mtproxy/tls_socket_utils.h
    mtproto/proxy/proxy_endpoint_context.cpp
    mtproto/proxy/proxy_endpoint_context.h
    mtproto/proxy/proxy_endpoint_context_p.h
    tests/test_mtproxy_tls_socket.cpp
)

target_link_libraries(test_mtproxy_tls_socket
PRIVATE
    tdesktop::td_scheme
    desktop-app::lib_base
    desktop-app::lib_crl
    desktop-app::external_qt
    desktop-app::external_openssl
)

set_target_properties(
    test_mtproxy_tls_socket
    PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

add_dependencies(Telegram test_mtproxy_tls_socket)

add_executable(test_mtproto_session_harness WIN32)
init_target(test_mtproto_session_harness "(tests)")

target_include_directories(test_mtproto_session_harness PRIVATE ${src_loc})

nice_target_sources(test_mtproto_session_harness ${src_loc}
PRIVATE
    tests/test_mtproto_session_harness.cpp
)

target_link_libraries(test_mtproto_session_harness
PRIVATE
    desktop-app::lib_base
    desktop-app::lib_crl
    desktop-app::external_qt
)

set_target_properties(
    test_mtproto_session_harness
    PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

add_dependencies(Telegram test_mtproto_session_harness)

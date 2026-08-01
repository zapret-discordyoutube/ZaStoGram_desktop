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

if (APPLE)
    add_custom_command(TARGET test_text POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E make_directory
            "$<TARGET_FILE_DIR:test_text>/Contents/Resources"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${CMAKE_BINARY_DIR}/test_text.rcc"
            "${CMAKE_BINARY_DIR}/lib_ui.rcc"
            "$<TARGET_FILE_DIR:test_text>/Contents/Resources/"
    )
endif()

add_executable(test_bot_callback_state WIN32)
init_target(test_bot_callback_state "(tests)")

target_include_directories(test_bot_callback_state PRIVATE ${src_loc})

nice_target_sources(test_bot_callback_state ${src_loc}
PRIVATE
    api/api_bot_callback_state.cpp
    api/api_bot_callback_state.h
    tests/test_bot_callback_state.cpp
)

target_precompile_headers(test_bot_callback_state
    PRIVATE $<$<COMPILE_LANGUAGE:CXX,OBJCXX>:${src_loc}/stdafx.h>)

target_compile_definitions(test_bot_callback_state
PRIVATE
    TDESKTOP_API_ID=${TDESKTOP_API_ID}
    TDESKTOP_API_HASH=${TDESKTOP_API_HASH}
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

target_precompile_headers(test_mtproxy_client_hello
    PRIVATE $<$<COMPILE_LANGUAGE:CXX,OBJCXX>:${src_loc}/stdafx.h>)

target_compile_definitions(test_mtproxy_client_hello
PRIVATE
    TDESKTOP_API_ID=${TDESKTOP_API_ID}
    TDESKTOP_API_HASH=${TDESKTOP_API_HASH}
)

target_link_libraries(test_mtproxy_client_hello
PRIVATE
    tdesktop::td_scheme
    desktop-app::lib_base
    desktop-app::lib_crl
    desktop-app::lib_ui
    desktop-app::external_qt
    desktop-app::external_openssl
)

set_target_properties(
    test_mtproxy_client_hello
    PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

add_dependencies(Telegram test_mtproxy_client_hello)

add_executable(test_mtproxy_tls_socket WIN32)
init_target(test_mtproxy_tls_socket "(tests)")

target_include_directories(test_mtproxy_tls_socket PRIVATE ${src_loc})

nice_target_sources(test_mtproxy_tls_socket ${src_loc}
PRIVATE
    tests/test_mtproxy_tls_socket.cpp
)

target_precompile_headers(test_mtproxy_tls_socket
    PRIVATE $<$<COMPILE_LANGUAGE:CXX,OBJCXX>:${src_loc}/stdafx.h>)

target_compile_definitions(test_mtproxy_tls_socket
PRIVATE
    TDESKTOP_API_ID=${TDESKTOP_API_ID}
    TDESKTOP_API_HASH=${TDESKTOP_API_HASH}
)

target_link_libraries(test_mtproxy_tls_socket
PRIVATE
    tdesktop::td_scheme
    desktop-app::lib_base
    desktop-app::lib_crl
    desktop-app::lib_ui
    desktop-app::external_qt
    desktop-app::external_openssl
)

set_target_properties(
    test_mtproxy_tls_socket
    PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

add_dependencies(Telegram test_mtproxy_tls_socket)

add_executable(test_e2e_cloud)
init_target(test_e2e_cloud "(tests)")

target_include_directories(test_e2e_cloud PRIVATE ${src_loc})

nice_target_sources(test_e2e_cloud ${src_loc}
PRIVATE
    tests/test_e2e_cloud.cpp
)

target_link_libraries(test_e2e_cloud
PRIVATE
    tdesktop::td_e2e_cloud
    desktop-app::external_qt
)

set_target_properties(
    test_e2e_cloud
    PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

add_dependencies(Telegram test_e2e_cloud)

add_executable(test_e2e_cloud_group)
init_target(test_e2e_cloud_group "(tests)")

target_include_directories(test_e2e_cloud_group PRIVATE ${src_loc})

nice_target_sources(test_e2e_cloud_group ${src_loc}
PRIVATE
    tests/test_e2e_cloud_group.cpp
)

target_link_libraries(test_e2e_cloud_group
PRIVATE
    tdesktop::td_e2e_cloud
    desktop-app::external_qt
)

set_target_properties(
    test_e2e_cloud_group
    PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

add_dependencies(Telegram test_e2e_cloud_group)

add_executable(test_e2e_cloud_identity)
init_target(test_e2e_cloud_identity "(tests)")

target_include_directories(test_e2e_cloud_identity PRIVATE ${src_loc})

nice_target_sources(test_e2e_cloud_identity ${src_loc}
PRIVATE
    tests/test_e2e_cloud_identity.cpp
)

target_link_libraries(test_e2e_cloud_identity
PRIVATE
    tdesktop::td_e2e_cloud
    desktop-app::external_openssl
    desktop-app::external_qt
)

set_target_properties(
    test_e2e_cloud_identity
    PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

add_dependencies(Telegram test_e2e_cloud_identity)

add_executable(test_e2e_cloud_storage)
init_target(test_e2e_cloud_storage "(tests)")

target_include_directories(test_e2e_cloud_storage PRIVATE ${src_loc})

nice_target_sources(test_e2e_cloud_storage ${src_loc}
PRIVATE
    tests/test_e2e_cloud_storage.cpp
)

target_link_libraries(test_e2e_cloud_storage
PRIVATE
    tdesktop::td_e2e_cloud
    desktop-app::external_openssl
    desktop-app::external_qt
)

set_target_properties(
    test_e2e_cloud_storage
    PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

add_dependencies(Telegram test_e2e_cloud_storage)

add_executable(test_e2e_cloud_vault)
init_target(test_e2e_cloud_vault "(tests)")

target_include_directories(test_e2e_cloud_vault PRIVATE ${src_loc})

nice_target_sources(test_e2e_cloud_vault ${src_loc}
PRIVATE
    tests/test_e2e_cloud_vault.cpp
)

target_link_libraries(test_e2e_cloud_vault
PRIVATE
    tdesktop::td_e2e_cloud
    tdesktop::lib_argon2
    desktop-app::external_qt
    desktop-app::external_openssl
)

set_target_properties(
    test_e2e_cloud_vault
    PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

add_dependencies(Telegram test_e2e_cloud_vault)

add_executable(test_e2e_cloud_inbound)
init_target(test_e2e_cloud_inbound "(tests)")

target_include_directories(test_e2e_cloud_inbound PRIVATE ${src_loc})

nice_target_sources(test_e2e_cloud_inbound ${src_loc}
PRIVATE
    tests/test_e2e_cloud_inbound.cpp
)

target_link_libraries(test_e2e_cloud_inbound
PRIVATE
    tdesktop::td_e2e_cloud
    desktop-app::external_qt
)

set_target_properties(
    test_e2e_cloud_inbound
    PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

add_dependencies(Telegram test_e2e_cloud_inbound)

add_executable(test_e2e_cloud_sync)
init_target(test_e2e_cloud_sync "(tests)")

target_include_directories(test_e2e_cloud_sync PRIVATE ${src_loc})

nice_target_sources(test_e2e_cloud_sync ${src_loc}
PRIVATE
    tests/test_e2e_cloud_sync.cpp
)

target_link_libraries(test_e2e_cloud_sync
PRIVATE
    tdesktop::td_e2e_cloud
    desktop-app::external_qt
)

set_target_properties(
    test_e2e_cloud_sync
    PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

add_test(
    NAME test_e2e_cloud_sync
    COMMAND test_e2e_cloud_sync
)

add_dependencies(Telegram test_e2e_cloud_sync)

add_executable(test_e2e_cloud_bootstrap)
init_target(test_e2e_cloud_bootstrap "(tests)")

target_include_directories(test_e2e_cloud_bootstrap PRIVATE ${src_loc})

nice_target_sources(test_e2e_cloud_bootstrap ${src_loc}
PRIVATE
    tests/test_e2e_cloud_bootstrap.cpp
)

target_link_libraries(test_e2e_cloud_bootstrap
PRIVATE
    tdesktop::td_e2e_cloud
    tdesktop::lib_openmls_bridge
    desktop-app::external_openssl
    desktop-app::external_qt
)

set_target_properties(
    test_e2e_cloud_bootstrap
    PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

add_test(
    NAME test_e2e_cloud_bootstrap
    COMMAND test_e2e_cloud_bootstrap
)

add_dependencies(Telegram test_e2e_cloud_bootstrap)

add_executable(test_e2e_cloud_files)
init_target(test_e2e_cloud_files "(tests)")

target_include_directories(test_e2e_cloud_files PRIVATE ${src_loc})

nice_target_sources(test_e2e_cloud_files ${src_loc}
PRIVATE
    tests/test_e2e_cloud_files.cpp
)

target_link_libraries(test_e2e_cloud_files
PRIVATE
    tdesktop::td_e2e_cloud
    desktop-app::external_openssl
    desktop-app::external_qt
)

set_target_properties(
    test_e2e_cloud_files
    PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

add_dependencies(Telegram test_e2e_cloud_files)

add_executable(test_e2e_cloud_openmls)
init_target(test_e2e_cloud_openmls "(tests)")

target_include_directories(test_e2e_cloud_openmls PRIVATE ${src_loc})

nice_target_sources(test_e2e_cloud_openmls ${src_loc}
PRIVATE
    tests/test_e2e_cloud_openmls_abi.cpp
)

target_link_libraries(test_e2e_cloud_openmls
PRIVATE
    tdesktop::lib_openmls_bridge
)

set_target_properties(
    test_e2e_cloud_openmls
    PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

add_test(
    NAME test_e2e_cloud_openmls
    COMMAND test_e2e_cloud_openmls
)

add_dependencies(Telegram test_e2e_cloud_openmls)

add_executable(test_e2e_cloud_openmls_application)
init_target(test_e2e_cloud_openmls_application "(tests)")

target_include_directories(
    test_e2e_cloud_openmls_application
    PRIVATE
    ${src_loc})

nice_target_sources(test_e2e_cloud_openmls_application ${src_loc}
PRIVATE
    tests/test_e2e_cloud_openmls_application.cpp
)

target_link_libraries(test_e2e_cloud_openmls_application
PRIVATE
    tdesktop::td_e2e_cloud
    tdesktop::lib_openmls_bridge
    desktop-app::external_openssl
    desktop-app::external_qt
)

set_target_properties(
    test_e2e_cloud_openmls_application
    PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

add_test(
    NAME test_e2e_cloud_openmls_application
    COMMAND test_e2e_cloud_openmls_application
)

add_dependencies(Telegram test_e2e_cloud_openmls_application)

add_executable(test_e2e_cloud_openmls_group_change)
init_target(test_e2e_cloud_openmls_group_change "(tests)")

target_include_directories(
    test_e2e_cloud_openmls_group_change
    PRIVATE ${src_loc})

nice_target_sources(test_e2e_cloud_openmls_group_change ${src_loc}
PRIVATE
    tests/test_e2e_cloud_openmls_group_change.cpp
)

target_link_libraries(test_e2e_cloud_openmls_group_change
PRIVATE
    tdesktop::td_e2e_cloud
    tdesktop::lib_openmls_bridge
    desktop-app::external_openssl
)

set_target_properties(
    test_e2e_cloud_openmls_group_change
    PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

add_test(
    NAME test_e2e_cloud_openmls_group_change
    COMMAND test_e2e_cloud_openmls_group_change
)

add_dependencies(Telegram test_e2e_cloud_openmls_group_change)

add_executable(test_e2e_cloud_archive)
init_target(test_e2e_cloud_archive "(tests)")

target_include_directories(test_e2e_cloud_archive PRIVATE ${src_loc})

nice_target_sources(test_e2e_cloud_archive ${src_loc}
PRIVATE
    tests/test_e2e_cloud_archive.cpp
)

target_link_libraries(test_e2e_cloud_archive
PRIVATE
    tdesktop::td_e2e_cloud
    tdesktop::lib_openmls_bridge
    desktop-app::external_openssl
    desktop-app::external_qt
)

set_target_properties(
    test_e2e_cloud_archive
    PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

add_test(
    NAME test_e2e_cloud_archive
    COMMAND test_e2e_cloud_archive
)

add_dependencies(Telegram test_e2e_cloud_archive)

add_executable(test_e2e_cloud_fork_recovery)
init_target(test_e2e_cloud_fork_recovery "(tests)")

target_include_directories(
    test_e2e_cloud_fork_recovery
    PRIVATE ${src_loc})

nice_target_sources(test_e2e_cloud_fork_recovery ${src_loc}
PRIVATE
    tests/test_e2e_cloud_fork_recovery.cpp
)

target_link_libraries(test_e2e_cloud_fork_recovery
PRIVATE
    tdesktop::td_e2e_cloud
    tdesktop::lib_openmls_bridge
    desktop-app::external_openssl
    desktop-app::external_qt
)

set_target_properties(
    test_e2e_cloud_fork_recovery
    PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

add_test(
    NAME test_e2e_cloud_fork_recovery
    COMMAND test_e2e_cloud_fork_recovery
)

add_dependencies(Telegram test_e2e_cloud_fork_recovery)

add_executable(test_e2e_cloud_openmls_fork_recovery)
init_target(test_e2e_cloud_openmls_fork_recovery "(tests)")

target_include_directories(
    test_e2e_cloud_openmls_fork_recovery
    PRIVATE ${src_loc})

nice_target_sources(test_e2e_cloud_openmls_fork_recovery ${src_loc}
PRIVATE
    tests/test_e2e_cloud_openmls_fork_recovery.cpp
)

target_link_libraries(test_e2e_cloud_openmls_fork_recovery
PRIVATE
    tdesktop::td_e2e_cloud
    tdesktop::lib_openmls_bridge
    desktop-app::external_openssl
    desktop-app::external_qt
)

set_target_properties(
    test_e2e_cloud_openmls_fork_recovery
    PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

add_test(
    NAME test_e2e_cloud_openmls_fork_recovery
    COMMAND test_e2e_cloud_openmls_fork_recovery
)

add_dependencies(Telegram test_e2e_cloud_openmls_fork_recovery)

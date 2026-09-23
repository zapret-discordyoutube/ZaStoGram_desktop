# This file is part of Telegram Desktop,
# the official desktop application for the Telegram messaging service.
#
# For license and copyright information please follow this link:
# https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL

find_program(TD_E2E_CARGO_EXECUTABLE cargo REQUIRED)

set(openmls_bridge_manifest
    ${src_loc}/e2e_cloud/mls/openmls_bridge/Cargo.toml)
set(openmls_bridge_target_dir
    ${CMAKE_BINARY_DIR}/rust/td_e2e_openmls_bridge)
set(openmls_bridge_profile
    $<IF:$<CONFIG:Debug>,debug,release>)
set(openmls_bridge_cargo_profile
    $<IF:$<CONFIG:Debug>,dev,release>)

if (WIN32)
    get_filename_component(openmls_bridge_cargo_dir
        ${TD_E2E_CARGO_EXECUTABLE} DIRECTORY)
    find_program(openmls_bridge_rustc rustc
        HINTS ${openmls_bridge_cargo_dir}
        REQUIRED)
    if (build_winarm)
        set(openmls_bridge_rust_target aarch64-pc-windows-msvc)
    elseif (build_win64)
        set(openmls_bridge_rust_target x86_64-pc-windows-msvc)
    else()
        set(openmls_bridge_rust_target i686-pc-windows-msvc)
    endif()
    set(openmls_bridge_library_dir
        ${openmls_bridge_target_dir}/${openmls_bridge_rust_target})
    set(openmls_bridge_debug_library
        ${openmls_bridge_library_dir}/debug/td_e2e_openmls_bridge.lib)
    set(openmls_bridge_release_library
        ${openmls_bridge_library_dir}/release/td_e2e_openmls_bridge.lib)
    set(openmls_bridge_library
        ${openmls_bridge_library_dir}/${openmls_bridge_profile}/td_e2e_openmls_bridge.lib)
    set(openmls_bridge_build_commands
        COMMAND ${CMAKE_COMMAND} -E env
            CARGO_TARGET_DIR=${openmls_bridge_target_dir}
            ${TD_E2E_CARGO_EXECUTABLE} build
            --manifest-path ${openmls_bridge_manifest}
            --locked
            --target ${openmls_bridge_rust_target}
            --profile ${openmls_bridge_cargo_profile}
        # tlottie is a second Rust static library in the same executable.
        COMMAND ${CMAKE_COMMAND}
            -D library=${openmls_bridge_library}
            -D rustc=${openmls_bridge_rustc}
            -P ${CMAKE_CURRENT_SOURCE_DIR}/cmake/rename_rust_eh_personality.cmake)
elseif (APPLE)
    set(openmls_bridge_library_dir
        ${openmls_bridge_target_dir}/universal)
    set(openmls_bridge_debug_library
        ${openmls_bridge_library_dir}/debug/libtd_e2e_openmls_bridge.a)
    set(openmls_bridge_release_library
        ${openmls_bridge_library_dir}/release/libtd_e2e_openmls_bridge.a)
    set(openmls_bridge_library
        ${openmls_bridge_library_dir}/${openmls_bridge_profile}/libtd_e2e_openmls_bridge.a)
    set(openmls_bridge_x86_library
        ${openmls_bridge_target_dir}/x86_64-apple-darwin/${openmls_bridge_profile}/libtd_e2e_openmls_bridge.a)
    set(openmls_bridge_arm_library
        ${openmls_bridge_target_dir}/aarch64-apple-darwin/${openmls_bridge_profile}/libtd_e2e_openmls_bridge.a)
    set(openmls_bridge_build_commands
        COMMAND ${CMAKE_COMMAND} -E env
            CARGO_TARGET_DIR=${openmls_bridge_target_dir}
            ${TD_E2E_CARGO_EXECUTABLE} build
            --manifest-path ${openmls_bridge_manifest}
            --locked
            --target x86_64-apple-darwin
            --profile ${openmls_bridge_cargo_profile}
        COMMAND ${CMAKE_COMMAND} -E env
            CARGO_TARGET_DIR=${openmls_bridge_target_dir}
            ${TD_E2E_CARGO_EXECUTABLE} build
            --manifest-path ${openmls_bridge_manifest}
            --locked
            --target aarch64-apple-darwin
            --profile ${openmls_bridge_cargo_profile}
        COMMAND ${CMAKE_COMMAND} -E make_directory
            ${openmls_bridge_target_dir}/universal/${openmls_bridge_profile}
        COMMAND lipo -create
            ${openmls_bridge_x86_library}
            ${openmls_bridge_arm_library}
            -output ${openmls_bridge_library})
else()
    set(openmls_bridge_library_dir ${openmls_bridge_target_dir})
    set(openmls_bridge_debug_library
        ${openmls_bridge_library_dir}/debug/libtd_e2e_openmls_bridge.a)
    set(openmls_bridge_release_library
        ${openmls_bridge_library_dir}/release/libtd_e2e_openmls_bridge.a)
    set(openmls_bridge_library
        ${openmls_bridge_library_dir}/${openmls_bridge_profile}/libtd_e2e_openmls_bridge.a)
    set(openmls_bridge_build_commands
        COMMAND ${CMAKE_COMMAND} -E env
            CARGO_TARGET_DIR=${openmls_bridge_target_dir}
            ${TD_E2E_CARGO_EXECUTABLE} build
            --manifest-path ${openmls_bridge_manifest}
            --locked
            --profile ${openmls_bridge_cargo_profile})
endif()

add_custom_target(lib_openmls_bridge_build
    ${openmls_bridge_build_commands}
    BYPRODUCTS ${openmls_bridge_library}
    WORKING_DIRECTORY
        ${src_loc}/e2e_cloud/mls/openmls_bridge
    USES_TERMINAL
    VERBATIM)

add_library(lib_openmls_bridge STATIC IMPORTED GLOBAL)
add_library(tdesktop::lib_openmls_bridge ALIAS lib_openmls_bridge)
set_target_properties(lib_openmls_bridge PROPERTIES
    IMPORTED_CONFIGURATIONS "DEBUG;RELEASE"
    IMPORTED_LOCATION ${openmls_bridge_release_library}
    IMPORTED_LOCATION_DEBUG ${openmls_bridge_debug_library}
    IMPORTED_LOCATION_RELEASE ${openmls_bridge_release_library}
    INTERFACE_INCLUDE_DIRECTORIES ${src_loc}/e2e_cloud/mls
    MAP_IMPORTED_CONFIG_MINSIZEREL Release
    MAP_IMPORTED_CONFIG_RELWITHDEBINFO Release)
add_dependencies(lib_openmls_bridge lib_openmls_bridge_build)

if (WIN32)
    target_link_libraries(lib_openmls_bridge INTERFACE
        advapi32
        bcrypt
        ntdll
        userenv
        ws2_32)
elseif (APPLE)
    find_library(openmls_bridge_security_framework Security REQUIRED)
    target_link_libraries(lib_openmls_bridge INTERFACE
        ${openmls_bridge_security_framework})
else()
    find_package(Threads REQUIRED)
    find_library(openmls_bridge_rt_library rt)
    find_library(openmls_bridge_util_library util)
    set(openmls_bridge_native_libraries
        Threads::Threads
        ${CMAKE_DL_LIBS}
        m)
    if (openmls_bridge_rt_library)
        list(APPEND openmls_bridge_native_libraries
            ${openmls_bridge_rt_library})
    endif()
    if (openmls_bridge_util_library)
        list(APPEND openmls_bridge_native_libraries
            ${openmls_bridge_util_library})
    endif()
    target_link_libraries(lib_openmls_bridge INTERFACE
        ${openmls_bridge_native_libraries})
endif()

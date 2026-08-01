# This file is part of Telegram Desktop,
# the official desktop application for the Telegram messaging service.
#
# For license and copyright information please follow this link:
# https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL

cmake_minimum_required(VERSION 3.25...3.31)

set_property(GLOBAL PROPERTY USE_FOLDERS ON)

include(cmake/validate_special_target.cmake)
include(cmake/version.cmake)
desktop_app_parse_version(Telegram/build/version)

if (NOT DEFINED CMAKE_CONFIGURATION_TYPES)
    set(configuration_types_init 1)
endif()

project(Telegram
    LANGUAGES C CXX
    VERSION ${desktop_app_version_cmake}
    DESCRIPTION "Official Telegram Desktop messenger"
    HOMEPAGE_URL "https://desktop.telegram.org"
)

if (APPLE)
    enable_language(OBJC OBJCXX)
endif()

if (configuration_types_init
    AND CMAKE_CONFIGURATION_TYPES
    AND NOT MinSizeRel IN_LIST CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_CONFIGURATION_TYPES "${CMAKE_CONFIGURATION_TYPES};MinSizeRel" CACHE STRING "" FORCE)
endif()

set_property(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} PROPERTY VS_STARTUP_PROJECT Telegram)

get_filename_component(third_party_loc "Telegram/ThirdParty" REALPATH)
get_filename_component(submodules_loc "Telegram" REALPATH)
get_filename_component(cmake_helpers_loc "cmake" REALPATH)

if (NOT DESKTOP_APP_USE_PACKAGED AND WIN32)
    set(Python3_EXECUTABLE ${CMAKE_CURRENT_SOURCE_DIR}/../ThirdParty/python/Scripts/python)
endif()

include(cmake/variables.cmake)
include(cmake/nice_target_sources.cmake)
include(cmake/target_compile_options_if_exists.cmake)
include(cmake/target_link_frameworks.cmake)
include(cmake/target_link_options_if_exists.cmake)
include(cmake/init_target.cmake)
include(cmake/generate_target.cmake)
include(cmake/nuget.cmake)
include(cmake/validate_d3d_compiler.cmake)
include(cmake/target_prepare_qrc.cmake)

include(cmake/options.cmake)
include(cmake/external/qt/package.cmake)

if (DESKTOP_APP_TEST_APPS)
    enable_testing()
endif()

set(desktop_app_skip_libs
    glibmm
    variant
)

block(SCOPE_FOR POLICIES)
    if (POLICY CMP0218)
        cmake_policy(SET CMP0218 OLD)
    endif()
    add_subdirectory(cmake)
endblock()

if (WIN32 AND NOT DESKTOP_APP_USE_PACKAGED AND TARGET external_ffmpeg)
    target_link_libraries(external_ffmpeg
    INTERFACE
        ${libs_loc}/dav1d/builddir-$<IF:$<CONFIG:Debug>,debug,release>/src/libdav1d.a
    )
endif()

add_subdirectory(Telegram)

# ZaStoGram: sccache mishandles the kimageformats Qt plugin's deep relative
# obj paths under MSVC (it passes an empty /Fd -> fatal C1083). Build that
# external plugin without the compiler launcher; sccache still accelerates
# the rest of the build (the Telegram app, lib_*, etc.).
if(TARGET external_qt_static_plugins_kimageformats)
    set_target_properties(external_qt_static_plugins_kimageformats PROPERTIES
        C_COMPILER_LAUNCHER ""
        CXX_COMPILER_LAUNCHER ""
        MSVC_DEBUG_INFORMATION_FORMAT "ProgramDatabase")
endif()

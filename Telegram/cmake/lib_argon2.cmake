# This file is part of Telegram Desktop,
# the official desktop application for the Telegram messaging service.
#
# For license and copyright information please follow this link:
# https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL

add_library(lib_argon2 STATIC)
init_target(lib_argon2 "(external)")
add_library(tdesktop::lib_argon2 ALIAS lib_argon2)

set(argon2_loc ${third_party_loc}/argon2)

nice_target_sources(lib_argon2 ${argon2_loc}
PRIVATE
    include/argon2.h
    src/argon2.c
    src/blake2/blake2-impl.h
    src/blake2/blake2.h
    src/blake2/blake2b.c
    src/blake2/blamka-round-ref.h
    src/core.c
    src/core.h
    src/encoding.c
    src/encoding.h
    src/ref.c
    src/thread.h
)

target_include_directories(lib_argon2
PUBLIC
    ${argon2_loc}/include
PRIVATE
    ${argon2_loc}/src
)

target_compile_definitions(lib_argon2 PRIVATE ARGON2_NO_THREADS)
if (WIN32)
    target_compile_definitions(lib_argon2 PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()

# Silence third-party C warnings. On MSVC the flags must ride an INTERFACE lib
# linked after common_options to land last and beat its /W4 /WX.
if (MSVC)
    add_library(lib_argon2_warnings_off INTERFACE)
    target_compile_options(lib_argon2_warnings_off
    INTERFACE
        /W0
        /WX-)
    target_link_libraries(lib_argon2 PRIVATE lib_argon2_warnings_off)
else()
    target_compile_options(lib_argon2 PRIVATE -w)
endif()

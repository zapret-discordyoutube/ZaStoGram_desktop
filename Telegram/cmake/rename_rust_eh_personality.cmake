# This file is part of Telegram Desktop,
# the official desktop application for the Telegram messaging service.
#
# For license and copyright information please follow this link:
# https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL

# Run as a script after cargo builds td_e2e_openmls_bridge on Windows:
#   cmake -D library=<.lib> -D rustc=<rustc> -P rename_rust_eh_personality.cmake
#
# Telegram links two Rust static libraries, the openmls bridge and tlottie,
# and each carries its own copy of std.  Everything in std is mangled with the
# toolchain hash except the rust_eh_personality lang item, so MSVC stops with
# LNK2005 on it.  windows-msvc code unwinds through __CxxFrameHandler3 and never
# calls rust_eh_personality, so renaming the bridge's copy is safe; tlottie's
# copy stays the only one with that name.  The step is idempotent: a library
# that already has no such symbol is left untouched.

if (NOT library OR NOT rustc)
    message(FATAL_ERROR "library and rustc must be set")
endif()

set(symbol rust_eh_personality)
set(renamed zsg_openmls_rust_eh_personality)

execute_process(
    COMMAND ${rustc} --print sysroot
    OUTPUT_VARIABLE sysroot
    OUTPUT_STRIP_TRAILING_WHITESPACE
    COMMAND_ERROR_IS_FATAL ANY)
execute_process(
    COMMAND ${rustc} -vV
    OUTPUT_VARIABLE rustc_version
    COMMAND_ERROR_IS_FATAL ANY)
string(REGEX MATCH "host: ([^\n]+)" _ "${rustc_version}")
set(tools ${sysroot}/lib/rustlib/${CMAKE_MATCH_1}/bin)
foreach (tool llvm-ar llvm-nm llvm-objcopy)
    if (NOT EXISTS ${tools}/${tool}.exe)
        message(FATAL_ERROR "${tool} not found in ${tools}: "
            "add the llvm-tools component to rust-toolchain.toml")
    endif()
endforeach()

execute_process(
    COMMAND ${tools}/llvm-nm.exe --defined-only ${library}
    OUTPUT_VARIABLE symbols
    ERROR_QUIET
    COMMAND_ERROR_IS_FATAL ANY)
if (NOT symbols MATCHES " T ${symbol}\n")
    return()
endif()

execute_process(
    COMMAND ${tools}/llvm-ar.exe t ${library}
    OUTPUT_VARIABLE members
    COMMAND_ERROR_IS_FATAL ANY)
string(REGEX MATCHALL "std-[^\n]+\\.rcgu\\.o" std_members "${members}")
list(REMOVE_DUPLICATES std_members)
list(LENGTH std_members std_count)
if (NOT std_count EQUAL 1)
    message(FATAL_ERROR "expected one std object in ${library}, "
        "found ${std_count}: review ${CMAKE_CURRENT_LIST_FILE}")
endif()

get_filename_component(library_dir ${library} DIRECTORY)
set(work ${library_dir}/rename_eh_personality)
file(REMOVE_RECURSE ${work})
file(MAKE_DIRECTORY ${work})
execute_process(
    COMMAND ${tools}/llvm-ar.exe x ${library} ${std_members}
    WORKING_DIRECTORY ${work}
    COMMAND_ERROR_IS_FATAL ANY)
execute_process(
    COMMAND ${tools}/llvm-objcopy.exe
        --redefine-sym ${symbol}=${renamed}
        ${std_members}
    WORKING_DIRECTORY ${work}
    COMMAND_ERROR_IS_FATAL ANY)
execute_process(
    COMMAND ${tools}/llvm-ar.exe r ${library} ${std_members}
    WORKING_DIRECTORY ${work}
    COMMAND_ERROR_IS_FATAL ANY)
file(REMOVE_RECURSE ${work})

execute_process(
    COMMAND ${tools}/llvm-nm.exe --defined-only ${library}
    OUTPUT_VARIABLE symbols
    ERROR_QUIET
    COMMAND_ERROR_IS_FATAL ANY)
if (symbols MATCHES " T ${symbol}\n")
    message(FATAL_ERROR "${symbol} is still defined in ${library}")
endif()
message(STATUS "Renamed ${symbol} to ${renamed} in ${library}")

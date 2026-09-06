# Keep the bundled renderer fix in this repository until it is upstreamed.
# Generate a patched translation unit without modifying the rlottie submodule.
function(zastogram_patch_rlottie_path source output)
    set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${source}")
    file(READ "${source}" contents)
    foreach(shape POLYSTAR POLYGON)
        set(marker "    const static float ${shape}_MAGIC_NUMBER")
        string(REGEX MATCHALL "${marker}" matches "${contents}")
        list(LENGTH matches count)
        if (NOT count EQUAL 1)
            message(FATAL_ERROR "rlottie ${shape} changed: review point-count validation")
        endif()
        set(replacement [=[
    // Animated point counts can be negative, non-finite or excessively large.
    // Validate before division, float-to-size_t conversion and reserve().
    // 10,000 vertices already exceed useful detail for a sticker; bounding
    // work also prevents finite values from exhausting memory or render time.
    if (!(points >= 1.0f && points <= 10000.0f)) return;
@MARKER@]=])
        string(REPLACE "@MARKER@" "${marker}" replacement "${replacement}")
        string(REPLACE "${marker}" "${replacement}" contents "${contents}")
    endforeach()
    # configure_file preserves the timestamp when generated contents match.
    file(WRITE "${output}.in" "${contents}")
    configure_file("${output}.in" "${output}" COPYONLY)
endfunction()

if (TARGET external_rlottie_bundled)
    set(rlottie_path_source "${third_party_loc}/rlottie/src/vector/vpath.cpp")
    set(rlottie_path_patched "${CMAKE_CURRENT_BINARY_DIR}/rlottie/vpath.cpp")
    zastogram_patch_rlottie_path("${rlottie_path_source}" "${rlottie_path_patched}")
    get_target_property(rlottie_sources external_rlottie_bundled SOURCES)
    if (NOT rlottie_path_source IN_LIST rlottie_sources)
        message(FATAL_ERROR "Bundled rlottie source list changed: review path patch")
    endif()
    list(REMOVE_ITEM rlottie_sources "${rlottie_path_source}")
    list(APPEND rlottie_sources "${rlottie_path_patched}")
    set_property(TARGET external_rlottie_bundled PROPERTY SOURCES "${rlottie_sources}")
endif()

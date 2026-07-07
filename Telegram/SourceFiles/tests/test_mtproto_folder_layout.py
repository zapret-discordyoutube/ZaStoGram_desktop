from pathlib import Path


SOURCE_DIR = Path(__file__).resolve().parents[1]
ROOT = SOURCE_DIR.parents[1]
MTPROTO_DIR = SOURCE_DIR / "mtproto"
CMAKE = ROOT / "Telegram" / "CMakeLists.txt"
TD_MTPROTO_CMAKE = ROOT / "Telegram" / "cmake" / "td_mtproto.cmake"
SETTINGS_EXPERIMENTAL = SOURCE_DIR / "settings" / "settings_experimental.cpp"


def read(path):
    assert path.exists(), f"missing expected source file: {path}"
    return path.read_text(encoding="utf-8")


def build_lists():
    return read(CMAKE) + "\n" + read(TD_MTPROTO_CMAKE)


def test_transport_sources_live_under_transport_folder():
    expected = (
        "transport/connection_abstract.cpp",
        "transport/connection_abstract.h",
        "transport/connection_http.cpp",
        "transport/connection_http.h",
        "transport/connection_tcp.cpp",
        "transport/connection_tcp.h",
        "transport/details/mtproto_abstract_socket.cpp",
        "transport/details/mtproto_abstract_socket.h",
        "transport/details/mtproto_tcp_socket.cpp",
        "transport/details/mtproto_tcp_socket.h",
    )
    removed = (
        "connection_abstract.cpp",
        "connection_abstract.h",
        "connection_http.cpp",
        "connection_http.h",
        "connection_tcp.cpp",
        "connection_tcp.h",
        "details/mtproto_abstract_socket.cpp",
        "details/mtproto_abstract_socket.h",
        "details/mtproto_tcp_socket.cpp",
        "details/mtproto_tcp_socket.h",
        "transport/mtproto_abstract_socket.cpp",
        "transport/mtproto_abstract_socket.h",
        "transport/mtproto_tcp_socket.cpp",
        "transport/mtproto_tcp_socket.h",
    )
    listed = build_lists()

    for path in expected:
        assert (MTPROTO_DIR / path).exists()
        assert f"mtproto/{path}" in listed

    for path in removed:
        assert not (MTPROTO_DIR / path).exists()
        assert f"mtproto/{path}" not in listed


def test_session_sources_live_under_session_folder():
    expected = (
        "session/session.cpp",
        "session/session.h",
        "session/session_state.h",
        "session/pause_state.cpp",
        "session/pause_state.h",
        "session/options.h",
        "session/private/session_private.cpp",
        "session/private/session_private.h",
        "session/private/auth.cpp",
        "session/private/connection.cpp",
        "session/private/receive.cpp",
        "session/private/send.cpp",
    )
    removed = (
        "session.cpp",
        "session.h",
        "session_state.h",
        "pause_state.cpp",
        "pause_state.h",
        "session_private.cpp",
        "session_private.h",
        "session_private/auth.cpp",
        "session_private/connection.cpp",
        "session_private/receive.cpp",
        "session_private/send.cpp",
        "session/state.h",
        "session/private.cpp",
        "session/private.h",
    )
    listed = build_lists()

    for path in expected:
        assert (MTPROTO_DIR / path).exists()
        assert f"mtproto/{path}" in listed

    for path in removed:
        assert not (MTPROTO_DIR / path).exists()
        assert f"mtproto/{path}" not in listed


def test_experimental_settings_does_not_include_session_private():
    source = read(SETTINGS_EXPERIMENTAL)

    assert '#include "mtproto/session/options.h"' in source
    assert '#include "mtproto/session/private/session_private.h"' not in source
    assert '#include "mtproto/session/private/session_private.h"' not in source
    assert "MTP::details::kOptionPreferIPv6" in source


def test_config_auth_protocol_and_files_have_folders():
    expected = (
        "config/config_loader.cpp",
        "config/config_loader.h",
        "config/special_config_request.cpp",
        "config/special_config_request.h",
        "auth/mtproto_bound_key_creator.cpp",
        "auth/mtproto_bound_key_creator.h",
        "auth/mtproto_dc_key_binder.cpp",
        "auth/mtproto_dc_key_binder.h",
        "auth/mtproto_dc_key_creator.cpp",
        "auth/mtproto_dc_key_creator.h",
        "auth/mtproto_dh_utils.cpp",
        "auth/mtproto_dh_utils.h",
        "protocol/mtproto_binary.h",
        "protocol/mtproto_dump_to_text.cpp",
        "protocol/mtproto_dump_to_text.h",
        "protocol/mtproto_serialized_request.cpp",
        "protocol/mtproto_serialized_request.h",
        "files/dedicated_file_loader.cpp",
        "files/dedicated_file_loader.h",
    )
    removed = (
        "config_loader.cpp",
        "config_loader.h",
        "special_config_request.cpp",
        "special_config_request.h",
        "details/mtproto_bound_key_creator.cpp",
        "details/mtproto_bound_key_creator.h",
        "details/mtproto_dc_key_binder.cpp",
        "details/mtproto_dc_key_binder.h",
        "details/mtproto_dc_key_creator.cpp",
        "details/mtproto_dc_key_creator.h",
        "mtproto_dh_utils.cpp",
        "mtproto_dh_utils.h",
        "details/mtproto_binary.h",
        "details/mtproto_dump_to_text.cpp",
        "details/mtproto_dump_to_text.h",
        "details/mtproto_serialized_request.cpp",
        "details/mtproto_serialized_request.h",
        "dedicated_file_loader.cpp",
        "dedicated_file_loader.h",
    )
    listed = build_lists()

    for path in expected:
        assert (MTPROTO_DIR / path).exists()
        assert f"mtproto/{path}" in listed

    for path in removed:
        assert not (MTPROTO_DIR / path).exists()
        assert f"mtproto/{path}" not in listed

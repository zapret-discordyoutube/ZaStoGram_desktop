from pathlib import Path


SOURCE_DIR = Path(__file__).resolve().parents[1]
MTPROTO_DIR = SOURCE_DIR / "mtproto"
TESTS_DIR = SOURCE_DIR / "tests"


def read(path):
    assert path.exists(), f"missing expected source file: {path}"
    return path.read_text(encoding="utf-8")


def assert_no_tokens(path, tokens):
    text = read(path)

    for token in tokens:
        assert token not in text, f"{path.relative_to(SOURCE_DIR)} contains {token}"


def test_runtime_headers_do_not_include_proxy_layer_headers():
    for path in (
            MTPROTO_DIR / "runtime" / "connection_status.h",
            MTPROTO_DIR / "runtime" / "runtime_environment.h"):
        assert_no_tokens(path, (
            '#include "mtproto/proxy/',
        ))


def test_transport_details_do_not_include_proxy_socket_subclasses():
    assert_no_tokens(
        MTPROTO_DIR
            / "transport"
            / "details"
            / "mtproto_abstract_socket.cpp",
        (
            '#include "mtproto/proxy/mtproxy/tls_socket.h"',
            '#include "mtproto/proxy/wss/socket.h"',
            "std::make_unique<TlsSocket>",
            "std::make_unique<WssSocket>",
        ))


def test_existing_source_guards_do_not_lock_old_cycles():
    for path in (
            TESTS_DIR / "test_proxy_connection_status.py",):
        assert_no_tokens(path, (
            'assert \'#include "mtproto/proxy/status.h"\' in abstract_socket_h',
        ))


if __name__ == "__main__":
    test_runtime_headers_do_not_include_proxy_layer_headers()
    test_transport_details_do_not_include_proxy_socket_subclasses()
    test_existing_source_guards_do_not_lock_old_cycles()

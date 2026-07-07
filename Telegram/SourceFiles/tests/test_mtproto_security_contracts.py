from pathlib import Path


SOURCE_DIR = Path(__file__).resolve().parents[1]
AUTH_KEY_H = SOURCE_DIR / "mtproto" / "mtproto_auth_key.h"
AUTH_KEY_CPP = SOURCE_DIR / "mtproto" / "mtproto_auth_key.cpp"
DC_KEY_CREATOR_CPP = (
    SOURCE_DIR / "mtproto" / "details" / "mtproto_dc_key_creator.cpp")
SESSION_CPP = SOURCE_DIR / "mtproto" / "session.cpp"
DC_OPTIONS_CPP = SOURCE_DIR / "mtproto" / "mtproto_dc_options.cpp"
CONCURRENT_SENDER_CPP = SOURCE_DIR / "mtproto" / "mtproto_concurrent_sender.cpp"
SPECIAL_CONFIG_CPP = SOURCE_DIR / "mtproto" / "special_config_request.cpp"
SPECIAL_CONFIG_H = SOURCE_DIR / "mtproto" / "special_config_request.h"
RSA_PUBLIC_KEY_CPP = (
    SOURCE_DIR / "mtproto" / "details" / "mtproto_rsa_public_key.cpp")
WSS_SOCKET_CPP = SOURCE_DIR / "mtproto" / "proxy" / "wss" / "socket.cpp"
WSS_TEST = SOURCE_DIR / "tests" / "test_proxy_wss_default.py"


def test_auth_key_cleans_secret_and_compares_in_constant_time():
    header = AUTH_KEY_H.read_text(encoding="utf-8")
    source = AUTH_KEY_CPP.read_text(encoding="utf-8")
    equals_body = function_body(source, "bool AuthKey::equals(")
    destructor_body = function_body(source, "AuthKey::~AuthKey()")

    assert "~AuthKey();" in header
    assert "OPENSSL_cleanse(_key.data(), _key.size());" in destructor_body
    assert "CRYPTO_memcmp(" in equals_body
    assert "_key == other->_key" not in equals_body


def test_auth_key_handshake_keeps_secret_nonce_out_of_logs():
    source = DC_KEY_CREATOR_CPP.read_text(encoding="utf-8")

    assert "Logs::mb(&attempt->data.new_nonce" not in source
    assert "Logs::mb(attempt->data.new_nonce_buf.data()" not in source


def test_auth_key_handshake_uses_constant_time_secret_checks():
    source = DC_KEY_CREATOR_CPP.read_text(encoding="utf-8")

    assert "ConstantTimeEqual(" in source
    assert "CRYPTO_memcmp(" in source
    assert "bytes::compare(sha1Dec, sha1Buffer)" not in source
    assert "data.vnew_nonce_hash() != NonceDigest(" not in source
    assert "data.vnew_nonce_hash1() != NonceDigest(" not in source
    assert "data.vnew_nonce_hash2() != NonceDigest(" not in source
    assert "data.vnew_nonce_hash3() != NonceDigest(" not in source


def test_session_connection_init_compares_passed_options_to_snapshot():
    source = SESSION_CPP.read_text(encoding="utf-8")
    body = function_body(source, "void SessionData::notifyConnectionInited(")

    assert "_options" not in body
    assert "current.cloudLangCode == options.cloudLangCode" in body
    assert "current.systemLangCode == options.systemLangCode" in body
    assert "current.langPackName == options.langPackName" in body
    assert "current.proxy == options.proxy" in body


def test_dc_options_copy_constructor_reads_source_under_lock():
    source = DC_OPTIONS_CPP.read_text(encoding="utf-8")
    body = function_body(source, "DcOptions::DcOptions(const DcOptions &other)")

    assert "ReadLocker lock(&other);" in body
    assert "_data = other._data;" in body
    assert "_cdnDcIds = other._cdnDcIds;" in body
    assert "_publicKeys = other._publicKeys;" in body
    assert "_cdnPublicKeys = other._cdnPublicKeys;" in body


def test_sender_request_cancel_all_reserves_before_collecting_ids():
    source = CONCURRENT_SENDER_CPP.read_text(encoding="utf-8")
    body = function_body(source, "void ConcurrentSender::senderRequestCancelAll()")

    assert "auto list = std::vector<mtpRequestId>();" in body
    assert "list.reserve(_requests.size());" in body
    assert "std::vector<mtpRequestId>(_requests.size())" not in body


def test_special_config_has_no_unreachable_realtime_attempt():
    header = SPECIAL_CONFIG_H.read_text(encoding="utf-8")
    source = SPECIAL_CONFIG_CPP.read_text(encoding="utf-8")

    assert "Realtime" not in header
    assert "Type::Realtime" not in source
    assert "ParseRealtimeResponse" not in source


def test_rsa_public_decrypt_logs_decrypt_failures():
    source = RSA_PUBLIC_KEY_CPP.read_text(encoding="utf-8")
    body = function_body(source, "bytes::vector RSAPublicKey::Private::decrypt(")

    assert "RSA_public_decrypt failed" in body
    assert "RSA_public_encrypt failed" not in body


def test_wss_connect_to_host_declares_relay_contract():
    source = WSS_SOCKET_CPP.read_text(encoding="utf-8")
    test = WSS_TEST.read_text(encoding="utf-8")
    body = function_body(source, "void WssSocket::connectToHost(")

    assert "Q_UNUSED(address);" in body
    assert "Q_UNUSED(port);" in body
    assert "connectToRelayHost();" in body
    assert "MTProto-over-WSS always connects to the relay route" in body
    assert "Q_UNUSED(address);" in test


def function_body(text: str, signature: str) -> str:
    start = text.index(signature)
    brace = text.index(" {\n", start) + 1
    depth = 0
    for index in range(brace, len(text)):
        char = text[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return text[brace + 1:index]
    raise AssertionError(f"body not found for {signature}")

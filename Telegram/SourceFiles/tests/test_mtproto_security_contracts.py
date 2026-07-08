from pathlib import Path


SOURCE_DIR = Path(__file__).resolve().parents[1]
AUTH_KEY_H = SOURCE_DIR / "mtproto" / "auth" / "mtproto_auth_key.h"
AUTH_KEY_CPP = SOURCE_DIR / "mtproto" / "auth" / "mtproto_auth_key.cpp"
TYPE_UTILS_H = SOURCE_DIR / "mtproto" / "type_utils.h"
DH_UTILS_H = SOURCE_DIR / "mtproto" / "auth" / "mtproto_dh_utils.h"
DH_UTILS_CPP = SOURCE_DIR / "mtproto" / "auth" / "mtproto_dh_utils.cpp"
DC_KEY_CREATOR_CPP = (
    SOURCE_DIR / "mtproto" / "auth" / "mtproto_dc_key_creator.cpp")
DC_KEY_CRYPTO_H = (
    SOURCE_DIR / "mtproto" / "auth" / "mtproto_dc_key_crypto.h")
DC_KEY_CRYPTO_CPP = (
    SOURCE_DIR / "mtproto" / "auth" / "mtproto_dc_key_crypto.cpp")
TD_MTPROTO_CMAKE = SOURCE_DIR.parents[1] / "Telegram" / "cmake" / "td_mtproto.cmake"
CALLS_CALL_H = SOURCE_DIR / "calls" / "calls_call.h"
CALLS_CALL_CPP = SOURCE_DIR / "calls" / "calls_call.cpp"
SESSION_CPP = SOURCE_DIR / "mtproto" / "session" / "session.cpp"
DC_OPTIONS_CPP = SOURCE_DIR / "mtproto" / "config" / "mtproto_dc_options.cpp"
CONCURRENT_SENDER_CPP = (
    SOURCE_DIR / "mtproto" / "instance" / "mtproto_concurrent_sender.cpp")
SPECIAL_CONFIG_CPP = SOURCE_DIR / "mtproto" / "config" / "special_config_request.cpp"
SPECIAL_CONFIG_H = SOURCE_DIR / "mtproto" / "config" / "special_config_request.h"
RSA_PUBLIC_KEY_CPP = (
    SOURCE_DIR / "mtproto" / "details" / "mtproto_rsa_public_key.cpp")
WSS_SOCKET_CPP = SOURCE_DIR / "mtproto" / "proxy" / "wss" / "socket.cpp"
WSS_TEST = SOURCE_DIR / "tests" / "test_proxy_wss_default.py"
WINDOW_SESSION_CONTROLLER_CPP = (
    SOURCE_DIR / "window" / "window_session_controller.cpp")


def test_type_utils_declares_direct_scheme_dependency():
    header = TYPE_UTILS_H.read_text(encoding="utf-8")

    assert '#include "scheme.h"' in header


def test_window_session_controller_does_not_justify_calls_include_stale():
    source = WINDOW_SESSION_CONTROLLER_CPP.read_text(encoding="utf-8")

    assert '#include "calls/calls_instance.h" // Core::App().calls().inCall().' not in source


def test_auth_key_raw_byte_hatches_are_not_public_api():
    header = AUTH_KEY_H.read_text(encoding="utf-8")
    public_api = class_public_section(header, "class AuthKey")

    assert "partForMsgKey(" not in public_api
    assert "void write(QDataStream &to) const;" not in public_api
    assert "[[nodiscard]] bytes::const_span data() const;" not in public_api


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
    if DC_KEY_CRYPTO_CPP.exists():
        source += "\n" + DC_KEY_CRYPTO_CPP.read_text(encoding="utf-8")

    assert "ConstantTimeEqual(" in source
    assert "CRYPTO_memcmp(" in source
    assert "bytes::compare(sha1Dec, sha1Buffer)" not in source
    assert "data.vnew_nonce_hash() != NonceDigest(" not in source
    assert "data.vnew_nonce_hash1() != NonceDigest(" not in source
    assert "data.vnew_nonce_hash2() != NonceDigest(" not in source
    assert "data.vnew_nonce_hash3() != NonceDigest(" not in source


def test_dc_key_creator_crypto_helpers_are_split_and_registered():
    assert DC_KEY_CRYPTO_H.exists()
    assert DC_KEY_CRYPTO_CPP.exists()

    creator = DC_KEY_CREATOR_CPP.read_text(encoding="utf-8")
    crypto_header = DC_KEY_CRYPTO_H.read_text(encoding="utf-8")
    crypto_source = DC_KEY_CRYPTO_CPP.read_text(encoding="utf-8")
    cmake = TD_MTPROTO_CMAKE.read_text(encoding="utf-8")

    assert len(creator.splitlines()) <= 620
    assert '#include "mtproto/auth/mtproto_dc_key_crypto.h"' in creator
    assert "mtproto/auth/mtproto_dc_key_crypto.cpp" in cmake
    assert "mtproto/auth/mtproto_dc_key_crypto.h" in cmake
    assert "struct ParsedPQ" in crypto_header
    assert "[[nodiscard]] ParsedPQ FactorizePQ(" in crypto_header
    assert "[[nodiscard]] bytes::vector EncryptPQInnerRSA(" in crypto_header
    assert "[[nodiscard]] std::string EncryptClientDHInner(" in crypto_header
    assert "MTPint128 NonceDigest(" in crypto_header
    assert "CRYPTO_memcmp(" in crypto_source
    assert "IsGoodEncryptedInner(" not in creator
    assert "template <typename PQInnerData>" not in creator
    assert "FactorizeSmallPQ(" not in creator


def test_dc_key_crypto_includes_auth_key_for_raw_aes_helpers():
    source = DC_KEY_CRYPTO_CPP.read_text(encoding="utf-8")
    header = AUTH_KEY_H.read_text(encoding="utf-8")

    assert "aesIgeEncryptRaw(" in source
    assert "void aesIgeEncryptRaw(" in header
    assert '#include "mtproto/auth/mtproto_auth_key.h"' in source


def test_dh_intermediate_secret_bytes_are_raii_cleansed():
    header = DH_UTILS_H.read_text(encoding="utf-8")
    source = DH_UTILS_CPP.read_text(encoding="utf-8")
    destructor_body = function_body(source, "SecureBytes::~SecureBytes()")

    assert "class SecureBytes" in header
    assert "OPENSSL_cleanse(_data.data(), _data.size());" in destructor_body
    assert "void clear();" in header
    assert "SecureBytes randomPower;" in header
    assert "[[nodiscard]] SecureBytes CreateAuthKey(" in header
    assert "return SecureBytes(BigNum::ModExp(" in source


def test_dc_key_creator_cleans_ephemeral_dh_secret_copies():
    source = DC_KEY_CREATOR_CPP.read_text(encoding="utf-8")
    body = function_body(source, "void DcKeyCreator::dhClientParamsSend(")

    assert "auto randomSeed = SecureBytes(" in body
    assert "bytes::set_random(randomSeed.bytes());" in body
    assert "CreateModExp(" in body
    assert "randomSeed.bytes());" in body
    assert "g_b_data.randomPower.clear();" in body
    assert (
        "AuthKey::FillData(attempt->authKey, computedAuthKey.bytes());"
        in body)
    assert "computedAuthKey.clear();" in body
    assert "auto randomSeed = bytes::vector(" not in body


def test_call_key_exchange_cleans_dh_secret_copies():
    header = CALLS_CALL_H.read_text(encoding="utf-8")
    source = CALLS_CALL_CPP.read_text(encoding="utf-8")
    destructor_body = function_body(source, "Call::~Call()")

    assert "MTP::SecureBytes _randomPower;" in header
    assert "OPENSSL_cleanse(_authKey.data(), _authKey.size());" in destructor_body
    assert "MTP::AuthKey::FillData(_authKey, computedAuthKey.bytes());" in source
    assert "_randomPower.clear();" in source
    assert "computedAuthKey.clear();" in source
    assert "bytes::vector _randomPower;" not in header


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


def test_special_config_uses_system_txt_before_doh_fallback():
    header = SPECIAL_CONFIG_H.read_text(encoding="utf-8")
    source = SPECIAL_CONFIG_CPP.read_text(encoding="utf-8")
    constructor = function_body(
        source,
        "SpecialConfigRequest::SpecialConfigRequest(")

    assert "#include <QtNetwork/QDnsLookup>" in source
    assert "std::unique_ptr<QDnsLookup> _systemLookup;" in header
    assert "void startSystemTxtLookup();" in header
    assert "void startWebRequests();" in header
    assert "void systemTxtLookupFinished();" in header

    assert "startSystemTxtLookup();" in constructor
    assert "startWebRequests();" in constructor
    assert "if (_timeDoneCallback) {" in constructor
    assert "} else {" in constructor
    assert "systemTxtLookupFinished()" in source
    system_done = function_body(
        source,
        "void SpecialConfigRequest::systemTxtLookupFinished(")
    assert "if (!entries.empty()" in system_done
    assert "&& handleResponse(ConcatenateDnsTxtFields(entries)))" in system_done
    assert "startWebRequests();" in system_done

    assert "QDnsLookup::TXT" in source
    assert "DohProviders()" in source
    assert "BuildDnsQuery(_domainString, 16)" in source
    assert "application/dns-message" in source
    assert "bool handleResponse(const QByteArray &bytes);" in header


def test_special_config_has_no_firebase_or_google_fronting_sources():
    header = SPECIAL_CONFIG_H.read_text(encoding="utf-8")
    source = SPECIAL_CONFIG_CPP.read_text(encoding="utf-8")

    assert "RemoteConfig" not in header
    assert "FireStore" not in header
    assert "RemoteConfig" not in source
    assert "FireStore" not in source
    assert "Firestore" not in source
    assert "firebase" not in source.lower()
    assert "googleapis.com" not in source
    assert "kRemoteProject" not in source
    assert "kFireProject" not in source
    assert "kApiKey" not in source
    assert "kAppId" not in source
    assert "GenerateInstanceId" not in source
    assert "DnsDomains()" not in source
    assert 'setRawHeader("Host"' not in source


def test_special_config_uses_local_time_for_signed_config_freshness():
    source = SPECIAL_CONFIG_CPP.read_text(encoding="utf-8")
    request_finished = function_body(
        source,
        "void SpecialConfigRequest::requestFinished(")
    handle_response = function_body(
        source,
        "bool SpecialConfigRequest::handleResponse(")

    before_time_branch = request_finished.split("if (_timeDoneCallback) {")[0]

    assert "if (_timeDoneCallback) {" in request_finished
    assert "handleHeaderUnixtime(reply);" not in before_time_branch
    assert "base::unixtime::http_now()" not in handle_response
    assert "const auto now = base::unixtime::now();" in handle_response


def test_special_config_sets_transfer_timeout_before_sending():
    source = SPECIAL_CONFIG_CPP.read_text(encoding="utf-8")
    body = function_body(
        source,
        "void SpecialConfigRequest::performRequest(")

    timeout_pos = body.index("request.setTransferTimeout(")
    send_pos = body.index("payload.isEmpty()")

    assert "kRequestTransferTimeout" in source
    assert timeout_pos < send_pos


def test_special_config_loader_reset_is_queued_from_terminal_callback():
    source = (SOURCE_DIR / "mtproto" / "config" / "config_loader.cpp"
        ).read_text(encoding="utf-8")
    body = function_body(source, "void ConfigLoader::createSpecialLoader()")

    queued_pos = body.index("InvokeQueued(")
    reset_pos = body.index("_specialLoader = nullptr;")

    assert queued_pos < reset_pos


def test_rsa_public_decrypt_logs_decrypt_failures():
    source = RSA_PUBLIC_KEY_CPP.read_text(encoding="utf-8")
    body = function_body(source, "bytes::vector RSAPublicKey::Private::decrypt(")

    assert "RSA_public_decrypt failed" in body
    assert "RSA_public_encrypt failed" not in body


def test_special_config_decrypts_rsa_block_behind_validated_boundary():
    source = SPECIAL_CONFIG_CPP.read_text(encoding="utf-8")
    assert "[[nodiscard]] bytes::vector DecryptSimpleConfigBlock(" in source

    decrypt_body = function_body(
        source,
        "[[nodiscard]] bytes::vector DecryptSimpleConfigBlock(")
    simple_body = function_body(
        source,
        "bool SpecialConfigRequest::decryptSimpleConfig(")

    call = "auto decrypted = DecryptSimpleConfigBlock(bytes::make_span(decodedBytes));"
    call_pos = simple_body.index(call)
    subspan_pos = simple_body.index("decryptedBytes.subspan(", call_pos)

    assert "kSimpleConfigBlockSize" in source
    assert "auto publicKey = details::RSAPublicKey(bytes::make_span(kPublicKey));" in decrypt_body
    assert "auto decrypted = publicKey.decrypt(encrypted);" in decrypt_body
    assert "decrypted.size() != kSimpleConfigBlockSize" in decrypt_body
    assert "return {};" in decrypt_body
    assert "publicKey.decrypt(" not in simple_body
    assert "decrypted.size()" not in simple_body
    assert call_pos < subspan_pos


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


def class_public_section(text: str, signature: str) -> str:
    start = text.index(signature)
    public = text.index("public:", start)
    private = text.index("private:", public)
    return text[public:private]


if __name__ == "__main__":
    test_auth_key_handshake_keeps_secret_nonce_out_of_logs()
    test_auth_key_handshake_uses_constant_time_secret_checks()
    test_dc_key_creator_crypto_helpers_are_split_and_registered()
    test_dc_key_creator_cleans_ephemeral_dh_secret_copies()

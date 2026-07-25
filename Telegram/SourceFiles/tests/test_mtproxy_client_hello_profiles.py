import hashlib
import json
import re
from pathlib import Path


SOURCE_DIR = Path(__file__).resolve().parents[1]
ROOT_DIR = SOURCE_DIR.parents[1]
MTPROXY_DIR = SOURCE_DIR / "mtproto" / "proxy" / "mtproxy"
CLIENT_HELLO_BUILDER_CPP = MTPROXY_DIR / "client_hello_builder.cpp"
CLIENT_HELLO_BUILDER_H = MTPROXY_DIR / "client_hello_builder.h"
CLIENT_HELLO_CONSTANTS_H = MTPROXY_DIR / "client_hello_constants.h"
CLIENT_HELLO_FACTS_CPP = MTPROXY_DIR / "client_hello_facts.cpp"
CLIENT_HELLO_FACTS_H = MTPROXY_DIR / "client_hello_facts.h"
CLIENT_HELLO_FRAGMENTATION_CPP = MTPROXY_DIR / "client_hello_fragmentation.cpp"
CLIENT_HELLO_RULES_CPP = MTPROXY_DIR / "client_hello_rules.cpp"
CPP_SMOKE = SOURCE_DIR / "tests" / "test_mtproxy_client_hello.cpp"
FIXTURE = SOURCE_DIR / "tests" / "fixtures" / "mtproxy" / "chrome_modern_client_hello.json"
TLS_SOCKET_HANDSHAKE_CPP = MTPROXY_DIR / "tls_socket_handshake.cpp"
TLS_SOCKET_RECORDS_CPP = MTPROXY_DIR / "tls_socket_records.cpp"


def test_chrome_modern_capture_fixture_is_ja4_consistent():
    fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
    parsed = parse_client_hello(bytes.fromhex(fixture["client_hello_hex"]))

    assert fixture["profile"] == "ChromeModern"
    assert fixture["validation"] == "validated"
    assert fixture["source"] == "local_chrome_headless_capture"
    assert fixture["ja4"] == parsed["ja4"]
    assert fixture["ja4"] == "t13d1516h2_8daaf6152771_d8a2da3f94cd"
    assert fixture["chrome_version"].startswith("Google Chrome ")


def test_profile_metadata_marks_only_capture_backed_profile_validated():
    header = (MTPROXY_DIR / "client_hello_profile.h").read_text(encoding="utf-8")
    source = (MTPROXY_DIR / "client_hello_profile.cpp").read_text(encoding="utf-8")

    assert "enum class ClientHelloProfileValidation" in header
    assert "Claimed" in header
    assert "Validated" in header
    assert "ClientHelloProfileInfo" in header
    assert "DefaultClientHelloProfile()" in header
    assert "ClientHelloProfile(" in header
    assert "ProxyTlsProfile profile" in header
    assert "ProxyTlsProfile::ChromeModern" in source
    assert "ClientHelloProfileValidation::Validated" in initializer_after(
        source,
        "ProxyTlsProfile::ChromeModern")
    for profile in ("AndroidChrome", "Firefox", "FirefoxAndroid", "Yandex", "AndroidOkHttp"):
        assert "ClientHelloProfileValidation::Claimed" in initializer_after(
            source,
            f"ProxyTlsProfile::{profile}")
    assert "t13d1516h2_8daaf6152771_d8a2da3f94cd" in source


def test_client_hello_builder_owns_templates_and_fragmentation_plan():
    builder_header = CLIENT_HELLO_BUILDER_H.read_text(encoding="utf-8")
    builder_source = CLIENT_HELLO_BUILDER_CPP.read_text(encoding="utf-8")
    rules_source = CLIENT_HELLO_RULES_CPP.read_text(encoding="utf-8")
    fragmentation_source = CLIENT_HELLO_FRAGMENTATION_CPP.read_text(
        encoding="utf-8")
    tls_socket = TLS_SOCKET_HANDSHAKE_CPP.read_text(encoding="utf-8")

    assert "struct ClientHelloFragmentationPlan" in builder_header
    assert "secondDelay" in builder_header
    assert "struct ClientHelloGenerationOptions" in builder_header
    assert "bool deterministic = false;" in builder_header
    assert "ClientHelloGenerationOptions options = {}" in builder_header
    assert "PrepareClientHelloFragmentation(" in builder_header
    assert "MTPTlsClientHello PrepareClientHelloRules(" in builder_header
    assert "class Generator" in builder_source
    assert "ClientHello PrepareClientHello(" in builder_source
    assert "MTPTlsClientHello PrepareClientHelloRules(" not in builder_source
    assert "PrepareClientHelloFragmentation(" not in builder_source
    assert "MTPTlsClientHello PrepareClientHelloRules(" in rules_source
    assert "PrepareClientHelloRulesInternal(" in rules_source
    assert "PrepareClientHelloFragmentation(" in fragmentation_source
    assert "_options.deterministic" in builder_source
    assert '#include "mtproto/proxy/mtproxy/client_hello_builder.h"' in tls_socket
    assert '#include "mtproto/proxy/mtproxy/client_hello_profile.h"' in rules_source
    assert "DefaultClientHelloProfile()" in rules_source
    assert "MTPTlsClientHello PrepareClientHelloRules(" not in tls_socket
    assert "class Generator" not in tls_socket
    assert "PrepareClientHelloFragmentation(" in tls_socket


def test_client_hello_uses_shared_constants_and_typed_absence():
    constants = CLIENT_HELLO_CONSTANTS_H.read_text(encoding="utf-8")
    builder = CLIENT_HELLO_BUILDER_CPP.read_text(encoding="utf-8")
    facts = CLIENT_HELLO_FACTS_CPP.read_text(encoding="utf-8")
    fragmentation = CLIENT_HELLO_FRAGMENTATION_CPP.read_text(encoding="utf-8")
    tls_handshake = TLS_SOCKET_HANDSHAKE_CPP.read_text(encoding="utf-8")
    tls_records = TLS_SOCKET_RECORDS_CPP.read_text(encoding="utf-8")

    for name in (
        "kClientHelloGreaseCount",
        "kClientHelloLimit",
        "kClientHelloDigestLength",
        "kTlsLengthFieldSize",
        "kClientHelloFragmentDelayMin",
        "kClientHelloFragmentDelayMax",
    ):
        assert name in constants
        assert name in builder + fragmentation + tls_handshake + tls_records

    for source in (builder, facts, fragmentation, tls_handshake, tls_records):
        assert "constexpr auto kHelloDigestLength" not in source
        assert "constexpr auto kLengthSize" not in source
        assert "constexpr auto kClientHelloFragmentDelayMin" not in source
        assert "constexpr auto kClientHelloFragmentDelayMax" not in source
        assert "return -1;" not in source
        assert "= -1" not in source

    assert "std::optional<int> _digestPosition;" in builder
    assert "std::optional<int> ClientHelloRead16(" in facts
    assert "std::optional<int> ClientHelloRead24(" in facts
    assert "std::optional<int> ClientHelloRead16(" in fragmentation
    assert "std::optional<int> ClientHelloRead24(" in fragmentation


def test_prepare_client_hello_has_external_linkage():
    source = CLIENT_HELLO_BUILDER_CPP.read_text(encoding="utf-8")
    prepare = source.index("ClientHello PrepareClientHello(")
    previous_open = source.rfind("namespace {", 0, prepare)
    previous_close = source.rfind("} // namespace", 0, prepare)

    assert previous_open >= 0
    assert previous_close > previous_open


def test_client_hello_facts_module_parses_and_computes_ja4():
    header = CLIENT_HELLO_FACTS_H.read_text(encoding="utf-8")
    source = CLIENT_HELLO_FACTS_CPP.read_text(encoding="utf-8")

    assert "struct ClientHelloFacts" in header
    assert "ComputeClientHelloFacts(" in header
    assert "const QByteArray &data" in header
    assert "ComputeClientHelloJa4(const ClientHelloFacts &facts)" in header
    assert "ComputeClientHelloJa4(const QByteArray &data)" in header
    assert "IsClientHelloGrease(uint16 value)" in header
    assert "openssl::Sha256" in source
    assert "extension != 0x0000" in source
    assert "extension != 0x0010" in source
    assert "signatureAlgorithms" in source
    assert "supportedVersions" in source
    assert "begin(values)" not in source
    assert "end(values)" not in source
    assert "begin(cleanVersions)" not in source
    assert "end(cleanVersions)" not in source


def test_chrome_modern_builder_template_matches_capture_ja4_facts():
    fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
    fixture_facts = parse_client_hello(bytes.fromhex(fixture["client_hello_hex"]))
    builder_facts = parse_client_hello(render_chrome_modern_builder_hello())

    assert builder_facts["ja4"] == profile_expected_ja4("ChromeModern")
    assert builder_facts["ja4"] == fixture["ja4"]
    assert builder_facts["ja4"] == fixture_facts["ja4"]
    for key in (
        "cipher_suites",
        "extensions",
        "signature_algorithms",
        "supported_versions",
        "first_alpn",
    ):
        assert builder_facts[key] == fixture_facts[key]


def test_chrome_modern_builder_matches_capture_extension_payloads():
    fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
    fixture_extensions = client_hello_extensions(
        bytes.fromhex(fixture["client_hello_hex"]))
    builder_extensions = client_hello_extensions(
        render_chrome_modern_builder_hello())

    for extension in (
        0x0005,
        0x000B,
        0x000D,
        0x0010,
        0x0012,
        0x0017,
        0x001B,
        0x002D,
        0x44CD,
        0xFF01,
    ):
        assert builder_extensions[extension] == fixture_extensions[extension]


def test_new_client_hello_sources_are_registered_for_build():
    cmake = (ROOT_DIR / "Telegram" / "CMakeLists.txt").read_text(encoding="utf-8")

    for path in (
        "mtproto/proxy/mtproxy/client_hello_builder.cpp",
        "mtproto/proxy/mtproxy/client_hello_builder.h",
        "mtproto/proxy/mtproxy/client_hello_constants.h",
        "mtproto/proxy/mtproxy/client_hello_facts.cpp",
        "mtproto/proxy/mtproxy/client_hello_facts.h",
        "mtproto/proxy/mtproxy/client_hello_fragmentation.cpp",
        "mtproto/proxy/mtproxy/client_hello_profile.cpp",
        "mtproto/proxy/mtproxy/client_hello_profile.h",
        "mtproto/proxy/mtproxy/client_hello_rules.cpp",
    ):
        assert path in cmake


def test_cpp_smoke_invokes_deterministic_builder_and_ja4_facts():
    cmake = (ROOT_DIR / "Telegram" / "cmake" / "tests.cmake").read_text(encoding="utf-8")
    source = CPP_SMOKE.read_text(encoding="utf-8")

    assert "add_executable(test_mtproxy_client_hello" in cmake
    assert "tests/test_mtproxy_client_hello.cpp" in cmake
    for path in (
        "mtproto/proxy/mtproxy/client_hello_builder.cpp",
        "mtproto/proxy/mtproxy/client_hello_constants.h",
        "mtproto/proxy/mtproxy/client_hello_facts.cpp",
        "mtproto/proxy/mtproxy/client_hello_fragmentation.cpp",
        "mtproto/proxy/mtproxy/client_hello_profile.cpp",
        "mtproto/proxy/mtproxy/client_hello_rules.cpp",
    ):
        assert path in cmake
    assert "tdesktop::td_scheme" in cmake
    assert "desktop-app::external_openssl" in cmake
    assert "PrepareClientHelloRules(" in source
    assert "ProxyTlsProfile::ChromeModern" in source
    assert "options.deterministic = true;" in source
    assert "PrepareClientHello(" in source
    assert "ComputeClientHelloFacts(hello.data)" in source
    assert "ComputeClientHelloJa4(*facts)" in source
    assert "ClientHelloProfile(" in source
    assert "expectedJa4" in source


def parse_client_hello(data: bytes) -> dict:
    if len(data) < 5 or data[0] != 0x16:
        raise AssertionError("fixture must start with a TLS handshake record")
    position = 5
    if data[position] != 0x01:
        raise AssertionError("fixture must contain a ClientHello")
    position += 4
    legacy_version = read16(data, position)
    position += 34
    session_id_length = data[position]
    position += 1 + session_id_length
    cipher_suites_length = read16(data, position)
    position += 2
    ciphers = [
        read16(data, offset)
        for offset in range(position, position + cipher_suites_length, 2)
    ]
    position += cipher_suites_length
    compression_methods_length = data[position]
    position += 1 + compression_methods_length
    extensions_length = read16(data, position)
    position += 2
    extensions_end = position + extensions_length
    extensions = []
    signature_algorithms = []
    supported_versions = []
    first_alpn = b""
    while position + 4 <= extensions_end:
        extension = read16(data, position)
        length = read16(data, position + 2)
        value = data[position + 4:position + 4 + length]
        position += 4 + length
        extensions.append(extension)
        if extension == 0x002B and value:
            supported_versions = [
                read16(value, offset)
                for offset in range(1, 1 + value[0], 2)
                if offset + 2 <= len(value)
            ]
        elif extension == 0x000D and len(value) >= 2:
            signature_algorithms = [
                read16(value, offset)
                for offset in range(2, 2 + read16(value, 0), 2)
                if offset + 2 <= len(value)
            ]
        elif extension == 0x0010 and len(value) >= 3:
            first_length = value[2]
            first_alpn = value[3:3 + first_length]
    clean_ciphers = [value for value in ciphers if not is_grease(value)]
    clean_extensions = [value for value in extensions if not is_grease(value)]
    clean_versions = [value for value in supported_versions if not is_grease(value)]
    version = max(clean_versions) if clean_versions else legacy_version
    ja4_a = (
        "t"
        + tls_version_code(version)
        + ("d" if 0x0000 in clean_extensions else "i")
        + f"{min(len(clean_ciphers), 99):02d}"
        + f"{min(len(clean_extensions), 99):02d}"
        + alpn_code(first_alpn)
    )
    cipher_hash_input = ",".join(sorted(f"{value:04x}" for value in clean_ciphers))
    extension_hash_input = ",".join(sorted(
        f"{value:04x}"
        for value in clean_extensions
        if value not in (0x0000, 0x0010)
    ))
    signature_input = ",".join(
        f"{value:04x}"
        for value in signature_algorithms
        if not is_grease(value)
    )
    if signature_input:
        extension_hash_input += "_" + signature_input
    return {
        "ja4": "_".join((
            ja4_a,
            sha12(cipher_hash_input),
            sha12(extension_hash_input),
        )),
        "cipher_suites": sorted(f"{value:04x}" for value in clean_ciphers),
        "extensions": sorted(f"{value:04x}" for value in clean_extensions),
        "signature_algorithms": [
            f"{value:04x}" for value in signature_algorithms if not is_grease(value)
        ],
        "supported_versions": sorted(f"{value:04x}" for value in clean_versions),
        "first_alpn": first_alpn.decode("ascii", errors="replace"),
    }


def client_hello_extensions(data: bytes) -> dict[int, bytes]:
    if len(data) < 5 or data[0] != 0x16:
        raise AssertionError("ClientHello must start with a TLS handshake record")
    position = 5
    if data[position] != 0x01:
        raise AssertionError("ClientHello record must contain a ClientHello")
    position += 4
    position += 2 + 32
    session_id_length = data[position]
    position += 1 + session_id_length
    cipher_suites_length = read16(data, position)
    position += 2 + cipher_suites_length
    compression_methods_length = data[position]
    position += 1 + compression_methods_length
    extensions_length = read16(data, position)
    position += 2
    extensions_end = position + extensions_length
    result = {}
    while position + 4 <= extensions_end:
        extension = read16(data, position)
        length = read16(data, position + 2)
        value = data[position + 4:position + 4 + length]
        position += 4 + length
        if not is_grease(extension):
            result[extension] = value
    return result


def profile_expected_ja4(profile: str) -> str:
    source = (MTPROXY_DIR / "client_hello_profile.cpp").read_text(
        encoding="utf-8")
    initializer = initializer_after(source, f"ProxyTlsProfile::{profile}")
    match = re.search(r'\.expectedJa4 = "([^"]+)"', initializer)
    if not match:
        raise AssertionError(f"expectedJa4 not found for {profile}")
    return match.group(1)


def read16(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset:offset + 2], "big")


def is_grease(value: int) -> bool:
    return (
        (value & 0x0F0F) == 0x0A0A
        and ((value >> 8) & 0xFF) == (value & 0xFF)
    )


def tls_version_code(value: int) -> str:
    return {
        0x0304: "13",
        0x0303: "12",
        0x0302: "11",
        0x0301: "10",
        0x0300: "s3",
        0x0002: "s2",
        0xFEFF: "d1",
        0xFEFD: "d2",
        0xFEFC: "d3",
    }.get(value, "00")


def alpn_code(value: bytes) -> str:
    if not value:
        return "00"
    first = value[0]
    last = value[-1]
    if is_alnum(first) and is_alnum(last):
        return chr(first) + chr(last)
    as_hex = value.hex()
    return as_hex[0] + as_hex[-1]


def is_alnum(value: int) -> bool:
    return (
        ord("0") <= value <= ord("9")
        or ord("A") <= value <= ord("Z")
        or ord("a") <= value <= ord("z")
    )


def sha12(value: str) -> str:
    if not value:
        return "000000000000"
    return hashlib.sha256(value.encode()).hexdigest()[:12]


def block_after(text: str, marker: str) -> str:
    start = text.index(marker)
    brace = text.index("{", start)
    depth = 0
    for index in range(brace, len(text)):
        char = text[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return text[brace + 1:index]
    raise AssertionError("block not found")


def function_body(text: str, signature: str) -> str:
    start = text.index(signature)
    brace = text.index(" {\n", start) + 1
    return body_from_brace(text, brace)


def body_from_brace(text: str, brace: int) -> str:
    depth = 0
    for index in range(brace, len(text)):
        char = text[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return text[brace + 1:index]
    raise AssertionError("body not found")


def initializer_after(text: str, marker: str) -> str:
    start = text.index(marker)
    end = text.index("\n\t},", start)
    return text[start:end]


def render_chrome_modern_builder_hello() -> bytes:
    source = CLIENT_HELLO_RULES_CPP.read_text(encoding="utf-8")
    body = block_after(source, "case ProxyTlsProfile::ChromeModern: {")
    return render_builder_scope(body, b"ja4-capture.test")


def render_builder_scope(body: str, domain: bytes) -> bytes:
    root = bytearray()
    stack = [root]
    permutations = []
    current_permutation = None
    for statement in cpp_builder_statements(body):
        target = stack[-1]
        if statement.startswith("S("):
            target.extend(cpp_string_bytes(statement))
        elif statement.startswith("Z(") or statement.startswith("R("):
            target.extend(b"\x00" * cpp_int_argument(statement))
        elif statement.startswith("G("):
            seed = cpp_int_argument(statement)
            target.extend(bytes([(seed << 4) + 0x0A]) * 2)
        elif statement == "D();":
            target.extend(domain)
        elif statement == "K();":
            target.extend(b"\x00" * 32)
        elif statement == "M();":
            target.extend(b"\x00" * (384 * 3 + 32))
        elif statement == "E();":
            target.extend(b"\x00" * 144)
        elif statement == "P();":
            pass
        elif statement.startswith("OpenScope"):
            stack.append(bytearray())
        elif statement.startswith("CloseScope"):
            content = stack.pop()
            stack[-1].extend(len(content).to_bytes(2, "big"))
            stack[-1].extend(content)
        elif statement.startswith("OpenPermutation"):
            current_permutation = []
            permutations.append(current_permutation)
        elif statement.startswith("StartPermutationElement"):
            stack.append(bytearray())
        elif statement.startswith("ClosePermutation"):
            for element in permutations.pop():
                stack[-1].extend(element)
            current_permutation = permutations[-1] if permutations else None
        elif statement == "}":
            if current_permutation is not None and stack[-1] is not root:
                current_permutation.append(bytes(stack.pop()))
        elif statement == "break;":
            break
    if len(stack) != 1:
        raise AssertionError("unterminated builder scope")
    return bytes(root)


def cpp_builder_statements(body: str) -> list[str]:
    statements = []
    lines = iter(body.splitlines())
    for raw in lines:
        stripped = raw.strip()
        if not stripped:
            continue
        if stripped.startswith("} ClosePermutation"):
            statements.append("ClosePermutation();")
            continue
        if stripped.startswith("S("):
            parts = [stripped]
            while ");" not in parts[-1]:
                parts.append(next(lines).strip())
            statements.append("\n".join(parts))
        elif stripped.startswith((
            "Z(", "R(", "G(", "D(", "K(", "M(", "E(", "P(",
            "OpenScope", "CloseScope", "OpenPermutation",
            "ClosePermutation", "StartPermutationElement",
        )):
            statements.append(stripped)
        elif stripped == "}" or stripped == "break;":
            statements.append(stripped)
    return statements


def cpp_string_bytes(statement: str) -> bytes:
    result = bytearray()
    for fragment in re.findall(r'"((?:\\.|[^"\\])*)"', statement):
        result.extend(bytes(fragment, "utf-8").decode("unicode_escape").encode("latin1"))
    return bytes(result)


def cpp_int_argument(statement: str) -> int:
    match = re.search(r"\((\\d+)\)", statement)
    if not match:
        match = re.search(r"\((\d+)\)", statement)
    if not match:
        raise AssertionError(f"integer argument not found: {statement}")
    return int(match.group(1))


if __name__ == "__main__":
    test_chrome_modern_capture_fixture_is_ja4_consistent()
    test_profile_metadata_marks_only_capture_backed_profile_validated()
    test_client_hello_builder_owns_templates_and_fragmentation_plan()
    test_client_hello_uses_shared_constants_and_typed_absence()
    test_client_hello_facts_module_parses_and_computes_ja4()
    test_chrome_modern_builder_template_matches_capture_ja4_facts()
    test_chrome_modern_builder_matches_capture_extension_payloads()
    test_new_client_hello_sources_are_registered_for_build()
    test_cpp_smoke_invokes_deterministic_builder_and_ja4_facts()

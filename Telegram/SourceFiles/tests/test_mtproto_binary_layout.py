import re
from pathlib import Path
from session_private_sources import read_session_private_sources


SOURCE_DIR = Path(__file__).resolve().parents[1]
ROOT = SOURCE_DIR.parents[1]
MTPROTO_DIR = SOURCE_DIR / "mtproto"
BINARY_H = MTPROTO_DIR / "details" / "mtproto_binary.h"
TD_MTPROTO_CMAKE = ROOT / "Telegram" / "cmake" / "td_mtproto.cmake"
SESSION_CPP = MTPROTO_DIR / "session_private.cpp"


def read(path):
    assert path.exists(), f"missing expected source file: {path}"
    return path.read_text(encoding="utf-8")


def mtproto_sources():
    for path in MTPROTO_DIR.rglob("*"):
        if path.suffix in {".cpp", ".h"}:
            yield path


def sanitized_source(path):
    return [re.sub(r"//.*", "", line) for line in read(path).splitlines()]


def raw_context(lines, index):
    first = max(0, index - 3)
    last = min(len(lines), index + 4)
    return " ".join(line.strip() for line in lines[first:last])


def is_allowed_bridge_cast(line, context):
    bridge_cast_targets = (
        "reinterpret_cast<const char*>",
        "reinterpret_cast<char*>",
        "reinterpret_cast<const uchar*>",
        "reinterpret_cast<uchar*>",
        "reinterpret_cast<const unsigned char*>",
        "reinterpret_cast<unsigned char*>",
        "reinterpret_cast<unsigned char *>",
        "reinterpret_cast<Bytef*>",
        "(Bytef*)",
        "(QObject*)",
        "(EVP_PKEY*)",
    )
    bridge_apis = (
        "QByteArray(",
        "QByteArray::fromRawData(",
        "QString::fromLatin1(",
        ".readRawData(",
        ".writeRawData(",
        ".read(",
        ".write(",
        ".append(",
        "crl::guard(",
        "AES_",
        "CRYPTO_",
        "RSA_",
        "BN_",
        "EVP_",
        "z_stream",
        "stream.next_in",
        "stream.next_out",
        "inflateInit2(",
        "inflate(",
    )
    return (
        any(target in line for target in bridge_cast_targets)
        and any(api in context for api in bridge_apis)
    )


def test_binary_layout_helper_is_mtproto_local_and_registered():
    header = read(BINARY_H)
    cmake = read(TD_MTPROTO_CMAKE)

    assert "namespace MTP::details::binary" in header
    for symbol in (
            "Read(",
            "Write(",
            "ReadAt(",
            "WriteAt(",
            "AsBytes(",
            "Copy(",
            "AppendBytes(",
            "AppendPrimes("):
        assert symbol in header
    assert '#include "base/bytes.h"' in header
    assert "mtproto/details/mtproto_binary.h" in cmake


def test_protocol_layout_uses_binary_helpers_not_raw_typed_aliasing():
    allowed_files = {
        BINARY_H,
    }
    raw_operation_patterns = (
        re.compile(r"reinterpret_cast\s*<"),
        re.compile(r"\(\s*(?:const\s+)?[A-Za-z_:<>0-9]+\s*\*\s*\)"),
        re.compile(r"\bmemcpy\s*\("),
    )
    typed_layout_patterns = (
        re.compile(r"\*\s*reinterpret_cast\s*<"),
        re.compile(r"reinterpret_cast\s*<\s*(?:const\s+)?(?:mtp|MTP|uint|int)\w+\s*\*"),
        re.compile(r"\(\s*(?:const\s+)?(?:mtp|MTP|uint|int)\w+\s*\*\s*\)"),
        re.compile(r"\bmemcpy\s*\("),
    )
    offenders = []

    for path in mtproto_sources():
        if path in allowed_files:
            continue
        lines = sanitized_source(path)
        for index, line in enumerate(lines):
            if "::*)" in line:
                continue
            if not any(pattern.search(line) for pattern in raw_operation_patterns):
                continue
            context = raw_context(lines, index)
            if any(pattern.search(line) for pattern in typed_layout_patterns):
                offenders.append(
                    f"{path.relative_to(ROOT)}:{index + 1}: {line.strip()}")
            elif not is_allowed_bridge_cast(line, context):
                offenders.append(
                    f"{path.relative_to(ROOT)}:{index + 1}: {line.strip()}")

    assert not offenders, "\n".join(offenders)


def test_session_container_layout_has_named_operations():
    source = read_session_private_sources()

    assert "//Assert(!haveSent.contains(msgId))" not in source
    for token in (
            "constData() + 4",
            "constData() + 8",
            "+ 3 * sizeof(mtpPrime)",
            "7 * sizeof(mtpPrime)",
            "reqNeedsLayer + 4",
            "reqNeedsLayer + 3"):
        assert token not in source
    for symbol in (
            "AppendContainerMessage(",
            "AppendInvokeAfter(",
            "AppendInvokeWithLayer(",
            "RegisterSentRequest("):
        assert symbol in source

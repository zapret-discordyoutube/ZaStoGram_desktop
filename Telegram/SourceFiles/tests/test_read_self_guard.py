#!/usr/bin/env python3

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "SourceFiles" / "storage" / "storage_account.cpp"


def read_self_body() -> str:
    text = SOURCE.read_text(encoding="utf-8")
    marker = "void Account::readSelf("
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
    raise AssertionError("Account::readSelf body was not found")


def main() -> None:
    body = read_self_body()
    read_peer = body.index("Serialize::readPeer(")
    guard = body[:read_peer]

    required = [
        "peerIdSerialized",
        "DeserializePeerId(peerIdSerialized)",
        "session->userPeerId()",
    ]
    missing = [item for item in required if item not in guard]
    if missing:
        raise AssertionError(
            "Account::readSelf must validate the stored self peer id "
            f"before Serialize::readPeer(); missing: {', '.join(missing)}")


if __name__ == "__main__":
    main()

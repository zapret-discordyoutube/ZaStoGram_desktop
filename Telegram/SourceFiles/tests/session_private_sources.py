from pathlib import Path


SOURCE_DIR = Path(__file__).resolve().parents[1]
MTPROTO_DIR = SOURCE_DIR / "mtproto"
SESSION_PRIVATE_DIR = MTPROTO_DIR / "session" / "private"

SESSION_PRIVATE_SOURCES = (
    SESSION_PRIVATE_DIR / "session_private.cpp",
    SESSION_PRIVATE_DIR / "transport.cpp",
    SESSION_PRIVATE_DIR / "message_handler.cpp",
    SESSION_PRIVATE_DIR / "connection.cpp",
    SESSION_PRIVATE_DIR / "send.cpp",
    SESSION_PRIVATE_DIR / "receive.cpp",
    SESSION_PRIVATE_DIR / "auth.cpp",
)


def read_session_private_sources():
    for path in SESSION_PRIVATE_SOURCES:
        assert path.exists(), f"missing expected source file: {path}"
    return "\n".join(path.read_text(encoding="utf-8")
        for path in SESSION_PRIVATE_SOURCES)

from pathlib import Path
from session_private_sources import SESSION_PRIVATE_SOURCES


SOURCE_DIR = Path(__file__).resolve().parents[1]
SESSION_H = SOURCE_DIR / "mtproto" / "session" / "session.h"
SESSION_CPP = SOURCE_DIR / "mtproto" / "session" / "session.cpp"
SEND_CPP = SOURCE_DIR / "mtproto" / "session" / "private" / "send.cpp"
RECEIVE_CPP = SOURCE_DIR / "mtproto" / "session" / "private" / "receive.cpp"


def read(path):
    assert path.exists(), f"missing expected source file: {path}"
    return path.read_text(encoding="utf-8")


def function_body(source, signature):
    start = source.index(signature)
    brace = source.index("{", start)
    depth = 0
    for index in range(brace, len(source)):
        char = source[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return source[brace + 1:index]
    raise AssertionError(f"function body not found: {signature}")


def private_sources():
    return "\n".join(read(path) for path in SESSION_PRIVATE_SOURCES)


def test_session_data_owns_cross_queue_transfer_api():
    header = read(SESSION_H)
    source = read(SESSION_CPP)

    for symbol in (
            "struct ToSendBatch",
            "struct SentRequest",
            "takeToSendBatch(",
            "takeSentRequest(",
            "takeAllSentRequests(",
            "takeToSendRequest(",
            "enqueueToSend(",
            "enqueueResentRequest(",
            "removeToSend(",
            "removeSent(",
            "hasToSend("):
        assert symbol in header

    for method in (
            "SessionData::takeToSendBatch(",
            "SessionData::takeSentRequest(",
            "SessionData::takeAllSentRequests(",
            "SessionData::takeToSendRequest(",
            "SessionData::enqueueToSend(",
            "SessionData::enqueueResentRequest(",
            "SessionData::removeToSend(",
            "SessionData::removeSent(",
            "SessionData::hasToSend("):
        assert method in source


def test_session_private_no_longer_reaches_into_to_send_queue():
    sources = private_sources()

    assert "toSendMutex()" not in sources
    assert "toSendMap()" not in sources


def test_cross_queue_paths_do_not_depend_on_manual_unlocks():
    send = read(SEND_CPP)
    receive = read(RECEIVE_CPP)
    bodies = {
        "tryToSend": function_body(send, "void SessionPrivate::tryToSend("),
        "requestsAcked": function_body(
            receive,
            "void SessionMessageHandler::requestsAcked("),
        "resend": function_body(receive, "void SessionMessageHandler::resend("),
        "resendAll": function_body(
            receive,
            "void SessionMessageHandler::resendAll("),
    }

    assert "takeToSendBatch(" in bodies["tryToSend"]
    assert "takeToSendRequest(" in bodies["requestsAcked"]
    assert "takeSentRequest(" in bodies["resend"]
    assert "takeAllSentRequests(" in bodies["resendAll"]

    for name, body in bodies.items():
        assert ".unlock()" not in body, name

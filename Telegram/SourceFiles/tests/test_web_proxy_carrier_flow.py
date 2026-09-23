from pathlib import Path


SOURCE_DIR = Path(__file__).resolve().parents[1]
WEB_DIR = SOURCE_DIR / "mtproto" / "web_proxy"
TRANSPORT_CPP = WEB_DIR / "web_proxy_transport.cpp"
FLOW_H = WEB_DIR / "web_proxy_flow.h"
SOCKET_CPP = SOURCE_DIR / "mtproto" / "details" / "mtproto_web_proxy_socket.cpp"
SOCKET_FACTORY_CPP = SOURCE_DIR / "mtproto" / "proxy" / "socket_factory.cpp"
CONNECTION_CPP = (
    SOURCE_DIR / "mtproto" / "session" / "private" / "connection.cpp")
SESSION_TRANSPORT_CPP = (
    SOURCE_DIR / "mtproto" / "session" / "private" / "transport.cpp")
FILE_UPLOAD_CPP = SOURCE_DIR / "storage" / "file_upload.cpp"
DOWNLOAD_MANAGER_CPP = SOURCE_DIR / "storage" / "download_manager_mtproto.cpp"
TESTS_CMAKE = SOURCE_DIR.parent / "cmake" / "tests.cmake"


def read(path):
    assert path.exists(), f"missing expected source file: {path}"
    return path.read_text(encoding="utf-8")


def function_body(source, signature):
    start = source.index(signature)
    brace = source.index("{", start)
    depth = 0
    for i in range(brace, len(source)):
        if source[i] == "{":
            depth += 1
        elif source[i] == "}":
            depth -= 1
            if depth == 0:
                return source[brace:i + 1]
    raise AssertionError(f"function body not found: {signature}")


def test_streams_are_classified_by_session_use():
    factory = read(SOCKET_FACTORY_CPP)
    socket = read(SOCKET_CPP)
    # The class comes from what the session is for (main, media, upload),
    # which is what decides uplink priority and downlink credit.
    assert "mtproxyAttempt.use);" in factory
    classify = function_body(socket, "WebProxy::StreamClass WebProxySocket::ClassFor(")
    assert "case ProxyConnectionUse::Media:" in classify
    assert "return WebProxy::StreamClass::Download;" in classify
    assert "return WebProxy::StreamClass::Upload;" in classify


def test_uplink_goes_through_the_scheduler():
    transport = read(TRANSPORT_CPP)
    flush = function_body(transport, "void Transport::Private::flushStreams()")
    assert "_scheduler.next()" in flush
    assert "flushStream(grant->streamId, grant->maxBytes);" in flush
    # The old FIFO of ready streams let bulk data sit in front of
    # interactive frames in the carrier.
    assert "_readyStreams" not in transport
    window = function_body(
        transport, "bool Transport::Private::processRelayFrame(")
    assert "creditUnacked(frame.streamId, stream, amount);" in window


def test_download_credit_is_shaped():
    transport = read(TRANSPORT_CPP)
    grant = function_body(
        transport, "void Transport::Private::grantWindow(")
    assert "stream.withheldWindow += amount;" in grant
    assert "releaseDownlinkCredit(stream)" in grant
    release = function_body(
        transport, "bool Transport::Private::releaseDownlinkCredit(")
    assert "DownlinkCreditTarget(" in release
    assert "DownlinkCreditRelease(" in release


def test_carrier_stall_is_recovered_once_by_the_carrier():
    transport = read(TRANSPORT_CPP)
    check = function_body(transport, "void Transport::Private::checkHealth()")
    assert "CarrierStalled(now, health, _livenessLimits)" in check
    assert "recoverStalledCarrier(" in check


def test_session_asks_the_carrier_before_dropping_a_web_stream():
    connection = read(CONNECTION_CPP)
    wait_received = function_body(
        connection, "void SessionTransport::waitReceivedFailed()")
    assert wait_received.index("extendWebProxyReceiveWait()") < (
        wait_received.index("doDisconnect();"))
    extend = function_body(
        connection, "bool SessionTransport::extendWebProxyReceiveWait()")
    assert "receiveWaitVerdict(startedAt)" in extend
    assert "ProxyDiagnosticsPhase::WebCarrier" in extend


def test_web_404_is_a_stream_reset_first():
    connection = read(CONNECTION_CPP)
    transport = read(SESSION_TRANSPORT_CPP)
    handle = function_body(connection, "void SessionTransport::handleError(")
    assert "kWebKeyNotFoundStrikesToAssumeKeyDestroyed" in handle
    assert "return restart();" in handle
    assert "_owner->destroyTemporaryKey();" in handle
    note = function_body(
        transport, "void SessionTransport::noteMtprotoPayloadReceived()")
    assert "_state.webKeyNotFoundStrikes = 0;" in note


def test_web_sessions_open_one_stream():
    connection = read(CONNECTION_CPP)
    connect = function_body(
        connection, "void SessionTransport::connectToServer(")
    assert "const auto single = webProxy();" in connect
    assert "if (enough()) {" in connect


def test_file_transfers_do_not_fan_out_over_a_web_carrier():
    upload = read(FILE_UPLOAD_CPP)
    download = read(DOWNLOAD_MANAGER_CPP)
    assert "kWebProxyMaxSessionsCount = 2;" in upload
    assert "kWebProxyMaxSessionsCount = 2;" in download
    assert "&& !SharedCarrier();" in upload
    assert "MaxSessionsCount()" in download


def test_flow_policy_has_a_unit_test_target():
    cmake = read(TESTS_CMAKE)
    flow = read(FLOW_H)
    assert "add_executable(test_web_proxy_flow WIN32)" in cmake
    assert "tests/test_web_proxy_flow.cpp" in cmake
    assert "class UplinkScheduler final" in flow
    assert "DecideReceiveWait(" in flow


if __name__ == "__main__":
    for name, value in list(globals().items()):
        if name.startswith("test_") and callable(value):
            value()
    print("ok")

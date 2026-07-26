"""The clock a fake TLS hello carries must be reported with its reference.

A relay refuses a timestamp more than three seconds ahead of its own clock,
and the client only corrects its clock through channels that bypass the proxy.
So the skew alone is not a diagnosis: with no correction obtained the client
sends the raw system clock and the skew it would compute is zero, however
wrong that clock is. These tests pin the shape that keeps the two apart.
"""

from pathlib import Path


SOURCE_DIR = Path(__file__).resolve().parents[1]
MTPROXY_DIR = SOURCE_DIR / "mtproto" / "proxy" / "mtproxy"
BUILDER_H = MTPROXY_DIR / "client_hello_builder.h"
BUILDER_CPP = MTPROXY_DIR / "client_hello_builder.cpp"
TLS_SOCKET_H = MTPROXY_DIR / "tls_socket.h"
TLS_SOCKET_HANDSHAKE_CPP = MTPROXY_DIR / "tls_socket_handshake.cpp"
TLS_SOCKET_DIAGNOSTICS_CPP = MTPROXY_DIR / "tls_socket_diagnostics.cpp"
DIAGNOSTICS_H = SOURCE_DIR / "mtproto" / "proxy" / "diagnostics.h"
DIAGNOSTICS_CPP = SOURCE_DIR / "mtproto" / "proxy" / "diagnostics.cpp"
RUNTIME_ENVIRONMENT_CPP = (
    SOURCE_DIR / "mtproto" / "runtime" / "runtime_environment.cpp")


def test_generated_hello_carries_the_timestamp_it_sent():
    header = BUILDER_H.read_text(encoding="utf-8")
    assert "struct ClientHello {" in header
    assert "TimeId timestamp = 0;" in header

    source = BUILDER_CPP.read_text(encoding="utf-8")
    # The value must come from the injection itself. Reading the clock again
    # later returns a different second than the one on the wire.
    assert "_injectedTimestamp = base::unixtime::http_now();" in source
    assert "already ^= qToLittleEndian(int32(_injectedTimestamp));" in source
    assert "TimeId injectedTimestamp() const" in source


def test_socket_snapshots_both_corrections_at_send_time():
    header = TLS_SOCKET_H.read_text(encoding="utf-8")
    for field in ("_clientHelloTimestamp", "_clockFromMtproto",
                  "_clockFromHttp", "_clockSkew"):
        assert field in header, field

    source = TLS_SOCKET_HANDSHAKE_CPP.read_text(encoding="utf-8")
    assert "void TlsSocket::noteClientHelloClock(TimeId timestamp)" in source
    # Snapshot, because an MTProto time update clears the HTTP correction as
    # a side effect - the state at send time is not the state a moment later.
    assert "base::unixtime::http_valid()" in source
    # The MTProto reference is the fact that a server told us the time, not
    # the size of the resulting shift: update() skips shifts under three
    # seconds, so a correct clock keeps a zero shift and would otherwise be
    # reported as having no reference at all.
    assert "_clockFromMtproto = ServerTimeReceived();" in source
    assert "corrected != local" not in source

    runtime = RUNTIME_ENVIRONMENT_CPP.read_text(encoding="utf-8")
    assert "void NoteServerTimeReceived()" in runtime
    assert "bool ServerTimeReceived()" in runtime
    # Every place a server time arrives has to raise the flag, or a client
    # that heard the time still reports none.
    receive = (SOURCE_DIR / "mtproto" / "session" / "private"
               / "receive.cpp").read_text(encoding="utf-8")
    creator = (SOURCE_DIR / "mtproto" / "auth"
               / "mtproto_dc_key_creator.cpp").read_text(encoding="utf-8")
    assert receive.count("NoteServerTimeReceived();") == 3
    assert creator.count("NoteServerTimeReceived();") == 1
    assert receive.count("base::unixtime::update(") == 3
    assert creator.count("base::unixtime::update(") == 1


def test_warning_fires_on_a_missing_reference_and_not_on_a_threshold():
    source = TLS_SOCKET_HANDSHAKE_CPP.read_text(encoding="utf-8")
    start = source.index("void TlsSocket::noteClientHelloClock")
    end = source.index("void TlsSocket::checkClientHelloContract")
    body = source[start:end]

    assert "if (_clockFromMtproto || _clockFromHttp) {\n\t\treturn;" in body
    assert "raw system clock" in body
    # Guard against a future "simplification" back into comparing the skew:
    # with no reference the skew is zero by construction and proves nothing.
    for forbidden in ("_clockSkew >", "_clockSkew <", "abs(_clockSkew"):
        assert forbidden not in body, forbidden


def test_diagnostics_carry_timestamp_reference_and_signed_skew():
    header = DIAGNOSTICS_H.read_text(encoding="utf-8")
    assert header.count("std::optional<TimeId> clientHelloTimestamp;") == 2
    assert header.count("QString clockReference;") == 2
    assert header.count("std::optional<TimeId> clockSkew;") == 2

    rendered = DIAGNOSTICS_CPP.read_text(encoding="utf-8")
    assert 'u"ch_timestamp=%1"_q' in rendered
    assert 'u"clock_ref=%1"_q' in rendered
    assert 'u"clock_skew=%1%2"_q' in rendered
    # Signed, because "ahead" is the direction a relay refuses.
    assert '(*safe.clockSkew > 0) ? u"+"_q : QString()' in rendered

    # The socket fills the report once, and the runtime copies the report
    # into the event that gets rendered - so the fields have to survive both
    # steps or they silently never reach a log line.
    filled = TLS_SOCKET_DIAGNOSTICS_CPP.read_text(encoding="utf-8")
    assert filled.count(".clockReference = clockReferenceName(),") == 1
    for name in ('u"both"_q', 'u"mtproto"_q', 'u"http"_q', 'u"none"_q'):
        assert name in filled, name

    carried = RUNTIME_ENVIRONMENT_CPP.read_text(encoding="utf-8")
    assert ".clientHelloTimestamp = report.clientHelloTimestamp," in carried
    assert ".clockReference = std::move(report.clockReference)," in carried
    assert ".clockSkew = report.clockSkew," in carried


def test_verified_server_hello_reports_the_clock_as_validated():
    source = TLS_SOCKET_HANDSHAKE_CPP.read_text(encoding="utf-8")
    # A verified ServerHello proves the timestamp sat inside the relay's
    # window, which answers "maybe it is our clock" for this attempt.
    assert "clock validated by relay" in source

"""Two client-side costs that showed up as "the proxy is slow".

Measured 26 July 2026 against live relays. Twenty-four simultaneous dials,
paced by nothing at all, reached resPQ 24 out of 24 with the whole batch done
in 170 ms. The same twenty-four through the client's own pacer cost about six
seconds of queue at a quarter second apiece, and a cold start pays that before
the first message moves - the client log shows it directly as tcp_ms climbing
past eight seconds on the later sockets.

The premise the quarter second rested on was that arriving as separate clients
is worth something against a filtered network. It is not: what that network
keys on was measured, and it is the exact shape of the hello plus the name in
SNI. A hello matching neither is answered however it arrives.

The other cost is Nagle. mtproto writes a short request and then waits, which
is the case Nagle penalises, and Qt applies socket options through the socket
engine - which does not exist until the connection is up. So the option has to
be set in the connected handler, not next to the buffer sizes in the
constructor, or it is silently dropped.
"""

from pathlib import Path


SOURCE_DIR = Path(__file__).resolve().parents[1]
PACER_CPP = SOURCE_DIR / "mtproto" / "proxy" / "dial_pacer.cpp"
TLS_HANDSHAKE_CPP = (SOURCE_DIR / "mtproto" / "proxy" / "mtproxy"
                     / "tls_socket_handshake.cpp")
TCP_SOCKET_CPP = (SOURCE_DIR / "mtproto" / "transport" / "details"
                  / "mtproto_tcp_socket.cpp")


def test_dial_spacing_stays_small_enough_for_a_fast_ramp():
    source = PACER_CPP.read_text(encoding="utf-8")
    line = next(l for l in source.splitlines()
                if "kDialSpacing = crl::time(" in l)
    spacing = int(line.split("crl::time(")[1].split(")")[0])
    # A full ramp is tens of sockets. At 250 ms that was six seconds of queue
    # before anything moved; the measurement that justified paying it does not
    # hold. Keep some spacing - a relay's own logs read better with distinct
    # arrivals - but not enough to be felt.
    assert 0 < spacing <= 80, spacing

    # The numbers belong next to the constant, so whoever raises it again has
    # to argue with them rather than with a guess.
    assert "170ms" in source
    assert "twenty-four" in source


def test_failure_backoff_survives_the_smaller_spacing():
    source = PACER_CPP.read_text(encoding="utf-8")
    # A relay that really does swallow the overflow is handled by the failure
    # spacing, and that is the part the smaller unconditional spacing leans
    # on. It must not be weakened along with it.
    assert "kFailureSpacingStep = crl::time(500)" in source
    assert "kFailureSpacingMax = crl::time(4000)" in source
    assert "kFailuresBeforeBackoff = 4" in source


def test_nagle_is_disabled_on_both_transports_after_connecting():
    for path in (TLS_HANDSHAKE_CPP, TCP_SOCKET_CPP):
        source = path.read_text(encoding="utf-8")
        assert "QAbstractSocket::LowDelayOption" in source, path.name
        # In the connected handler, not the constructor: Qt drops options set
        # before the socket engine exists.
        head = source.split("LowDelayOption", 1)[0]
        assert ("plainConnected" in head
                or "QTcpSocket::connected" in head), path.name

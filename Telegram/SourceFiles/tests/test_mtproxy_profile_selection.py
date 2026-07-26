"""A fingerprint measured as refused must not be what the client sends.

Measured 26 July 2026, one relay, two networks, twelve attempts per profile
per network. Unfiltered, every profile is answered in under fifty
milliseconds. Filtered, the four profiles that keep a fixed extension order
are answered twelve out of twelve, and the two that permute their extensions
on every hello - chrome_modern and android_chrome - are answered three out of
twelve, silence otherwise, on the same relay with the same secret in the same
minutes. The client defaulted to one of the two refused ones, which is what
"no proxy works here" looked like from the inside.

These tests pin the two halves of the fix: the default is a profile that was
answered everywhere it was measured, and a refused fingerprint is steered
away from at both sites that turn a setting into a hello - including for a
user who selected it by hand before the measurement existed.
"""

from pathlib import Path


SOURCE_DIR = Path(__file__).resolve().parents[1]
MTPROXY_DIR = SOURCE_DIR / "mtproto" / "proxy" / "mtproxy"
PROFILE_H = MTPROXY_DIR / "client_hello_profile.h"
PROFILE_CPP = MTPROXY_DIR / "client_hello_profile.cpp"
HANDSHAKE_PLAN_CPP = MTPROXY_DIR / "handshake_plan.cpp"
TLS_SOCKET_CPP = MTPROXY_DIR / "tls_socket.cpp"


def test_default_profile_is_one_that_was_answered_everywhere():
    source = PROFILE_CPP.read_text(encoding="utf-8")
    body = source.split("ProxyTlsProfile DefaultClientHelloProfile()", 1)[1]
    body = body.split("}", 1)[0]
    assert "ProxyTlsProfile::Yandex" in body
    # The two that a filtered network refused must not be the default, by
    # name: reintroducing either here is the whole bug coming back.
    assert "ChromeModern" not in body
    assert "AndroidChrome" not in body


def test_refused_fingerprints_are_marked_withheld_with_their_reason():
    header = PROFILE_H.read_text(encoding="utf-8")
    assert "bool withheld = false;" in header
    assert "const char *withheldReason" in header

    source = PROFILE_CPP.read_text(encoding="utf-8")
    for profile in ("ProxyTlsProfile::ChromeModern",
                    "ProxyTlsProfile::AndroidChrome"):
        entry = source.split(profile, 1)[1].split("},", 1)[0]
        assert ".withheld = true," in entry, profile
        assert ".withheldReason" in entry, profile

    # The measurement itself belongs in the source, not only in a commit
    # message: whoever reconsiders this needs the numbers.
    assert "3/12" in source
    assert "12/12" in source


def test_profiles_that_passed_are_not_withheld():
    source = PROFILE_CPP.read_text(encoding="utf-8")
    for profile in ("ProxyTlsProfile::Yandex",
                    "ProxyTlsProfile::Firefox",
                    "ProxyTlsProfile::FirefoxAndroid",
                    "ProxyTlsProfile::AndroidOkHttp"):
        entry = source.split(profile, 1)[1].split("},", 1)[0]
        assert ".withheld" not in entry, profile


def test_both_plan_sites_resolve_through_the_effective_profile():
    header = PROFILE_H.read_text(encoding="utf-8")
    assert "ProxyTlsProfile EffectiveClientHelloProfile(" in header

    source = PROFILE_CPP.read_text(encoding="utf-8")
    body = source.split(
        "ProxyTlsProfile EffectiveClientHelloProfile(", 1)[1]
    body = body.split("\n}", 1)[0]
    assert "info.withheld ? DefaultClientHelloProfile()" in body

    # A plain lookup still answers about a withheld profile - the JA4 guard
    # checks one - so the steering has to happen where a setting becomes a
    # hello, and at every such place.
    plan = HANDSHAKE_PLAN_CPP.read_text(encoding="utf-8")
    assert "EffectiveClientHelloProfile(stealth.tlsProfile)" in plan
    assert "ClientHelloProfile(stealth.tlsProfile).profile" not in plan

    socket = TLS_SOCKET_CPP.read_text(encoding="utf-8")
    assert "EffectiveClientHelloProfile(fallback.tlsProfile)" in socket
    assert "ClientHelloProfile(fallback.tlsProfile).profile" not in socket

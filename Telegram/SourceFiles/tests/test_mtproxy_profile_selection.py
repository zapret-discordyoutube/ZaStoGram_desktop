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

Three follow-up experiments narrowed what is refused: not one field, but an
exact match. Changing the trailing GREASE payload byte from 0x00 to 0xff,
moving it to the first GREASE extension, or taking the ECH payload length off
the set the builder draws from - each on its own turns a refused hello into an
answered one. So the trait that decides a profile's fate is its tail, and the
two refused profiles are exactly the two that end with a GREASE extension
carrying one zero byte, which is what Chromium really sends. A byte-for-byte
capture of a real browser is refused too, so the copy has to stay imperfect;
the last test here guards that, because "align the template to a real dump"
is the obvious improvement to make and it would break connectivity.
"""

from pathlib import Path


SOURCE_DIR = Path(__file__).resolve().parents[1]
MTPROXY_DIR = SOURCE_DIR / "mtproto" / "proxy" / "mtproxy"
PROFILE_H = MTPROXY_DIR / "client_hello_profile.h"
PROFILE_CPP = MTPROXY_DIR / "client_hello_profile.cpp"
RULES_CPP = MTPROXY_DIR / "client_hello_rules.cpp"
HANDSHAKE_PLAN_CPP = MTPROXY_DIR / "handshake_plan.cpp"
TLS_SOCKET_CPP = MTPROXY_DIR / "tls_socket.cpp"

# A GREASE extension carrying a single zero byte, written out as the rules
# write it. This is the shape a filtered network matches on.
REFUSED_TAIL = 'S("\\x00\\x01\\x00"_q);'
EMPTY_TAIL = 'S("\\x00\\x00"_q);'
# ALPS, which only the Chromium-shaped profiles carry.
ALPS_EXTENSION = "\\x44\\xcd"


def rule_bodies():
    """Each profile's rule block, by profile name."""
    source = RULES_CPP.read_text(encoding="utf-8")
    bodies = {}
    for chunk in source.split("case ProxyTlsProfile::")[1:]:
        name = chunk.split(":", 1)[0].strip()
        bodies[name] = chunk.split("break;", 1)[0]
    return bodies


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


def test_no_sent_profile_combines_the_tail_with_the_chromium_shape():
    """The refusal needs both halves, so no sent profile may have both.

    android_okhttp ends with that same GREASE byte and is answered 12/12,
    which is what proves the tail alone is not the trigger: it carries none
    of the rest - no ECH payload, no ALPS, no post-quantum share. The two
    refused profiles are the only ones with the tail AND the full Chromium
    shape around it. Both halves are guarded, because either one added to a
    passing profile would bring the outage back.
    """
    bodies = rule_bodies()
    for name in ("Yandex", "ChromeModern", "AndroidChrome", "Firefox",
                 "FirefoxAndroid", "AndroidOkHttp"):
        assert name in bodies, name

    def chromium_shaped(body):
        return "E();" in body and ALPS_EXTENSION in body

    for name in ("ChromeModern", "AndroidChrome"):
        assert REFUSED_TAIL in bodies[name], name
        assert chromium_shaped(bodies[name]), name

    for name in ("Yandex", "Firefox", "FirefoxAndroid", "AndroidOkHttp"):
        body = bodies[name]
        assert not (REFUSED_TAIL in body and chromium_shaped(body)), name


def test_yandex_tail_stays_an_imperfect_copy():
    body = rule_bodies()["Yandex"]
    # The profile ends with a GREASE extension, and that extension has to
    # stay empty: a real Yandex Browser capture carries one zero byte there
    # and is refused where this template is answered.
    assert "G(3);" in body
    tail = body.rsplit("G(3);", 1)[1]
    assert EMPTY_TAIL in tail
    assert REFUSED_TAIL not in tail
    # And the reason lives next to the line, because "make the copy exact" is
    # the obvious thing for the next reader to try.
    assert "do not" in tail.lower()

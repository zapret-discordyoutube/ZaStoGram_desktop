"""The logged SNI hash has to be salted, or it is not a hash worth logging.

The masqueraded domain goes into the log as a hash so a log can be handed
over without naming it. Unsalted, that does not hold: the name is short and
comes from a small set of plausible ones, so eight bytes of SHA-256 fall to a
wordlist immediately - `www.google.com` was recovered from a real log this way
in well under a second while investigating a proxy.

Salting per run keeps the field's actual use - telling apart, inside one log,
which connections carried which name - and removes the part that never worked.
The cost is that hashes from two runs no longer line up, which is the correct
trade for a field whose stated purpose was not naming the domain.
"""

from pathlib import Path


SOURCE_DIR = Path(__file__).resolve().parents[1]
DIAGNOSTICS_CPP = (SOURCE_DIR / "mtproto" / "proxy" / "mtproxy"
                   / "tls_socket_diagnostics.cpp")


def test_the_salt_is_random_and_drawn_once_per_run():
    source = DIAGNOSTICS_CPP.read_text(encoding="utf-8")
    body = source.split("QByteArray SniHashSalt()", 1)[1].split("\n}", 1)[0]
    # Random, not derived from anything an outsider could reconstruct.
    assert "base::RandomFill" in body
    # Once per run: a fresh salt per call would make the field useless for
    # matching connections inside one log, which is the only thing it is for.
    assert "static const auto" in body


def test_every_logged_sni_hash_goes_through_the_salt():
    source = DIAGNOSTICS_CPP.read_text(encoding="utf-8")
    assert "QByteArray HashedSni(" in source

    # Both report builders hash the domain; neither may do it directly.
    assert source.count("HashedSni(domain)") == 2
    hashed_raw = "QCryptographicHash::hash(\n\t\tdomainBytes"
    assert hashed_raw not in source

    # And the salt has to be the first thing hashed, not appended after the
    # domain, so that no prefix of the digest depends on the domain alone.
    body = source.split("QByteArray HashedSni(", 1)[1].split("\n}", 1)[0]
    salt_at = body.index("SniHashSalt()")
    domain_at = body.index("domain.data()")
    assert salt_at < domain_at


def test_the_reason_is_recorded_next_to_the_code():
    source = DIAGNOSTICS_CPP.read_text(encoding="utf-8")
    # Whoever removes the salt for convenience should meet the reason first.
    assert "www.google.com was read back out of a log" in source

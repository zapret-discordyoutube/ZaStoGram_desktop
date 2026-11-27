import json
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

SOURCE_DIR = Path(__file__).resolve().parents[1]
TELEGRAM_DIR = SOURCE_DIR.parent
TOOL = TELEGRAM_DIR / "build" / "zastogram" / "update_keys.py"
COMMITTED = TELEGRAM_DIR / "Resources" / "update"
CHECKER = SOURCE_DIR / "core" / "update_checker.cpp"

GIT_OPENSSL = Path(r"C:\Program Files\Git\usr\bin\openssl.exe")
assert shutil.which("openssl") or GIT_OPENSSL.is_file(), \
    "openssl is required for the update key tests"


def tool(*args):
    return subprocess.run(
        [sys.executable, "-I", str(TOOL), *args],
        capture_output=True,
        text=True)


def test_committed_trust_files_verify_against_the_committed_root():
    result = tool("check", "--out", str(COMMITTED))
    assert result.returncode == 0, result.stdout + result.stderr
    manifest = json.loads((COMMITTED / "manifest.min.json").read_bytes())
    # The fork's own chain: Telegram's key ids must not be trusted.
    ids = {key["id"] for key in manifest["keys"]}
    assert ids.isdisjoint({"rl-2026b", "rc-2026a", "cp-2026a", "cx-2026a"})
    assert set(manifest["channels"]) == {"stable", "beta"}


def test_no_private_key_is_committed_with_the_trust_files():
    for path in COMMITTED.iterdir():
        if path.is_file():
            assert b"PRIVATE KEY" not in path.read_bytes(), path


def test_init_creates_private_keys_once_and_signs_the_manifest():
    with tempfile.TemporaryDirectory() as scratch:
        _test_init_creates_private_keys_once_and_signs_the_manifest(Path(scratch))


def _test_init_creates_private_keys_once_and_signs_the_manifest(tmp_path):
    keys = tmp_path / "keys"
    out = tmp_path / "out"
    args = ["--keys-dir", str(keys), "--out", str(out), "--issued", "1700000000"]
    first = tool("init", *args)
    assert first.returncode == 0, first.stdout + first.stderr
    assert "root created, release created" in first.stdout

    if sys.platform != "win32":  # POSIX modes mean nothing on Windows.
        for name in ("root-private.pem", "release-private.pem"):
            mode = stat.S_IMODE((keys / name).stat().st_mode)
            assert mode == 0o600, name
        assert stat.S_IMODE(keys.stat().st_mode) == 0o700
    # Private keys never reach the output of the tool.
    assert "PRIVATE" not in first.stdout + first.stderr

    root_before = (keys / "root-private.pem").read_bytes()
    second = tool("init", *args)
    assert second.returncode == 0, second.stdout + second.stderr
    assert "root kept, release kept" in second.stdout
    assert (keys / "root-private.pem").read_bytes() == root_before


def test_manifest_command_raises_the_version_and_keeps_keys():
    with tempfile.TemporaryDirectory() as scratch:
        _test_manifest_command_raises_the_version_and_keeps_keys(Path(scratch))


def _test_manifest_command_raises_the_version_and_keeps_keys(tmp_path):
    keys = tmp_path / "keys"
    out = tmp_path / "out"
    args = ["--keys-dir", str(keys), "--out", str(out), "--issued", "1700000000"]
    assert tool("init", *args).returncode == 0
    before = json.loads((out / "manifest.min.json").read_bytes())
    assert tool("manifest", *args).returncode == 0
    after = json.loads((out / "manifest.min.json").read_bytes())
    assert after["manifest_version"] == before["manifest_version"] + 1
    assert after["keys"] == before["keys"]
    assert tool("check", "--out", str(out)).returncode == 0


def test_check_rejects_a_tampered_manifest_and_a_foreign_signature():
    with tempfile.TemporaryDirectory() as scratch:
        _test_check_rejects_a_tampered_manifest_and_a_foreign_signature(Path(scratch))


def _test_check_rejects_a_tampered_manifest_and_a_foreign_signature(tmp_path):
    keys = tmp_path / "keys"
    out = tmp_path / "out"
    assert tool(
        "init", "--keys-dir", str(keys), "--out", str(out)).returncode == 0
    manifest = out / "manifest.min.json"
    original = manifest.read_bytes()

    manifest.write_bytes(original.replace(b'"revoked":[]', b'"revoked":["x"]'))
    assert tool("check", "--out", str(out)).returncode != 0
    manifest.write_bytes(original)
    assert tool("check", "--out", str(out)).returncode == 0

    other = tmp_path / "other"
    assert tool(
        "init", "--keys-dir", str(tmp_path / "keys2"),
        "--out", str(other)).returncode == 0
    shutil.copy(other / "manifest.sig", out / "manifest.sig")
    assert tool("check", "--out", str(out)).returncode != 0


def test_dev_builds_verify_against_a_running_version_one_step_lower():
    text = CHECKER.read_text(encoding="utf-8")
    start = text.index("VerifyUpdateV2(")
    body = text[start:start + 2500]
    assert "IsZaStoGramDevBuild()" in body
    assert "Updates::DevRunningVersion(RunningUpdateVersion())" in body


if __name__ == "__main__":
    for name, value in list(globals().items()):
        if name.startswith("test_") and callable(value):
            value()

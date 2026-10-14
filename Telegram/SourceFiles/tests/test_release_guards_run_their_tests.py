import re
from pathlib import Path


TESTS_DIR = Path(__file__).resolve().parent
REPO_DIR = TESTS_DIR.parents[2]
GUARD_LIST = TESTS_DIR / "release_guards.txt"
THIS_GUARD = "Telegram/SourceFiles/tests/test_release_guards_run_their_tests.py"
RUNNER = '''if __name__ == "__main__":
    for name, value in list(globals().items()):
        if name.startswith("test_") and callable(value):
            value()
'''


def guard_lines():
    return [
        line.strip()
        for line in GUARD_LIST.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    ]


def test_every_guard_runs_all_of_its_tests():
    # The release script and CI run each guard as `python <file>` and look
    # only at the exit code. A guard that defines test_* functions without
    # calling them passes without checking anything, and a hand-written list
    # of calls silently falls behind the tests added later.
    for line in guard_lines():
        path = REPO_DIR / line
        assert path.exists(), f"missing guard: {line}"
        source = path.read_text(encoding="utf-8")
        if re.search(r"^def test_", source, re.M):
            assert RUNNER in source, f"{line} does not run its test_* functions"


def test_guard_list_includes_this_check():
    assert THIS_GUARD in guard_lines()


if __name__ == "__main__":
    for name, value in list(globals().items()):
        if name.startswith("test_") and callable(value):
            value()
    print("ok")

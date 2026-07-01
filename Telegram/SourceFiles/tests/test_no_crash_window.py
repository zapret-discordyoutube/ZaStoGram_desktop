from pathlib import Path


SOURCE_DIR = Path(__file__).resolve().parents[1]
SANDBOX_CPP = SOURCE_DIR / "core" / "sandbox.cpp"
SANDBOX_H = SOURCE_DIR / "core" / "sandbox.h"


def function_body(source: str, signature: str) -> str:
    start = source.index(signature)
    brace = source.index(" {\n", start) + 1
    depth = 0
    for index in range(brace, len(source)):
        char = source[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return source[brace + 1:index]
    raise AssertionError(f"body not found for {signature}")


def test_startup_does_not_show_crash_report_window():
    sandbox = SANDBOX_CPP.read_text(encoding="utf-8")
    sandbox_h = SANDBOX_H.read_text(encoding="utf-8")
    body = function_body(sandbox, "void Sandbox::singleInstanceChecked")

    assert "LastCrashedWindow" not in body
    assert "_lastCrashDump" not in sandbox_h
    assert body.count("launchApplication();") >= 2


if __name__ == "__main__":
    test_startup_does_not_show_crash_report_window()

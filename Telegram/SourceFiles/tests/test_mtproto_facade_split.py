from pathlib import Path


SOURCE_DIR = Path(__file__).resolve().parents[1]
ROOT = SOURCE_DIR.parents[1]
MTPROTO_DIR = SOURCE_DIR / "mtproto"
CMAKE = ROOT / "Telegram" / "CMakeLists.txt"


def read(path):
    assert path.exists(), f"missing expected source file: {path}"
    return path.read_text(encoding="utf-8")


def test_facade_module_is_split_by_responsibility():
    assert not (MTPROTO_DIR / "facade.h").exists()
    assert not (MTPROTO_DIR / "facade.cpp").exists()

    dc_id = read(MTPROTO_DIR / "dc_id.h")
    pause_header = read(MTPROTO_DIR / "pause_state.h")
    pause_source = read(MTPROTO_DIR / "pause_state.cpp")
    session_state = read(MTPROTO_DIR / "session_state.h")

    for symbol in (
        "configDcId",
        "downloadDcId",
        "uploadDcId",
        "destroyKeyNextDcId",
        "getTemporaryIdFromRealDcId",
    ):
        assert symbol in dc_id

    assert "pause()" not in dc_id
    assert "PauseLevel" not in dc_id
    assert "ConnectedState" not in dc_id
    assert '#include "mtproto/mtp_instance.h"' not in dc_id

    for symbol in ("paused()", "pause()", "unpause()", "unpaused()"):
        assert symbol in pause_header

    assert "PauseLevel" in pause_source
    assert "downloadDcId" not in pause_header
    assert "ShiftDcId" not in pause_header

    assert "DisconnectedState" in session_state
    assert "RequestSending" in session_state
    assert "ShiftDcId" not in session_state


def test_mtproto_facade_include_is_gone():
    offenders = []
    for path in SOURCE_DIR.rglob("*"):
        if path == Path(__file__):
            continue
        if path.suffix not in {".cpp", ".h", ".hpp"}:
            continue
        if path.parts[-2:] == ("storage", "storage_facade.h"):
            continue
        text = path.read_text(encoding="utf-8")
        if '#include "mtproto/facade.h"' in text:
            offenders.append(path.relative_to(SOURCE_DIR).as_posix())

    assert offenders == []


def test_pause_state_sources_are_registered_for_build():
    cmake = read(CMAKE)

    assert "mtproto/dc_id.h" in cmake
    assert "mtproto/pause_state.cpp" in cmake
    assert "mtproto/pause_state.h" in cmake
    assert "mtproto/session_state.h" in cmake
    assert "mtproto/facade.cpp" not in cmake
    assert "mtproto/facade.h" not in cmake


if __name__ == "__main__":
    test_facade_module_is_split_by_responsibility()
    test_mtproto_facade_include_is_gone()
    test_pause_state_sources_are_registered_for_build()

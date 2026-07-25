from pathlib import Path


SOURCE_DIR = Path(__file__).resolve().parents[1]
ROOT = SOURCE_DIR.parents[1]
CMAKE_TESTS = ROOT / "Telegram" / "cmake" / "tests.cmake"
RUNTIME_H = SOURCE_DIR / "mtproto" / "runtime" / "runtime_environment.h"
RUNTIME_CPP = SOURCE_DIR / "mtproto" / "runtime" / "runtime_environment.cpp"


def read(path):
    assert path.exists(), f"missing expected source file: {path}"
    return path.read_text(encoding="utf-8")


def test_runtime_environment_exposes_async_gateway():
    header = read(RUNTIME_H)
    source = read(RUNTIME_CPP)

    assert '#include "mtproto/runtime/connection_status_types.h"' in header
    assert "struct RuntimeAsyncGateway final" in header
    assert "Fn<crl::time()> now;" in header
    assert "Fn<int(int)> randomIndex;" in header
    assert "Fn<void(crl::time, QObject*, Fn<void()>)> singleShot;" in header
    assert "RuntimeAsyncGateway async;" in header
    assert "const RuntimeAsyncGateway &async() const;" in header
    assert "RuntimeAsyncGateway CreateAsyncGateway()" in source
    assert ".async = CreateAsyncGateway()" in source
    assert "crl::now();" in source
    assert "base::RandomIndex(limit);" in source
    assert "QTimer::singleShot(int(delay)" in source

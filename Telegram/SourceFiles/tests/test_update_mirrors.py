from pathlib import Path


SOURCE_DIR = Path(__file__).resolve().parents[1]
CHECKER = SOURCE_DIR / "core" / "update_checker.cpp"
MIRRORS = SOURCE_DIR / "core" / "zsg_mirrors.cpp"
APPLICATION = SOURCE_DIR / "core" / "application.cpp"
CMAKE = SOURCE_DIR.parent / "CMakeLists.txt"


def body_after(source: Path, signature: str) -> str:
    text = source.read_text(encoding="utf-8")
    start = text.index(signature)
    brace = text.index(" {\n", start) + 1
    depth = 0
    for index in range(brace, len(text)):
        char = text[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return text[brace + 1:index]
    raise AssertionError(f"body not found for {signature}")


def test_checker_falls_back_to_the_next_mirror():
    request = body_after(CHECKER, "void HttpChecker::request(")
    assert "ZsgMirrors::Hosts()" in request

    failure = body_after(CHECKER, "void HttpChecker::gotFailure(")
    assert failure.index("tryNextHost()") < failure.index("fail();")

    response = body_after(CHECKER, "void HttpChecker::gotResponse()")
    assert "tryNextHost()" in response
    assert "ZsgMirrors::RememberGood(host)" in response


def test_download_url_follows_the_host_that_answered():
    checker = CHECKER.read_text(encoding="utf-8")
    assert "std::make_shared<HttpLoader>(mirrored(bestUrl))" in checker
    assert "std::make_shared<HttpLoader>(mirrored(url))" in checker


def test_loader_resumes_from_another_mirror():
    failed = body_after(CHECKER, "void HttpLoaderActor::partFailed(")
    assert failed.index("tryNextHost()") < failed.index("threadSafeFailed()")
    finished = body_after(CHECKER, "void HttpLoaderActor::partFinished(")
    assert "tryNextHost()" in finished


def test_only_numbered_git_names_stand_in_for_each_other():
    mirrors = MIRRORS.read_text(encoding="utf-8")
    assert 'u"^git\\\\d{0,2}\\\\.zapret\\\\.moe$"_q' in mirrors
    assert 'u"git2.zapret.moe"_q' in mirrors


def test_changelog_link_uses_a_reachable_mirror():
    assert "ZsgMirrors::Hosts().front()" in APPLICATION.read_text(encoding="utf-8")


def test_mirrors_are_built():
    cmake = CMAKE.read_text(encoding="utf-8")
    assert "core/zsg_mirrors.cpp" in cmake
    assert "core/zsg_mirrors.h" in cmake


if __name__ == "__main__":
    for name, value in list(globals().items()):
        if name.startswith("test_") and callable(value):
            value()

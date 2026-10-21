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


def test_checker_races_the_mirrors_instead_of_waiting_for_each():
    request = body_after(CHECKER, "void HttpChecker::request(")
    assert "ZsgMirrors::Hosts()" in request

    # A host dropped silently never errors: the next one has to start on a
    # timer, not after the previous one failed.
    start = body_after(CHECKER, "void HttpChecker::startNext()")
    assert "_staggerTimer.callOnce(kMirrorStagger)" in start

    failed = body_after(CHECKER, "void HttpChecker::attemptFailed()")
    assert "startNext()" in failed
    assert failed.index("startNext()") < failed.index("fail();")

    response = body_after(CHECKER, "void HttpChecker::gotResponse(")
    assert "attemptFailed()" in response
    assert "ZsgMirrors::RememberGood(host)" in response


def test_whole_check_has_room_for_every_mirror():
    checker = CHECKER.read_text(encoding="utf-8")

    # Updater gave the entire check 6 seconds, which a blocked first name
    # used up alone: the mirrors never got their turn.
    assert "kUpdateCheckBudget = 25 * crl::time(1000)" in checker
    checking = body_after(CHECKER, "void Updater::reportChecking()")
    assert "kUpdateCheckBudget" in checking
    assert "kUpdateCheckTimeout" not in checking


def test_proxied_attempts_are_backed_by_direct_ones():
    request = body_after(CHECKER, "void HttpChecker::request(")
    # An app-wide proxy that only carries Telegram swallows these requests
    # silently while a browser on the same machine works: race a direct route.
    assert "QNetworkProxy::applicationProxy().type()" in request
    assert "usesSystemConfiguration()" in request
    assert "_directManager->setProxy(QNetworkProxy::NoProxy)" in request
    assert "{ _attempts[i].host, true }" in request

    send = body_after(CHECKER, "void HttpChecker::sendTo(")
    assert "attempt.direct ? _directManager : _manager" in send


def test_failures_are_diagnosable_from_the_log():
    response = body_after(CHECKER, "void HttpChecker::gotResponse(")
    assert "LOG((\"Update Info: %1%2 -> %3 (%4), http %5" in response
    request = body_after(CHECKER, "void HttpChecker::request(")
    assert "QHostInfo::lookupHost(" in request


def test_builtin_order_puts_the_filtered_name_last():
    mirrors = MIRRORS.read_text(encoding="utf-8")
    builtin = body_after(MIRRORS, "[[nodiscard]] QStringList Builtin()")
    assert builtin.index("git2.zapret.moe") < builtin.index('u"git.zapret.moe"_q')


def test_download_url_follows_the_host_that_answered():
    checker = CHECKER.read_text(encoding="utf-8")
    assert "std::make_shared<HttpLoader>(mirrored(bestUrl), _answeredDirect)" in checker
    assert "std::make_shared<HttpLoader>(mirrored(url), _answeredDirect)" in checker


def test_loader_gives_up_on_a_silent_host():
    send = body_after(CHECKER, "void HttpLoaderActor::sendRequest()")
    assert "setTransferTimeout(kLoaderSilence)" in send


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

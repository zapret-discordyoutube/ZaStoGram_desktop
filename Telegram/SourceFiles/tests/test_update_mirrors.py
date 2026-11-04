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
    assert "kUpdateCheckBudget = 40 * crl::time(1000)" in checker
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
    added = body_after(CHECKER, "void HttpChecker::addAttempts(")
    assert "_attempts.push_back({ host, direct, false });" in added
    assert "if (_proxied)" in added and "add(true);" in added

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
    assert "mirrored(bestUrl),\n\t\tbestFallback,\n\t\t_answeredDirect" in checker
    assert "mirrored(url),\n\t\t\t\tQString(),\n\t\t\t\t_answeredDirect" in checker


def test_loader_gives_up_on_a_silent_host():
    send = body_after(CHECKER, "void HttpLoaderActor::sendRequest()")
    assert "setTransferTimeout(kLoaderSilence)" in send


def test_loader_resumes_from_another_mirror():
    failed = body_after(CHECKER, "void HttpLoaderActor::partFailed(")
    assert failed.index("tryNextHost()") < failed.index("threadSafeFailed()")
    finished = body_after(CHECKER, "void HttpLoaderActor::partFinished(")
    assert "tryNextHost()" in finished


def test_git_names_stand_in_for_each_other_but_never_another_site():
    # Since 2026-10-30 the names handed out are random labels (cwdnvtsqdc.zapret.moe):
    # any *.zapret.moe name may stand in, except the wiki's numbered names.
    is_git = body_after(MIRRORS, "bool IsGitHost(")
    assert 'u"^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\\\\.zapret\\\\.moe$"_q' in is_git
    assert 'u"^wiki\\\\d*\\\\.zapret\\\\.moe$"_q' in is_git
    assert "!otherSite.match(host).hasMatch()" in is_git
    builtin = body_after(MIRRORS, "[[nodiscard]] QStringList Builtin()")
    assert builtin.index('u"git4.zapret.moe"_q') < builtin.index('u"git.zapret.moe"_q')


def test_entry_pages_give_the_names_when_every_known_one_is_silent():
    lists = body_after(MIRRORS, "[[nodiscard]] QStringList EntryLists()")
    assert "script.google.com/macros/s/" in lists and "?format=json" in lists
    assert "gist.githubusercontent.com/fuckyourkn/" in lists
    parse = body_after(MIRRORS, "QStringList ParseEntry(")
    assert 'value("schema").toInt() != 1' in parse
    assert '.value("git").toObject().value("hosts").toArray()' in parse
    assert "IsGitHost(name)" in parse

    # The entry pages are asked as soon as every known name has been started,
    # not after the silent ones time out: the new names must fit the budget.
    start = body_after(CHECKER, "void HttpChecker::startNext()")
    assert start.index("requestEntryNames();") < start.index("sendTo(attempt)")
    failed = body_after(CHECKER, "void HttpChecker::attemptFailed()")
    assert failed.index("requestEntryNames();") < failed.index("fail();")
    assert "_entryState == EntryState::Done" in failed

    entry = body_after(CHECKER, "void HttpChecker::requestEntryNames()")
    assert "Core::ZsgMirrors::FetchEntryNames(tried" in entry
    # A late answer after the check ended must not start requests on released managers.
    assert "strong->_entryState != EntryState::Pending" in entry
    assert "_entryState = EntryState::Done;" in body_after(CHECKER, "void HttpChecker::clearSentRequest()")


def test_entry_pages_are_raced_and_reached_around_the_app_proxy():
    # The entry pages are the only way to learn a fresh name when every known
    # one is dropped; the app-wide proxy that swallows the git requests must
    # not swallow them too, and a silent list must not hold the other one back.
    fetch = body_after(MIRRORS, "void FetchEntryNames(")
    assert "QNetworkProxy::applicationProxy().type()" in fetch
    assert "usesSystemConfiguration()" in fetch
    assert "setProxy(QNetworkProxy::NoProxy)" in fetch
    assert "for (const auto &list : lists)" in fetch
    # Names are handed over as each page answers; the last call says that
    # none is pending, so the check waits for the slow Apps Script too.
    assert "race->delivered" in fetch
    assert "done(fresh, !race->pending)" in fetch
    assert "kEntryTimeout" in fetch
    assert "LOG((\"Update Info: entry page" in fetch


def test_loader_goes_round_the_whole_mirror_list():
    # The host that answered the check may be the last in the list: the
    # loader starts with the answered address, then tries every other one.
    start = body_after(CHECKER, "void HttpLoader::startLoading()")
    assert "auto urls = QStringList(_url);" in start
    assert "Core::ZsgMirrors::Hosts()" in start
    assert "addMirrors(_fallbackUrl)" in start
    next_host = body_after(CHECKER, "bool HttpLoaderActor::tryNextHost()")
    assert "_urlIndex + 1 >= _urls.size()" in next_host
    send = body_after(CHECKER, "void HttpLoaderActor::sendRequest()")
    # GitHub hands its files over through a redirect to another host.
    assert "QNetworkRequest::RedirectPolicyAttribute" in send
    assert "QUrl(_urls[_urlIndex])" in send


def test_github_is_the_first_route_for_dev_builds():
    # The git names are cut by name where the project is blocked; the same
    # releases are mirrored to GitHub, which answers there.
    checker = CHECKER.read_text(encoding="utf-8")
    assert "api.github.com/repos/zapret-discordyoutube/" in checker
    assert "ZaStoGram_desktop/releases?per_page=6" in checker
    request = body_after(CHECKER, "void HttpChecker::request(")
    assert "type == ResponseType::DevReleases" in request
    added = body_after(CHECKER, "void HttpChecker::addAttempts(")
    assert "_attempts.push_back({ QString(), direct, true });" in added
    # GitHub is tried before the git names, and again directly after them.
    assert added.index("if (github)") < added.index("for (const auto &host : hosts)")
    send = body_after(CHECKER, "void HttpChecker::sendTo(")
    assert "attempt.github" in send and "kZaStoGramGithubApi" in send
    # A package found there can still be fetched from the git mirrors.
    dev = body_after(CHECKER, "bool HttpChecker::handleDevReleases(")
    assert "kZaStoGramForgejoDownload" in dev
    assert "_answeredGithub" in dev


def test_a_stuck_check_ends_and_says_so():
    updater = CHECKER.read_text(encoding="utf-8")
    # The budget timer ends a check that nobody answered.
    timeout = body_after(CHECKER, "void Updater::handleTimeout()")
    assert "Action::Checking" in timeout and "tryLoaders()" in timeout
    # A check that lost its timer is ended by the next manual restart.
    start = body_after(CHECKER, "void Updater::start(bool forceWait)")
    assert "!_retryTimer.isActive()" in start
    assert start.index("handleTimeout()") < start.index("!cAutoUpdate()")
    # The settings page leaves "Checking" as soon as a download starts.
    loaders = body_after(CHECKER, "bool Updater::tryLoaders()")
    assert "_progress.fire(Progress{" in loaders
    assert "Update Info: the update check ended with a failure" in updater
    # The entry pages are asked soon after the start, and the check waits
    # for every one of them before it gives up.
    request = body_after(CHECKER, "void HttpChecker::request(")
    assert "_entryTimer.callOnce(kEntryDelay)" in request
    entry = body_after(CHECKER, "void HttpChecker::requestEntryNames()")
    assert "bool last" in entry and "if (last)" in entry


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

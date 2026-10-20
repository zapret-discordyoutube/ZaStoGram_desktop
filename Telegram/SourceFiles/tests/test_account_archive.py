from pathlib import Path


SOURCE_DIR = Path(__file__).resolve().parents[1]
ACCOUNT = SOURCE_DIR / "main" / "main_account.cpp"
SESSION = SOURCE_DIR / "main" / "main_session.cpp"
ARCHIVE = SOURCE_DIR / "main" / "main_account_archive.cpp"
CMAKE = SOURCE_DIR.parent / "CMakeLists.txt"


def test_forced_logout_saves_before_the_wipe():
    account = ACCOUNT.read_text(encoding="utf-8")

    fail_handler = account[account.index("setGlobalFailHandler"):]
    fail_handler = fail_handler[:fail_handler.index("setStateChangedHandler")]
    assert "AccountArchive::Save(" in fail_handler
    assert fail_handler.index("AccountArchive::Save(") < fail_handler.index("logOut();")

    forced = account[account.index("void Account::forcedLogOut()"):]
    forced = forced[:forced.index("void Account::loggedOut()")]
    assert forced.index("AccountArchive::Save(") < forced.index("loggedOut();")


def test_pending_notice_is_shown_after_logout_finished():
    account = ACCOUNT.read_text(encoding="utf-8")
    logged_out = account[account.index("void Account::loggedOut()"):]
    logged_out = logged_out[:logged_out.index("}\n")]

    assert logged_out.index("local().reset();") < logged_out.index("AccountArchive::NotifyPending();")


def test_live_mirror_and_frozen_copy_are_wired():
    session = SESSION.read_text(encoding="utf-8")
    account = ACCOUNT.read_text(encoding="utf-8")

    assert "AccountArchive::Watch(this);" in session
    assert "AccountArchive::SaveFrozenOnce(this," in session
    assert "DestroyReason::Quitting" in account
    assert "AccountArchive::Reason::Live" in account


def test_archive_never_replaces_live_copy_with_an_empty_one():
    archive = ARCHIVE.read_text(encoding="utf-8")

    assert "if (histories.empty())" in archive
    assert "live_" in archive


def test_archive_is_built():
    cmake = CMAKE.read_text(encoding="utf-8")

    assert "main/main_account_archive.cpp" in cmake
    assert "main/main_account_archive.h" in cmake


if __name__ == "__main__":
    for name, value in list(globals().items()):
        if name.startswith("test_") and callable(value):
            value()

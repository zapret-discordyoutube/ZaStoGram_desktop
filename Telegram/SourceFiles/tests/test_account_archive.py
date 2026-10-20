from pathlib import Path


SOURCE_DIR = Path(__file__).resolve().parents[1]
ACCOUNT = SOURCE_DIR / "main" / "main_account.cpp"
SESSION = SOURCE_DIR / "main" / "main_session.cpp"
ARCHIVE = SOURCE_DIR / "main" / "main_account_archive.cpp"
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
    # Saving on quit stalled the exit of an account with many chats.
    assert "AccountArchive::Reason::Live" not in account


def test_archive_never_replaces_live_copy_with_an_empty_one():
    archive = ARCHIVE.read_text(encoding="utf-8")

    assert "ExistingLive(" in archive
    assert "live_" in archive


def test_live_mirror_never_blocks_the_window():
    archive = ARCHIVE.read_text(encoding="utf-8")

    # A synchronous walk over every chat of every account froze the window
    # every 15 minutes: collect in slices, write on a background thread.
    step = body_after(ARCHIVE, "void Step(")
    assert "kSliceBudget" in step
    assert "base::call_delayed(kSliceGap" in step
    assert "crl::async(" in step
    assert "WriteAll(" in step

    live = body_after(ARCHIVE, "void Watch(")
    assert "Save(session" not in live
    assert "LiveTick(session)" in live

    # Only one account is written at a time.
    assert "if (Busy)" in archive


def test_live_copy_skips_disk_checks_and_old_messages():
    media = body_after(ARCHIVE, "void DescribeMedia(")
    assert media.index("if (full)") < media.index("filepath(true)")
    assert media.index("if (full)") < media.index("createMediaView()")

    chat = body_after(ARCHIVE, "[[nodiscard]] ChatData CollectChat(")
    assert "kLiveMessages" in chat


def test_only_the_logout_path_saves_synchronously():
    for source in (SESSION, SOURCE_DIR / "settings" / "sections" / "settings_advanced.cpp"):
        assert "AccountArchive::Save(" not in source.read_text(encoding="utf-8")


def test_archive_is_built():
    cmake = CMAKE.read_text(encoding="utf-8")

    assert "main/main_account_archive.cpp" in cmake
    assert "main/main_account_archive.h" in cmake


if __name__ == "__main__":
    for name, value in list(globals().items()):
        if name.startswith("test_") and callable(value):
            value()

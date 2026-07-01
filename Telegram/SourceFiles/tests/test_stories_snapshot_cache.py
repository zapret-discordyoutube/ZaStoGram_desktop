from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def function_body(source: str, signature: str) -> str:
    start = source.index(signature)
    brace = source.index("{", start)
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


def test_stories_snapshot_cache_has_storage_hooks():
    header = read("SourceFiles/storage/storage_account.h")
    source = read("SourceFiles/storage/storage_account.cpp")

    assert "readPrefImpl<QByteArray>" in source
    assert "writePrefImpl<QByteArray>" in source
    assert "writePrefGeneric(key, value)" in source
    assert "return readPrefGeneric(key)" in source
    assert "readPref(" in header
    assert "writePref(" in header


def test_stories_snapshot_cache_restores_and_refreshes_from_state():
    header = read("SourceFiles/data/data_stories.h")
    source = read("SourceFiles/data/data_stories.cpp")

    assert "restoreFromLocal()" in header
    assert "void Stories::restoreFromLocal()" in source
    assert "kStoriesSnapshotPref" in source
    assert "Serialize::writePeer" in source
    assert "Serialize::readPeer" in source
    assert "scheduleSnapshotWrite" in source
    assert "writeSnapshotNow" in source
    assert "readPref<QByteArray>" in source
    assert "writePref<QByteArray>" in source
    assert "clearPref(kStoriesSnapshotPref)" in source


def test_stories_snapshot_restore_waits_for_main_session_data():
    data_session = read("SourceFiles/data/data_session.cpp")
    data_header = read("SourceFiles/data/data_session.h")
    main_session = read("SourceFiles/main/main_session.cpp")
    data_constructor = function_body(data_session, "Session::Session(")
    restore_body = function_body(data_session, "void Session::restoreLocalState()")

    assert "stories().restoreFromLocal()" not in data_constructor
    assert "void restoreLocalState();" in data_header
    assert "void Session::restoreLocalState()" in data_session
    assert "stories().restoreFromLocal();" in restore_body
    assert "_data(std::make_unique<Data::Session>(this))" in main_session
    assert "_user(_data->processUser(user))" in main_session

    data_created = main_session.index(
        "_data(std::make_unique<Data::Session>(this))")
    user_loaded = main_session.index("_user(_data->processUser(user))")
    restore = main_session.index("data().restoreLocalState();")

    assert data_created < user_loaded < restore


def test_stories_not_modified_response_marks_snapshot_state_loaded():
    source = read("SourceFiles/data/data_stories.cpp")
    marker = "const MTPDstories_allStoriesNotModified"
    assert marker in source
    block = source[source.index(marker):source.index("});", source.index(marker))]

    assert "_sourcesLoaded[index] = true" in block
    assert "scheduleSnapshotWrite()" in block


def test_restored_state_does_not_skip_hidden_list_validation():
    source = read("SourceFiles/data/data_stories.cpp")
    marker = "const auto countLoaded = [&](StorySourcesList list)"
    assert marker in source
    block = source[source.index(marker):source.index("};", source.index(marker))]

    assert "_sourcesLoaded[index]" in block
    assert "!_sourcesStateFromSnapshot[index]" in block
    assert "!_sourcesStates[index].isEmpty()" in block


def main() -> None:
    test_stories_snapshot_cache_has_storage_hooks()
    test_stories_snapshot_cache_restores_and_refreshes_from_state()
    test_stories_snapshot_restore_waits_for_main_session_data()
    test_stories_not_modified_response_marks_snapshot_state_loaded()
    test_restored_state_does_not_skip_hidden_list_validation()


if __name__ == "__main__":
    main()

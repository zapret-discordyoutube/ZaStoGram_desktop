from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


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
    session = read("SourceFiles/data/data_session.cpp")

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
    assert "stories().restoreFromLocal()" in session


def test_stories_not_modified_response_marks_snapshot_state_loaded():
    source = read("SourceFiles/data/data_stories.cpp")
    marker = "const MTPDstories_allStoriesNotModified"
    assert marker in source
    block = source[source.index(marker):source.index("});", source.index(marker))]

    assert "_sourcesLoaded[index] = true" in block
    assert "scheduleSnapshotWrite()" in block

from pathlib import Path


SOURCE_DIR = Path(__file__).resolve().parents[1]
SETTINGS = SOURCE_DIR / "core" / "core_settings.h"
DATA_TYPES = SOURCE_DIR / "data" / "data_types.h"
DATA_SESSION = SOURCE_DIR / "data" / "data_session.cpp"
HISTORY_ITEM_H = SOURCE_DIR / "history" / "history_item.h"
HISTORY_ITEM_CPP = SOURCE_DIR / "history" / "history_item.cpp"
HISTORY_CPP = SOURCE_DIR / "history" / "history.cpp"
BOTTOM_INFO_H = SOURCE_DIR / "history" / "view" / "history_view_bottom_info.h"
BOTTOM_INFO_CPP = SOURCE_DIR / "history" / "view" / "history_view_bottom_info.cpp"
LANG = SOURCE_DIR.parent / "Resources" / "langs" / "lang.strings"


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


def test_keep_deleted_messages_pref_defaults_on():
    settings = SETTINGS.read_text(encoding="utf-8")

    assert "bool keepDeletedMessages()" in settings
    assert 'readPref<bool>("zastoKeepDeleted", true)' in settings
    assert "void setKeepDeletedMessages(bool value)" in settings
    assert 'writePref<bool>("zastoKeepDeleted", value)' in settings


def test_deleted_by_sender_flag_and_marker_exist():
    data_types = DATA_TYPES.read_text(encoding="utf-8")
    history_header = HISTORY_ITEM_H.read_text(encoding="utf-8")
    history_source = HISTORY_ITEM_CPP.read_text(encoding="utf-8")

    # MessageFlag ran out of bits after upstream 7.0 (Ephemeral took 1<<63),
    # so the mark lives in a dedicated HistoryItem member instead.
    assert "DeletedBySender" not in data_types
    assert "bool isDeletedBySender() const" in history_header
    assert "bool _deletedBySender = false;" in history_header
    assert "void markDeletedBySender();" in history_header
    assert "void HistoryItem::markDeletedBySender()" in history_source
    assert "_deletedBySender = true;" in history_source
    assert "requestItemRepaint(this);" in history_source


def test_delete_updates_keep_items_when_pref_enabled():
    session = DATA_SESSION.read_text(encoding="utf-8")
    messages_deleted = body_after(
        DATA_SESSION,
        "void Session::processMessagesDeleted")
    non_channel_deleted = body_after(
        DATA_SESSION,
        "void Session::processNonChannelMessagesDeleted")

    assert session.count("Core::App().settings().keepDeletedMessages()") == 2
    for body in (messages_deleted, non_channel_deleted):
        assert "Core::App().settings().keepDeletedMessages()" in body
        assert "item->markDeletedBySender();" in body
        assert "notifyItemsAboutToBeDestroyed(toDestroy);" in body
        assert "item->destroy();" in body
        assert body.index("item->markDeletedBySender();") < body.index(
            "notifyItemsAboutToBeDestroyed(toDestroy);")


def test_late_loaded_unknown_deleted_messages_get_marker():
    history = body_after(
        HISTORY_CPP,
        "not_null<HistoryItem*> History::addNewMessage")

    assert "const auto unknownDeleted = newMessage" in history
    assert "&& isUnknownMessageDeleted(id);" in history
    assert "if (unknownDeleted)" in history
    assert "item->markDeletedBySender();" in history
    assert history.index("const auto item = createItem(") < history.index(
        "item->markDeletedBySender();")


def test_kept_deleted_messages_show_bottom_info_marker():
    bottom_info_h = BOTTOM_INFO_H.read_text(encoding="utf-8")
    bottom_info_cpp = BOTTOM_INFO_CPP.read_text(encoding="utf-8")
    history_source = HISTORY_ITEM_CPP.read_text(encoding="utf-8")
    lang = LANG.read_text(encoding="utf-8")

    assert "DeletedBySender = 0x2000," in bottom_info_h
    assert '\"lng_deleted_by_sender\" = \"deleted\";' in lang
    assert "Data::Flag::DeletedBySender" in bottom_info_cpp
    assert "tr::lng_deleted_by_sender(tr::now)" in bottom_info_cpp
    assert "item->isDeletedBySender()" in bottom_info_cpp
    assert "result.flags |= Flag::DeletedBySender;" in bottom_info_cpp
    assert "_history->owner().notifyItemDataChange(this);" in history_source


if __name__ == "__main__":
    test_keep_deleted_messages_pref_defaults_on()
    test_deleted_by_sender_flag_and_marker_exist()
    test_delete_updates_keep_items_when_pref_enabled()
    test_late_loaded_unknown_deleted_messages_get_marker()
    test_kept_deleted_messages_show_bottom_info_marker()

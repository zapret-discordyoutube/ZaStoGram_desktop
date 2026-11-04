from pathlib import Path


SOURCES = Path(__file__).resolve().parents[1]


def source(relative):
    return (SOURCES / relative).read_text(encoding="utf-8")


def between(text, start, end):
    begin = text.index(start)
    return text[begin:text.index(end, begin)]


def test_settings_define_four_independent_ghost_switches():
    header = source("core/core_settings.h")

    for name in ("NoRead", "NoStories", "NoOnline", "NoTyping"):
        assert f"bool ghost{name}()" in header
        assert f"void setGhost{name}(bool value)" in header
        assert f'"zastoGhost{name}"' in header
    # Режим призрака выключен, пока пользователь сам его не включил.
    assert 'readPref<bool>("zastoGhostNoRead", false)' in header
    assert 'readPref<bool>("zastoGhostNoStories", false)' in header
    assert 'readPref<bool>("zastoGhostNoOnline", false)' in header
    assert 'readPref<bool>("zastoGhostNoTyping", false)' in header


def test_read_marks_are_not_sent_in_ghost_mode():
    histories = source("data/data_histories.cpp")
    body = between(
        histories,
        "void Histories::sendReadRequest(",
        "void Histories::checkEmptyState(")
    # Проверка стоит раньше любого запроса к серверу.
    assert body.index("ghostNoRead()") < body.index("MTPmessages_ReadHistory")
    assert body.index("ghostNoRead()") < body.index("MTPchannels_ReadHistory")
    assert body.index("ghostNoRead()") < body.index("sentReadTill = ")

    replies = source("data/data_replies_list.cpp")
    body = between(
        replies,
        "void RepliesList::sendReadTillRequest()",
        "void RepliesList::reloadUnreadCountIfNeeded()")
    assert body.index("ghostNoRead()") < body.index("MTPmessages_ReadDiscussion")


def test_story_views_are_not_sent_in_ghost_mode():
    stories = source("data/data_stories.cpp")
    body = between(
        stories,
        "void Stories::markAsRead(",
        "bool Stories::bumpReadTill(")
    assert "ghostNoStories()" in body
    # Ни счётчик просмотров, ни отметка «просмотрено» не должны запускаться.
    assert body.index("ghostNoStories()") < body.index("_incrementViewsPending")
    assert body.index("|| ghost") < body.index("_markReadPending")


def test_typing_is_not_sent_in_ghost_mode():
    progress = source("api/api_send_progress.cpp")
    body = between(
        progress,
        "void SendProgressManager::update(",
        "bool SendProgressManager::updated(")
    assert "ghostNoTyping()" in body
    assert body.index("ghostNoTyping()") < body.index("send(key, progress)")
    # Речь в групповом звонке этим переключателем не гасится.
    assert "SendProgressType::Speaking" in body


def test_online_status_is_not_sent_in_ghost_mode():
    updates = source("api/api_updates.cpp")
    body = between(
        updates,
        "void Updates::updateOnline(crl::time lastNonIdleTime, bool gotOtherOffline)",
        "void Updates::checkIdleFinish(")
    assert "ghostNoOnline()" in body
    assert body.index("ghostNoOnline()") < body.index("MTPaccount_UpdateStatus")


def test_settings_page_lists_every_switch():
    page = source("settings/sections/settings_advanced.cpp")

    assert "BuildGhostSection(builder);" in page
    for setter in ("setGhostNoRead", "setGhostNoStories",
                   "setGhostNoOnline", "setGhostNoTyping"):
        assert f"&Core::Settings::{setter}" in page


if __name__ == "__main__":
    for name, value in list(globals().items()):
        if name.startswith("test_") and callable(value):
            value()

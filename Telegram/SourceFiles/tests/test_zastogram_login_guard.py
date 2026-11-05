from pathlib import Path


SOURCES = Path(__file__).resolve().parents[1]
ROOT = SOURCES.parent


def source(relative):
    return (SOURCES / relative).read_text(encoding="utf-8")


def between(text, start, end):
    begin = text.index(start)
    return text[begin:text.index(end, begin)]


def test_guard_module_is_built():
    cmake = (ROOT / "CMakeLists.txt").read_text(encoding="utf-8")
    assert "core/zsg_login_guard.cpp" in cmake
    assert "core/zsg_login_guard.h" in cmake


def test_session_watches_login_codes():
    session = source("main/main_session.cpp")
    assert "Core::ZsgLoginGuard::Watch(this)" in session


def test_service_chat_cannot_be_forwarded():
    item = source("history/history_item.cpp")
    body = between(
        item,
        "bool HistoryItem::allowsForward() const",
        "bool HistoryItem::isTooOldForEdit(")
    assert "ZsgLoginGuard::BlocksForward(this)" in body


def test_login_code_is_not_sent_as_text():
    api = source("apiwrap.cpp")
    body = between(
        api,
        "void ApiWrap::sendMessage(",
        "const auto topicRootId = draftTopicRootId")
    assert "ZsgLoginGuard::CheckOutgoing(" in body
    # Проверка раньше любого действия: ни «печатает», ни локального сообщения.
    assert body.index("CheckOutgoing(") < body.index("sendAction(action)")
    assert body.index("CheckOutgoing(") < body.index("generateLocal = true")


def test_mini_apps_are_closed_when_code_arrives():
    guard = source("core/zsg_login_guard.cpp")
    body = between(guard, "void HandleNewItem(", "} // namespace\n")
    # Только входящие из служебного чата и только свежие.
    assert "item->out()" in body
    assert "IsLoginCodeChat(" in body
    assert "kFreshMessage" in body
    # Мини-приложения закрываются до диалога.
    assert body.index("closeAll()") < body.index("AskToBlock(")
    assert "openBots()" in body
    web = source("inline_bots/bot_attach_web_view.cpp")
    assert "AttachWebView::openBots() const" in web


def test_service_chat_is_exactly_777000():
    guard = source("core/zsg_login_guard.cpp")
    body = between(
        guard,
        "bool IsLoginCodeChat(",
        "bool BlocksForward(")
    assert "PeerData::kServiceNotificationsId" in body
    data = source("data/data_peer.h")
    assert "kServiceNotificationsId = peerFromUser(777000)" in data


def test_block_and_report_goes_together():
    guard = source("core/zsg_login_guard.cpp")
    body = between(guard, "void BlockAndReport(", "void LeaveWarning(")
    assert "blockedPeers().block(bot)" in body
    assert "MTPmessages_ReportSpam" in body


if __name__ == "__main__":
    for name, value in list(globals().items()):
        if name.startswith("test_") and callable(value):
            value()

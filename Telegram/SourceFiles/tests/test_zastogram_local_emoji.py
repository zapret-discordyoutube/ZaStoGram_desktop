from pathlib import Path


SOURCES = Path(__file__).resolve().parents[1]


def source(relative):
    return (SOURCES / relative).read_text(encoding="utf-8")


def between(text, start, end):
    begin = text.index(start)
    return text[begin:text.index(end, begin)]


def test_setting_is_on_by_default_and_has_a_toggle():
    header = source("core/core_settings.h")
    assert "bool localPremiumEmoji()" in header
    assert "void setLocalPremiumEmoji(bool value)" in header
    assert 'readPref<bool>("zastoLocalPremiumEmoji", true)' in header

    advanced = source("settings/sections/settings_advanced.cpp")
    assert "setLocalPremiumEmoji(" in advanced
    assert "BuildLocalEmojiSection(builder);" in advanced


def test_server_rule_helper_is_not_changed_by_the_local_mode():
    # Другие поля (опросы, подарки, приветствия) продолжают отправлять
    # эмодзи на сервер, поэтому общий помощник остаётся серверным правилом.
    body = between(
        source("data/stickers/data_custom_emoji.cpp"),
        "bool AllowEmojiWithoutPremium(",
        "bool AllowEmojiLocalOnly(")
    assert "localPremiumEmoji" not in body


def test_chat_surface_uses_the_local_mode():
    for relative in (
            "history/history_widget.cpp",
            "history/view/controls/history_view_compose_controls.cpp"):
        text = source(relative)
        assert "Data::AllowEmojiWithoutPremium(" not in text
        assert "Data::AllowEmojiInChat(" in text
    assert "AllowEmojiInChat(peer)" in source("chat_helpers/tabbed_selector.cpp")
    assert "AllowEmojiLocalOnly(_peer)" in source("history/history_widget.cpp")


def test_wire_never_gets_local_only_emoji():
    api = source("apiwrap.cpp")
    body = between(
        api,
        "void ApiWrap::sendMessage(",
        "void ApiWrap::sendBotStart(")
    assert "DropDisallowedCustomEmoji(peer, sending).entities" in body
    # Локальное сообщение строится из полного текста.
    assert "}, sending, media);" in body
    assert body.index("DropDisallowedCustomEmoji(peer, sending)") < body.index(
        "}, sending, media);")
    assert api.count("DropDisallowedCustomEmoji(") >= 4

    editing = source("api/api_editing.cpp")
    assert editing.count("DropDisallowedCustomEmoji(") == 2


def test_server_reply_keeps_local_only_emoji():
    item = source("history/history_item.cpp")
    assert "KeepLocalOnlyEmoji(" in item
    body = between(
        item,
        "[[nodiscard]] TextWithEntities KeepLocalOnlyEmoji(",
        "void HistoryItem::updateSentContent(const MTPDmessage &data)")
    # Только свой текст и только без Premium.
    assert "localPremiumEmoji()" in body
    assert "session->premium()" in body
    assert "current.text != received.text" in body
    assert "setText(KeepLocalOnlyEmoji(" in item

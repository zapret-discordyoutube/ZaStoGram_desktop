from pathlib import Path


SOURCES = Path(__file__).resolve().parents[1]


def source(relative):
    return (SOURCES / relative).read_text(encoding="utf-8")


def between(text, start, end):
    begin = text.index(start)
    return text[begin:text.index(end, begin)]


def test_folder_keeps_a_custom_emoji_icon_with_a_plain_fallback():
    header = source("data/data_chat_filters_tree.h")
    assert "uint64 iconCustom = 0;" in header
    assert "uint64 iconCustom = 0);" in header  # setIcon

    tree = source("data/data_chat_filters_tree.cpp")
    # В JSON ключ лишний только у тех, кто выбрал анимированный значок,
    # поэтому старые клиенты и Android читают обычный «icon».
    assert 'u"iconCustom"_q' in tree
    assert 'object.insert(u"icon"_q, folder.iconEmoji);' in tree
    # Синхронизация переносит значок вместе с запасным эмодзи.
    assert "folder->iconCustom = incoming.iconCustom;" in tree


def test_folder_title_gets_a_custom_emoji_entity_locally():
    filters = source("data/data_chat_filters.cpp")
    body = between(
        filters,
        "auto titleText = TextWithEntities{ .text = title };",
        "base::flat_set<not_null<History*>>());")
    assert "EntityType::CustomEmoji" in body
    assert "Data::SerializeCustomEmojiId(folder->iconCustom)" in body
    # Локальные папки на сервер не уходят, Premium для значка не нужен.
    assert "isPremium" not in body


def test_editor_saves_the_chosen_custom_icon():
    editor = source("boxes/filters/edit_local_folder_box.cpp")
    assert "customEmojiChosen(" in editor
    assert "*customIcon = data.document->id;" in editor
    assert "local.setIcon(target, icon->getLastText().trimmed(), *customIcon);" in editor
    # Ручной ввод сбрасывает анимированный значок.
    assert "*customIcon = 0; // Typed by hand" in editor
    # Premium-окно здесь не показывается.
    assert "ShowPremiumPreviewBox" not in editor


if __name__ == "__main__":
    for name, value in list(globals().items()):
        if name.startswith("test_") and callable(value):
            value()

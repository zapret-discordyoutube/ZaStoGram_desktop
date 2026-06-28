from pathlib import Path


SOURCE_DIR = Path(__file__).resolve().parents[1]
SOURCE = SOURCE_DIR / "boxes" / "connection_box.cpp"
HEADER = SOURCE_DIR / "boxes" / "connection_box.h"


def body_after(signature: str) -> str:
    text = SOURCE.read_text(encoding="utf-8")
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


def test_proxy_list_open_does_not_start_bulk_checks():
    constructor = body_after("ProxiesBoxController::ProxiesBoxController")

    assert "refreshChecker(" not in constructor


def test_proxy_rows_start_unchecked_and_offer_manual_check():
    header = HEADER.read_text(encoding="utf-8")
    paint = body_after("void ProxyRow::paintEvent")
    menu = body_after("void ProxyRow::showMenu")
    setup_buttons = body_after("void ProxiesBox::setupButtons")

    assert "Unknown," in header
    assert "ItemState state = ItemState::Unknown;" in header
    assert "rpl::producer<> checkClicks() const;" in SOURCE.read_text(
        encoding="utf-8")
    assert "case State::Unknown:" in paint
    assert "tr::lng_proxy_box_check_status(tr::now)" in paint
    assert "_checkClicks.fire({})" in menu
    assert "_controller->checkItem(id)" in setup_buttons


def test_explicit_proxy_changes_still_start_check():
    add_new = body_after("void ProxiesBoxController::addNewItem")
    replace = body_after("void ProxiesBoxController::replaceItemValue")

    assert "refreshChecker(_list.back())" in add_new
    assert "refreshChecker(*which)" in replace


if __name__ == "__main__":
    test_proxy_list_open_does_not_start_bulk_checks()
    test_proxy_rows_start_unchecked_and_offer_manual_check()
    test_explicit_proxy_changes_still_start_check()

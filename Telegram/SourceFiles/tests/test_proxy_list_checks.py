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


def test_proxy_window_open_path_does_not_start_probe_checks():
    bodies = [
        body_after("ProxiesBoxController::ProxiesBoxController"),
        body_after("object_ptr<Ui::BoxContent> ProxiesBoxController::create"),
        body_after("ProxiesBox::ProxiesBox("),
        body_after("void ProxiesBox::prepare"),
        body_after("void ProxiesBox::setupContent"),
        body_after("void ProxiesBox::applyView"),
        body_after("void ProxiesBox::setupButtons"),
    ]
    open_path = "\n".join(bodies)

    assert "refreshChecker(" not in open_path
    assert "MTP::StartProxyCheck(" not in open_path


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


def test_initial_proxy_rows_are_batched_on_open():
    source = SOURCE.read_text(encoding="utf-8")

    assert "void ProxiesBox::beginInitialRows()" in source
    assert "void ProxiesBox::finishInitialRows()" in source

    create = body_after("object_ptr<Ui::BoxContent> ProxiesBoxController::create")
    apply = body_after("void ProxiesBox::applyView")
    finish = body_after("void ProxiesBox::finishInitialRows")

    assert "result->beginInitialRows();" in create
    assert "for (auto i = _list.rbegin(); i != _list.rend(); ++i)" in create
    assert "updateView(*i);" in create
    assert "result->finishInitialRows();" in create
    assert "_initializingRows" in apply
    assert "wrap->add(" in apply
    assert "wrap->insert(" in apply
    assert "if (!_initializingRows)" in apply
    assert "wrap->resizeToWidth(st::proxySettingsListColumnWidth);" in finish


def test_proxy_switch_avoids_duplicate_row_and_rotation_updates():
    header = HEADER.read_text(encoding="utf-8")
    apply = body_after("void ProxiesBoxController::applyItem")
    settings = body_after("bool ProxiesBoxController::setProxySettings")

    assert "auto old = findByProxy(_settings.selected());" in apply
    assert "saveDelayed();" in apply
    assert "old->id != id" in apply
    assert "updateView(*old)" in apply
    assert "updateView(*item)" not in apply
    assert "Core::App().setCurrentProxy(_settings.selected(), value);" in settings
    assert "saveDelayed();" in settings


def test_explicit_proxy_changes_still_start_check():
    add_new = body_after("void ProxiesBoxController::addNewItem")
    replace = body_after("void ProxiesBoxController::replaceItemValue")

    assert "refreshChecker(_list.back())" in add_new
    assert "refreshChecker(*which)" in replace


if __name__ == "__main__":
    test_proxy_list_open_does_not_start_bulk_checks()
    test_proxy_window_open_path_does_not_start_probe_checks()
    test_proxy_rows_start_unchecked_and_offer_manual_check()
    test_initial_proxy_rows_are_batched_on_open()
    test_proxy_switch_avoids_duplicate_row_and_rotation_updates()
    test_explicit_proxy_changes_still_start_check()

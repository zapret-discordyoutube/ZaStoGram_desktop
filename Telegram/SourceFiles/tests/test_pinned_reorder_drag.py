from pathlib import Path


SOURCE_DIR = Path(__file__).resolve().parents[1]
INNER = SOURCE_DIR / "dialogs" / "dialogs_inner_widget.cpp"
PINNED_H = SOURCE_DIR / "dialogs" / "dialogs_pinned_list.h"
PINNED_CPP = SOURCE_DIR / "dialogs" / "dialogs_pinned_list.cpp"
SESSION_H = SOURCE_DIR / "data" / "data_session.h"
SESSION_CPP = SOURCE_DIR / "data" / "data_session.cpp"


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


def test_pinned_drag_batches_model_reorder_once_per_pointer_update():
    body = body_after(INNER, "bool InnerWidget::updateReorderPinned")

    assert "_shownList->movePinned(_dragging, shift);" in body
    assert "_shownList->movePinned(_dragging, -1);" not in body
    assert "_shownList->movePinned(_dragging, 1);" not in body


def test_pinned_model_supports_delta_move():
    pinned_header = PINNED_H.read_text(encoding="utf-8")
    pinned_source = PINNED_CPP.read_text(encoding="utf-8")
    session_header = SESSION_H.read_text(encoding="utf-8")
    session_source = SESSION_CPP.read_text(encoding="utf-8")

    assert "void move(Key key, int delta);" in pinned_header
    assert "void PinnedList::move(Key key, int delta)" in pinned_source
    assert "void movePinnedChat(" in session_header
    assert "void Session::movePinnedChat(" in session_source


if __name__ == "__main__":
    test_pinned_drag_batches_model_reorder_once_per_pointer_update()
    test_pinned_model_supports_delta_move()

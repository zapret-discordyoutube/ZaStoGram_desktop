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


def test_scheduler_api_and_build_registration():
    cmake = read("CMakeLists.txt")
    header = read("SourceFiles/chat_helpers/picker_animation_scheduler.h")
    source = read("SourceFiles/chat_helpers/picker_animation_scheduler.cpp")

    assert "chat_helpers/picker_animation_scheduler.cpp" in cmake
    assert "chat_helpers/picker_animation_scheduler.h" in cmake
    assert "enum class PickerAnimationKind" in header
    assert "struct PickerAnimationKey" in header
    assert "struct PickerAnimationLease" in header
    assert "class PickerAnimationScheduler" in header
    assert "kRepaintTick = crl::time(33)" in source
    assert "kColdStartTick = crl::time(50)" in source
    assert "kMaxClipStartsPerTick = 4" in source
    assert "kMaxVectorStartsPerTick = 8" in source


def test_tabbed_selector_owns_active_animation_gate():
    header = read("SourceFiles/chat_helpers/tabbed_selector.h")
    source = read("SourceFiles/chat_helpers/tabbed_selector.cpp")

    assert "PickerAnimationScheduler &animationScheduler() const" in header
    assert "void setAnimationActive(bool active);" in header
    assert "virtual void animationActiveChanged(bool active)" in header
    assert "std::unique_ptr<PickerAnimationScheduler> _animationScheduler;" in header
    assert "setAnimationActive(false)" in source
    assert "setAnimationActive(true)" in source


def test_inline_layout_items_expose_animation_lifecycle():
    header = read("SourceFiles/inline_bots/inline_bot_layout_item.h")
    source = read("SourceFiles/inline_bots/inline_bot_layout_internal.cpp")

    assert "PickerAnimationLease lease" in header
    assert "virtual void prepareAnimation(PickerAnimationLease lease) const" in header
    assert "virtual void stopAnimation() const" in header
    assert "void Gif::prepareAnimation(PickerAnimationLease lease) const" in source
    assert "void Gif::stopAnimation() const" in source


def test_gif_animation_work_is_outside_paint():
    source = read("SourceFiles/inline_bots/inline_bot_layout_internal.cpp")
    paint = function_body(
        source,
        "void Gif::paint(Painter &p, const QRect &clip, const PaintContext *context) const")
    prepare = function_body(source, "void Gif::prepareAnimation(")

    assert "automaticLoad(" not in paint
    assert "makeAnimation(" not in paint
    assert "ensureDataMediaCreated()" not in paint
    assert "automaticLoad(" in prepare
    assert "makeAnimation(" in prepare


def test_gif_picker_uses_visible_range_and_dirty_rects():
    header = read("SourceFiles/chat_helpers/gifs_list_widget.h")
    source = read("SourceFiles/chat_helpers/gifs_list_widget.cpp")
    repaint = function_body(
        source,
        "void GifsListWidget::inlineItemRepaint(")
    preload = function_body(source, "void GifsListWidget::preloadImages()")

    assert "void syncVisibleAnimations();" in header
    assert "void repaintItem(" in header
    assert "syncVisibleAnimations();" in source
    assert "queueRepaint(this" in repaint
    assert "updateInlineItems()" not in repaint
    assert "_mosaic.forEach" not in preload
    assert "forEachVisibleGif" in preload


def test_sticker_animation_work_is_outside_paint():
    header = read("SourceFiles/chat_helpers/stickers_list_widget.h")
    source = read("SourceFiles/chat_helpers/stickers_list_widget.cpp")
    paint = function_body(
        source,
        "void StickersListWidget::paintSticker(")
    callback = function_body(
        source,
        "void StickersListWidget::clipCallback(")

    assert "void syncVisibleAnimations();" in header
    assert "QRect stickerRect(" in header
    assert "setupLottie(" not in paint
    assert "setupWebm(" not in paint
    assert "queueRepaint(this" in callback
    assert "updateSet(info)" not in callback


def main() -> None:
    test_scheduler_api_and_build_registration()
    test_tabbed_selector_owns_active_animation_gate()
    test_inline_layout_items_expose_animation_lifecycle()
    test_gif_animation_work_is_outside_paint()
    test_gif_picker_uses_visible_range_and_dirty_rects()
    test_sticker_animation_work_is_outside_paint()


if __name__ == "__main__":
    main()

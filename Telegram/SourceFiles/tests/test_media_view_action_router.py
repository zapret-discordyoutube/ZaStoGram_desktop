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


def test_action_router_api_exists():
    header = read("SourceFiles/media/view/media_view_action_router.h")
    source = read("SourceFiles/media/view/media_view_action_router.cpp")

    assert "enum class Action" in header
    assert "StepFrame" in header
    assert "struct ActionContext" in header
    assert "struct ActionRequest" in header
    assert "struct ActionHandlers" in header
    assert "ResolveAction(" in header
    assert "ExecuteAction(" in header
    assert "ActionContext context" in header
    assert "enum class OpenRoute" in header
    assert "ResolveOpenRoute(" in header
    assert "ResolveAction(ActionContext context)" in source
    assert "ExecuteAction(" in source
    assert "ResolveOpenRoute(" in source
    assert "OpenRoute::MediaView" in source


def test_action_router_is_registered_in_build_list():
    source = read("CMakeLists.txt")

    assert "media/view/media_view_action_router.cpp" in source
    assert "media/view/media_view_action_router.h" in source


def test_ctrl_arrow_resolves_to_frame_step():
    source = read("SourceFiles/media/view/media_view_action_router.cpp")

    assert "Qt::Key_Left" in source
    assert "Qt::Key_Right" in source
    assert "Qt::ControlModifier" in source
    assert "Action::StepFrame" in source
    assert "direction = -1" in source
    assert "direction = 1" in source


def test_router_owns_chapter_and_legacy_frame_step_keys():
    header = read("SourceFiles/media/view/media_view_action_router.h")
    source = read("SourceFiles/media/view/media_view_action_router.cpp")
    overlay = read("SourceFiles/media/view/media_view_overlay_widget.cpp")

    assert "JumpChapter" in header
    assert "Action::JumpChapter" in source
    assert "context.hasTimestamps" in source
    assert "Qt::AltModifier" in source
    assert "Qt::Key_Period" in source
    assert "Qt::Key_Comma" in source
    assert "context.paused" in source
    assert "nextTimestamp" in overlay
    assert "prevTimestamp" in overlay
    assert "showChapterIndicator" in overlay


def test_overlay_delegates_media_keys_before_story_fallback():
    source = read("SourceFiles/media/view/media_view_overlay_widget.cpp")
    body = function_body(
        source,
        "void OverlayWidget::handleKeyPress(not_null<QKeyEvent*> e)")

    assert "Media::View::ResolveAction" in body
    assert "executeMediaViewAction" in body
    assert body.index("Media::View::ResolveAction") < body.index(
        "_stories->tryProcessKeyInput(e)")
    router = read("SourceFiles/media/view/media_view_action_router.cpp")

    assert "Action::StepFrame" in router
    assert "flushPendingFrameStep()" in source


def test_overlay_handle_keypress_no_longer_duplicates_router_actions():
    source = read("SourceFiles/media/view/media_view_overlay_widget.cpp")
    body = function_body(
        source,
        "void OverlayWidget::handleKeyPress(not_null<QKeyEvent*> e)")

    assert "const auto toggleFull" not in body
    assert "key == Qt::Key_K" not in body
    assert "key == Qt::Key_J" not in body
    assert "key == Qt::Key_L)" not in body
    assert "key == Qt::Key_Period" not in body
    assert "key == Qt::Key_Comma" not in body
    assert "restartAtProgress(index / 10.0)" not in body
    assert "seekRelativeTime(" not in body


def test_story_media_actions_keep_story_pause_state():
    source = read("SourceFiles/media/view/media_view_overlay_widget.cpp")
    body = function_body(
        source,
        "bool OverlayWidget::executeMediaViewAction(")

    assert "Media::View::ExecuteAction" in body
    assert "switch (request.action)" not in body
    assert "_stories->togglePaused(!_stories->paused())" in body
    assert "_stories->togglePaused(true)" in body


def test_video_message_open_routing_uses_shared_helper():
    source = read("SourceFiles/history/view/media/history_view_gif.cpp")
    text_state = function_body(source, "TextState Gif::textState(")
    play_animation = function_body(source, "void Gif::playAnimation(bool autoplay)")

    assert "media/view/media_view_action_router.h" in source
    assert "ResolveOpenRoute(_data)" in text_state
    assert "OpenRoute::MediaView" in text_state
    assert "} else if (_data->isVideoMessage()) {\n\t\t\tresult.link = _openl;" not in text_state
    assert "ResolveOpenRoute(_data)" in play_animation
    assert "OpenRoute::MediaView" in play_animation
    assert "elementOpenDocument(" in play_animation
    assert "if (_data->isVideoMessage() && !autoplay) {\n\t\treturn;" not in play_animation


def main() -> None:
    test_action_router_api_exists()
    test_action_router_is_registered_in_build_list()
    test_ctrl_arrow_resolves_to_frame_step()
    test_router_owns_chapter_and_legacy_frame_step_keys()
    test_overlay_delegates_media_keys_before_story_fallback()
    test_overlay_handle_keypress_no_longer_duplicates_router_actions()
    test_story_media_actions_keep_story_pause_state()
    test_video_message_open_routing_uses_shared_helper()


if __name__ == "__main__":
    main()

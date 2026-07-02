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


def test_story_streaming_is_seekable_and_has_controls():
    source = read("SourceFiles/media/view/media_view_overlay_widget.cpp")
    restart = function_body(
        source,
        "void OverlayWidget::restartAtSeekPosition(crl::time position)")
    create = function_body(
        source,
        "bool OverlayWidget::createStreamingObjects()")

    assert ".seekable = true" in restart
    assert ".seekable = !_stories" not in restart
    assert "streamingRequiresControls() || _stories" in create


def test_story_slider_exposes_seek_callbacks():
    delegate = read("SourceFiles/media/stories/media_stories_delegate.h")
    controller_h = read("SourceFiles/media/stories/media_stories_controller.h")
    controller_cpp = read("SourceFiles/media/stories/media_stories_controller.cpp")
    slider_h = read("SourceFiles/media/stories/media_stories_slider.h")
    slider_cpp = read("SourceFiles/media/stories/media_stories_slider.cpp")

    assert "virtual void storiesSeekProgress(float64 progress) = 0;" in delegate
    assert "virtual void storiesSeekFinished(float64 progress) = 0;" in delegate
    assert "void sliderSeekProgress(float64 progress);" in controller_h
    assert "void sliderSeekFinished(float64 progress);" in controller_h
    assert "Controller::sliderSeekProgress(float64 progress)" in controller_cpp
    assert "Controller::sliderSeekFinished(float64 progress)" in controller_cpp
    assert "handleSeekProgress(QPoint position)" in slider_h
    assert "handleSeekFinished(QPoint position)" in slider_h
    assert "QEvent::MouseButtonPress" in slider_cpp
    assert "QEvent::MouseMove" in slider_cpp
    assert "QEvent::MouseButtonRelease" in slider_cpp


def test_story_content_click_toggles_pause_on_release():
    source = read("SourceFiles/media/view/media_view_overlay_widget.cpp")
    release = function_body(source, "void OverlayWidget::handleMouseRelease(")

    assert "_storyContentPressTogglesPause" in source
    assert "_stories->togglePaused(!_stories->paused())" in release
    assert "_stories->contentPressed(false)" not in release


def test_video_message_content_click_opens_media_viewer():
    source = read("SourceFiles/history/view/media/history_view_gif.cpp")
    text_state = function_body(source, "TextState Gif::textState(")
    play_animation = function_body(source, "void Gif::playAnimation(bool autoplay)")
    pressed = function_body(
        source,
        "void Gif::clickHandlerPressedChanged(")

    assert "::Media::View::ResolveOpenRoute(_data)" in text_state
    assert "::Media::View::OpenRoute::MediaView" in text_state
    assert "::Media::View::ResolveOpenRoute(_data)" in play_animation
    assert "::Media::View::OpenRoute::MediaView" in play_animation
    assert "result.link = _openl;" in text_state
    assert "playPauseCancelClicked" not in pressed


def main() -> None:
    test_story_streaming_is_seekable_and_has_controls()
    test_story_slider_exposes_seek_callbacks()
    test_story_content_click_toggles_pause_on_release()
    test_video_message_content_click_opens_media_viewer()


if __name__ == "__main__":
    main()

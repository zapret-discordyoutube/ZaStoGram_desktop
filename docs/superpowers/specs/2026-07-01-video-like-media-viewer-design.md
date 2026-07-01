# Video-Like Media Viewer Controls Design

Date: 2026-07-01

## Goal

Make all video-like viewing feel like one precise video player:

- stories can be paused by tapping the visible story content
- stories can be scrubbed with drag seeking instead of only auto-progress
- video messages open in the full media viewer on single click
- a click on video content inside the media viewer toggles pause/play
- seek behavior uses the existing media viewer playback controls where possible
- paused video keeps precise frame stepping through the existing fps-based path

## Current Behavior

The media viewer already owns normal video playback controls through
`Media::View::PlaybackControls`, including continuous slider drag callbacks.
The same overlay has frame-step support for paused videos through
`OverlayWidget::flushPendingFrameStep()`.

Stories use the media viewer overlay, but story playback is deliberately not
seekable today: `OverlayWidget::restartAtSeekPosition()` sets
`PlaybackOptions::seekable` to false for stories, and playback controls are not
created for story streams. The story progress bar is visual-only and does not
handle mouse drag seeking.

Round video messages are still routed like voice/video messages in the chat
player path. `HistoryView::Gif` has a circular progress/seek interaction for
active round playback, but the user-facing model is still "round message in
chat", not "open as a video".

## Recommended Approach

Use the media viewer as the primary video surface.

### Stories

Story video documents should be seekable in the media viewer. The story progress
bar should become interactive for the active segment: pressing and dragging maps
the pointer to a playback progress value, pauses playback during the drag, and
seeks to the selected position on release. A simple tap on story content toggles
pause/play unless the tap is consumed by an existing story control, caption,
navigation button, reaction, menu, or slider drag.

Story auto-advance should stay tied to real playback completion. Manual seek
must not immediately advance to the next story unless the player actually
reaches the end after the seek.

### Video Messages

Single-clicking a video message in the chat opens the media viewer with
`showInMediaView = true`. The old chat-surface play/pause is no longer the
primary action for video messages. Existing download, spoiler, TTL, transcribe,
and context-menu behavior must keep their current priority before the open
action.

Inside the media viewer, clicking the video content toggles pause/play for
video documents, including video messages. Existing drag, menu, navigation,
caption, and control interactions keep priority over that content-click toggle.

### Precise Seeking

Normal viewer seeking should keep using `PlaybackControls` so drag progress and
release seek use one shared path for regular videos, video messages, and story
videos. While the user drags the progress control, the player should pause and
show the target time. On release it should restart at the exact selected
position and resume only if playback was running before the drag.

Paused frame stepping should reuse the existing fps-based overlay path. The
change does not add a new decoder or frame indexer; it makes the existing
viewer behavior consistently reachable for video-like media.

## Components

- `media/view/media_view_overlay_widget.*`
  - allow story streams to be seekable
  - allow controls for story video where useful
  - route content clicks to pause/play for viewer video
  - keep controls/caption/navigation priority unchanged

- `media/stories/media_stories_slider.*`
  - add active-segment drag/tap mapping to progress
  - call back into the stories delegate for seek progress and seek finish

- `media/stories/media_stories_delegate.h`
  - expose story seek progress and seek finish callbacks from the slider to the
    overlay

- `history/view/media/history_view_gif.*`
  - route single-click video messages to `elementOpenDocument(..., true)`
  - preserve existing higher-priority links and controls

## Error Handling

If a story has no seekable video stream, slider interaction should do nothing
and leave the current visual-only behavior intact. If a seek target is outside
the media duration, clamp it to the valid range. If a stream fails or finishes
while the user is dragging, cancel the drag state and keep the viewer stable.

## Testing

No compile/build is part of the default verification for this WSL checkout
unless explicitly requested.

Focused verification should include:

- a source guard that story playback no longer hard-disables seekability
- a source guard that story slider exposes seek callbacks
- a source guard that video-message click routing opens the media viewer
- `git diff --check`

Manual runtime verification, when a build is requested, should cover:

- story tap pauses and resumes
- story progress drag seeks without accidental story advance
- video message single click opens the viewer
- viewer content click toggles pause/play
- viewer progress drag is precise enough for short videos
- paused frame-step keys still move one frame at a time

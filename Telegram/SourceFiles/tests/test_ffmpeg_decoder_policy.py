from pathlib import Path


SOURCE_DIR = Path(__file__).resolve().parents[1]
FFMPEG_HEADER = SOURCE_DIR / "ffmpeg" / "ffmpeg_utility.h"
FFMPEG_SOURCE = SOURCE_DIR / "ffmpeg" / "ffmpeg_utility.cpp"
CLIP_SOURCE = SOURCE_DIR / "media" / "clip" / "media_clip_ffmpeg.cpp"
CLIP_READER_SOURCE = SOURCE_DIR / "media" / "clip" / "media_clip_reader.cpp"


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


def test_ffmpeg_decoder_threads_have_shared_policy():
    header = FFMPEG_HEADER.read_text(encoding="utf-8")
    ffmpeg = FFMPEG_SOURCE.read_text(encoding="utf-8")
    make_codec = body_after(FFMPEG_SOURCE, "CodecPointer MakeCodecPointer")
    clip = CLIP_SOURCE.read_text(encoding="utf-8")

    assert "ConfigureDecoderThreads(not_null<AVCodecContext*> context);" in header
    assert "kMaxSoftwareVideoDecoderThreads = 2" in ffmpeg
    assert "\"threads\", \"auto\"" not in ffmpeg

    # The capped default applies unless the experimental options are tuned.
    configure = body_after(FFMPEG_SOURCE, "void ConfigureDecoderThreads")
    assert "OptionFFmpegThreadCount.value()" in configure
    assert "OptionFFmpegMultiThread.value()" in configure
    assert "kMaxSoftwareVideoDecoderThreads" in configure
    assert "FF_THREAD_FRAME" in configure
    assert "ConfigureDecoderThreads(context);" in make_codec
    assert (
        make_codec.index("ConfigureDecoderThreads(context);")
        < make_codec.index("const auto codec = FindDecoder(context);")
    )
    assert "FFmpeg::ConfigureDecoderThreads(_codecContext);" in clip
    assert (
        clip.index("FFmpeg::ConfigureDecoderThreads(_codecContext);")
        < clip.index("const auto codec = FFmpeg::FindDecoder(_codecContext);")
    )


def test_clip_reader_queues_decoder_starts_under_load():
    reader = CLIP_READER_SOURCE.read_text(encoding="utf-8")
    process = body_after(CLIP_READER_SOURCE, "void Manager::process")

    assert "kBusyClipReadersForStartThrottle" in reader
    assert "kQueuedClipStartDelay" in reader
    assert "bool hasDecoder() const" in reader
    assert "bool needsDecoderStart() const" in reader
    assert "needsDecoderStart()" in process
    assert "busyReaders >= kBusyClipReadersForStartThrottle" in process


def test_clip_reader_start_queue_never_starves_a_reader():
    reader = CLIP_READER_SOURCE.read_text(encoding="utf-8")
    process = body_after(CLIP_READER_SOURCE, "void Manager::process")
    decoding = body_after(CLIP_READER_SOURCE, "bool decoding() const")

    # Paused readers keep their decoder but do no work, so they must not
    # count as load: the media preview pauses every other clip and still
    # has to start its own one.
    assert "_implementation" in decoding
    assert "!_autoPausedGif" in decoding
    assert "!_videoPausedAtMs" in decoding
    assert "i.key()->decoding()" in process
    assert "i.key()->hasDecoder()" not in process

    # The queue is a delay with a deadline, not a cap: a waiting reader is
    # rescheduled to the moment the next start is allowed and starts then.
    assert "crl::time _nextQueuedStartAt = 0;" in reader
    assert "&& ms < _nextQueuedStartAt" in process
    assert "i.value() = _nextQueuedStartAt;" in process
    assert "_nextQueuedStartAt = ms + kQueuedClipStartDelay;" in process
    assert "kMaxStartedClipReadersPerWorker" not in reader

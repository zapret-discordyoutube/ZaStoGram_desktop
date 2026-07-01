from pathlib import Path


SOURCE_DIR = Path(__file__).resolve().parents[1]
ROOT = SOURCE_DIR.parents[1]
MIME_H = SOURCE_DIR / "core" / "mime_type.h"
MIME_CPP = SOURCE_DIR / "core" / "mime_type.cpp"
PHOTO_MEDIA_CPP = SOURCE_DIR / "data" / "data_photo_media.cpp"
MEDIA_VIEW_CPP = SOURCE_DIR / "media" / "view" / "media_view_overlay_widget.cpp"
PEER_QR_CPP = SOURCE_DIR / "ui" / "boxes" / "peer_qr_box.cpp"
WIN_CLIPBOARD_H = SOURCE_DIR / "platform" / "win" / "media_clipboard_win.h"
WIN_CLIPBOARD_CPP = SOURCE_DIR / "platform" / "win" / "media_clipboard_win.cpp"
CMAKE = ROOT / "Telegram" / "CMakeLists.txt"


def test_media_clipboard_payload_is_central_api():
    header = MIME_H.read_text(encoding="utf-8")

    assert "struct MediaClipboardPayload" in header
    assert "QByteArray content;" in header
    assert "QString mime;" in header
    assert "QImage image;" in header
    assert "QString filepath;" in header
    assert "QString suggestedName;" in header
    assert "bool alreadyTransformed = false;" in header
    assert "bool SetMediaClipboard(MediaClipboardPayload &&payload);" in header


def test_paste_prefers_valid_encoded_image_before_raw_image_data():
    source = MIME_CPP.read_text(encoding="utf-8")
    read_start = source.index("MimeImageData ReadMimeImage")
    read_body = source[read_start:source.index("QString ReadMimeText", read_start)]

    marker = 'data->hasFormat(u"application/x-td-use-jpeg"_q)'
    jpeg = 'ReadEncodedImage(data, u"image/jpeg"_q)'
    png = 'ReadEncodedImage(data, u"image/png"_q)'
    raw = "qvariant_cast<QImage>(data->imageData())"

    assert marker in read_body
    assert jpeg in read_body
    assert png in read_body
    assert raw in read_body
    assert read_body.index(marker) < read_body.index(png)
    assert read_body.index(png) < read_body.index(raw)
    assert read_body.count(jpeg) >= 2
    assert "else if (data->hasImage())" not in read_body


def test_windows_backend_uses_ole_data_object_without_flush():
    header = WIN_CLIPBOARD_H.read_text(encoding="utf-8")
    source = WIN_CLIPBOARD_CPP.read_text(encoding="utf-8")
    cmake = CMAKE.read_text(encoding="utf-8")

    assert "bool SetMediaClipboard(" in header
    assert "IDataObject" in source
    assert "IEnumFORMATETC" in source
    assert "OleSetClipboard" in source
    assert "OleFlushClipboard" not in source
    assert "CF_HDROP" in source
    assert "CF_DIB" in source
    assert "RegisterClipboardFormat" in source
    assert "platform/win/media_clipboard_win.cpp" in cmake
    assert "platform/win/media_clipboard_win.h" in cmake


def test_image_copy_call_sites_use_media_clipboard_api():
    photo_media = PHOTO_MEDIA_CPP.read_text(encoding="utf-8")
    media_view = MEDIA_VIEW_CPP.read_text(encoding="utf-8")
    peer_qr = PEER_QR_CPP.read_text(encoding="utf-8")

    assert "Core::SetMediaClipboard" in photo_media
    assert "Core::SetMediaClipboard" in media_view
    assert "Core::SetMediaClipboard" in peer_qr
    assert "QGuiApplication::clipboard()->setMimeData" not in photo_media
    assert "QGuiApplication::clipboard()->setMimeData" not in media_view
    assert "QGuiApplication::clipboard()->setMimeData" not in peer_qr


def test_void_media_clipboard_call_sites_discard_result_explicitly():
    media_view = MEDIA_VIEW_CPP.read_text(encoding="utf-8")
    peer_qr = PEER_QR_CPP.read_text(encoding="utf-8")

    assert "(void)Core::SetMediaClipboard({" in media_view
    assert "(void)Core::SetMediaClipboard({" in peer_qr

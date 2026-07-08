from pathlib import Path


SOURCE_DIR = Path(__file__).resolve().parents[1]
MTPROTO_DEDICATED_H = (
    SOURCE_DIR / "mtproto" / "files" / "dedicated_file_loader.h")
MTPROTO_DEDICATED_CPP = (
    SOURCE_DIR / "mtproto" / "files" / "dedicated_file_loader.cpp")
STORAGE_CLOUD_BLOB_H = SOURCE_DIR / "storage" / "storage_cloud_blob.h"
STORAGE_CLOUD_BLOB_CPP = SOURCE_DIR / "storage" / "storage_cloud_blob.cpp"
DOWNLOAD_MANAGER_H = SOURCE_DIR / "storage" / "download_manager_mtproto.h"
DOWNLOAD_MANAGER_CPP = SOURCE_DIR / "storage" / "download_manager_mtproto.cpp"
FILE_DOWNLOAD_MTPROTO_H = SOURCE_DIR / "storage" / "file_download_mtproto.h"
FILE_DOWNLOAD_MTPROTO_CPP = SOURCE_DIR / "storage" / "file_download_mtproto.cpp"
FILE_UPLOAD_H = SOURCE_DIR / "storage" / "file_upload.h"
FILE_UPLOAD_CPP = SOURCE_DIR / "storage" / "file_upload.cpp"
STREAMED_DOWNLOADER_H = SOURCE_DIR / "storage" / "streamed_file_downloader.h"
STREAMED_DOWNLOADER_CPP = SOURCE_DIR / "storage" / "streamed_file_downloader.cpp"


def read(path):
    assert path.exists(), f"missing expected source file: {path}"
    return path.read_text(encoding="utf-8")


def test_dedicated_loader_is_small_update_cloud_blob_loader():
    header = read(MTPROTO_DEDICATED_H)
    source = read(MTPROTO_DEDICATED_CPP)
    cloud_blob = read(STORAGE_CLOUD_BLOB_H) + "\n" + read(STORAGE_CLOUD_BLOB_CPP)

    assert "class DedicatedLoader" in header
    assert "static constexpr auto kRequestsCount = 2;" in header
    assert "MTPupload_GetFile(" in source
    assert "base::call_delayed(kNextRequestDelay" in source
    assert '#include "mtproto/files/dedicated_file_loader.h"' in cloud_blob
    assert "std::unique_ptr<MTP::DedicatedLoader>" in cloud_blob


def test_storage_owns_primary_mtproto_media_download_pipeline():
    manager = read(DOWNLOAD_MANAGER_H) + "\n" + read(DOWNLOAD_MANAGER_CPP)
    mtproto_download = (
        read(FILE_DOWNLOAD_MTPROTO_H)
        + "\n"
        + read(FILE_DOWNLOAD_MTPROTO_CPP))
    streamed = read(STREAMED_DOWNLOADER_H) + "\n" + read(STREAMED_DOWNLOADER_CPP)

    assert "class DownloadManagerMtproto final" in manager
    assert "class DownloadMtprotoTask" in manager
    assert "kStartSessionsCount = 1" in manager
    assert "kMaxSessionsCount = 8" in manager
    assert "trySendNextPart(" in manager
    assert "requestSucceeded(" in manager
    assert "class mtpFileLoader final" in mtproto_download
    assert "private Storage::DownloadMtprotoTask" in mtproto_download
    assert "class StreamedFileDownloader final : public FileLoader" in streamed
    assert "Media::Streaming::Reader" in streamed


def test_storage_owns_primary_media_upload_pipeline():
    upload = read(FILE_UPLOAD_H) + "\n" + read(FILE_UPLOAD_CPP)

    assert "class Uploader final" in upload
    assert "MTPupload_SaveFilePart" in upload
    assert "MTPupload_SaveBigFilePart" in upload
    assert "kUseBigFilesFrom" in upload


def test_primary_media_pipeline_does_not_include_dedicated_loader():
    primary_sources = "\n".join(
        read(path)
        for path in (
            DOWNLOAD_MANAGER_H,
            DOWNLOAD_MANAGER_CPP,
            FILE_DOWNLOAD_MTPROTO_H,
            FILE_DOWNLOAD_MTPROTO_CPP,
            FILE_UPLOAD_H,
            FILE_UPLOAD_CPP,
            STREAMED_DOWNLOADER_H,
            STREAMED_DOWNLOADER_CPP,
        ))

    assert "mtproto/files/dedicated_file_loader.h" not in primary_sources
    assert "DedicatedLoader" not in primary_sources

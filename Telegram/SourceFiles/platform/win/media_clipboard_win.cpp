/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "platform/win/media_clipboard_win.h"

#include "core/mime_type.h"

#include <QtCore/QBuffer>
#include <QtCore/QDir>
#include <QtCore/QFileInfo>
#include <QtCore/QIODevice>
#include <QtCore/QString>
#include <QtGui/QImage>

#include <ObjIdl.h>
#include <Ole2.h>
#include <ShlObj_core.h>
#include <Shellapi.h>
#include <Windows.h>

#include <algorithm>
#include <atomic>
#include <cstring>
#include <utility>
#include <vector>

namespace Platform {
namespace {

enum class EntryType {
	FileDrop,
	Encoded,
	PngFromImage,
	Dib,
	DibV5,
};

struct FormatEntry {
	FORMATETC format = {};
	EntryType type = EntryType::Encoded;
};

[[nodiscard]] HGLOBAL BytesToGlobal(const QByteArray &bytes) {
	if (bytes.isEmpty()) {
		return nullptr;
	}
	const auto size = SIZE_T(bytes.size());
	const auto result = ::GlobalAlloc(GMEM_MOVEABLE, size);
	if (!result) {
		return nullptr;
	}
	const auto locked = ::GlobalLock(result);
	if (!locked) {
		::GlobalFree(result);
		return nullptr;
	}
	memcpy(locked, bytes.constData(), size);
	::GlobalUnlock(result);
	return result;
}

[[nodiscard]] QByteArray EncodePng(const QImage &image) {
	if (image.isNull()) {
		return {};
	}
	auto result = QByteArray();
	auto buffer = QBuffer(&result);
	if (!buffer.open(QIODevice::WriteOnly) || !image.save(&buffer, "PNG")) {
		return {};
	}
	return result;
}

[[nodiscard]] HGLOBAL FileDropToGlobal(const QString &filepath) {
	if (filepath.isEmpty()) {
		return nullptr;
	}
	const auto native = QDir::toNativeSeparators(filepath).toStdWString();
	const auto chars = native.size() + 2;
	const auto bytes = sizeof(DROPFILES) + (chars * sizeof(wchar_t));
	const auto result = ::GlobalAlloc(GMEM_MOVEABLE | GMEM_ZEROINIT, bytes);
	if (!result) {
		return nullptr;
	}
	const auto locked = ::GlobalLock(result);
	if (!locked) {
		::GlobalFree(result);
		return nullptr;
	}
	auto drop = static_cast<DROPFILES*>(locked);
	drop->pFiles = sizeof(DROPFILES);
	drop->fWide = TRUE;
	memcpy(
		static_cast<char*>(locked) + sizeof(DROPFILES),
		native.data(),
		native.size() * sizeof(wchar_t));
	::GlobalUnlock(result);
	return result;
}

[[nodiscard]] QImage PayloadImage(const Core::MediaClipboardPayload &payload) {
	if (!payload.image.isNull()) {
		return payload.image;
	}
	return payload.content.isEmpty()
		? QImage()
		: QImage::fromData(payload.content);
}

[[nodiscard]] HGLOBAL ImageToDibGlobal(
		const Core::MediaClipboardPayload &payload,
		bool v5) {
	auto image = PayloadImage(payload);
	if (image.isNull()) {
		return nullptr;
	}
	image = image.convertToFormat(QImage::Format_ARGB32);
	const auto width = image.width();
	const auto height = image.height();
	if (width <= 0 || height <= 0) {
		return nullptr;
	}
	const auto headerSize = v5 ? sizeof(BITMAPV5HEADER) : sizeof(BITMAPINFOHEADER);
	const auto stride = SIZE_T(width) * 4;
	const auto imageBytes = stride * SIZE_T(height);
	const auto result = ::GlobalAlloc(
		GMEM_MOVEABLE | GMEM_ZEROINIT,
		headerSize + imageBytes);
	if (!result) {
		return nullptr;
	}
	const auto locked = ::GlobalLock(result);
	if (!locked) {
		::GlobalFree(result);
		return nullptr;
	}
	if (v5) {
		auto header = static_cast<BITMAPV5HEADER*>(locked);
		header->bV5Size = sizeof(BITMAPV5HEADER);
		header->bV5Width = width;
		header->bV5Height = -height;
		header->bV5Planes = 1;
		header->bV5BitCount = 32;
		header->bV5Compression = BI_BITFIELDS;
		header->bV5RedMask = 0x00FF0000;
		header->bV5GreenMask = 0x0000FF00;
		header->bV5BlueMask = 0x000000FF;
		header->bV5AlphaMask = 0xFF000000;
		header->bV5CSType = LCS_sRGB;
	} else {
		auto header = static_cast<BITMAPINFOHEADER*>(locked);
		header->biSize = sizeof(BITMAPINFOHEADER);
		header->biWidth = width;
		header->biHeight = -height;
		header->biPlanes = 1;
		header->biBitCount = 32;
		header->biCompression = BI_RGB;
		header->biSizeImage = DWORD(imageBytes);
	}
	auto bits = static_cast<uchar*>(locked) + headerSize;
	for (auto y = 0; y != height; ++y) {
		memcpy(bits + (stride * y), image.constScanLine(y), stride);
	}
	::GlobalUnlock(result);
	return result;
}

[[nodiscard]] CLIPFORMAT RegisteredFormat(const wchar_t *name) {
	return static_cast<CLIPFORMAT>(::RegisterClipboardFormatW(name));
}

[[nodiscard]] FORMATETC MakeFormat(CLIPFORMAT format) {
	return FORMATETC{
		.cfFormat = format,
		.ptd = nullptr,
		.dwAspect = DVASPECT_CONTENT,
		.lindex = -1,
		.tymed = TYMED_HGLOBAL,
	};
}

[[nodiscard]] bool FormatMatches(
		const FORMATETC &requested,
		const FORMATETC &offered) {
	return (requested.cfFormat == offered.cfFormat)
		&& (requested.dwAspect & offered.dwAspect)
		&& (requested.tymed & offered.tymed)
		&& (requested.lindex == -1 || offered.lindex == requested.lindex);
}

class FormatEnumerator final : public IEnumFORMATETC {
public:
	explicit FormatEnumerator(
		std::vector<FORMATETC> formats,
		ULONG index = 0)
	: _formats(std::move(formats))
	, _index(index) {
	}

	HRESULT STDMETHODCALLTYPE QueryInterface(
			REFIID riid,
			void **object) override {
		if (!object) {
			return E_POINTER;
		}
		*object = nullptr;
		if (riid == IID_IUnknown || riid == IID_IEnumFORMATETC) {
			*object = static_cast<IEnumFORMATETC*>(this);
			AddRef();
			return S_OK;
		}
		return E_NOINTERFACE;
	}

	ULONG STDMETHODCALLTYPE AddRef() override {
		return ++_refs;
	}

	ULONG STDMETHODCALLTYPE Release() override {
		const auto result = --_refs;
		if (!result) {
			delete this;
		}
		return result;
	}

	HRESULT STDMETHODCALLTYPE Next(
			ULONG count,
			FORMATETC *formats,
			ULONG *fetched) override {
		if (!formats || (count > 1 && !fetched)) {
			return E_POINTER;
		}
		auto copied = ULONG(0);
		while (copied != count && _index < _formats.size()) {
			formats[copied++] = _formats[_index++];
		}
		if (fetched) {
			*fetched = copied;
		}
		return (copied == count) ? S_OK : S_FALSE;
	}

	HRESULT STDMETHODCALLTYPE Skip(ULONG count) override {
		_index = std::min<ULONG>(
			ULONG(_formats.size()),
			_index + count);
		return (_index < _formats.size()) ? S_OK : S_FALSE;
	}

	HRESULT STDMETHODCALLTYPE Reset() override {
		_index = 0;
		return S_OK;
	}

	HRESULT STDMETHODCALLTYPE Clone(IEnumFORMATETC **result) override {
		if (!result) {
			return E_POINTER;
		}
		*result = new FormatEnumerator(_formats, _index);
		return S_OK;
	}

private:
	std::atomic<ULONG> _refs = 1;
	std::vector<FORMATETC> _formats;
	ULONG _index = 0;
};

class MediaDataObject final : public IDataObject {
public:
	explicit MediaDataObject(Core::MediaClipboardPayload &&payload)
	: _payload(std::move(payload)) {
		prepareFormats();
	}

	HRESULT STDMETHODCALLTYPE QueryInterface(
			REFIID riid,
			void **object) override {
		if (!object) {
			return E_POINTER;
		}
		*object = nullptr;
		if (riid == IID_IUnknown || riid == IID_IDataObject) {
			*object = static_cast<IDataObject*>(this);
			AddRef();
			return S_OK;
		}
		return E_NOINTERFACE;
	}

	ULONG STDMETHODCALLTYPE AddRef() override {
		return ++_refs;
	}

	ULONG STDMETHODCALLTYPE Release() override {
		const auto result = --_refs;
		if (!result) {
			delete this;
		}
		return result;
	}

	HRESULT STDMETHODCALLTYPE GetData(
			FORMATETC *format,
			STGMEDIUM *medium) override {
		if (!format || !medium) {
			return E_POINTER;
		}
		for (const auto &entry : _entries) {
			if (!FormatMatches(*format, entry.format)) {
				continue;
			}
			auto handle = HGLOBAL(nullptr);
			switch (entry.type) {
			case EntryType::FileDrop:
				handle = FileDropToGlobal(_payload.filepath);
				break;
			case EntryType::Encoded:
				handle = BytesToGlobal(_payload.content);
				break;
			case EntryType::PngFromImage:
				handle = BytesToGlobal(EncodePng(PayloadImage(_payload)));
				break;
			case EntryType::Dib:
				handle = ImageToDibGlobal(_payload, false);
				break;
			case EntryType::DibV5:
				handle = ImageToDibGlobal(_payload, true);
				break;
			}
			if (!handle) {
				return STG_E_MEDIUMFULL;
			}
			medium->tymed = TYMED_HGLOBAL;
			medium->hGlobal = handle;
			medium->pUnkForRelease = nullptr;
			return S_OK;
		}
		return DV_E_FORMATETC;
	}

	HRESULT STDMETHODCALLTYPE GetDataHere(
			FORMATETC*,
			STGMEDIUM*) override {
		return DATA_E_FORMATETC;
	}

	HRESULT STDMETHODCALLTYPE QueryGetData(FORMATETC *format) override {
		if (!format) {
			return E_POINTER;
		}
		for (const auto &entry : _entries) {
			if (FormatMatches(*format, entry.format)) {
				return S_OK;
			}
		}
		return DV_E_FORMATETC;
	}

	HRESULT STDMETHODCALLTYPE GetCanonicalFormatEtc(
			FORMATETC*,
			FORMATETC *format) override {
		if (format) {
			format->ptd = nullptr;
		}
		return E_NOTIMPL;
	}

	HRESULT STDMETHODCALLTYPE SetData(
			FORMATETC*,
			STGMEDIUM*,
			BOOL) override {
		return E_NOTIMPL;
	}

	HRESULT STDMETHODCALLTYPE EnumFormatEtc(
			DWORD direction,
			IEnumFORMATETC **result) override {
		if (!result) {
			return E_POINTER;
		}
		*result = nullptr;
		if (direction != DATADIR_GET) {
			return E_NOTIMPL;
		}
		auto formats = std::vector<FORMATETC>();
		formats.reserve(_entries.size());
		for (const auto &entry : _entries) {
			formats.push_back(entry.format);
		}
		*result = new FormatEnumerator(std::move(formats));
		return S_OK;
	}

	HRESULT STDMETHODCALLTYPE DAdvise(
			FORMATETC*,
			DWORD,
			IAdviseSink*,
			DWORD*) override {
		return OLE_E_ADVISENOTSUPPORTED;
	}

	HRESULT STDMETHODCALLTYPE DUnadvise(DWORD) override {
		return OLE_E_ADVISENOTSUPPORTED;
	}

	HRESULT STDMETHODCALLTYPE EnumDAdvise(
			IEnumSTATDATA**) override {
		return OLE_E_ADVISENOTSUPPORTED;
	}

private:
	void add(CLIPFORMAT format, EntryType type) {
		if (!format) {
			return;
		}
		_entries.push_back({
			.format = MakeFormat(format),
			.type = type,
		});
	}

	void addEncodedFormats() {
		if (_payload.mime == u"image/png"_q) {
			if (_payload.content.isEmpty()) {
				if (!_payload.image.isNull()) {
					add(RegisteredFormat(L"PNG"), EntryType::PngFromImage);
					add(RegisteredFormat(L"image/png"), EntryType::PngFromImage);
				}
			} else {
				add(RegisteredFormat(L"PNG"), EntryType::Encoded);
				add(RegisteredFormat(L"image/png"), EntryType::Encoded);
			}
		} else if (_payload.mime == u"image/jpeg"_q) {
			if (!_payload.content.isEmpty()) {
				add(RegisteredFormat(L"JFIF"), EntryType::Encoded);
				add(RegisteredFormat(L"JPEG"), EntryType::Encoded);
				add(RegisteredFormat(L"image/jpeg"), EntryType::Encoded);
			}
		} else if (!_payload.image.isNull()) {
			add(RegisteredFormat(L"PNG"), EntryType::PngFromImage);
			add(RegisteredFormat(L"image/png"), EntryType::PngFromImage);
		}
	}

	void prepareFormats() {
		if (!_payload.filepath.isEmpty()
			&& QFileInfo(_payload.filepath).isFile()) {
			add(CF_HDROP, EntryType::FileDrop);
		}
		addEncodedFormats();
		if (!PayloadImage(_payload).isNull()) {
			add(CF_DIBV5, EntryType::DibV5);
			add(CF_DIB, EntryType::Dib);
		}
	}

	std::atomic<ULONG> _refs = 1;
	Core::MediaClipboardPayload _payload;
	std::vector<FormatEntry> _entries;
};

} // namespace

bool SetMediaClipboard(Core::MediaClipboardPayload &&payload) {
	if (payload.content.isEmpty()
		&& payload.image.isNull()
		&& payload.filepath.isEmpty()) {
		return false;
	}
	const auto object = new MediaDataObject(std::move(payload));
	const auto hr = ::OleSetClipboard(object);
	object->Release();
	return SUCCEEDED(hr);
}

} // namespace Platform

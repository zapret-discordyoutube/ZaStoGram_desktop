/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "e2e_cloud/storage/file_atomic_blob_store.h"

#include <QtCore/QDir>
#include <QtCore/QFile>
#include <QtCore/QFileInfo>
#include <QtCore/QSaveFile>

#include <utility>

namespace E2ECloud {

FileAtomicBlobStore::FileAtomicBlobStore(QString path)
: _path(std::move(path)) {
}

BlobReadResult FileAtomicBlobStore::read() const {
	auto file = QFile(_path);
	if (!file.exists()) {
		return {
			.status = BlobReadStatus::Missing,
			.bytes = {},
		};
	} else if (!file.open(QIODevice::ReadOnly)) {
		return {
			.status = BlobReadStatus::Error,
			.bytes = {},
		};
	}
	return {
		.status = BlobReadStatus::Found,
		.bytes = file.readAll(),
	};
}

bool FileAtomicBlobStore::writeAtomic(const QByteArray &bytes) {
	const auto directory = QFileInfo(_path).absoluteDir();
	if (!directory.exists() && !QDir().mkpath(directory.absolutePath())) {
		return false;
	}
	auto file = QSaveFile(_path);
	if (!file.open(QIODevice::WriteOnly)) {
		return false;
	}
	file.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner);
	if (file.write(bytes) != bytes.size()) {
		file.cancelWriting();
		return false;
	}
	return file.commit();
}

} // namespace E2ECloud

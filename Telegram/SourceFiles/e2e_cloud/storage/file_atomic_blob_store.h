/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "e2e_cloud/storage/local_storage.h"

#include <QtCore/QString>

namespace E2ECloud {

class FileAtomicBlobStore final : public AtomicBlobStore {
public:
	explicit FileAtomicBlobStore(QString path);

	[[nodiscard]] BlobReadResult read() const override;
	bool writeAtomic(const QByteArray &bytes) override;

private:
	QString _path;

};

} // namespace E2ECloud

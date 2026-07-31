/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include <QtCore/QByteArray>

#include <optional>

namespace E2ECloud {

enum class BlobReadStatus {
	Missing,
	Found,
	Error,
};

struct BlobReadResult {
	BlobReadStatus status = BlobReadStatus::Missing;
	QByteArray bytes;
};

class AtomicBlobStore {
public:
	virtual ~AtomicBlobStore() = default;

	[[nodiscard]] virtual BlobReadResult read() const = 0;
	virtual bool writeAtomic(const QByteArray &bytes) = 0;

};

class LocalRecordProtector {
public:
	virtual ~LocalRecordProtector() = default;

	[[nodiscard]] virtual std::optional<QByteArray> seal(
		const QByteArray &purpose,
		const QByteArray &plaintext) const = 0;
	[[nodiscard]] virtual std::optional<QByteArray> open(
		const QByteArray &purpose,
		const QByteArray &ciphertext) const = 0;

};

} // namespace E2ECloud

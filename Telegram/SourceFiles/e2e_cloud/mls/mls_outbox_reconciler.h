/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

namespace E2ECloud {

class PersistentMlsStateStore;
class ProtectedOutboxStore;

enum class MlsReceiptReconcileResult {
	Reconciled,
	NothingToDo,
	StateNotLoaded,
	PersistenceFailed,
};

[[nodiscard]] MlsReceiptReconcileResult ReconcileMlsOutboxReceipts(
	PersistentMlsStateStore &mlsState,
	const ProtectedOutboxStore &outbox);

} // namespace E2ECloud

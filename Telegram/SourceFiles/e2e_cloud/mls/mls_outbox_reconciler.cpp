/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "e2e_cloud/mls/mls_outbox_reconciler.h"

#include "e2e_cloud/core/outbox.h"
#include "e2e_cloud/storage/persistent_mls_state.h"

#include <vector>

namespace E2ECloud {

MlsReceiptReconcileResult ReconcileMlsOutboxReceipts(
		PersistentMlsStateStore &mlsState,
		const ProtectedOutboxStore &outbox) {
	if (!mlsState.loaded()) {
		return MlsReceiptReconcileResult::StateNotLoaded;
	}
	auto delivered = std::vector<ObjectId>();
	for (const auto &receipt : mlsState.receipts()) {
		if (!outbox.contains(receipt.objectId)) {
			delivered.push_back(receipt.objectId);
		}
	}
	if (delivered.empty()) {
		return MlsReceiptReconcileResult::NothingToDo;
	}
	return mlsState.acknowledgeReceipts(delivered)
		? MlsReceiptReconcileResult::Reconciled
		: MlsReceiptReconcileResult::PersistenceFailed;
}

} // namespace E2ECloud

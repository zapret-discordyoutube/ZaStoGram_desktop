/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "e2e_cloud/mls/mls_outbox_reconciler.h"

#include "e2e_cloud/core/envelope_codec.h"
#include "e2e_cloud/core/outbox.h"
#include "e2e_cloud/storage/persistent_inbound_journal.h"
#include "e2e_cloud/storage/persistent_mls_state.h"

#include <vector>

namespace E2ECloud {

MlsReceiptReconcileResult ReconcileMlsOutboxReceipts(
		PersistentMlsStateStore &mlsState,
		const ProtectedOutboxStore &outbox,
		const EnvelopeCodec &envelopeCodec,
		PersistentInboundJournal &inboundJournal) {
	if (!mlsState.loaded()) {
		return MlsReceiptReconcileResult::StateNotLoaded;
	}
	const auto receipts = mlsState.receipts();
	auto reconciled = false;
	for (const auto &receipt : receipts) {
		if (outbox.contains(receipt.objectId)) {
			continue;
		}
		const auto envelope = envelopeCodec.decode(receipt.envelope);
		const auto result = envelope
			? ReconcileObservedMlsReceipt(
				*envelope,
				envelopeCodec,
				mlsState,
				inboundJournal)
			: ObservedMlsReceiptReconcileResult::ObjectIdConflict;
		if (result == ObservedMlsReceiptReconcileResult::ObjectIdConflict) {
			return MlsReceiptReconcileResult::ObjectIdConflict;
		} else if (result
				!= ObservedMlsReceiptReconcileResult::Reconciled) {
			return MlsReceiptReconcileResult::PersistenceFailed;
		}
		reconciled = true;
	}
	return reconciled
		? MlsReceiptReconcileResult::Reconciled
		: MlsReceiptReconcileResult::NothingToDo;
}

ObservedMlsReceiptReconcileResult ReconcileObservedMlsReceipt(
		const TransportEnvelope &envelope,
		const EnvelopeCodec &envelopeCodec,
		PersistentMlsStateStore &mlsState,
		PersistentInboundJournal &inboundJournal) {
	const auto receipt = mlsState.receipt(envelope.objectId);
	if (!receipt) {
		return ObservedMlsReceiptReconcileResult::ReceiptMissing;
	}
	const auto exact = envelopeCodec.decode(receipt->envelope);
	if (!exact || *exact != envelope) {
		return ObservedMlsReceiptReconcileResult::ObjectIdConflict;
	}
	const auto lookup = inboundJournal.lookup(
		envelope.conversationId,
		envelope.objectId,
		envelope.payloadHash);
	switch (lookup) {
	case InboundJournalLookup::Missing:
		if (!inboundJournal.begin(envelope)) {
			return ObservedMlsReceiptReconcileResult::JournalFailure;
		}
		[[fallthrough]];
	case InboundJournalLookup::Pending:
		if (!inboundJournal.accept(
				envelope.conversationId,
				envelope.objectId)) {
			return ObservedMlsReceiptReconcileResult::JournalFailure;
		}
		break;
	case InboundJournalLookup::Accepted:
		break;
	case InboundJournalLookup::ObjectIdConflict:
		return ObservedMlsReceiptReconcileResult::ObjectIdConflict;
	case InboundJournalLookup::StorageError:
		return ObservedMlsReceiptReconcileResult::JournalFailure;
	}
	return mlsState.acknowledgeReceipt(envelope.objectId)
		? ObservedMlsReceiptReconcileResult::Reconciled
		: ObservedMlsReceiptReconcileResult::MlsStateFailure;
}

} // namespace E2ECloud

/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

namespace E2ECloud {

class EnvelopeCodec;
class PersistentInboundJournal;
class PersistentMlsStateStore;
class ProtectedOutboxStore;
struct TransportEnvelope;

enum class MlsReceiptReconcileResult {
	Reconciled,
	NothingToDo,
	StateNotLoaded,
	ObjectIdConflict,
	PersistenceFailed,
};

[[nodiscard]] MlsReceiptReconcileResult ReconcileMlsOutboxReceipts(
	PersistentMlsStateStore &mlsState,
	const ProtectedOutboxStore &outbox,
	const EnvelopeCodec &envelopeCodec,
	PersistentInboundJournal &inboundJournal);

enum class ObservedMlsReceiptReconcileResult {
	Reconciled,
	ReceiptMissing,
	ObjectIdConflict,
	JournalFailure,
	MlsStateFailure,
};

[[nodiscard]] ObservedMlsReceiptReconcileResult
ReconcileObservedMlsReceipt(
	const TransportEnvelope &envelope,
	const EnvelopeCodec &envelopeCodec,
	PersistentMlsStateStore &mlsState,
	PersistentInboundJournal &inboundJournal);

} // namespace E2ECloud

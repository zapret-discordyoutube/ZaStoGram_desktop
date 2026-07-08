/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "mtproto/core_types.h"

namespace MTP {

constexpr auto kTemporaryMainDcId = DcId(1000);

constexpr ShiftedDcId configDcId(DcId dcId) {
	return ShiftDcId(dcId, kConfigDcShift);
}

constexpr ShiftedDcId logoutDcId(DcId dcId) {
	return ShiftDcId(dcId, kLogoutDcShift);
}

constexpr ShiftedDcId updaterDcId(DcId dcId) {
	return ShiftDcId(dcId, kUpdaterDcShift);
}

constexpr ShiftedDcId groupCallStreamDcId(DcId dcId) {
	return ShiftDcId(dcId, kGroupCallStreamDcShift);
}

namespace details {

constexpr ShiftedDcId downloadDcId(DcId dcId, int index) {
	Expects(index < kMaxMediaDcCount);

	return ShiftDcId(dcId, kBaseDownloadDcShift + index);
};

} // namespace details

inline ShiftedDcId downloadDcId(DcId dcId, int index) {
	return details::downloadDcId(dcId, index);
}

inline constexpr bool isDownloadDcId(ShiftedDcId shiftedDcId) {
	return (shiftedDcId >= details::downloadDcId(0, 0))
		&& (shiftedDcId < details::downloadDcId(0, kMaxMediaDcCount - 1) + kDcShift);
}

inline constexpr bool isMediaClusterDcId(ShiftedDcId shiftedDcId) {
	const auto shift = GetDcIdShift(shiftedDcId);
	return isDownloadDcId(shiftedDcId)
		|| (shift == kGroupCallStreamDcShift)
		|| (shift == kExportMediaDcShift)
		|| (shift == kUpdaterDcShift);
}

inline bool isTemporaryDcId(ShiftedDcId shiftedDcId) {
	auto dcId = BareDcId(shiftedDcId);
	return (dcId >= kTemporaryMainDcId);
}

inline DcId getRealIdFromTemporaryDcId(ShiftedDcId shiftedDcId) {
	auto dcId = BareDcId(shiftedDcId);
	return (dcId >= kTemporaryMainDcId) ? (dcId - kTemporaryMainDcId) : 0;
}

inline DcId getTemporaryIdFromRealDcId(ShiftedDcId shiftedDcId) {
	auto dcId = BareDcId(shiftedDcId);
	return (dcId < kTemporaryMainDcId) ? (dcId + kTemporaryMainDcId) : 0;
}

namespace details {

constexpr ShiftedDcId uploadDcId(DcId dcId, int index) {
	return ShiftDcId(dcId, kBaseUploadDcShift + index);
};

} // namespace details

inline ShiftedDcId uploadDcId(int index) {
	Expects(index >= 0 && index < kMaxMediaDcCount);

	return details::uploadDcId(0, index);
};

constexpr bool isUploadDcId(ShiftedDcId shiftedDcId) {
	return (shiftedDcId >= details::uploadDcId(0, 0))
		&& (shiftedDcId < details::uploadDcId(0, kMaxMediaDcCount - 1) + kDcShift);
}

inline ShiftedDcId destroyKeyNextDcId(ShiftedDcId shiftedDcId) {
	const auto shift = GetDcIdShift(shiftedDcId);
	return ShiftDcId(BareDcId(shiftedDcId), shift ? (shift + 1) : kDestroyKeyStartDcShift);
}

} // namespace MTP

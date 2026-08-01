/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "e2e_cloud/core/types.h"
#include "e2e_cloud/identity/openssl_account_crypto.h"
#include "e2e_cloud/storage/aes_gcm_local_record_protector.h"

#include <cstdint>
#include <optional>

namespace E2ECloud {

[[nodiscard]] std::optional<LocalRecordKey>
DeriveConversationLocalRecordKey(
	const SecureKey32 &vaultMasterKey,
	std::uint64_t telegramUserIdBinding,
	ConversationId conversationId);

} // namespace E2ECloud

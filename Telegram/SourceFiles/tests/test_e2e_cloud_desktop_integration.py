#!/usr/bin/env python3

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def source(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def function_body(text: str, signature: str, next_signature: str) -> str:
    start = text.index(signature)
    end = text.index(next_signature, start)
    return text[start:end]


def verify_carrier_tracking() -> None:
    header = source("SourceFiles/history/history.h")
    history = source("SourceFiles/history/history.cpp")
    item = source("SourceFiles/history/history_item.cpp")

    assert "base::flat_set<not_null<HistoryItem*>> " \
        "_e2eCloudGroupCarriers;" in header
    assert "refreshE2ECloudGroupCarrier(result);" in history
    assert "_e2eCloudGroupCarriers.remove(item);" in history
    assert "return !_e2eCloudGroupCarriers.empty();" in history
    assert "owner().notifyHistoryChangeDelayed(this);" in history
    assert item.count("_history->refreshE2ECloudGroupCarrier(this);") >= 5
    carrier = function_body(
        item,
        "bool HistoryItem::isE2ECloudCarrier() const",
        "bool HistoryItem::isE2ECloudGroupCarrier() const",
    )
    group_carrier = function_body(
        item,
        "bool HistoryItem::isE2ECloudGroupCarrier() const",
        "ItemPreview HistoryItem::toPreview(",
    )
    assert "peer->isSelf()" in carrier
    assert "peer->isChat() || peer->isMegagroup()" in carrier
    assert "!peer->isChat() && !peer->isMegagroup()" in group_carrier


def verify_group_scope() -> None:
    widget = source("SourceFiles/history/history_widget.cpp")
    service = source("SourceFiles/e2e_cloud/desktop/desktop_service.cpp")
    protected_peer = function_body(
        widget,
        "bool HistoryWidget::isE2ECloudProtectedPeer() const",
        "void HistoryWidget::openE2ECloudProtectedConversation()",
    )
    create_group = function_body(
        service,
        "bool DesktopService::createProtectedGroup(",
        "bool DesktopService::retryProtectedGroupCreation()",
    )
    new_item = function_body(
        service,
        "void DesktopService::handleNewTelegramItem(",
        "void DesktopService::queueGroupDiscovery(",
    )
    discovery = function_body(
        service,
        "void DesktopService::queueGroupDiscovery(",
        "void DesktopService::startNextGroupDiscovery()",
    )
    group_check = "!peer->isChat() && !peer->isMegagroup()"

    assert "!_peer->isChat() && !_peer->isMegagroup()" in protected_peer
    assert group_check in create_group
    assert group_check in new_item
    assert "peerLoaded(PeerId(telegramPeerIdBinding))" in discovery
    assert group_check in discovery
    assert service.count("IsProtectedGroupPeerBinding(") >= 3


def verify_all_e2e_tests_are_registered() -> None:
    cmake = source("cmake/tests.cmake")
    root_cmake = (ROOT.parent / "CMakeLists.txt").read_text(encoding="utf-8")
    executables = set(re.findall(
        r"add_executable\((test_e2e_cloud(?:_[a-z_]+)?)\)",
        cmake,
    ))
    registered = set(re.findall(
        r"add_test\(\s+NAME (test_e2e_cloud(?:_[a-z_]+)?)\s+",
        cmake,
    ))

    assert executables
    assert registered == executables
    assert "if (DESKTOP_APP_TEST_APPS)\n    enable_testing()\nendif()" \
        in root_cmake.replace("\r\n", "\n")


def verify_discovery_has_a_timeout() -> None:
    backend = source(
        "SourceFiles/e2e_cloud/transport/"
        "telegram_session_carrier_backend.cpp"
    )

    assert "kDiscoveryTimeout = crl::time(15'000)" in backend
    assert "discoveryTimedOut(requestId, token);" in backend
    assert "api.request(base::take(discoveryRequestId)).cancel();" in backend
    assert "UploadResult::RetryableError" in function_body(
        backend,
        "void discoveryTimedOut(\n"
        "\t\t\tmtpRequestId requestId,",
        "void discoveryLoaded(const MTPmessages_Messages &result)",
    )


def verify_all_carrier_operations_have_timeouts() -> None:
    backend = source(
        "SourceFiles/e2e_cloud/transport/"
        "telegram_session_carrier_backend.cpp"
    )

    assert "kCarrierOperationTimeout = crl::time(120'000)" in backend
    assert "weak->uploadTimedOut(id);" in backend
    assert "weak->downloadTimedOut(token);" in backend
    assert "weak->api.request(requestId).cancel();" in backend
    assert "api.request(base::take(downloadRequestId)).cancel();" in backend


def verify_carrier_backfill_searches_documents() -> None:
    backend = source(
        "SourceFiles/e2e_cloud/transport/"
        "telegram_session_carrier_backend.cpp"
    )
    download = function_body(
        backend,
        "void downloadDocuments(\n",
        "void downloadTimedOut(",
    )

    assert "MTPmessages_Search(" in download
    assert "MTP_inputMessagesFilterDocument()" in download
    assert "MTPmessages_GetHistory(" not in download


def verify_late_vault_uploads_cannot_cross_lock_boundary() -> None:
    header = source("SourceFiles/e2e_cloud/desktop/desktop_service.h")
    service = source("SourceFiles/e2e_cloud/desktop/desktop_service.cpp")

    assert "std::uint64_t _operationEpoch = 1;" in header
    assert "if (++_operationEpoch == 0)" in function_body(
        service,
        "void DesktopService::lock()",
        "void DesktopService::applyVaultDiscoveryResult(",
    )
    assert service.count("weak->_operationEpoch != operationEpoch") == 2


def verify_file_chunk_self_observation_uses_exact_ciphertext() -> None:
    processor = source(
        "SourceFiles/e2e_cloud/protocol/observed_content_processor.cpp"
    )
    protector = source(
        "SourceFiles/e2e_cloud/files/idempotent_file_chunk_protector.cpp"
    )

    assert "HasExactFileChunkCiphertext(" in processor
    matcher = function_body(
        protector,
        "bool HasExactFileChunkCiphertext(",
        "IdempotentFileChunkProtector::IdempotentFileChunkProtector(",
    )
    assert "stored.chunk.exactCiphertext == ciphertext" in matcher
    assert "plaintextHash" not in matcher


def verify_pending_plaintext_is_cleansed() -> None:
    outbox = source("SourceFiles/e2e_cloud/storage/persistent_outbox.cpp")
    coordinator = source("SourceFiles/e2e_cloud/core/outbox.cpp")
    bootstrap = source(
        "SourceFiles/e2e_cloud/protocol/group_bootstrap_transaction.cpp"
    )

    assert "PersistentOutboxStore::~PersistentOutboxStore()" in outbox
    assert outbox.count("CleanseItems(_items);") >= 6
    assert "CleansePendingMessage(i->draft);" in outbox
    assert "CleanseOutboxItem(*item);" in coordinator
    assert bootstrap.count("Cleanse(*_pending);") >= 2
    assert bootstrap.count("Cleanse(transaction);") >= 2


def verify_manifest_key_is_owned_before_variable_fields() -> None:
    manifest = source("SourceFiles/e2e_cloud/files/private_file_manifest.cpp")
    decode = function_body(
        manifest,
        "std::optional<PrivateFileManifest> "
        "PrivateFileManifestCodecV1::decodePlaintext(",
        "} // namespace E2ECloud",
    )

    assert decode.index("auto key = FileEncryptionKey") \
        < decode.index("const auto filenameSize")


def verify_control_sync_blocks_outgoing_races() -> None:
    service = source("SourceFiles/e2e_cloud/desktop/desktop_service.cpp")
    pump = function_body(
        service,
        "void DesktopService::pumpActiveOutbox(",
        "void DesktopService::completeActiveUpload(",
    )
    observation = function_body(
        service,
        "void DesktopService::beginGroupObservation(",
        "void DesktopService::beginContentObservation(",
    )
    result = function_body(
        service,
        "void DesktopService::applyGroupObservation(",
        "void DesktopService::handleNewTelegramItem(",
    )
    text_send = function_body(
        service,
        "bool DesktopService::sendProtectedText(",
        "bool DesktopService::sendProtectedFile(",
    )
    file_send = function_body(
        service,
        "bool DesktopService::sendProtectedFile(",
        "bool DesktopService::saveProtectedFile(",
    )

    assert "group.observationDirty && !group.outbox.size()" in pump
    assert "group.observationDirty = true;" in observation
    assert "group.uploadInProgress" in observation
    assert "i->second->observationDirty = true;" in result
    assert "if (rerun) {\n\t\t\tbeginGroupObservation" in result
    assert "i->second->observation" in text_send
    assert "i->second->observationDirty" in text_send
    assert "i->second->observation" in file_send
    assert "i->second->observationDirty" in file_send


def verify_freshness_wait_does_not_busy_poll() -> None:
    service = source("SourceFiles/e2e_cloud/desktop/desktop_service.cpp")
    pump = function_body(
        service,
        "void DesktopService::pumpActiveOutbox(",
        "void DesktopService::completeActiveUpload(",
    )
    waiting = pump.index(
        "DesktopContentState::AwaitingFreshness);\n\t\t\treturn;"
    )
    challenge_upload = pump.index(
        "group.transport.uploadExact(",
        waiting,
    )

    assert "beginGroupObservation" not in pump[waiting:challenge_upload]
    manual_sync = function_body(
        service,
        "void DesktopService::synchronizeProtectedContent(",
        "void DesktopService::lock()",
    )
    assert "beginGroupObservation(conversationId);" in manual_sync


def verify_control_sync_uses_a_persistent_boundary() -> None:
    service = source("SourceFiles/e2e_cloud/desktop/desktop_service.cpp")
    controller = source(
        "SourceFiles/e2e_cloud/transport/"
        "public_bootstrap_sync_controller.cpp"
    )
    observation = function_body(
        service,
        "void DesktopService::beginGroupObservation(",
        "void DesktopService::beginContentObservation(",
    )
    result = function_body(
        service,
        "void DesktopService::applyGroupObservation(",
        "void DesktopService::handleNewTelegramItem(",
    )

    assert 'u"control-sync.state"_q' in service
    assert "ObservedSyncStream::Control" in service
    assert "startFromBoundary(boundary)" in observation
    assert "group.controlSyncState.advance(" in result
    assert "messageId >= _lastObservedMessageId" in controller
    assert "messageId < _boundaryMessageId" in controller


def verify_protected_groups_layout_uses_own_visibility() -> None:
    box = source("SourceFiles/e2e_cloud/desktop/protected_groups_box.cpp")

    assert "isVisible()" not in box
    assert box.count("isHidden()") >= 4
    assert "GroupInfoBox::Type::Megagroup" in box


def verify_protected_history_can_page_back() -> None:
    conversation = source(
        "SourceFiles/e2e_cloud/desktop/protected_conversation_box.cpp"
    )

    assert "kVisiblePageSize = std::size_t(200)" in conversation
    assert "tr::lng_e2e_cloud_show_older(" in conversation
    assert "*visibleLimit += count;" in conversation


def main() -> None:
    verify_carrier_tracking()
    verify_group_scope()
    verify_all_e2e_tests_are_registered()
    verify_discovery_has_a_timeout()
    verify_all_carrier_operations_have_timeouts()
    verify_carrier_backfill_searches_documents()
    verify_late_vault_uploads_cannot_cross_lock_boundary()
    verify_file_chunk_self_observation_uses_exact_ciphertext()
    verify_pending_plaintext_is_cleansed()
    verify_manifest_key_is_owned_before_variable_fields()
    verify_control_sync_blocks_outgoing_races()
    verify_freshness_wait_does_not_busy_poll()
    verify_control_sync_uses_a_persistent_boundary()
    verify_protected_groups_layout_uses_own_visibility()
    verify_protected_history_can_page_back()


if __name__ == "__main__":
    main()

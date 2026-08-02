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


def verify_protected_peers_never_downgrade_to_plaintext() -> None:
    header = source("SourceFiles/e2e_cloud/desktop/desktop_service.h")
    service = source("SourceFiles/e2e_cloud/desktop/desktop_service.cpp")
    widget = source("SourceFiles/history/history_widget.cpp")
    constructor = function_body(
        service,
        "DesktopService::DesktopService(not_null<Main::Session*> session)",
        "DesktopService::~DesktopService()",
    )
    presentation = function_body(
        service,
        "bool DesktopService::isProtectedPeerForPresentation(",
        "std::vector<ProtectedContentRecord> "
        "DesktopService::protectedContent(",
    )
    lock = function_body(
        service,
        "void DesktopService::lock()",
        "void DesktopService::applyVaultDiscoveryResult(",
    )

    assert "bool isProtectedPeerForPresentation(" in header
    assert "_presentationProtectedPeers" in header
    assert "_presentationProtectedPeersValid" in header
    assert "readPref<QByteArray>(kProtectedPeersPref)" in constructor
    assert "writePrefNow<QByteArray>(" in presentation
    assert "EncodeProtectedPeerMarkers(" in presentation
    assert "!_presentationProtectedPeersValid" in presentation
    assert "_presentationProtectedPeers.contains(" in presentation
    assert "isProtectedPeerForPresentation(" in widget
    assert "linkedTelegramPeerIdBinding" in presentation
    assert "rememberProtectedPeerForPresentation(telegramPeerIdBinding)" in presentation
    assert "_migrated ? _migrated->peer->id.value : 0" in widget
    assert "if (!conversationId && _migrated)" in widget
    marker_check = widget.index("service.isProtectedPeerForPresentation(")
    peer_classification = widget.index(
        "!_peer->isChat() && !_peer->isMegagroup()",
        marker_check,
    )
    assert marker_check < peer_classification
    assert service.count("rememberProtectedPeerForPresentation(") >= 5
    assert "_presentationProtectedPeers.clear()" not in lock
    assert "_presentationProtectedPeers.erase(" not in service


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


def verify_ambiguous_search_results_fail_closed() -> None:
    backend = source(
        "SourceFiles/e2e_cloud/transport/"
        "telegram_session_carrier_backend.cpp"
    )
    discovery = function_body(
        backend,
        "void discoveryLoaded(const MTPmessages_Messages &result)",
        "void finishDiscovery(",
    )
    history = function_body(
        backend,
        "void historyLoaded(const MTPmessages_Messages &result, int limit)",
        "void downloadProgress(",
    )

    for body in (discovery, history):
        assert "MTPDmessages_messagesNotModified" in body
        not_modified = body.index("MTPDmessages_messagesNotModified")
        assert "valid = false;" in body[not_modified:]
        assert "if (!valid)" in body
        assert "UploadResult::RetryableError" in body
    assert "complete = valid;" in discovery
    assert discovery.count("data.vcount().v >= int(messages.size())") == 2
    assert "complete\n\t\t\t\t? UploadResult::Accepted" not in discovery
    assert "complete\n\t\t\t\t? TelegramTransport::UploadResult::Accepted" \
        in discovery


def verify_download_pages_are_bounded_at_every_layer() -> None:
    backend = source(
        "SourceFiles/e2e_cloud/transport/"
        "telegram_session_carrier_backend.cpp"
    )
    history = function_body(
        backend,
        "void historyLoaded(const MTPmessages_Messages &result, int limit)",
        "void downloadProgress(",
    )
    discovery = function_body(
        backend,
        "void discoveryLoaded(const MTPmessages_Messages &result)",
        "void finishDiscovery(",
    )

    assert history.count("messages.size() <= limit") == 3
    assert discovery.count("messages.size() <= kDiscoverySearchLimit") == 3
    controllers = [
        "carrier_sync_controller",
        "cloud_vault_sync_controller",
        "file_chunk_download_controller",
        "observed_content_sync_controller",
        "public_bootstrap_discovery_controller",
        "public_bootstrap_sync_controller",
    ]
    for name in controllers:
        implementation = source(
            f"SourceFiles/e2e_cloud/transport/{name}.cpp"
        )
        assert "untrustedObjects.size()" in implementation
        assert "> std::size_t(kDownloadPageLimit)" in implementation


def verify_key_packages_bind_the_observed_telegram_author() -> None:
    lifecycle = source(
        "SourceFiles/e2e_cloud/mls/key_package_lifecycle.cpp"
    )
    observed = source(
        "SourceFiles/e2e_cloud/mls/observed_key_package.cpp"
    )
    service = source("SourceFiles/e2e_cloud/desktop/desktop_service.cpp")

    assert "DeriveClientKeyPackageObjectId(" in lifecycle
    assert "args.telegramUserIdBinding" in lifecycle
    assert "object.observedSenderTelegramUserIdBinding" in observed
    assert "envelope->objectId != *expectedObjectId" in observed
    assert "InvalidTelegramAuthorBinding" in observed
    assert service.count("DeriveClientKeyPackageObjectId(") >= 1
    assert ".telegramUserIdBinding = _telegramUserIdBinding" in service


def verify_unanchored_vault_history_is_contiguous() -> None:
    selector = source(
        "SourceFiles/e2e_cloud/vault/cloud_vault_selection.cpp"
    )

    assert "if (!localAnchor)" in selector
    assert "opened.front().generation != 1" in selector
    assert "opened.front().previousBlobDigest" in selector
    assert "current.generation != previous.generation + 1" in selector
    assert "current.previousBlobDigest != previous.blobDigest" in selector


def verify_late_vault_uploads_cannot_cross_lock_boundary() -> None:
    header = source("SourceFiles/e2e_cloud/desktop/desktop_service.h")
    service = source("SourceFiles/e2e_cloud/desktop/desktop_service.cpp")

    assert "std::uint64_t _operationEpoch = 1;" in header
    assert "if (++_operationEpoch == 0)" in function_body(
        service,
        "void DesktopService::lock()",
        "void DesktopService::applyVaultDiscoveryResult(",
    )
    assert service.count("weak->_operationEpoch != operationEpoch") >= 2


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
    state = source(
        "SourceFiles/e2e_cloud/storage/"
        "persistent_control_observation_state.cpp"
    )
    controller = source(
        "SourceFiles/e2e_cloud/transport/"
        "public_bootstrap_sync_controller.cpp"
    )
    discovery = source(
        "SourceFiles/e2e_cloud/transport/"
        "public_bootstrap_discovery_controller.cpp"
    )
    join = source("SourceFiles/e2e_cloud/protocol/public_join_catchup.cpp")
    group_sync = source(
        "SourceFiles/e2e_cloud/protocol/observed_group_change_sync.cpp"
    )
    inbox = source(
        "SourceFiles/e2e_cloud/protocol/group_change_inbox.cpp"
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
    assert 'u"group-change-inbox.state"_q' in service
    assert "PersistentControlObservationState controlSyncState" in service
    assert "PersistentGroupChangeInbox changeInbox" in service
    assert "startFromBoundary(boundary)" in observation
    assert "safetyWitnessGeneration\n\t\t?" not in observation
    assert "group.controlSyncState.advance(" in result
    assert "group.safetyWitnesses" in result
    assert "group.ownSafetyGossipObserved" in result
    assert "kLegacyPurpose" in state
    assert "safetyWitnesses" in state
    assert "startForJoin()" in service
    assert "startForJoinFromBoundary(boundary)" in observation
    assert "IsPublicJoinRelevantObject(" in controller
    assert "IsPublicGroupBootstrapCandidate(" in discovery
    assert "ObjectKind::SafetyCodeGossip" not in join[
        join.index("bool JoinRelevantKind("):join.index("bool ValidPayload(")
    ]
    assert "messageId >= _lastObservedMessageId" in controller
    assert "messageId < _boundaryMessageId" in controller
    assert "group.changeInbox" in service
    assert "inbox.stageObserved(" in group_sync
    assert "observedSenderTelegramUserIdBinding" in inbox
    assert "!synchronized.appliedTransitions" in service
    assert "StagePublicJoinObjects(" in service
    assert "ReconstructPublicJoinObjects(" in service
    assert "resumeObservedJoinHistory(" in service
    assert "joinTargetCheckpoint" in service
    assert "PublicGroupBootstrapCanReachCheckpoint(" in service
    assert "verified.checkpoint != conversation.checkpoint" not in service
    assert "groupLedger.stateAt(1)" in service


def verify_content_sync_requires_its_saved_boundary() -> None:
    service = source("SourceFiles/e2e_cloud/desktop/desktop_service.cpp")
    controller = source(
        "SourceFiles/e2e_cloud/transport/"
        "observed_content_sync_controller.cpp"
    )
    result = function_body(
        service,
        "void DesktopService::applyContentObservation(",
        "void DesktopService::applyGroupObservation(",
    )

    assert "messageId < _boundaryMessageId" in controller
    assert "result.complete && _boundaryMessageId" in controller
    assert "kBoundaryOverlap" in controller
    assert "Phase::Replaying" in controller
    assert "PageFingerprint(_cursor, result, _sha256)" in controller
    assert "_scannedPages.front().retainedNewestObjects" in controller
    assert "completion.nextBoundaryMessageId" in result
    assert "group.contentSyncState.advance(" in result


def verify_deferred_content_keeps_its_saved_boundary() -> None:
    processor = source(
        "SourceFiles/e2e_cloud/protocol/observed_content_processor.cpp"
    )
    observed = source(
        "SourceFiles/e2e_cloud/transport/"
        "observed_content_sync_controller.cpp"
    )
    carrier = source(
        "SourceFiles/e2e_cloud/transport/carrier_sync_controller.cpp"
    )
    service = source("SourceFiles/e2e_cloud/desktop/desktop_service.cpp")
    content = function_body(
        processor,
        "ObservedContentProcessOutcome ProcessObservedContentPage(",
        "} // namespace E2ECloud",
    )
    deferred = content.index("case InboundProcessResult::Deferred:")
    conflict = content.index(
        "case InboundProcessResult::ObjectIdConflict:",
        deferred,
    )
    deferred_branch = content[deferred:conflict]
    page = function_body(
        service,
        "ObservedContentPageResult DesktopService::processObservedContentPage(",
        "void DesktopService::applyContentObservation(",
    )

    assert "ObservedContentProcessStatus::RetryRequired" in deferred_branch
    assert "return outcome;" in deferred_branch
    assert "outcome.stats.ignored" not in deferred_branch
    assert "ObservedContentPageResult::RetryRequired" in page
    assert "PageFailureStatus(persisted)" in observed
    assert "ObservedContentSyncStatus::RetryRequired" in observed
    assert "finish(CarrierSyncFinishReason::RetryRequired);" in carrier


def verify_pagination_cursor_tracking_is_bounded() -> None:
    controllers = [
        "carrier_sync_controller",
        "cloud_vault_sync_controller",
        "observed_content_sync_controller",
        "public_bootstrap_discovery_controller",
        "public_bootstrap_sync_controller",
    ]
    for name in controllers:
        header = source(f"SourceFiles/e2e_cloud/transport/{name}.h")
        implementation = source(
            f"SourceFiles/e2e_cloud/transport/{name}.cpp"
        )
        assert "std::set<QByteArray> _seenCursors;" in header
        assert "kMaximumStoredCursorBytes" in implementation
        assert "_seenCursors.contains(" in implementation
        assert "_storedCursorBytes +=" in implementation


def verify_freshness_witness_is_rechecked_after_catchup() -> None:
    gate = source("SourceFiles/e2e_cloud/core/freshness_gate.cpp")
    crypto = source("SourceFiles/e2e_cloud/core/freshness_crypto.cpp")
    service = source("SourceFiles/e2e_cloud/desktop/desktop_service.cpp")

    assert "_resynchronizationResponse = response;" in gate
    assert "verifier.verify(*_resynchronizationResponse)" in gate
    assert crypto.count("_groupLedger.wasClientActiveAt(") >= 2
    assert service.count("completeResynchronization(") >= 2


def verify_completion_callbacks_survive_owner_reset() -> None:
    paths = [
        "SourceFiles/e2e_cloud/transport/cloud_vault_sync_controller.cpp",
        "SourceFiles/e2e_cloud/transport/public_bootstrap_sync_controller.cpp",
        "SourceFiles/e2e_cloud/transport/carrier_sync_controller.cpp",
        "SourceFiles/e2e_cloud/transport/observed_content_sync_controller.cpp",
    ]
    for path in paths:
        controller = source(path)
        finish = controller[controller.rfind("::finish("):]
        assert "const auto callback = _completionCallback;" in finish
        assert "_completionCallback(" not in finish

    uploader = source(
        "SourceFiles/e2e_cloud/transport/outbox_upload_controller.cpp"
    )
    complete = uploader[uploader.rfind("::complete("):]
    assert "const auto callback = _completionCallback;" in complete
    assert "_completionCallback(" not in complete

    observed = source(
        "SourceFiles/e2e_cloud/transport/"
        "observed_content_sync_controller.cpp"
    )
    page = function_body(
        observed,
        "bool ObservedContentSyncController::deliverPage(",
        "void ObservedContentSyncController::finish(",
    )
    assert "const auto callback = _pageCallback;" in page
    assert "guard->controller != this || !_running" in page


def verify_group_discovery_retries_without_creation_races() -> None:
    service = source("SourceFiles/e2e_cloud/desktop/desktop_service.cpp")
    creation = function_body(
        service,
        "bool DesktopService::createProtectedGroup(",
        "bool DesktopService::retryProtectedGroupCreation(",
    )
    discovery = function_body(
        service,
        "void DesktopService::applyGroupDiscovery(",
        "bool DesktopService::completeObservedJoin(",
    )

    assert "|| _pendingGroupJoin" in creation
    assert "|| _pendingGroupDiscovery" in creation
    assert "PublicBootstrapSyncStatus::RetryableTransportError" in discovery
    assert "_groupDiscoveryQueue.emplace(peerId);" in discovery


def verify_group_setup_commits_metadata_last() -> None:
    service = source("SourceFiles/e2e_cloud/desktop/desktop_service.cpp")
    creation = function_body(
        service,
        "bool DesktopService::createProtectedGroup(",
        "bool DesktopService::retryProtectedGroupCreation(",
    )
    join = function_body(
        service,
        "bool DesktopService::prepareGroupJoin(",
        "bool DesktopService::queueFreshnessChallenge(",
    )
    recovery = function_body(
        service,
        "void DesktopService::resumePendingGroupCreation()",
        "void DesktopService::beginIndexedGroupJoin(",
    )

    assert creation.index("coordinator.apply(") < creation.rindex(
        "metadata.initialize("
    )
    assert creation.index("BeginConversationSetup(") < creation.index(
        "coordinator.apply("
    )
    assert creation.rindex("metadata.initialize(") < creation.index(
        "FinishConversationSetup("
    )
    assert creation.index("freshnessTrust.initialize(true)") < creation.rindex(
        "metadata.initialize("
    )
    assert join.index("groupLedger.initialize(") < join.rindex(
        "metadata.initialize("
    )
    assert join.index("keyPackages.enqueuePending(") < join.rindex(
        "metadata.initialize("
    )
    assert join.index("BeginConversationSetup(") < join.index(
        "groupLedger.initialize("
    )
    assert join.rindex("metadata.initialize(") < join.index(
        "FinishConversationSetup("
    )
    assert creation.count("DiscardUncommittedConversationDirectory(") >= 2
    assert join.count("DiscardUncommittedConversationDirectory(") >= 2
    assert "DiscardUncommittedConversationDirectory(" in recovery
    assert 'u"setup.pending"_q' in service
    assert "ConversationSetupPending(directory)" in recovery


def verify_group_carriers_publish_before_vault_index() -> None:
    service = source("SourceFiles/e2e_cloud/desktop/desktop_service.cpp")
    creation = function_body(
        service,
        "bool DesktopService::createProtectedGroup(",
        "bool DesktopService::retryProtectedGroupCreation(",
    )
    publisher = function_body(
        service,
        "void DesktopService::publishNextBootstrapObject()",
        "void DesktopService::resumePendingGroupCreation()",
    )
    recovery = function_body(
        service,
        "DesktopService::LocalGroupRecoveryResult DesktopService::restoreLocalGroup(",
        "bool DesktopService::commitVaultAnchor(",
    )

    assert "publishNextBootstrapObject();" in creation
    assert "beginGroupVaultPreflight();" not in creation
    assert publisher.index("if (!item) {") < publisher.index(
        "beginGroupVaultPreflight();"
    )
    assert "_pendingGroupCreation->vaultPreflightRequired" in publisher
    assert service.count("beginGroupVaultPreflight();") == 1
    assert "const auto requiresVaultUpdate = localAhead" in recovery
    assert "awaitingAdmission || localIsGenesisOwner" in recovery


def verify_freshness_challenges_resume_and_replays_stop() -> None:
    service = source("SourceFiles/e2e_cloud/desktop/desktop_service.cpp")
    protocol = source(
        "SourceFiles/e2e_cloud/protocol/freshness_protocol.cpp"
    )
    publisher = function_body(
        service,
        "void DesktopService::publishNextBootstrapObject(",
        "void DesktopService::resumePendingGroupCreation(",
    )
    pump = function_body(
        service,
        "void DesktopService::pumpActiveOutbox(",
        "void DesktopService::completeActiveUpload(",
    )

    assert 'u"control-inbound.state"_q' in service
    assert "InboundJournalDomain::Control" in service
    assert "controlInboundJournal.load()" in service
    assert "resumeQueuedFreshnessChallenge(" in publisher
    assert "resumeQueuedFreshnessChallenge(group, *item->sealed)" in pump
    assert "FreshnessState::WaitingForWitness" in service
    assert "QueueFreshnessResponseOnce(" in service
    assert "FreshnessResponseQueueResult::AlreadyResponded" in protocol


def verify_observed_mls_receipts_finish_crash_recovery() -> None:
    reconciler = source(
        "SourceFiles/e2e_cloud/mls/mls_outbox_reconciler.cpp"
    )
    processor = source(
        "SourceFiles/e2e_cloud/protocol/observed_content_processor.cpp"
    )
    service = source("SourceFiles/e2e_cloud/desktop/desktop_service.cpp")

    assert "case InboundJournalLookup::Pending:" in reconciler
    assert "inboundJournal.accept(" in reconciler
    assert "mlsState.acknowledgeReceipt(" in reconciler
    assert "ReconcileObservedMlsReceipt(" in processor
    assert "ReconcileObservedMlsReceipt(" in service


def verify_protected_groups_layout_uses_own_visibility() -> None:
    box = source("SourceFiles/e2e_cloud/desktop/protected_groups_box.cpp")
    ready = box[
        box.index("case DesktopVaultState::Ready:"):
        box.index("case DesktopVaultState::WrongPasswordOrDamaged:")
    ]

    assert "isVisible()" not in box
    assert box.count("isHidden()") >= 4
    assert "GroupInfoBox::Type::Megagroup" in box
    open_chats = ready.index("tr::lng_e2e_cloud_open_chats()")
    retryable = ready.index(
        "creation == DesktopGroupCreationState::RetryableTransportError"
    )
    assert open_chats < retryable
    assert ready.count("tr::lng_e2e_cloud_open_chats()") == 1


def verify_protected_history_can_page_back() -> None:
    conversation = source(
        "SourceFiles/e2e_cloud/desktop/protected_conversation_box.cpp"
    )

    assert "kVisiblePageSize = std::size_t(200)" in conversation
    assert "tr::lng_e2e_cloud_show_older(" in conversation
    assert "*visibleLimit += count;" in conversation


def verify_protected_plaintext_is_loaded_by_page() -> None:
    store_header = source(
        "SourceFiles/e2e_cloud/storage/persistent_content_store.h"
    )
    store = source(
        "SourceFiles/e2e_cloud/storage/persistent_content_store.cpp"
    )
    service = source("SourceFiles/e2e_cloud/desktop/desktop_service.cpp")
    conversation = source(
        "SourceFiles/e2e_cloud/desktop/protected_conversation_box.cpp"
    )

    assert "std::vector<ProtectedContentRecord> _records" not in store_header
    assert "std::vector<std::size_t> _orderedEntries;" in store_header
    assert "AppendUint16(plaintext, 3);" in store
    assert "version != 1 && version != 2 && version != 3" in store
    assert "EarliestObservedMessageId(" in store
    assert "std::optional<std::int64_t> observedTelegramMessageId;" in store_header
    assert "(void)persistIndex(_entries, _revision);" in store
    assert "readRecord(entry);" in store
    assert "contentStore.records(offset, limit, kind)" in service
    assert conversation.count("protectedContentCount(") >= 2
    assert conversation.count("protectedContent(\n") >= 2


def verify_local_record_reads_are_bounded() -> None:
    blob = source("SourceFiles/e2e_cloud/storage/file_atomic_blob_store.cpp")
    chunks = source("SourceFiles/e2e_cloud/files/file_chunk_file_store.cpp")
    backend = source(
        "SourceFiles/e2e_cloud/transport/"
        "telegram_session_carrier_backend.cpp"
    )

    assert "readAll()" not in blob
    assert "kMaximumBlobSize" in blob
    assert "size > kMaximumBlobSize" in blob
    assert "readAll()" not in chunks
    assert "kMaximumProtectedSize" in chunks
    assert "size > kMaximumProtectedSize" in chunks
    assert "size != entry.document->size" in backend
    assert "bytes = file.read(size);" in backend


def verify_file_chunks_require_manifests_and_quota() -> None:
    processor = source(
        "SourceFiles/e2e_cloud/protocol/observed_content_processor.cpp"
    )
    chunk_store = source(
        "SourceFiles/e2e_cloud/files/file_chunk_file_store.cpp"
    )
    sync = source(
        "SourceFiles/e2e_cloud/transport/"
        "observed_content_sync_controller.cpp"
    )
    service = source("SourceFiles/e2e_cloud/desktop/desktop_service.cpp")
    transfer = source(
        "SourceFiles/e2e_cloud/files/persistent_file_transfer.cpp"
    )
    upload_controller = source(
        "SourceFiles/e2e_cloud/transport/outbox_upload_controller.cpp"
    )
    bootstrap_publish = function_body(
        service,
        "void DesktopService::publishNextBootstrapObject()",
        "void DesktopService::resumePendingGroupCreation()",
    )
    group_observation = function_body(
        service,
        "void DesktopService::applyGroupObservation(",
        "void DesktopService::handleNewTelegramItem(",
    )
    admission = function_body(
        processor,
        "[[nodiscard]] FileChunkAdmissionStatus AdmitObservedFileChunk(",
        "} // namespace",
    )
    manifest = function_body(
        processor,
        "[[nodiscard]] ObservedContentProcessStatus ProcessObservedManifest(",
        "enum class FileChunkAdmissionStatus",
    )
    page = function_body(
        sync,
        "void ObservedContentSyncController::pageReceived(",
        "bool ObservedContentSyncController::previewPage(",
    )
    pump = function_body(
        service,
        "void DesktopService::pumpActiveOutbox(",
        "void DesktopService::completeActiveUpload(",
    )

    assert "chunkStore.authorization(" in admission
    assert "authorization.manifestEventObjectId" in admission
    assert "AesGcmFileChunkCipher().decrypt(" in admission
    assert processor.index("AesGcmFileChunkCipher().decrypt(") \
        < processor.index("chunkStore.storeIfAbsent(")
    assert "FileChunkStoreResult::QuotaExceeded" in processor
    assert "authorized == FileChunkAuthorizeResult::QuotaExceeded" in processor
    assert manifest.index("chunkStore.authorize(authorization)") \
        < manifest.index("contentStore.append(")
    assert "kMinimumFreeBytes" in chunk_store
    assert "_storedBytes > _maximumStoredBytes - size" in chunk_store
    assert page.index("previewPage(result.untrustedObjects") \
        < page.index("_scannedPages.push_back(")
    assert pump.index("queuePendingFileManifest(") \
        < pump.index("pumpFileTransfer(")
    assert "!pending->manifestPublished" in pump
    assert "!group.outbox.contains(pending->eventObjectId)" in pump
    assert "markManifestPublished(" in service
    assert "prepareActiveUploadAcknowledgement(" in service
    assert "group.outbox.size() != 1" not in service
    assert bootstrap_publish.index("prepareFileManifestAcknowledgement(") \
        < bootstrap_publish.index("outbox.remove(objectId)")
    assert "pumpActiveOutbox(conversationId);" in group_observation
    assert upload_controller.index("_beforeAcknowledgeCallback(objectId)") \
        < upload_controller.index("_outbox.acknowledgeUploaded(objectId)")
    assert "|| !_pending->manifestPublished" in transfer


def verify_file_chunks_download_only_on_demand() -> None:
    carrier = source(
        "SourceFiles/e2e_cloud/transport/telegram_carrier_transport.cpp"
    )
    backend = source(
        "SourceFiles/e2e_cloud/transport/"
        "telegram_session_carrier_backend.cpp"
    )
    service = source("SourceFiles/e2e_cloud/desktop/desktop_service.cpp")
    chunk_store = source(
        "SourceFiles/e2e_cloud/files/file_chunk_file_store.cpp"
    )
    upload = function_body(
        service,
        "bool DesktopService::pumpFileTransfer(",
        "void DesktopService::completeFileChunkUpload(",
    )
    complete = function_body(
        service,
        "void DesktopService::completeFileChunkUpload(",
        "bool DesktopService::queuePendingFileManifest(",
    )
    write_file = function_body(
        service,
        "bool DesktopService::writePendingProtectedFile(",
        "void DesktopService::finishFileChunkDownload(",
    )
    incoming = function_body(
        service,
        "void DesktopService::handleNewTelegramItem(",
        "void DesktopService::queueGroupDiscovery(",
    )
    download = function_body(
        service,
        "bool DesktopService::beginFileChunkDownload(",
        "FileChunkDownloadPageStatus "
        "DesktopService::processFileChunkDownloadPage(",
    )

    assert "ProtectedFileChunkCarrierFilename(" in carrier
    assert "DecodeFileChunkEnvelopeMetadata(" in carrier
    assert "group.transport.uploadExact(" in upload
    assert "group.contentTransport.uploadExact(" not in upload
    assert "ProtectedFileChunkCarrierFilename(" not in incoming
    assert "ProtectedFileChunkCarrierFilename(" in download
    assert "kFileDownloadPageBytes" in download
    assert "minimumMessageIdExclusive" in backend
    assert complete.index("fileTransfer.advance(chunkIndex)") \
        < complete.index("group.chunkStore.removeChunk(")
    assert write_file.index("if (write.committed)") \
        < write_file.index("group.chunkStore.removeChunk(")
    assert write_file.index("write.output->commit()") \
        < write_file.index("write.committed = true;")
    assert "write.nextChunkIndex" in write_file
    assert "scheduleNext();" in write_file
    assert "kFileCleanupChunksPerTurn" in write_file
    assert "group.chunkStore.hasChunk(" in service
    assert "bool FileChunkFileStore::hasChunk(" in chunk_store
    assert "bool FileChunkFileStore::removeChunk(" in chunk_store
    assert "releaseStorage(std::uint64_t(size));" in chunk_store


def verify_accepted_file_chunks_are_recovered_and_cleaned() -> None:
    service = source("SourceFiles/e2e_cloud/desktop/desktop_service.cpp")
    chunk_store = source(
        "SourceFiles/e2e_cloud/files/file_chunk_file_store.cpp"
    )
    cancel = function_body(
        service,
        "bool DesktopService::finishFileTransferCancellation(",
        "void DesktopService::completeActiveUpload(",
    )
    upload = function_body(
        service,
        "bool DesktopService::pumpFileTransfer(",
        "void DesktopService::completeFileChunkUpload(",
    )
    finalize = function_body(
        service,
        "bool DesktopService::finalizeFileTransfer(",
        "void DesktopService::beginGroupObservation(",
    )

    assert "bool FileChunkFileStore::removeChunksBefore(" in chunk_store
    assert "pending->nextChunkIndex" in upload
    assert "group.chunkStore.removeChunksBefore(" in upload
    assert "manifest->context.chunkCount" in cancel
    assert "group.chunkStore.removeChunksBefore(" in cancel
    assert "manifest->context.chunkCount" in finalize
    assert "group.chunkStore.removeChunksBefore(" in finalize
    assert "tryLock(5000)" not in chunk_store
    assert chunk_store.count("tryLock(0)") == 3


def verify_new_file_cannot_replace_pending_transfer() -> None:
    service = source("SourceFiles/e2e_cloud/desktop/desktop_service.cpp")
    file_send = function_body(
        service,
        "bool DesktopService::sendProtectedFile(",
        "bool DesktopService::saveProtectedFile(",
    )
    queue_manifest = function_body(
        service,
        "bool DesktopService::queuePendingFileManifest(",
        "bool DesktopService::finalizeFileTransfer(",
    )
    finalize = function_body(
        service,
        "bool DesktopService::finalizeFileTransfer(",
        "void DesktopService::beginGroupObservation(",
    )

    assert file_send.index("i->second->fileTransfer.pending()") \
        < file_send.index("crl::async(")
    assert file_send.index("crl::async(") \
        < file_send.index("HashFile(absolutePath, cancellation)")
    assert "group.fileHashInProgress = true;" in file_send
    assert "commitPreparedFileTransfer(conversationId)" in service
    assert "group.fileTransfer.begin(std::move(transfer))" in service
    assert "group.fileTransfer.replace(" not in file_send
    assert "HashFile(" not in queue_manifest
    assert finalize.index("crl::async(") \
        < finalize.index("HashFile(sourcePath, cancellation)")


def verify_failed_file_transfer_can_be_cancelled_durably() -> None:
    service = source("SourceFiles/e2e_cloud/desktop/desktop_service.cpp")
    transfer = source(
        "SourceFiles/e2e_cloud/files/persistent_file_transfer.cpp"
    )
    outbox = source("SourceFiles/e2e_cloud/storage/persistent_outbox.cpp")
    box = source(
        "SourceFiles/e2e_cloud/desktop/protected_conversation_box.cpp"
    )
    pump = function_body(
        service,
        "void DesktopService::pumpActiveOutbox(",
        "bool DesktopService::prepareActiveUploadAcknowledgement(",
    )
    cancel = function_body(
        service,
        "bool DesktopService::cancelProtectedFileTransfer(",
        "bool DesktopService::saveProtectedFile(",
    )
    complete_upload = function_body(
        service,
        "void DesktopService::completeActiveUpload(",
        "bool DesktopService::pumpFileTransfer(",
    )
    complete_chunk = function_body(
        service,
        "void DesktopService::completeFileChunkUpload(",
        "bool DesktopService::queuePendingFileManifest(",
    )
    restore = function_body(
        service,
        "DesktopService::LocalGroupRecoveryResult "
        "DesktopService::restoreLocalGroup(",
        "bool DesktopService::commitVaultAnchor(",
    )
    publisher = function_body(
        service,
        "void DesktopService::publishNextBootstrapObject()",
        "void DesktopService::resumePendingGroupCreation()",
    )

    assert "FileTransferCommitResult " \
        "PersistentFileTransfer::requestCancel()" in transfer
    assert "AppendUint16(plaintext, 3);" in transfer
    assert "AppendUint8(plaintext, pending->cancelRequested ? 1 : 0)" \
        in transfer
    mark_manifest = function_body(
        transfer,
        "FileTransferCommitResult "
        "PersistentFileTransfer::markManifestPublished(",
        "FileTransferCommitResult PersistentFileTransfer::requestCancel()",
    )
    assert "_pending->cancelRequested" not in mark_manifest
    assert "bool PersistentOutboxStore::removePair(" in outbox
    assert pump.index("pending->cancelRequested") \
        < pump.index("queuePendingFileManifest(conversationId)")
    assert "uploadInProgress" not in cancel
    cancel_branch = pump[
        pump.index("pending && pending->cancelRequested"):
        pump.index("if (group.fileHashInProgress)")
    ]
    assert "group.uploadInProgress" in cancel_branch
    assert "group.fileFinalHashInProgress" in cancel_branch
    assert "uploadController->uploadInProgress()" in cancel_branch
    assert "DesktopContentState::Synchronizing" in cancel_branch
    assert complete_upload.index("pending->cancelRequested") \
        < complete_upload.index(
            "TelegramTransport::UploadResult::RetryableError"
        )
    assert complete_chunk.index("pending->cancelRequested") \
        < complete_chunk.index(
            "TelegramTransport::UploadResult::RetryableError"
        )
    assert "finishFileTransferCancellation(*operation)" not in restore
    assert "finishFileTransferCancellation(group)" in publisher
    finish = function_body(
        service,
        "bool DesktopService::finishFileTransferCancellation(",
        "void DesktopService::completeActiveUpload(",
    )
    assert "group.fileFinalHashInProgress" in finish
    assert "cancelProtectedFileTransfer(" in box
    assert "fileTransferPending" in box


def verify_file_preparation_can_be_cancelled() -> None:
    service = source("SourceFiles/e2e_cloud/desktop/desktop_service.cpp")
    summary = function_body(
        service,
        "DesktopService::protectedGroups() const",
        "std::optional<ConversationId> "
        "DesktopService::protectedConversationForPeer(",
    )
    send_text = function_body(
        service,
        "bool DesktopService::sendProtectedText(",
        "bool DesktopService::sendProtectedFile(",
    )
    send_file = function_body(
        service,
        "bool DesktopService::sendProtectedFile(",
        "bool DesktopService::cancelProtectedFileTransfer(",
    )
    cancel = function_body(
        service,
        "bool DesktopService::cancelProtectedFileTransfer(",
        "bool DesktopService::saveProtectedFile(",
    )
    finalize = function_body(
        service,
        "bool DesktopService::finalizeFileTransfer(",
        "void DesktopService::beginGroupObservation(",
    )
    hashing = function_body(
        service,
        "[[nodiscard]] std::optional<HashedFile> HashFile(",
        "} // namespace",
    )

    assert "group->fileHashInProgress" in summary
    assert "!group->filePreparationPath.isEmpty()" in summary
    assert "i->second->fileHashInProgress" in send_text
    assert "!i->second->filePreparationPath.isEmpty()" in send_text
    assert "group.fileHashCancellation = cancellation;" in send_file
    assert "notifyFileTransferRevision();" in send_file
    assert "group.fileHashCancelRequested = true;" in cancel
    assert "group.fileHashCancellation->store(" in cancel
    assert "group.fileFinalHashCancellation->store(" in cancel
    assert "fileFinalHashCancellation = cancellation;" in finalize
    assert hashing.count("cancellation->load(std::memory_order_relaxed)") >= 2


def verify_administration_waits_for_outgoing_work() -> None:
    service = source("SourceFiles/e2e_cloud/desktop/desktop_service.cpp")
    administration = function_body(
        service,
        "bool DesktopService::applyAdministrativeTransition(",
        "bool DesktopService::admitObservedClient(",
    )
    move_to_creation = administration.index(
        "_pendingGroupCreation = std::move(i->second)"
    )

    assert administration.index("group.fileHashInProgress") \
        < move_to_creation
    assert administration.index("group.fileTransfer.pending()") \
        < move_to_creation
    assert administration.index("group.uploadInProgress") \
        < move_to_creation
    assert administration.index("group.outbox.size()") \
        < move_to_creation
    assert administration.index("uploadController->uploadInProgress()") \
        < move_to_creation


def verify_transient_file_work_serializes_control_changes() -> None:
    service = source("SourceFiles/e2e_cloud/desktop/desktop_service.cpp")
    save_file = function_body(
        service,
        "bool DesktopService::saveProtectedFile(",
        "bool DesktopService::beginFileChunkDownload(",
    )
    finish_download = function_body(
        service,
        "void DesktopService::finishFileChunkDownload(",
        "bool DesktopService::setProtectedDefaultHistory(",
    )
    observation = function_body(
        service,
        "void DesktopService::beginGroupObservation(",
        "void DesktopService::beginContentObservation(",
    )
    administration = function_body(
        service,
        "bool DesktopService::applyAdministrativeTransition(",
        "bool DesktopService::admitObservedClient(",
    )
    observation_start = observation.index(
        "group.observation = std::make_unique<PublicBootstrapSyncController>"
    )

    assert save_file.index("group.observation") \
        < save_file.index("group.pendingFileDownload =")
    assert save_file.index("group.observationDirty") \
        < save_file.index("group.pendingFileDownload =")
    assert observation.index("group.fileHashInProgress") \
        < observation_start
    assert observation.index("group.fileFinalHashInProgress") \
        < observation_start
    assert observation.index("group.pendingFileDownload") \
        < observation_start
    assert finish_download.index("group.pendingFileDownload.reset()") \
        < finish_download.index("beginGroupObservation(conversationId)")
    assert administration.index("group.pendingFileDownload") \
        < administration.index("_pendingGroupCreation = std::move(i->second)")


def verify_control_precedes_content_observation() -> None:
    service = source("SourceFiles/e2e_cloud/desktop/desktop_service.cpp")
    pump = function_body(
        service,
        "void DesktopService::pumpActiveOutbox(",
        "bool DesktopService::prepareActiveUploadAcknowledgement(",
    )
    control = function_body(
        service,
        "void DesktopService::beginGroupObservation(",
        "void DesktopService::beginContentObservation(",
    )
    content = function_body(
        service,
        "void DesktopService::beginContentObservation(",
        "ObservedContentPageResult DesktopService::previewObservedFileManifests(",
    )
    apply_content = function_body(
        service,
        "void DesktopService::applyContentObservation(",
        "void DesktopService::applyGroupObservation(",
    )
    administration = function_body(
        service,
        "bool DesktopService::applyAdministrativeTransition(",
        "bool DesktopService::admitObservedClient(",
    )

    assert control.index("group.contentObservation") \
        < control.index(
            "group.observation = std::make_unique<PublicBootstrapSyncController>"
        )
    assert content.index("group.observation") \
        < content.index(
            "std::make_unique<ObservedContentSyncController>"
        )
    assert content.index("group.observationDirty") \
        < content.index(
            "std::make_unique<ObservedContentSyncController>"
        )
    assert "const auto resumeControlObservation = qScopeGuard" \
        in apply_content
    assert "beginGroupObservation(conversationId);" in apply_content
    assert administration.index("group.contentObservation") \
        < administration.index("_pendingGroupCreation = std::move(i->second)")
    active = pump.index("if (group.observation)")
    dirty = pump.index(
        "else if (group.observationDirty && !group.outbox.size())"
    )
    assert active < dirty
    assert "beginGroupObservation(conversationId);" not in pump[active:dirty]


def verify_transport_failures_can_be_retried_manually() -> None:
    service = source("SourceFiles/e2e_cloud/desktop/desktop_service.cpp")
    box = source("SourceFiles/e2e_cloud/desktop/protected_groups_box.cpp")
    discovery = function_body(
        service,
        "void DesktopService::ensureVaultDiscovery()",
        "bool DesktopService::unlock(",
    )
    unlock = function_body(
        service,
        "bool DesktopService::unlock(",
        "bool DesktopService::createVault(",
    )
    retry_group = function_body(
        service,
        "bool DesktopService::retryProtectedGroupCreation()",
        "std::vector<DesktopProtectedGroupSummary>",
    )
    refresh = function_body(
        box,
        "void ProtectedGroupsBox::refresh()",
        "void ProtectedGroupsBox::submit()",
    )

    assert "DesktopVaultState::DiscoveryPermanentError" in discovery
    assert "DesktopVaultState::PermanentTransportError" in unlock
    assert "DesktopGroupCreationState::PermanentTransportError" \
        in retry_group
    assert refresh.count(
        "case DesktopVaultState::PermanentTransportError:"
    ) == 1
    assert refresh.count(
        "case DesktopVaultState::DiscoveryPermanentError:"
    ) == 1
    permanent = refresh[
        refresh.index("case DesktopVaultState::PermanentTransportError:"):
        refresh.index("case DesktopVaultState::DiscoveryRetryableError:")
    ]
    discovery_permanent = refresh[
        refresh.index("case DesktopVaultState::DiscoveryPermanentError:"):
        refresh.index("case DesktopVaultState::SecurityBlocked:")
    ]
    security_blocked = refresh[
        refresh.index("case DesktopVaultState::SecurityBlocked:"):
        refresh.index("addButton(tr::lng_close()")
    ]
    assert "tr::lng_e2e_cloud_retry()" in permanent
    assert "tr::lng_e2e_cloud_retry()" in discovery_permanent
    assert "tr::lng_e2e_cloud_retry()" not in security_blocked


def verify_lock_closes_protected_plaintext_surfaces() -> None:
    header = source("SourceFiles/e2e_cloud/desktop/desktop_service.h")
    service = source("SourceFiles/e2e_cloud/desktop/desktop_service.cpp")
    conversation = source(
        "SourceFiles/e2e_cloud/desktop/protected_conversation_box.cpp"
    )
    groups = source(
        "SourceFiles/e2e_cloud/desktop/protected_groups_box.cpp"
    )
    lock = function_body(
        service,
        "void DesktopService::lock()",
        "void DesktopService::applyVaultDiscoveryResult(",
    )
    refresh = function_body(
        groups,
        "void ProtectedGroupsBox::refresh()",
        "void ProtectedGroupsBox::submit()",
    )
    locked = refresh[
        refresh.index("case DesktopVaultState::Locked:"):
        refresh.index("case DesktopVaultState::Loading:")
    ]

    assert "void notifyContentRevision();" in header
    assert "void notifyFileTransferRevision();" in header
    assert "void notifySecurityRevision();" in header
    for revision in (
        "_contentRevision = 0",
        "_fileTransferRevision = 0",
        "_securityRevision = 0",
    ):
        assert revision not in lock
    assert lock.index("_groups.clear();") < lock.index("_vault.reset();")
    assert lock.index("_vault.reset();") \
        < lock.index("notifyFileTransferRevision();")
    assert lock.index("notifyFileTransferRevision();") \
        < lock.index("notifyContentRevision();")
    assert lock.index("notifyContentRevision();") \
        < lock.index("notifySecurityRevision();")
    assert "void CloseWhenVaultUnavailable(" in conversation
    assert "state != DesktopVaultState::Ready" in conversation
    assert conversation.count("CloseWhenVaultUnavailable(box, service);") == 5
    assert "_password->setText(QString());" in locked
    assert "_confirm->setText(QString());" in locked
    assert service.count("notifySecurityRevision();") >= 6


def verify_security_failures_destroy_the_unlocked_runtime() -> None:
    header = source("SourceFiles/e2e_cloud/desktop/desktop_service.h")
    service = source("SourceFiles/e2e_cloud/desktop/desktop_service.cpp")
    constructor = function_body(
        service,
        "DesktopService::DesktopService(not_null<Main::Session*> session)",
        "DesktopService::~DesktopService()",
    )
    schedule = function_body(
        service,
        "void DesktopService::scheduleSecurityLock()",
        "void DesktopService::ensureVaultDiscovery()",
    )
    create_upload = function_body(
        service,
        "void DesktopService::uploadPendingCreation()",
        "void DesktopService::beginGroupVaultPreflight()",
    )

    assert "bool _securityLockScheduled = false;" in header
    assert "[[nodiscard]] bool vaultReady() const;" in header
    assert "void scheduleSecurityLock();" in header
    assert "_vaultState.value(" in constructor
    assert "state == DesktopVaultState::SecurityBlocked" in constructor
    assert "scheduleSecurityLock();" in constructor
    assert "crl::on_main(" in schedule
    assert "_securityLockScheduled = false;" in schedule
    assert "weak->hasProtectedRuntimeState()" in schedule
    assert "weak->lock();" in schedule
    assert "return vaultReady() ? &*_vault : nullptr;" in service
    assert "!weak->vaultReady()" not in create_upload

    guarded_functions = (
        ("std::vector<DesktopProtectedGroupSummary>\n"
         "DesktopService::protectedGroups() const", "std::optional<ConversationId>"),
        ("std::optional<ConversationId> DesktopService::protectedConversationForPeer(",
         "std::vector<ProtectedContentRecord>"),
        ("std::vector<ProtectedContentRecord> DesktopService::protectedContent(",
         "std::size_t DesktopService::protectedContentCount("),
        ("std::size_t DesktopService::protectedContentCount(",
         "std::optional<DesktopProtectedSecurity>"),
        ("std::optional<DesktopProtectedSecurity> DesktopService::protectedSecurity(",
         "bool DesktopService::sendProtectedText("),
        ("bool DesktopService::sendProtectedText(",
         "bool DesktopService::sendProtectedFile("),
        ("bool DesktopService::sendProtectedFile(",
         "bool DesktopService::cancelProtectedFileTransfer("),
        ("bool DesktopService::cancelProtectedFileTransfer(",
         "bool DesktopService::saveProtectedFile("),
        ("bool DesktopService::saveProtectedFile(",
         "bool DesktopService::beginFileChunkDownload("),
        ("void DesktopService::synchronizeProtectedContent(",
         "void DesktopService::lock()"),
        ("bool DesktopService::applyAdministrativeTransition(",
         "bool DesktopService::admitObservedClient("),
        ("void DesktopService::handleNewTelegramItem(",
         "void DesktopService::queueGroupDiscovery("),
        ("void DesktopService::pumpActiveOutbox(",
         "bool DesktopService::prepareActiveUploadAcknowledgement("),
        ("void DesktopService::beginGroupObservation(",
         "void DesktopService::beginContentObservation("),
        ("void DesktopService::beginContentObservation(",
         "ObservedContentPageResult DesktopService::previewObservedFileManifests("),
        ("void DesktopService::publishNextBootstrapObject(",
         "void DesktopService::resumePendingGroupCreation("),
        ("bool DesktopService::processObservedFreshness(",
         "bool DesktopService::processObservedSafetyGossip("),
        ("bool DesktopService::processObservedSafetyGossip(",
         "bool DesktopService::synchronizeObservedGroupChanges("),
        ("bool DesktopService::completeObservedJoin(",
         "bool DesktopService::acceptObservedHistoryGrant("),
        ("bool DesktopService::admitObservedClient(",
         "DesktopService::LocalGroupRecoveryResult"),
    )
    for signature, next_signature in guarded_functions:
        body = function_body(service, signature, next_signature)
        assert "vaultReady()" in body, signature


def verify_admission_and_discovery_failures_can_be_retried() -> None:
    service = source("SourceFiles/e2e_cloud/desktop/desktop_service.cpp")
    retry = function_body(
        service,
        "bool DesktopService::retryProtectedGroupCreation()",
        "std::vector<DesktopProtectedGroupSummary>",
    )
    start_discovery = function_body(
        service,
        "void DesktopService::startNextGroupDiscovery()",
        "void DesktopService::applyGroupDiscovery(",
    )
    apply_discovery = function_body(
        service,
        "void DesktopService::applyGroupDiscovery(",
        "bool DesktopService::completeObservedJoin(",
    )
    apply_observation = function_body(
        service,
        "void DesktopService::applyGroupObservation(",
        "void DesktopService::handleNewTelegramItem(",
    )

    assert "auto admissions = std::vector<ConversationId>();" in retry
    assert "PendingGroupCreation::Phase::AwaitingAdmission" in retry
    assert "beginGroupObservation(conversationId);" in retry
    assert "restartedAdmission || !stillAwaiting" in retry
    assert "admissionRestartFailed" in retry
    assert "if (stillAwaiting && admissionRestartFailed)" in retry
    assert "DesktopGroupCreationState::AwaitingAdmission" in retry
    assert retry.index("DesktopGroupCreationState::AwaitingAdmission") \
        < retry.index("beginGroupObservation(conversationId);")
    assert "const auto operationState = _groupCreationState.current();" \
        in start_discovery
    assert "operationState != DesktopGroupCreationState::Idle" \
        in start_discovery
    assert "operationState != DesktopGroupCreationState::Ready" \
        in start_discovery
    preparing = start_discovery.index(
        "_groupCreationState = DesktopGroupCreationState::Preparing;"
    )
    start_call = start_discovery.index(
        "if (!_pendingGroupDiscovery->sync->start())"
    )
    assert preparing < start_call
    failed_start = start_discovery.index(
        "if (!_pendingGroupDiscovery->sync->start())"
    )
    failed_start_body = start_discovery[failed_start:]
    assert "_groupDiscoveryQueue.emplace(peerId);" in failed_start_body
    assert "DesktopGroupCreationState::RetryableTransportError" \
        in failed_start_body
    assert "continue;" not in failed_start_body
    permanent = apply_discovery.index(
        "PublicBootstrapSyncStatus::PermanentTransportError"
    )
    queued = apply_discovery.index("_groupDiscoveryQueue.emplace(peerId);")
    assert permanent < queued
    assert "DesktopGroupCreationState::PermanentTransportError" \
        in apply_discovery[permanent:]
    assert "const auto awaiting = i->second->phase" in apply_observation
    error = apply_observation.index(
        "result.status != PublicBootstrapSyncStatus::Verified"
    )
    success = apply_observation.index("auto changed = false;")
    admission_error = apply_observation[error:success]
    assert "if (awaiting)" in admission_error
    assert "DesktopGroupCreationState::RetryableTransportError" \
        in admission_error
    assert "DesktopGroupCreationState::PermanentTransportError" \
        in admission_error
    assert "startNextGroupDiscovery();" in apply_observation


def verify_open_protected_views_do_not_keep_stale_state() -> None:
    conversation = source(
        "SourceFiles/e2e_cloud/desktop/protected_conversation_box.cpp"
    )
    member = function_body(
        conversation,
        "void ShowProtectedMemberSecurity(",
        "void ShowProtectedSecurity(",
    )
    security = function_body(
        conversation,
        "void ShowProtectedSecurity(",
        "void ShowProtectedFiles(",
    )
    files = function_body(
        conversation,
        "void ShowProtectedFiles(",
        "} // namespace",
    )
    chat = function_body(
        conversation,
        "void ShowProtectedConversation(",
        "} // namespace E2ECloud",
    )

    assert "void CloseWhenSecurityChanges(" in conversation
    assert "rpl::skip(1)" in conversation
    assert "box->closeBox();" in conversation[
        conversation.index("void CloseWhenSecurityChanges("):
        conversation.index("[[nodiscard]] QString RecordText(")
    ]
    assert "CloseWhenSecurityChanges(box, service);" in member
    assert "CloseWhenSecurityChanges(box, service);" in security
    assert "service->contentRevisionValue(" in files
    assert "RebuildProtectedFiles(" in files
    assert "service->securityRevisionValue(" in chat
    assert "refreshStatus();" in chat[
        chat.index("service->securityRevisionValue("):]


def verify_failed_control_start_does_not_wait_forever() -> None:
    service = source("SourceFiles/e2e_cloud/desktop/desktop_service.cpp")
    begin = function_body(
        service,
        "void DesktopService::beginGroupObservation(",
        "void DesktopService::beginContentObservation(",
    )
    pump = function_body(
        service,
        "void DesktopService::pumpActiveOutbox(",
        "bool DesktopService::prepareActiveUploadAcknowledgement(",
    )

    failed = begin[begin.index("if (!started) {"):]
    assert "DesktopContentState::RetryableTransportError" in failed
    assert "PendingGroupCreation::Phase::AwaitingAdmission" in failed
    assert "DesktopGroupCreationState::RetryableTransportError" in failed
    start = pump.index("beginGroupObservation(conversationId);")
    after_start = pump[start:]
    assert "const auto current = _groups.find(conversationId);" \
        in after_start
    assert after_start.index("const auto current = _groups.find") \
        < after_start.index("current->second->observation")
    assert "group.observation || group.observationDirty" not in after_start
    dirty = after_start.index("current->second->observationDirty")
    ready = after_start.index("if (const auto pending")
    assert "DesktopContentState::Synchronizing" not in after_start[
        dirty:ready
    ]


def verify_file_download_security_failures_lock_the_vault() -> None:
    service = source("SourceFiles/e2e_cloud/desktop/desktop_service.cpp")
    apply = function_body(
        service,
        "void DesktopService::applyFileChunkDownload(",
        "bool DesktopService::writePendingProtectedFile(",
    )
    security = apply[
        apply.index("FileChunkDownloadStatus::SecurityBlocked"):
        apply.index("FileChunkDownloadStatus::Complete")
    ]

    assert "FileChunkDownloadStatus::InvalidPagination" in security
    assert "FileChunkDownloadStatus::LimitExceeded" in security
    assert "_vaultState = DesktopVaultState::SecurityBlocked;" in security
    assert "DesktopContentState::SecurityBlocked" in security
    assert "ProtectedFileSaveResult::SecurityBlocked" in security
    assert security.index("_vaultState = DesktopVaultState::SecurityBlocked;") \
        < security.index("finishFileChunkDownload(")


def verify_vault_changing_group_operations_are_serialized() -> None:
    service = source("SourceFiles/e2e_cloud/desktop/desktop_service.cpp")
    create = function_body(
        service,
        "bool DesktopService::createProtectedGroup(",
        "bool DesktopService::retryProtectedGroupCreation()",
    )
    administration = function_body(
        service,
        "bool DesktopService::applyAdministrativeTransition(",
        "bool DesktopService::admitObservedClient(",
    )

    for body in (create, administration):
        assert "const auto operationState = _groupCreationState.current();" \
            in body
        assert "operationState != DesktopGroupCreationState::Idle" in body
        assert "operationState != DesktopGroupCreationState::Ready" in body
    assert "|| _pendingGroupCreation" in administration
    assert "|| _pendingGroupJoin" in administration
    assert "|| _pendingGroupDiscovery" in administration


def verify_global_vault_work_defers_control_boundaries() -> None:
    header = source("SourceFiles/e2e_cloud/desktop/desktop_service.h")
    service = source("SourceFiles/e2e_cloud/desktop/desktop_service.cpp")
    begin = function_body(
        service,
        "void DesktopService::beginGroupObservation(",
        "void DesktopService::resumeDeferredGroupObservations(",
    )
    resume = function_body(
        service,
        "void DesktopService::resumeDeferredGroupObservations(",
        "void DesktopService::beginContentObservation(",
    )
    apply = function_body(
        service,
        "void DesktopService::applyGroupObservation(",
        "void DesktopService::handleNewTelegramItem(",
    )
    discovery = function_body(
        service,
        "void DesktopService::startNextGroupDiscovery()",
        "void DesktopService::applyGroupDiscovery(",
    )

    assert "void resumeDeferredGroupObservations();" in header
    for body in (begin, resume, apply):
        assert "_pendingGroupCreation" in body
        assert "_pendingGroupJoin" in body
        assert "_pendingGroupDiscovery" in body
    assert "group.observationDirty = true;" in begin
    assert "auto conversations = std::vector<ConversationId>();" in resume
    assert "beginGroupObservation(conversationId);" in resume
    deferred = apply.index("if (_pendingGroupCreation")
    process_changes = apply.index("synchronizeObservedGroupChanges(")
    security = apply.index("PublicBootstrapSyncStatus::ObjectConflict")
    assert security < deferred < process_changes
    assert "i->second->observationDirty = true;" \
        in apply[deferred:process_changes]
    assert "entry.second->observation" in discovery
    assert "entry.second->observationDirty" in discovery
    assert service.count("resumeDeferredGroupObservations();") >= 8


def verify_removed_clients_discard_outgoing_work() -> None:
    service = source("SourceFiles/e2e_cloud/desktop/desktop_service.cpp")
    outbox = source("SourceFiles/e2e_cloud/storage/persistent_outbox.cpp")
    publisher = function_body(
        service,
        "void DesktopService::publishNextBootstrapObject()",
        "void DesktopService::resumePendingGroupCreation()",
    )
    restore = function_body(
        service,
        "DesktopService::LocalGroupRecoveryResult "
        "DesktopService::restoreLocalGroup(",
        "bool DesktopService::commitVaultAnchor(",
    )

    item = publisher.index("auto item = _pendingGroupCreation->outbox.front(")
    assert publisher.index("group.fileTransfer.requestCancel()") < item
    assert publisher.index("finishFileTransferCancellation(group)") < item
    assert publisher.index("group.outbox.clear()") < item
    assert "bool PersistentOutboxStore::clear()" in outbox
    assert "persist({}, revision)" in outbox
    assert "!(removed && operation->fileTransfer.pending())" in restore


def verify_equal_content_states_notify_every_group() -> None:
    service = source("SourceFiles/e2e_cloud/desktop/desktop_service.cpp")
    setter = function_body(
        service,
        "void DesktopService::setContentState(",
        "void DesktopService::notifyContentRevision()",
    )

    assert "_contentStates[conversationId] = state;" in setter
    assert "_contentState.force_assign(state);" in setter
    assert "_contentState = state;" not in setter


def main() -> None:
    verify_carrier_tracking()
    verify_group_scope()
    verify_protected_peers_never_downgrade_to_plaintext()
    verify_all_e2e_tests_are_registered()
    verify_discovery_has_a_timeout()
    verify_all_carrier_operations_have_timeouts()
    verify_carrier_backfill_searches_documents()
    verify_ambiguous_search_results_fail_closed()
    verify_download_pages_are_bounded_at_every_layer()
    verify_key_packages_bind_the_observed_telegram_author()
    verify_unanchored_vault_history_is_contiguous()
    verify_late_vault_uploads_cannot_cross_lock_boundary()
    verify_file_chunk_self_observation_uses_exact_ciphertext()
    verify_pending_plaintext_is_cleansed()
    verify_manifest_key_is_owned_before_variable_fields()
    verify_control_sync_blocks_outgoing_races()
    verify_freshness_wait_does_not_busy_poll()
    verify_control_sync_uses_a_persistent_boundary()
    verify_content_sync_requires_its_saved_boundary()
    verify_deferred_content_keeps_its_saved_boundary()
    verify_pagination_cursor_tracking_is_bounded()
    verify_freshness_witness_is_rechecked_after_catchup()
    verify_completion_callbacks_survive_owner_reset()
    verify_group_discovery_retries_without_creation_races()
    verify_group_setup_commits_metadata_last()
    verify_group_carriers_publish_before_vault_index()
    verify_freshness_challenges_resume_and_replays_stop()
    verify_observed_mls_receipts_finish_crash_recovery()
    verify_protected_groups_layout_uses_own_visibility()
    verify_protected_history_can_page_back()
    verify_protected_plaintext_is_loaded_by_page()
    verify_local_record_reads_are_bounded()
    verify_file_chunks_require_manifests_and_quota()
    verify_file_chunks_download_only_on_demand()
    verify_accepted_file_chunks_are_recovered_and_cleaned()
    verify_new_file_cannot_replace_pending_transfer()
    verify_failed_file_transfer_can_be_cancelled_durably()
    verify_file_preparation_can_be_cancelled()
    verify_administration_waits_for_outgoing_work()
    verify_transient_file_work_serializes_control_changes()
    verify_control_precedes_content_observation()
    verify_transport_failures_can_be_retried_manually()
    verify_lock_closes_protected_plaintext_surfaces()
    verify_security_failures_destroy_the_unlocked_runtime()
    verify_admission_and_discovery_failures_can_be_retried()
    verify_open_protected_views_do_not_keep_stale_state()
    verify_failed_control_start_does_not_wait_forever()
    verify_file_download_security_failures_lock_the_vault()
    verify_vault_changing_group_operations_are_serialized()
    verify_global_vault_work_defers_control_boundaries()
    verify_removed_clients_discard_outgoing_work()
    verify_equal_content_states_notify_every_group()


if __name__ == "__main__":
    main()

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
    assert "discoveryTimedOut(requestId);" in backend
    assert "api.request(base::take(discoveryRequestId)).cancel();" in backend
    assert "UploadResult::RetryableError" in function_body(
        backend,
        "void discoveryTimedOut(mtpRequestId requestId)",
        "void discoveryLoaded(const MTPmessages_Messages &result)",
    )


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
    verify_protected_groups_layout_uses_own_visibility()
    verify_protected_history_can_page_back()


if __name__ == "__main__":
    main()

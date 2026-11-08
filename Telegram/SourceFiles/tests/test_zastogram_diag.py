from pathlib import Path


SOURCES = Path(__file__).resolve().parents[1]
ROOT = SOURCES.parent


def source(relative):
    return (SOURCES / relative).read_text(encoding="utf-8")


def between(text, start, end):
    begin = text.index(start)
    return text[begin:text.index(end, begin)]


def test_module_is_built():
    cmake = (ROOT / "CMakeLists.txt").read_text(encoding="utf-8")
    assert "core/zsg_diag.cpp" in cmake
    assert "core/zsg_diag.h" in cmake


def test_link_map_is_produced():
    # Без карты отчёт о падении — только смещения, имён функций не получить.
    cmake = (ROOT / "CMakeLists.txt").read_text(encoding="utf-8")
    assert "/MAP:$<TARGET_FILE_DIR:Telegram>/Telegram.map" in cmake


def test_breakpad_reaches_the_module():
    crash = source("core/crash_reports.cpp")
    callback = between(
        crash,
        "bool DumpCallback(const wchar_t*",
        "#endif // !Q_OS_MAC || MAC_USE_BREAKPAD")
    assert "Core::ZsgDiag::OnBreakpadException(exinfo)" in callback
    # Обработчик ставится в конце StartCatching, а SIGABRT — после Start().
    catching = between(crash, "void StartCatching()", "bool WriteMinidumpNow()")
    assert "Core::ZsgDiag::Install()" in catching
    assert "bool WriteMinidumpNow()" in crash
    sandbox = source("core/sandbox.cpp")
    start = sandbox.index("CrashReports::Start()")
    assert sandbox.index("ZsgDiag::Arm()", start) > start
    assert sandbox.index("ZsgDiag::ReportPreviousCrashes()", start) > start


def test_dumps_carry_memory():
    crash = source("core/crash_reports.cpp")
    assert "MiniDumpWithIndirectlyReferencedMemory" in crash
    assert "MINIDUMP_TYPE(MiniDumpNormal)" not in crash


def test_every_kind_of_death_is_covered():
    diag = source("core/zsg_diag.cpp")
    assert "std::set_terminate(TerminateHandler)" in diag
    assert "std::signal(SIGABRT, AbortHandler)" in diag
    assert "AddVectoredExceptionHandler(1, VectoredHandler)" in diag
    for code in ("0xC00000FDUL", "0xC0000374UL", "0xC0000409UL"):
        assert code in diag
    # Реальный стек по данным развёртывания образа, а не угадывание по стеку.
    assert "RtlVirtualUnwind" in diag


def test_signal_handler_chains_the_previous_one():
    diag = source("core/zsg_diag.cpp")
    body = between(diag, "void AbortHandler(", "// First-chance look")
    assert "PreviousAbort(sig)" in body


def test_report_path_does_not_allocate():
    diag = source("core/zsg_diag.cpp")
    body = between(diag, "void WriteReport(", "// Asks Breakpad")
    for forbidden in ("QString", "QFile", "new ", "std::string", "LOG("):
        assert forbidden not in body, forbidden


def test_old_reports_reach_the_log():
    diag = source("core/zsg_diag.cpp")
    body = between(diag, "void ReportPreviousCrashes()", "void Note(")
    assert "LOG((" in body
    assert ".reported" in body


def test_delete_path_leaves_breadcrumbs():
    histories = source("data/data_histories.cpp")
    body = between(
        histories,
        "void Histories::deleteMessages(const MessageIdsList &ids",
        "int Histories::sendRequest(")
    for note in ("delete: begin", "delete: destroying local items", "delete: done"):
        assert note in body
    assert "ZsgDiag::Scope" in body
    history = source("history/history.cpp")
    body = between(history, "void History::destroyMessage(", "bool History::hasE2ECloudGroupCarrier")
    assert "ZsgDiag::Scope" in body
    session = source("data/data_session.cpp")
    assert "server delete: begin" in session
    assert "Session::notifyItemsAboutToBeDestroyed" in session
    box = source("boxes/delete_messages_box.cpp")
    assert "delete: box confirmed" in box


def test_notification_gate_survives_merges():
    # upstream d23928eefa: без этого условия clearFromItem вызывается для
    # сообщений, которые не могут держать уведомление.
    history = source("history/history.cpp")
    body = between(history, "void History::destroyMessage(", "bool History::hasE2ECloudGroupCarrier")
    assert "if (CanHoldItemNotification(item))" in body
    assert body.index("CanHoldItemNotification(item)") < body.index("clearFromItem(item)")


def test_release_script_keeps_the_map():
    script = (ROOT.parent.parent / "zsg-release.sh")
    if not script.exists():
        return
    text = script.read_text(encoding="utf-8")
    assert "Telegram.map" in text
    assert "symbols" in text


if __name__ == "__main__":
    for name, value in list(globals().items()):
        if name.startswith("test_") and callable(value):
            value()

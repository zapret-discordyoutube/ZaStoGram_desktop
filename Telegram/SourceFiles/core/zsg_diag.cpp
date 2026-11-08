/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information see the local LEGAL file.
*/
#include "core/zsg_diag.h"

#include "base/debug_log.h"
#include "core/crash_reports.h"
#include "core/version.h"
#include "settings.h"

#include <QtCore/QDir>
#include <QtCore/QFile>
#include <QtCore/QFileInfo>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <stdexcept>
#include <iterator>
#include <typeinfo>

#ifdef Q_OS_WIN
#include <windows.h>
#endif // Q_OS_WIN

namespace Core::ZsgDiag {
namespace {

constexpr auto kNotes = 128;
constexpr auto kNoteSize = 96;
constexpr auto kReportSize = 48 * 1024;
constexpr auto kMaxFrames = 48;
constexpr auto kKeepReported = 20;
constexpr auto kKeepDumps = 10;

struct NoteEntry {
	char text[kNoteSize];
	unsigned long long when;
	unsigned long thread;
};

NoteEntry Notes[kNotes];
std::atomic<unsigned> NoteCounter = 0;

// Everything below is touched while the process is dying, so it is static:
// no allocation, no locks.
char Report[kReportSize];
size_t ReportLen = 0;
std::atomic<bool> ReportWritten = false;
std::atomic<bool> Installed = false;
std::atomic<bool> Armed = false;
const char *PendingKind = nullptr;
char PendingDetail[256] = {};

[[nodiscard]] unsigned long long NowMs() noexcept {
	using namespace std::chrono;
	return duration_cast<milliseconds>(
		steady_clock::now().time_since_epoch()).count();
}

[[nodiscard]] unsigned long ThreadId() noexcept {
#ifdef Q_OS_WIN
	return ::GetCurrentThreadId();
#else // Q_OS_WIN
	return 0;
#endif // else for Q_OS_WIN
}

void NoteImpl(
		char mark,
		const char *what,
		qint64 a,
		qint64 b) noexcept {
	const auto index = NoteCounter.fetch_add(1, std::memory_order_relaxed)
		% unsigned(kNotes);
	auto &entry = Notes[index];
	entry.when = NowMs();
	entry.thread = ThreadId();
	std::snprintf(
		entry.text,
		kNoteSize,
		"%c %s %lld %lld",
		mark,
		what ? what : "?",
		static_cast<long long>(a),
		static_cast<long long>(b));
}

void Append(const char *format, ...) noexcept {
	if (ReportLen + 1 >= size_t(kReportSize)) {
		return;
	}
	va_list args;
	va_start(args, format);
	const auto written = std::vsnprintf(
		Report + ReportLen,
		size_t(kReportSize) - ReportLen,
		format,
		args);
	va_end(args);
	if (written > 0) {
		ReportLen = std::min(
			ReportLen + size_t(written),
			size_t(kReportSize) - 1);
	}
}

[[nodiscard]] QString ReportsFolder() {
	return cWorkingDir() + QStringLiteral("tdata/dumps");
}

void AppendNotes() noexcept {
	const auto total = NoteCounter.load(std::memory_order_relaxed);
	const auto first = (total > unsigned(kNotes)) ? (total - kNotes) : 0U;
	const auto now = NowMs();
	Append("Recent actions (oldest first, '>' enter, '<' leave):\n");
	for (auto i = first; i != total; ++i) {
		const auto &entry = Notes[i % unsigned(kNotes)];
		if (!entry.text[0]) {
			continue;
		}
		Append(
			"  -%llums thread %lu %s\n",
			now - entry.when,
			entry.thread,
			entry.text);
	}
}

// Describes the exception that is being handled right now, if any.
void DescribeCurrentException(char *detail, size_t size) noexcept {
	detail[0] = 0;
	try {
		if (const auto current = std::current_exception()) {
			std::rethrow_exception(current);
		}
	} catch (const std::exception &e) {
		std::snprintf(
			detail,
			size,
			"%s: %.160s",
			typeid(e).name(),
			e.what());
	} catch (...) {
		std::snprintf(detail, size, "non-standard exception");
	}
}

#ifdef Q_OS_WIN

wchar_t Folder[600] = {};

#if defined(_M_X64)
[[nodiscard]] bool ReadQword(
		unsigned long long address,
		unsigned long long &result) {
	__try {
		result = *reinterpret_cast<const unsigned long long*>(address);
		return true;
	} __except (EXCEPTION_EXECUTE_HANDLER) {
		return false;
	}
}

// Walks the stack with the unwind data of the image (.pdata), so that the
// frames are real even in an optimized build without frame pointers.
[[nodiscard]] int Unwind(CONTEXT context, unsigned long long *frames) {
	auto count = 0;
	__try {
		while (count < kMaxFrames && context.Rip) {
			const auto pc = context.Rip;
			frames[count++] = pc;
			auto base = DWORD64(0);
			const auto entry = ::RtlLookupFunctionEntry(pc, &base, nullptr);
			if (!entry) {
				auto ret = 0ULL;
				if (!context.Rsp || !ReadQword(context.Rsp, ret)) {
					break;
				}
				context.Rip = ret;
				context.Rsp += 8;
			} else {
				auto data = PVOID(nullptr);
				auto frame = DWORD64(0);
				::RtlVirtualUnwind(
					UNW_FLAG_NHANDLER,
					base,
					pc,
					entry,
					&context,
					&data,
					&frame,
					nullptr);
			}
		}
	} __except (EXCEPTION_EXECUTE_HANDLER) {
	}
	return count;
}
#endif // _M_X64

void AppendFrame(int index, unsigned long long pc) noexcept {
	auto base = PVOID(nullptr);
	const auto header = ::RtlPcToFileHeader(PVOID(pc), &base);
	if (!header) {
		Append("  #%d 0x%llx (no module)\n", index, pc);
		return;
	}
	char path[MAX_PATH] = {};
	::GetModuleFileNameA(HMODULE(header), path, MAX_PATH);
	const auto slash = std::strrchr(path, '\\');
	Append(
		"  #%d %s+0x%llx\n",
		index,
		slash ? (slash + 1) : path,
		pc - reinterpret_cast<unsigned long long>(header));
}

void AppendProcessInfo() noexcept {
	const auto module = ::GetModuleHandleW(nullptr);
	char path[MAX_PATH] = {};
	::GetModuleFileNameA(module, path, MAX_PATH);
	const auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(module);
	const auto nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(
		reinterpret_cast<const char*>(module) + dos->e_lfanew);
	Append(
		"Exe: %s\n"
		"ImageBase: 0x%llx\n"
		"ImageSize: 0x%lx\n"
		"TimeDateStamp: 0x%08lx\n",
		path,
		reinterpret_cast<unsigned long long>(module),
		static_cast<unsigned long>(nt->OptionalHeader.SizeOfImage),
		static_cast<unsigned long>(nt->FileHeader.TimeDateStamp));
}

void WriteReport(
		const char *kind,
		const char *detail,
		const CONTEXT *context,
		const EXCEPTION_RECORD *record) noexcept {
	if (ReportWritten.exchange(true)) {
		return;
	}
	ReportLen = 0;
	SYSTEMTIME time = {};
	::GetLocalTime(&time);
	Append("ZaStoGram crash report\n");
	Append("Reason: %s\n", kind ? kind : "unknown");
	if (detail && detail[0]) {
		Append("Detail: %s\n", detail);
	}
	Append(
		"Version: %s\n"
		"Time: %04u-%02u-%02u %02u:%02u:%02u\n"
		"Process: %lu\n"
		"Thread: %lu\n",
		AppVersionStr,
		unsigned(time.wYear),
		unsigned(time.wMonth),
		unsigned(time.wDay),
		unsigned(time.wHour),
		unsigned(time.wMinute),
		unsigned(time.wSecond),
		::GetCurrentProcessId(),
		::GetCurrentThreadId());
	AppendProcessInfo();
	if (record) {
		Append(
			"ExceptionCode: 0x%08lx\n"
			"ExceptionAddress: 0x%llx\n",
			static_cast<unsigned long>(record->ExceptionCode),
			reinterpret_cast<unsigned long long>(record->ExceptionAddress));
		if (record->ExceptionCode == EXCEPTION_ACCESS_VIOLATION
			&& record->NumberParameters >= 2) {
			const auto access = record->ExceptionInformation[0];
			Append(
				"Access: %s of address 0x%llx\n",
				(access == 0) ? "read" : (access == 1) ? "write" : "execute",
				static_cast<unsigned long long>(
					record->ExceptionInformation[1]));
		}
	}
#if defined(_M_X64)
	auto local = CONTEXT();
	if (!context) {
		::RtlCaptureContext(&local);
		context = &local;
	}
	unsigned long long frames[kMaxFrames];
	const auto count = Unwind(*context, frames);
	Append("Stack (module+offset, subtract 1 from #1.. when resolving):\n");
	for (auto i = 0; i != count; ++i) {
		AppendFrame(i, frames[i]);
	}
#else // _M_X64
	(void)context;
#endif // else for _M_X64
	AppendNotes();

	wchar_t path[800] = {};
	_snwprintf_s(
		path,
		_TRUNCATE,
		L"%s\\zsg-crash-%04u%02u%02u-%02u%02u%02u-%lu.txt",
		Folder,
		unsigned(time.wYear),
		unsigned(time.wMonth),
		unsigned(time.wDay),
		unsigned(time.wHour),
		unsigned(time.wMinute),
		unsigned(time.wSecond),
		::GetCurrentProcessId());
	const auto file = ::CreateFileW(
		path,
		GENERIC_WRITE,
		FILE_SHARE_READ,
		nullptr,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		nullptr);
	if (file != INVALID_HANDLE_VALUE) {
		auto written = DWORD(0);
		::WriteFile(file, Report, DWORD(ReportLen), &written, nullptr);
		::FlushFileBuffers(file);
		::CloseHandle(file);
	}
}

// Asks Breakpad for a minidump of the dying process. Its callback comes back
// to OnBreakpadException(), which writes the report. If Breakpad is not
// there, the report is written directly.
void DumpAndReport(const char *kind, const char *detail) noexcept {
	PendingKind = kind;
	std::snprintf(
		PendingDetail,
		sizeof(PendingDetail),
		"%s",
		detail ? detail : "");
	CrashReports::WriteMinidumpNow();
	WriteReport(kind, detail, nullptr, nullptr);
}

using TerminateFn = void (*)();
using SignalFn = void (*)(int);
TerminateFn PreviousTerminate = nullptr;
SignalFn PreviousAbort = nullptr;

[[noreturn]] void TerminateHandler() {
	char detail[256];
	DescribeCurrentException(detail, sizeof(detail));
	if (!detail[0]) {
		std::snprintf(detail, sizeof(detail), "no active exception");
	}
	DumpAndReport("std::terminate", detail);
	if (PreviousTerminate) {
		PreviousTerminate();
	}
	std::abort();
}

void AbortHandler(int sig) {
	char detail[256];
	DescribeCurrentException(detail, sizeof(detail));
	DumpAndReport("abort()", detail);
	if (PreviousAbort
		&& PreviousAbort != SIG_DFL
		&& PreviousAbort != SIG_IGN
		&& PreviousAbort != SIG_ERR) {
		PreviousAbort(sig);
	}
}

// First-chance look at the failures Breakpad's unhandled filter does not get
// to see in good shape.
LONG CALLBACK VectoredHandler(PEXCEPTION_POINTERS pointers) {
	const auto code = pointers->ExceptionRecord->ExceptionCode;
	const char *kind = nullptr;
	switch (code) {
	case 0xC00000FDUL: kind = "stack overflow"; break;
	case 0xC0000374UL: kind = "heap corruption"; break;
	case 0xC0000409UL: kind = "fast fail / stack buffer overrun"; break;
	}
	if (kind) {
		WriteReport(
			kind,
			"",
			pointers->ContextRecord,
			pointers->ExceptionRecord);
	}
	return EXCEPTION_CONTINUE_SEARCH;
}

#endif // Q_OS_WIN

// ZSG_DIAG_SELFTEST=abort|terminate|access|stack makes the launch fail in the
// chosen way, to check on a real build that the report gets written. It does
// nothing when the variable is not set.
volatile int SelfTestStop = 0;

int SelfTestRecursion(int depth) {
	volatile char pad[512];
	pad[0] = char(depth);
	if (SelfTestStop) {
		return pad[0];
	}
	return SelfTestRecursion(depth + 1) + pad[0];
}

void RunSelfTest() {
	const auto what = qEnvironmentVariable("ZSG_DIAG_SELFTEST");
	if (what.isEmpty()) {
		return;
	}
	Note("selftest", 1);
	if (what == QStringLiteral("abort")) {
		std::abort();
	} else if (what == QStringLiteral("terminate")) {
		[]() noexcept {
			throw std::runtime_error("diag selftest exception");
		}();
	} else if (what == QStringLiteral("access")) {
		*static_cast<volatile int*>(nullptr) = 1;
	} else if (what == QStringLiteral("stack")) {
		SelfTestRecursion(0);
	}
}

} // namespace

void Install() {
	if (Installed.exchange(true)) {
		return;
	}
#ifdef Q_OS_WIN
	const auto folder = QDir::toNativeSeparators(ReportsFolder());
	QDir().mkpath(ReportsFolder());
	if (folder.size() < int(std::size(Folder))) {
		folder.toWCharArray(Folder);
		Folder[folder.size()] = 0;
	}

	// Room for the handlers when the stack is the thing that ran out.
	auto guarantee = ULONG(64 * 1024);
	::SetThreadStackGuarantee(&guarantee);

	PreviousTerminate = std::set_terminate(TerminateHandler);
	::AddVectoredExceptionHandler(1, VectoredHandler);
#endif // Q_OS_WIN
	Note("diag installed");
}

void Arm() {
	if (Armed.exchange(true)) {
		return;
	}
#ifdef Q_OS_WIN
	// abort() raises SIGABRT in every thread, unlike the per-thread
	// terminate handler. CrashReports sets its own handler on top of the
	// default one, so this has to come after it and call it.
	PreviousAbort = std::signal(SIGABRT, AbortHandler);
#endif // Q_OS_WIN
	Note("diag armed");
	RunSelfTest();
}

void OnBreakpadException(void *exceptionPointers) noexcept {
#ifdef Q_OS_WIN
	const auto pointers = static_cast<PEXCEPTION_POINTERS>(exceptionPointers);
	// When we asked for the dump ourselves, Breakpad's exception record is a
	// made-up one; the context is still the real place of the failure.
	const auto record = (pointers && !PendingKind)
		? pointers->ExceptionRecord
		: nullptr;
	const auto context = pointers ? pointers->ContextRecord : nullptr;
	WriteReport(
		PendingKind ? PendingKind : "unhandled exception",
		PendingDetail,
		context,
		record);
#else // Q_OS_WIN
	(void)exceptionPointers;
#endif // else for Q_OS_WIN
}

void ReportPreviousCrashes() {
	const auto folder = ReportsFolder();
	auto dir = QDir(folder);
	const auto reports = dir.entryInfoList(
		{ QStringLiteral("zsg-crash-*.txt") },
		QDir::Files,
		QDir::Time | QDir::Reversed);
	for (const auto &info : reports) {
		auto file = QFile(info.absoluteFilePath());
		if (!file.open(QIODevice::ReadOnly)) {
			continue;
		}
		const auto text = QString::fromUtf8(file.read(24 * 1024));
		file.close();
		LOG(("[diag] crash report of a previous launch (%1):\n%2"
			).arg(info.fileName()
			).arg(text));
		QFile::rename(
			info.absoluteFilePath(),
			info.absoluteFilePath() + QStringLiteral(".reported"));
	}

	const auto trim = [&](const QString &filter, int keep) {
		const auto list = dir.entryInfoList(
			{ filter },
			QDir::Files,
			QDir::Time);
		for (auto i = keep; i < list.size(); ++i) {
			QFile::remove(list[i].absoluteFilePath());
		}
	};
	trim(QStringLiteral("zsg-crash-*.reported"), kKeepReported);
	trim(QStringLiteral("*.dmp"), kKeepDumps);
}

void Note(const char *what, qint64 a, qint64 b) noexcept {
	NoteImpl(' ', what, a, b);
}

void Trace(const char *what, qint64 a, qint64 b) {
	NoteImpl(' ', what, a, b);
	LOG(("[diag] %1 %2 %3"
		).arg(QString::fromLatin1(what)
		).arg(a
		).arg(b));
}

Scope::Scope(const char *what, qint64 a) noexcept
: _what(what)
, _a(a) {
	NoteImpl('>', _what, _a, 0);
}

Scope::~Scope() {
	NoteImpl('<', _what, _a, 0);
}

} // namespace Core::ZsgDiag

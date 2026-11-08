/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information see the local LEGAL file.
*/
#pragma once

// ZaStoGram: the single diagnostics module.
//
// Everything that helps to find out why the app died lives here and nowhere
// else, so that a merge with upstream cannot scatter it:
//
//  * breadcrumbs - a lock-free ring of the last actions (Note / Trace /
//    Scope); they end up in every crash report and in log.txt;
//  * crash reports - a plain text file `tdata/dumps/zsg-crash-*.txt` for every
//    kind of death: access violation (through the Breakpad callback),
//    std::terminate, abort(), stack overflow, heap corruption, fast fail.
//    The report holds the reason, the exception, a real call stack as
//    `module+offset` and the breadcrumbs. Offsets are turned into function
//    names with tools/zsg-crash-resolve.py and the Telegram.map that
//    zsg-release.sh keeps for every build;
//  * the next launch copies unreported crash reports into log.txt.

namespace Core::ZsgDiag {

// Early, from CrashReports::StartCatching(): terminate handler, vectored
// exception handler, stack guarantee. Safe to call twice.
void Install();

// After CrashReports::Start(), when the other signal handlers are in place:
// chains the abort() handler on top of them.
void Arm();

// When logging works: moves reports of earlier launches into log.txt.
void ReportPreviousCrashes();

// Breadcrumbs. Note() only fills the ring (cheap, allocation free, may be
// called from any thread); Trace() also writes a line to log.txt, use it for
// rare events like deletions. `what` must be a string literal.
void Note(const char *what, qint64 a = 0, qint64 b = 0) noexcept;
void Trace(const char *what, qint64 a = 0, qint64 b = 0);

// Leaves "> what" and "< what" breadcrumbs; the missing "<" in a crash report
// shows which scope the process died in.
class Scope final {
public:
	explicit Scope(const char *what, qint64 a = 0) noexcept;
	~Scope();

	Scope(const Scope &other) = delete;
	Scope &operator=(const Scope &other) = delete;

private:
	const char *_what = nullptr;
	qint64 _a = 0;

};

// Called by the Breakpad callback of core/crash_reports.cpp.
// `exceptionPointers` is EXCEPTION_POINTERS* on Windows, may be null.
void OnBreakpadException(void *exceptionPointers) noexcept;

} // namespace Core::ZsgDiag

/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "logs.h"

#include <crl/crl_time.h>

#include "platform/platform_specific.h"
#include "core/crash_reports.h"
#include "core/launcher.h"
#include "core/version.h"
#include "mtproto/facade.h"

#include <QtCore/QCoreApplication>

namespace {

std::atomic<int> ThreadCounter/* = 0*/;
thread_local bool WritingEntryFlag/* = false*/;

class WritingEntryScope final {
public:
	WritingEntryScope() {
		WritingEntryFlag = true;
	}
	~WritingEntryScope() {
		WritingEntryFlag = false;
	}
};

constexpr auto kDebugLogRetentionDays = 7;
constexpr auto kDebugLogRetentionCheckPeriod = crl::time(24 * 60 * 60 * 1000);

} // namespace

enum LogDataType {
	LogDataMain,
	LogDataDebug,
	LogDataMtp,
	LogDataMtproxy,

	LogDataCount
};

QMutex *_logsMutex(LogDataType type, bool clear = false) {
	static QMutex *LogsMutexes = 0;
	if (clear) {
		delete[] LogsMutexes;
		LogsMutexes = 0;
	} else if (!LogsMutexes) {
		LogsMutexes = new QMutex[LogDataCount];
	}
	return &LogsMutexes[type];
}

QString _logsFilePath(LogDataType type, const QString &postfix = QString()) {
	QString path(cWorkingDir());
	switch (type) {
	case LogDataMain: path += u"log"_q + postfix + u".txt"_q; break;
	case LogDataDebug: path += u"DebugLogs/log"_q + postfix + u".txt"_q; break;
	case LogDataMtp: path += u"DebugLogs/mtp"_q + postfix + u".txt"_q; break;
	case LogDataMtproxy: path += u"DebugLogs/mtproxy"_q + postfix + u".txt"_q; break;
	}
	return path;
}

bool AlwaysWriteLogData(LogDataType type) {
	return (type == LogDataMain) || (type == LogDataMtproxy);
}

bool IsDebugLogData(LogDataType type) {
	return (type == LogDataDebug)
		|| (type == LogDataMtp)
		|| (type == LogDataMtproxy);
}

QString DebugLogPrefix(LogDataType type) {
	switch (type) {
	case LogDataDebug:
		return u"log"_q;
	case LogDataMtp:
		return u"mtp"_q;
	case LogDataMtproxy:
		return u"mtproxy"_q;
	case LogDataMain:
		break;
	}
	return u"log"_q;
}

QString MakeDebugLogRunId() {
	const auto now = QDateTime::currentDateTime();
	return now.toString(u"yyyyMMdd_hhmmss_zzz"_q)
		+ '_'
		+ QString::number(QCoreApplication::applicationPid());
}

QString RunScopedDebugLogPath(
		LogDataType type,
		const QString &debugLogRunId) {
	return cWorkingDir()
		+ u"DebugLogs/"_q
		+ DebugLogPrefix(type)
		+ '_'
		+ debugLogRunId
		+ u".txt"_q;
}

int32 LogsStartIndexChosen = -1;
QString _logsEntryStart() {
	static thread_local auto threadId = ThreadCounter++;
	static auto index = 0;

	const auto tm = QDateTime::currentDateTime();

	return QString("[%1 %2-%3]").arg(tm.toString("hh:mm:ss.zzz"), QString("%1").arg(threadId, 2, 10, QChar('0'))).arg(++index, 7, 10, QChar('0'));
}

class LogsDataFields {
public:

	LogsDataFields() {
		for (int32 i = 0; i < LogDataCount; ++i) {
			files[i].reset(new QFile());
		}
	}

	void CleanOldDebugLogs() {
		const auto now = crl::now();
		if (lastDebugLogCleanup
			&& now - lastDebugLogCleanup < kDebugLogRetentionCheckPeriod) {
			return;
		}
		lastDebugLogCleanup = now;

		auto dir = QDir(cWorkingDir() + u"DebugLogs"_q);
		if (!dir.exists()) {
			return;
		}

		auto opened = QStringList();
		for (auto i = 0; i != LogDataCount; ++i) {
			const auto file = files[i].get();
			if (file && file->isOpen()) {
				opened.push_back(QFileInfo(file->fileName()).absoluteFilePath());
			}
		}

		const auto cutoff = QDateTime::currentDateTime().addDays(
			-kDebugLogRetentionDays);
		const auto patterns = QStringList{
			u"log*.txt"_q,
			u"mtp*.txt"_q,
			u"mtproxy*.txt"_q,
		};
		const auto old = dir.entryInfoList(patterns, QDir::Files);
		for (const auto &info : old) {
			const auto path = info.absoluteFilePath();
			if (opened.contains(path) || info.lastModified() >= cutoff) {
				continue;
			}
			auto file = QFile(path);
			if (!file.remove()) {
				LOG(("Could not delete old debug log '%1': %2"
					).arg(path, file.errorString()));
			}
		}
	}

	bool openMain() {
		return reopen(LogDataMain, 0, u"start"_q);
	}

	void closeMain() {
		QMutexLocker lock(_logsMutex(LogDataMain));
		WritingEntryScope scope;

		const auto file = files[LogDataMain].get();
		if (file && file->isOpen()) {
			file->close();
		}
	}

	bool instanceChecked() {
		return reopen(LogDataMain, 0, QString());
	}

	QString full() {
		const auto file = files[LogDataMain].get();
		if (!file || !file->isOpen()) {
			return QString();
		}

		QFile out(file->fileName());
		if (out.open(QIODevice::ReadOnly)) {
			return QString::fromUtf8(out.readAll());
		}
		return QString();
	}

	void write(LogDataType type, const QString &msg) {
		QMutexLocker lock(_logsMutex(type));
		WritingEntryScope scope;

		if (IsDebugLogData(type)) {
			ensureDebugLogOpen(type);
		}
		const auto file = files[type].get();
		if (!file || !file->isOpen()) {
			return;
		}
		file->write(msg.toUtf8());
		file->flush();
	}

private:
	std::unique_ptr<QFile> files[LogDataCount];

	QString debugLogRunId = MakeDebugLogRunId();
	bool debugLogOpened[LogDataCount] = {};
	crl::time lastDebugLogCleanup = 0;

	bool reopen(LogDataType type, int32 dayIndex, const QString &postfix) {
		if (files[type] && files[type]->isOpen()) {
			if (type == LogDataMain) {
				if (!postfix.isEmpty()) {
					return true;
				}
			} else {
				files[type]->close();
			}
		}

		auto mode = QIODevice::WriteOnly | QIODevice::Text;
		if (type == LogDataMain) { // we can call LOG() in LogDataMain reopen - mutex not locked
			if (postfix.isEmpty()) { // instance checked, need to move to log.txt
				Assert(!files[type]->fileName().isEmpty()); // one of log_startXX.txt should've been opened already

				const auto startName = files[type]->fileName();
				const auto targetName = _logsFilePath(type, postfix);

				auto target = QFile(targetName);
				if (target.exists() && !target.remove()) {
					LOG(("Could not delete '%1' file to start new logging: %2").arg(targetName, target.errorString()));
					return false;
				}

				files[type]->close();

				const auto reopenStart = [&](const QString &name) {
					files[type]->setFileName(name);
					return files[type]->open(mode | QIODevice::Append);
				};

				auto source = QFile(startName);
				if (!source.rename(targetName)) {
					if (reopenStart(startName)) {
						LOG(("Could not rename '%1' to '%2' to start new logging: %3").arg(startName, targetName, source.errorString()));
					}
					return false;
				}
				if (!reopenStart(targetName)) {
					LOG(("Could not open '%1' file to start new logging: %2").arg(targetName, files[type]->errorString()));
					return false;
				}
				LOG(("Moved logging from '%1' to '%2'!").arg(startName, files[type]->fileName()));

				LogsStartIndexChosen = -1;

				QDir working(cWorkingDir()); // delete all other log_startXX.txt that we can
				QStringList oldlogs = working.entryList(QStringList("log_start*.txt"), QDir::Files);
				for (QStringList::const_iterator i = oldlogs.cbegin(), e = oldlogs.cend(); i != e; ++i) {
					QString oldlog = cWorkingDir() + *i, oldlogend = i->mid(u"log_start"_q.size());
					if (oldlogend.size() == 1 + u".txt"_q.size() && oldlogend.at(0).isDigit() && base::StringViewMid(oldlogend, 1) == u".txt"_q) {
						bool removed = QFile(oldlog).remove();
						LOG(("Old start log '%1' found, deleted: %2").arg(*i, Logs::b(removed)));
					}
				}

				return true;
			} else {
				bool found = false;
				int32 oldest = -1; // find not existing log_startX.txt or pick the oldest one (by lastModified)
				QDateTime oldestLastModified;
				for (int32 i = 0; i < 10; ++i) {
					QString trying = _logsFilePath(type, u"_start%1"_q.arg(i));
					files[type]->setFileName(trying);
					if (!files[type]->exists()) {
						LogsStartIndexChosen = i;
						found = true;
						break;
					}
					QDateTime lastModified = QFileInfo(trying).lastModified();
					if (oldest < 0 || lastModified < oldestLastModified) {
						oldestLastModified = lastModified;
						oldest = i;
					}
				}
				if (!found) {
					files[type]->setFileName(_logsFilePath(type, u"_start%1"_q.arg(oldest)));
					LogsStartIndexChosen = oldest;
				}
			}
		} else {
			files[type]->setFileName(_logsFilePath(type, postfix));
			if (files[type]->exists()) {
				if (files[type]->open(QIODevice::ReadOnly | QIODevice::Text)) {
					if (QString::fromUtf8(files[type]->readLine()).toInt() == dayIndex) {
						mode |= QIODevice::Append;
					}
					files[type]->close();
				}
			} else {
				QDir().mkdir(cWorkingDir() + u"DebugLogs"_q);
			}
		}
		if (files[type]->open(mode)) {
			if (type != LogDataMain) {
				files[type]->write(((mode & QIODevice::Append)
					? qsl("\
----------------------------------------------------------------\n\
NEW LOGGING INSTANCE STARTED!!!\n\
----------------------------------------------------------------\n")
					: qsl("%1\n").arg(dayIndex)).toUtf8());
				files[type]->flush();
			}

			return true;
		} else if (type != LogDataMain) {
			LOG(("Could not open debug log '%1': %2"
				).arg(files[type]->fileName(), files[type]->errorString()));
		}
		return false;
	}

	void ensureDebugLogOpen(LogDataType type) {
		Expects(IsDebugLogData(type));

		const auto file = files[type].get();
		if (file && file->isOpen()) {
			return;
		}
		CleanOldDebugLogs();
		QDir().mkpath(cWorkingDir() + u"DebugLogs"_q);
		file->setFileName(RunScopedDebugLogPath(type, debugLogRunId));
		if (!file->open(
				QIODevice::WriteOnly | QIODevice::Text | QIODevice::Append)) {
			LOG(("Could not open debug log '%1': %2"
				).arg(file->fileName(), file->errorString()));
			return;
		}
		if (!debugLogOpened[type]) {
			file->write(qsl("run=%1\n").arg(debugLogRunId).toUtf8());
			file->write(qsl("\
----------------------------------------------------------------\n\
NEW LOGGING INSTANCE STARTED!!!\n\
----------------------------------------------------------------\n").toUtf8());
			file->flush();
			debugLogOpened[type] = true;
		}
	}

};

LogsDataFields *LogsData = 0;

using LogsInMemoryList = QList<QPair<LogDataType, QString>>;
LogsInMemoryList *LogsInMemory = 0;
LogsInMemoryList *DeletedLogsInMemory = SharedMemoryLocation<LogsInMemoryList, 0>();

QString LogsBeforeSingleInstanceChecked; // LogsInMemory already dumped in LogsData, but LogsData is about to be deleted

void _logsWrite(LogDataType type, const QString &msg) {
	if (LogsData && (AlwaysWriteLogData(type) || LogsStartIndexChosen < 0)) {
		if (AlwaysWriteLogData(type) || Logs::DebugEnabled()) {
			LogsData->write(type, msg);
		}
	} else if (LogsInMemory != DeletedLogsInMemory) {
		if (!LogsInMemory) {
			LogsInMemory = new LogsInMemoryList;
		}
		LogsInMemory->push_back(qMakePair(type, msg));
	} else if (!LogsBeforeSingleInstanceChecked.isEmpty() && type == LogDataMain) {
		LogsBeforeSingleInstanceChecked += msg;
	}
}

namespace Logs {
namespace {

bool DebugModeEnabled = false;

[[maybe_unused]] void MoveOldDataFiles(const QString &wasDir) {
	if (wasDir.isEmpty()) {
		return;
	}
	QFile data(wasDir + "data"), dataConfig(wasDir + "data_config"), tdataConfig(wasDir + "tdata/config");
	if (data.exists() && dataConfig.exists() && !QFileInfo::exists(cWorkingDir() + "data") && !QFileInfo::exists(cWorkingDir() + "data_config")) { // move to home dir
		LOG(("Copying data to home dir '%1' from '%2'").arg(cWorkingDir(), wasDir));
		if (data.copy(cWorkingDir() + "data")) {
			LOG(("Copied 'data' to home dir"));
			if (dataConfig.copy(cWorkingDir() + "data_config")) {
				LOG(("Copied 'data_config' to home dir"));
				bool tdataGood = true;
				if (tdataConfig.exists()) {
					tdataGood = false;
					QDir().mkpath(cWorkingDir() + "tdata");
					if (tdataConfig.copy(cWorkingDir() + "tdata/config")) {
						LOG(("Copied 'tdata/config' to home dir"));
						tdataGood = true;
					} else {
						LOG(("Copied 'data' and 'data_config', but could not copy 'tdata/config'!"));
					}
				}
				if (tdataGood) {
					if (data.remove()) {
						LOG(("Removed 'data'"));
					} else {
						LOG(("Could not remove 'data'"));
					}
					if (dataConfig.remove()) {
						LOG(("Removed 'data_config'"));
					} else {
						LOG(("Could not remove 'data_config'"));
					}
					if (!tdataConfig.exists() || tdataConfig.remove()) {
						LOG(("Removed 'tdata/config'"));
					} else {
						LOG(("Could not remove 'tdata/config'"));
					}
					QDir().rmdir(wasDir + "tdata");
				}
			} else {
				LOG(("Copied 'data', but could not copy 'data_config'!!"));
			}
		} else {
			LOG(("Could not copy 'data'!"));
		}
	}
}

} // namespace

void SetDebugEnabled(bool enabled) {
	DebugModeEnabled = enabled;
}

bool DebugEnabled() {
	return DebugModeEnabled;
}

bool WritingEntry() {
	return WritingEntryFlag;
}

void start() {
	Assert(LogsData == nullptr);

	auto &launcher = Core::Launcher::Instance();
	if (!launcher.checkPortableVersionFolder()) {
		return;
	}

	LogsData = new LogsDataFields();
	if (cWorkingDir().isEmpty()) {
#if (!defined Q_OS_WIN && !defined _DEBUG) || defined Q_OS_WINRT || defined OS_WIN_STORE || defined OS_MAC_STORE
		cForceWorkingDir(psAppDataPath());
#else // (!Q_OS_WIN && !_DEBUG) || Q_OS_WINRT || OS_WIN_STORE || OS_MAC_STORE
		cForceWorkingDir(cExeDir());
		if (!LogsData->openMain()) {
			cForceWorkingDir(psAppDataPath());
		}
#endif // (!Q_OS_WIN && !_DEBUG) || Q_OS_WINRT || OS_WIN_STORE || OS_MAC_STORE
	}

	if (launcher.validateCustomWorkingDir()) {
		delete LogsData;
		LogsData = new LogsDataFields();
	}

// WinRT build requires the working dir to stay the same for plugin loading.
#ifndef Q_OS_WINRT
	QDir::setCurrent(cWorkingDir());
#endif // !Q_OS_WINRT

	QDir().mkpath(cWorkingDir() + u"tdata"_q);

	launcher.workingFolderReady();
	CrashReports::StartCatching();

	if (!LogsData->openMain()) {
		delete LogsData;
		LogsData = nullptr;
	}

	LOG(("Launched version: %1, install beta: %2, alpha: %3, debug mode: %4"
		).arg(AppVersion
		).arg(Logs::b(cInstallBetaVersion())
		).arg(cAlphaVersion()
		).arg(Logs::b(DebugEnabled())));
	LOG(("Executable dir: %1, name: %2").arg(cExeDir(), cExeName()));
	LOG(("Initial working dir: %1").arg(launcher.initialWorkingDir()));
	LOG(("Working dir: %1").arg(cWorkingDir()));
	LOG(("Command line: %1").arg(launcher.arguments().join(' ')));

	if (!LogsData) {
		LOG(("FATAL: Could not open '%1' for writing log!"
			).arg(_logsFilePath(LogDataMain, u"_startXX"_q)));
		return;
	}

#ifdef Q_OS_WIN
	if (cWorkingDir() == psAppDataPath()) { // fix old "Telegram Win (Unofficial)" version
		MoveOldDataFiles(psAppDataPathOld());
	}
#elif !defined Q_OS_MAC && !defined _DEBUG // fix first version
	MoveOldDataFiles(launcher.initialWorkingDir());
#endif

	if (LogsInMemory) {
		Assert(LogsInMemory != DeletedLogsInMemory);
		LogsInMemoryList list = *LogsInMemory;
		for (LogsInMemoryList::const_iterator i = list.cbegin(), e = list.cend(); i != e; ++i) {
			if (i->first == LogDataMain) {
				_logsWrite(i->first, i->second);
			}
		}
	}

	LOG(("Logs started"));
	LogsData->CleanOldDebugLogs();
}

void finish() {
	delete LogsData;
	LogsData = 0;

	if (LogsInMemory && LogsInMemory != DeletedLogsInMemory) {
		delete LogsInMemory;
	}
	LogsInMemory = DeletedLogsInMemory;

	_logsMutex(LogDataMain, true);

	CrashReports::FinishCatching();
}

bool started() {
	return LogsData != 0;
}

bool instanceChecked() {
	if (!LogsData) return false;

	if (!LogsData->instanceChecked()) {
		LogsBeforeSingleInstanceChecked = Logs::full();

		delete LogsData;
		LogsData = 0;
		LOG(("FATAL: Could not move logging to '%1'!").arg(_logsFilePath(LogDataMain)));
		return false;
	}

	if (LogsInMemory) {
		Assert(LogsInMemory != DeletedLogsInMemory);
		LogsInMemoryList list = *LogsInMemory;
		for (LogsInMemoryList::const_iterator i = list.cbegin(), e = list.cend(); i != e; ++i) {
			if (i->first != LogDataMain) {
				_logsWrite(i->first, i->second);
			}
		}
	}
	if (LogsInMemory) {
		Assert(LogsInMemory != DeletedLogsInMemory);
		delete LogsInMemory;
	}
	LogsInMemory = DeletedLogsInMemory;

	DEBUG_LOG(("Debug logs started."));
	LogsBeforeSingleInstanceChecked.clear();
	return true;
}

void multipleInstances() {
	if (LogsInMemory) {
		Assert(LogsInMemory != DeletedLogsInMemory);
		delete LogsInMemory;
	}
	LogsInMemory = DeletedLogsInMemory;

	if (Logs::DebugEnabled()) {
		LOG(("WARNING: debug logs are not written in multiple instances mode!"));
	}
	LogsBeforeSingleInstanceChecked.clear();
}

void closeMain() {
	LOG(("Explicitly closing main log and finishing crash handlers."));
	if (LogsData) {
		LogsData->closeMain();
	}
}

void writeMain(const QString &v) {
	time_t t = time(NULL);
	struct tm tm;
	mylocaltime(&tm, &t);

	const auto msg = QString("[%1.%2.%3 %4:%5:%6] %7\n"
	).arg(tm.tm_year + 1900
	).arg(tm.tm_mon + 1, 2, 10, QChar('0')
	).arg(tm.tm_mday, 2, 10, QChar('0')
	).arg(tm.tm_hour, 2, 10, QChar('0')
	).arg(tm.tm_min, 2, 10, QChar('0')
	).arg(tm.tm_sec, 2, 10, QChar('0')
	).arg(v);
	_logsWrite(LogDataMain, msg);

	writeDebug(v);
}

void writeDebug(const QString &v) {
	const auto msg = QString("%1 %2\n").arg(_logsEntryStart(), v);
	_logsWrite(LogDataDebug, msg);

#ifdef Q_OS_WIN
	//OutputDebugString(reinterpret_cast<const wchar_t *>(msg.utf16()));
#elif defined Q_OS_MAC
	//objc_outputDebugString(msg);
#elif defined _DEBUG
	//std::cout << msg.toUtf8().constData();
#endif
}

void writeMtp(int32 dc, const QString &v) {
	const auto expanded = [&] {
		const auto bare = MTP::isTemporaryDcId(dc)
			? MTP::getRealIdFromTemporaryDcId(dc)
			: MTP::BareDcId(dc);
		const auto base = (MTP::isTemporaryDcId(dc) ? "temporary_" : "")
			+ QString::number(bare);
		const auto shift = MTP::GetDcIdShift(dc);
		if (shift == 0) {
			return base + "_main";
		} else if (shift == MTP::kExportDcShift) {
			return base + "_export";
		} else if (shift == MTP::kExportMediaDcShift) {
			return base + "_export_download";
		} else if (shift == MTP::kConfigDcShift) {
			return base + "_config_enumeration";
		} else if (shift == MTP::kLogoutDcShift) {
			return base + "_logout_guest";
		} else if (shift == MTP::kUpdaterDcShift) {
			return base + "_download_update";
		} else if (shift == MTP::kGroupCallStreamDcShift) {
			return base + "_stream";
		} else if (MTP::isDownloadDcId(dc)) {
			const auto index = shift - MTP::kBaseDownloadDcShift;
			return base + "_download" + QString::number(index);
		} else if (MTP::isUploadDcId(dc)) {
			const auto index = shift - MTP::kBaseUploadDcShift;
			return base + "_upload" + QString::number(index);
		} else if (shift >= MTP::kDestroyKeyStartDcShift) {
			const auto index = shift - MTP::kDestroyKeyStartDcShift;
			return base + "_key_destroyer" + QString::number(index);
		}
		return base + "_unknown" + QString::number(shift);
	}();
	const auto msg = _logsEntryStart()
		+ u" (dc:%1) "_q.arg(expanded)
		+ v
		+ '\n';
	_logsWrite(LogDataMtp, msg);
}

void writeMtproxy(const QString &v) {
	const auto msg = _logsEntryStart()
		+ u" "_q
		+ v
		+ '\n';
	_logsWrite(LogDataMtproxy, msg);
}

QString full() {
	if (LogsData) {
		return LogsData->full();
	}
	if (!LogsInMemory || LogsInMemory == DeletedLogsInMemory) {
		return LogsBeforeSingleInstanceChecked;
	}

	int32 size = LogsBeforeSingleInstanceChecked.size();
	for (LogsInMemoryList::const_iterator i = LogsInMemory->cbegin(), e = LogsInMemory->cend(); i != e; ++i) {
		if (i->first == LogDataMain) {
			size += i->second.size();
		}
	}
	QString result;
	result.reserve(size);
	if (!LogsBeforeSingleInstanceChecked.isEmpty()) {
		result.append(LogsBeforeSingleInstanceChecked);
	}
	for (LogsInMemoryList::const_iterator i = LogsInMemory->cbegin(), e = LogsInMemory->cend(); i != e; ++i) {
		if (i->first == LogDataMain) {
			result += i->second;
		}
	}
	return result;
}

} // namespace Logs

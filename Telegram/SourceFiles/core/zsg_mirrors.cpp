/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information see the local LEGAL file.
*/
#include "core/zsg_mirrors.h"

#include "base/qthelp_url.h"
#include "core/launcher.h"

#include <QtCore/QFile>
#include <QtCore/QJsonArray>
#include <QtCore/QJsonDocument>
#include <QtCore/QJsonObject>
#include <QtCore/QRegularExpression>
#include <QtCore/QUrl>
#include <QtNetwork/QNetworkAccessManager>
#include <QtNetwork/QNetworkReply>
#include <QtNetwork/QNetworkRequest>

namespace Core::ZsgMirrors {
namespace {

constexpr auto kMaxHosts = 4;
constexpr auto kRefreshTimeout = 6 * 1000;
constexpr auto kMaxResponseSize = 256 * 1024;

[[nodiscard]] QStringList Builtin() {
	return {
		u"git.zapret.moe"_q,
		u"git2.zapret.moe"_q,
		u"git3.zapret.moe"_q,
	};
}

[[nodiscard]] QString StatePath() {
	return cWorkingDir() + u"tdata/zsg_mirrors"_q;
}

struct State {
	QString good;
	QStringList names;
};

// Line one is the host that worked last, the rest are the published names.
[[nodiscard]] State ReadState() {
	auto result = State();
	auto file = QFile(StatePath());
	if (!file.open(QIODevice::ReadOnly)) {
		return result;
	}
	const auto lines = QString::fromUtf8(
		file.read(kMaxResponseSize)).split('\n', Qt::SkipEmptyParts);
	for (auto i = 0; i != lines.size(); ++i) {
		const auto line = lines[i].trimmed().toLower();
		if (!IsGitHost(line)) {
			continue;
		} else if (i == 0) {
			result.good = line;
		} else if (!result.names.contains(line)) {
			result.names.push_back(line);
		}
	}
	return result;
}

void WriteState(const State &state) {
	auto file = QFile(StatePath());
	if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
		return;
	}
	auto text = state.good + '\n';
	for (const auto &name : state.names) {
		text += name + '\n';
	}
	file.write(text.toUtf8());
}

void Refresh(const QString &host) {
	const auto manager = new QNetworkAccessManager();
	auto request = QNetworkRequest(
		QUrl(u"https://%1/_sites/mirrors.json"_q.arg(host)));
	request.setTransferTimeout(kRefreshTimeout);
	const auto reply = manager->get(request);
	QObject::connect(reply, &QNetworkReply::finished, [=] {
		const auto body = reply->error() == QNetworkReply::NoError
			? reply->read(kMaxResponseSize)
			: QByteArray();
		const auto names = ParseNames(body);
		if (!names.isEmpty()) {
			auto state = ReadState();
			state.names = names;
			WriteState(state);
		}
		reply->deleteLater();
		manager->deleteLater();
	});
}

} // namespace

bool IsGitHost(const QString &host) {
	static const auto expression = QRegularExpression(
		u"^git\\d{0,2}\\.zapret\\.moe$"_q,
		QRegularExpression::CaseInsensitiveOption);
	return expression.match(host).hasMatch();
}

QStringList Hosts() {
	auto result = QStringList();
	const auto add = [&](const QString &host) {
		if (IsGitHost(host) && !result.contains(host)) {
			result.push_back(host);
		}
	};
	const auto state = ReadState();
	add(state.good);
	for (const auto &name : state.names) {
		add(name);
	}
	for (const auto &name : Builtin()) {
		add(name);
	}
	while (result.size() > kMaxHosts) {
		result.removeLast();
	}
	return result;
}

QString WithHost(const QString &url, const QString &host) {
	return WithHost(QUrl(url), host).toString();
}

QUrl WithHost(const QUrl &url, const QString &host) {
	if (!IsGitHost(url.host())) {
		return url;
	}
	auto result = url;
	result.setHost(host);
	return result;
}

void RememberGood(const QString &host) {
	if (!IsGitHost(host)) {
		return;
	}
	auto state = ReadState();
	const auto changed = (state.good != host);
	state.good = host;
	if (changed) {
		WriteState(state);
	}
	Refresh(host);
}

QStringList ParseNames(const QByteArray &json) {
	const auto document = QJsonDocument::fromJson(json);
	if (!document.isObject()) {
		return {};
	}
	const auto family = document.object().value("families").toObject()
		.value("git").toObject();
	const auto preferred = family.value("preferred").toString().toLower();
	auto open = QStringList();
	auto rest = QStringList();
	for (const auto &value : family.value("names").toArray()) {
		const auto entry = value.toObject();
		const auto name = entry.value("name").toString().toLower();
		if (!IsGitHost(name)) {
			continue;
		} else if (entry.value("blocked").toBool()
			|| !entry.value("open").toBool(true)) {
			rest.push_back(name);
		} else if (name == preferred) {
			open.push_front(name);
		} else {
			open.push_back(name);
		}
	}
	return open + rest;
}

} // namespace Core::ZsgMirrors

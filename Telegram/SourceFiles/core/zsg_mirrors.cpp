/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information see the local LEGAL file.
*/
#include "core/zsg_mirrors.h"

#include "base/qthelp_url.h"
#include "core/launcher.h"
#include "logs.h"

#include <crl/crl_time.h>

#include <QtCore/QFile>
#include <QtCore/QJsonArray>
#include <QtCore/QJsonDocument>
#include <QtCore/QJsonObject>
#include <QtCore/QRegularExpression>
#include <QtCore/QUrl>
#include <QtNetwork/QNetworkAccessManager>
#include <QtNetwork/QNetworkProxy>
#include <QtNetwork/QNetworkReply>
#include <QtNetwork/QNetworkRequest>

#include <memory>

namespace Core::ZsgMirrors {
namespace {

constexpr auto kMaxHosts = 6;
constexpr auto kRefreshTimeout = 6 * 1000;
constexpr auto kMaxResponseSize = 256 * 1024;

[[nodiscard]] QStringList Builtin() {
	// The numbered mirrors go first: the plain name is the one that gets
	// filtered by name, and the others are the same Forgejo.
	return {
		u"git2.zapret.moe"_q,
		u"git3.zapret.moe"_q,
		u"git4.zapret.moe"_q,
		u"git.zapret.moe"_q,
	};
}

[[nodiscard]] QStringList EntryLists() {
	return {
		u"https://script.google.com/macros/s/AKfycbzcEPk67WW6fYC0vPVm397QyDFHd4m-SrfKDBnfvG8jAD-n_HXVv8AqQnEHZ6A42oIh/exec?format=json"_q,
		u"https://gist.githubusercontent.com/fuckyourkn/ecb9b6a03f53bddcdd47023ebc12d4f9/raw/targets.json"_q,
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

// One race over every list and every route: a proxy that swallows requests
// (the app-wide one only carries Telegram) must not hide the pages that a
// browser on the same machine opens directly, and a silent list must not
// delay the other one. The first answer with new names wins.
struct EntryRace {
	int pending = 0;
	bool finished = false;
};

} // namespace

bool IsGitHost(const QString &host) {
	static const auto name = QRegularExpression(
		u"^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\\.zapret\\.moe$"_q,
		QRegularExpression::CaseInsensitiveOption);
	static const auto otherSite = QRegularExpression(
		u"^wiki\\d*\\.zapret\\.moe$"_q,
		QRegularExpression::CaseInsensitiveOption);
	return name.match(host).hasMatch() && !otherSite.match(host).hasMatch();
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

QStringList ParseEntry(const QByteArray &json) {
	const auto document = QJsonDocument::fromJson(json);
	if (!document.isObject()
		|| document.object().value("schema").toInt() != 1) {
		return {};
	}
	auto result = QStringList();
	const auto hosts = document.object().value("families").toObject()
		.value("git").toObject().value("hosts").toArray();
	for (const auto &value : hosts) {
		const auto name = value.toString().trimmed().toLower();
		if (IsGitHost(name) && !result.contains(name)) {
			result.push_back(name);
		}
	}
	return result;
}

void FetchEntryNames(QStringList tried, Fn<void(QStringList)> done) {
	const auto lists = EntryLists();
	const auto proxied = (QNetworkProxy::applicationProxy().type()
			!= QNetworkProxy::NoProxy)
		|| QNetworkProxyFactory::usesSystemConfiguration();
	const auto routes = proxied ? 2 : 1;
	const auto race = std::make_shared<EntryRace>();
	race->pending = int(lists.size()) * routes;
	for (const auto &list : lists) {
		for (auto route = 0; route != routes; ++route) {
			const auto direct = (route == 1);
			const auto manager = new QNetworkAccessManager();
			if (direct) {
				manager->setProxy(QNetworkProxy::NoProxy);
			}
			auto request = QNetworkRequest(QUrl(list));
			request.setTransferTimeout(kRefreshTimeout);
			// Apps Script answers through a redirect to
			// script.googleusercontent.com.
			request.setAttribute(
				QNetworkRequest::RedirectPolicyAttribute,
				QNetworkRequest::NoLessSafeRedirectPolicy);
			const auto started = crl::now();
			const auto reply = manager->get(request);
			QObject::connect(reply, &QNetworkReply::finished, [=] {
				const auto ok = (reply->error() == QNetworkReply::NoError);
				const auto body = ok
					? reply->read(kMaxResponseSize)
					: QByteArray();
				LOG(("Update Info: entry page %1%2 -> %3 (%4), %5 bytes, %6 ms"
					).arg(QUrl(list).host()
					).arg(direct ? u" [direct]"_q : QString()
					).arg(int(reply->error())
					).arg(reply->errorString()
					).arg(body.size()
					).arg(crl::now() - started));
				reply->deleteLater();
				manager->deleteLater();
				if (race->finished) {
					return;
				}
				--race->pending;
				auto fresh = QStringList();
				for (const auto &name : ParseEntry(body)) {
					if (!tried.contains(name)) {
						fresh.push_back(name);
					}
				}
				if (!fresh.isEmpty()) {
					race->finished = true;
					auto state = ReadState();
					state.names = fresh;
					WriteState(state);
					done(fresh);
				} else if (!race->pending) {
					race->finished = true;
					done({});
				}
			});
		}
	}
	if (!race->pending) {
		race->finished = true;
		done({});
	}
}

} // namespace Core::ZsgMirrors

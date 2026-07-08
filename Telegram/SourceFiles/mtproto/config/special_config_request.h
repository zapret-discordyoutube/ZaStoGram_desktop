/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "mtproto/details/mtproto_domain_resolver.h"
#include "base/bytes.h"
#include "base/weak_ptr.h"

#include <QtCore/QPointer>
#include <QtNetwork/QNetworkReply>
#include <QtNetwork/QNetworkAccessManager>
#include <QtNetwork/QDnsLookup>
#include <memory>

namespace MTP::details {

class SpecialConfigRequest : public QObject {
public:
	SpecialConfigRequest(
		Fn<void(
			DcId dcId,
			const std::string &ip,
			int port,
			bytes::const_span secret)> callback,
		bool isTestMode,
		const QString &domainString,
		const QString &phone);
	SpecialConfigRequest(
		Fn<void()> timeDoneCallback,
		bool isTestMode,
		const QString &domainString);

private:
	enum class Type {
		Doh,
	};
	struct Attempt {
		Type type;
		DohProvider provider;
	};

	SpecialConfigRequest(
		Fn<void(
			DcId dcId,
			const std::string &ip,
			int port,
			bytes::const_span secret)> callback,
		Fn<void()> timeDoneCallback,
		bool isTestMode,
		const QString &domainString,
		const QString &phone);

	void startSystemTxtLookup();
	void systemTxtLookupFinished();
	void startWebRequests();
	void sendNextRequest();
	void performRequest(const Attempt &attempt);
	void requestFinished(Type type, not_null<QNetworkReply*> reply);
	void handleHeaderUnixtime(not_null<QNetworkReply*> reply);
	QByteArray finalizeRequest(not_null<QNetworkReply*> reply);
	bool handleResponse(const QByteArray &bytes);
	bool decryptSimpleConfig(const QByteArray &bytes);

	Fn<void(
		DcId dcId,
		const std::string &ip,
		int port,
		bytes::const_span secret)> _callback;
	Fn<void()> _timeDoneCallback;
	QString _domainString;
	QString _phone;
	MTPhelp_ConfigSimple _simpleConfig;

	QNetworkAccessManager _manager;
	std::unique_ptr<QDnsLookup> _systemLookup;
	std::vector<Attempt> _attempts;
	std::vector<ServiceWebRequest> _requests;

};

} // namespace MTP::details

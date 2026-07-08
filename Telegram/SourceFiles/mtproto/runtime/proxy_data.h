/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "base/bytes.h"
#include "base/basic_types.h"

#include <QtCore/QString>

#include <vector>

namespace MTP {

struct ProxyData {
	enum class Settings {
		System,
		Enabled,
		Disabled,
	};
	enum class Type {
		None,
		Socks5,
		Http,
		Mtproto,
	};
	enum class Status {
		Valid,
		Unsupported,
		IncorrectSecret,
		Invalid,
	};

	Type type = Type::None;
	QString host;
	uint32 port = 0;
	QString user, password;
	QString originalHost;

	std::vector<QString> resolvedIPs;
	crl::time resolvedExpireAt = 0;

	[[nodiscard]] bool valid() const;
	[[nodiscard]] Status status() const;
	[[nodiscard]] bool supportsCalls() const;
	[[nodiscard]] bool tryCustomResolve() const;
	[[nodiscard]] bytes::vector secretFromMtprotoPassword() const;
	[[nodiscard]] explicit operator bool() const;
	[[nodiscard]] bool operator==(const ProxyData &other) const;
	[[nodiscard]] bool operator!=(const ProxyData &other) const;

	[[nodiscard]] static bool ValidMtprotoPassword(const QString &password);
	[[nodiscard]] static Status MtprotoPasswordStatus(
		const QString &password);

};

enum class ProxyTlsProfile {
	Auto,
	Firefox,
	AndroidChrome,
	Yandex,
	FirefoxAndroid,
	AndroidOkHttp,
	AutoRotate,
	ChromeModern,
};
enum class ProxyClientHelloFragmentation {
	Off,
	Soft,
};
enum class ProxyConnectionPattern {
	Off,
	Soft,
	Quiet,
	Strict,
	Browser,
};
enum class ProxyRecordSizing {
	Off,
	Conservative,
	Varied,
};
enum class ProxyTiming {
	Off,
	Gentle,
	Balanced,
};
enum class ProxyStartupCover {
	Off,
	Soft,
	Strict,
};
enum class ProxyTransport {
	Tcp,
	Wss,
};
enum class ProxyStealthLevel {
	CompatStrict,
	CompatModern,
	DpiAdaptiveHandshake,
	DpiAdaptiveData,
	Experimental,
};

struct ProxyStealthOptions {
	ProxyStealthLevel level = ProxyStealthLevel::DpiAdaptiveData;
	ProxyTlsProfile tlsProfile = ProxyTlsProfile::Auto;
	ProxyClientHelloFragmentation clientHelloFragmentation
		= ProxyClientHelloFragmentation::Off;
	ProxyConnectionPattern connectionPattern = ProxyConnectionPattern::Browser;
	ProxyRecordSizing recordSizing = ProxyRecordSizing::Off;
	ProxyTiming timing = ProxyTiming::Off;
	ProxyStartupCover startupCover = ProxyStartupCover::Off;
	bool syntheticPsk = false;
	ProxyTransport transport = ProxyTransport::Wss;

	QString wssCustomHost;
	int wssCustomPort = 443;
	QString wssCustomPath;
	QString wssCustomDomain;

	friend bool operator==(
		const ProxyStealthOptions &,
		const ProxyStealthOptions &) = default;
};

} // namespace MTP

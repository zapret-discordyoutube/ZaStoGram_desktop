/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "base/basic_types.h"

#include <QtCore/QByteArray>
#include <QtCore/QString>
#include <QtCore/QVector>

#include <optional>

namespace MTP::details {

struct ClientHelloFacts {
	int legacyVersion = 0;
	int tlsVersion = 0;
	bool hasSni = false;
	QByteArray firstAlpn;
	QVector<int> cipherSuites;
	QVector<int> extensions;
	QVector<int> signatureAlgorithms;
	QVector<int> supportedVersions;
};

[[nodiscard]] bool IsClientHelloGrease(uint16 value);

[[nodiscard]] std::optional<ClientHelloFacts> ComputeClientHelloFacts(
	const QByteArray &data);

[[nodiscard]] QString ComputeClientHelloJa4(const ClientHelloFacts &facts);

[[nodiscard]] QString ComputeClientHelloJa4(const QByteArray &data);

} // namespace MTP::details

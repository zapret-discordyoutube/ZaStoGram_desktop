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
	QByteArray sniHost;
	QByteArray firstAlpn;
	QVector<int> cipherSuites;
	QVector<int> extensions;
	QVector<int> signatureAlgorithms;
	QVector<int> supportedVersions;
};

// Everything a relay checks before it accepts a ClientHello as its own. A
// hello that fails any of these is not answered with an error - the relay
// hands the connection to the site it fronts for, and the failure surfaces
// much later as an unsigned ServerHello. Checking the same list before the
// hello leaves means the log names the real cause instead of the symptom.
enum class ClientHelloContractIssue {
	None,
	BadRecordHeader,     // not 16 03 01, or the record too short to qualify
	TooShort,            // under the canonical length the relay requires
	TooLong,             // over what the relay reads in one go
	InconsistentLength,  // declared record/handshake/extension sizes disagree
	FirstCipherNotTls13, // first non-GREASE suite is not 1301/1302/1303
	SniMissing,
	SniMismatch,         // not the domain carried in the secret
};

[[nodiscard]] ClientHelloContractIssue CheckClientHelloContract(
	const QByteArray &hello,
	const QByteArray &domainFromSecret);

// Stable slug for the diagnostics line - greppable, no spaces.
[[nodiscard]] QString ClientHelloContractIssueSlug(
	ClientHelloContractIssue issue);

[[nodiscard]] bool IsClientHelloGrease(uint16 value);

[[nodiscard]] std::optional<ClientHelloFacts> ComputeClientHelloFacts(
	const QByteArray &data);

[[nodiscard]] QString ComputeClientHelloJa4(const ClientHelloFacts &facts);

[[nodiscard]] QString ComputeClientHelloJa4(const QByteArray &data);

} // namespace MTP::details

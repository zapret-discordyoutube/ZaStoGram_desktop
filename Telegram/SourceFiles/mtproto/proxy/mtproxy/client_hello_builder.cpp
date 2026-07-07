/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/proxy/mtproxy/client_hello_builder.h"

#include "mtproto/details/mtproto_binary.h"
#include "mtproto/proxy/mtproxy/client_hello_profile.h"
#include "base/openssl_help.h"
#include "base/bytes.h"
#include "base/random.h"
#include "base/unixtime.h"

#include <QtCore/QtEndian>

#include <algorithm>
#include <array>
#include <variant>
#include <vector>

namespace MTP::details {
namespace {

constexpr auto kMaxGrease = 8;
constexpr auto kClientHelloLimit = 4096;
constexpr auto kHelloDigestLength = 32;
constexpr auto kLengthSize = sizeof(uint16);
constexpr auto kClientHelloFragmentDelayMin = crl::time(2);
constexpr auto kClientHelloFragmentDelayMax = crl::time(7);

[[nodiscard]] MTPTlsClientHello PrepareClientHelloRulesInternal(
		ProxyTlsProfile profile) {
	using Scope = QVector<MTPTlsBlock>;
	using Permutation = std::vector<Scope>;
	using StackElement = std::variant<Scope, Permutation>;
	auto stack = std::vector<StackElement>();
	const auto pushToBack = [&](MTPTlsBlock &&block) {
		Expects(!stack.empty());

		if (const auto scope = std::get_if<Scope>(&stack.back())) {
			scope->push_back(std::move(block));
		} else {
			auto &permutation = v::get<Permutation>(stack.back());
			Assert(!permutation.empty());
			permutation.back().push_back(std::move(block));
		}
	};
	const auto S = [&](QByteArray data) {
		pushToBack(MTP_tlsBlockString(MTP_bytes(data)));
	};
	const auto Z = [&](int length) {
		pushToBack(MTP_tlsBlockZero(MTP_int(length)));
	};
	const auto G = [&](int seed) {
		pushToBack(MTP_tlsBlockGrease(MTP_int(seed)));
	};
	const auto R = [&](int length) {
		pushToBack(MTP_tlsBlockRandom(MTP_int(length)));
	};
	const auto D = [&] {
		pushToBack(MTP_tlsBlockDomain());
	};
	const auto K = [&] {
		pushToBack(MTP_tlsBlockPublicKey());
	};
	const auto M = [&] {
		pushToBack(MTP_tlsBlockM());
	};
	const auto E = [&] {
		pushToBack(MTP_tlsBlockE());
	};
	const auto P = [&] {
		pushToBack(MTP_tlsBlockPadding());
	};
	const auto OpenScope = [&] {
		stack.emplace_back(Scope());
	};
	const auto CloseScope = [&] {
		Expects(stack.size() > 1);
		Expects(v::is<Scope>(stack.back()));

		const auto blocks = std::move(v::get<Scope>(stack.back()));
		stack.pop_back();
		pushToBack(MTP_tlsBlockScope(MTP_vector<MTPTlsBlock>(blocks)));
	};
	const auto OpenPermutation = [&] {
		stack.emplace_back(Permutation());
	};
	const auto ClosePermutation = [&] {
		Expects(stack.size() > 1);
		Expects(v::is<Permutation>(stack.back()));

		const auto list = std::move(v::get<Permutation>(stack.back()));
		stack.pop_back();

		const auto wrapped = list | ranges::views::transform([](
				const QVector<MTPTlsBlock> &elements) {
			return MTP_vector<MTPTlsBlock>(elements);
		}) | ranges::to<QVector<MTPVector<MTPTlsBlock>>>();

		pushToBack(MTP_tlsBlockPermutation(
			MTP_vector<MTPVector<MTPTlsBlock>>(wrapped)));
	};
	const auto StartPermutationElement = [&] {
		Expects(stack.size() > 1);
		Expects(v::is<Permutation>(stack.back()));

		v::get<Permutation>(stack.back()).emplace_back();
	};
	const auto Finish = [&] {
		Expects(stack.size() == 1);
		Expects(v::is<Scope>(stack.back()));

		return v::get<Scope>(stack.back());
	};

	stack.emplace_back(Scope());

	switch (profile) {
	case ProxyTlsProfile::Firefox: {
		S("\x16\x03\x01"_q);
		OpenScope();
		S("\x01\x00"_q);
		OpenScope();
		S("\x03\x03"_q);
		Z(32);
		S("\x20"_q);
		R(32);
		S("\x00\x22"_q);
		G(0);
		S(""
			"\x13\x01\x13\x03\x13\x02\xc0\x2b\xc0\x2f\xcc\xa9\xcc\xa8\xc0\x2c"
			"\xc0\x30\xc0\x0a\xc0\x13\xc0\x14\x00\x9c\x00\x9d\x00\x2f\x00\x35"_q);
		S("\x01\x00"_q);
		OpenScope();
		S("\x00\x00"_q);
		OpenScope();
		OpenScope();
		S("\x00"_q);
		OpenScope();
		D();
		CloseScope();
		CloseScope();
		CloseScope();
		S("\x00\x17\x00\x00"_q);
		S("\xff\x01\x00\x01\x00"_q);
		S("\x00\x0a\x00\x10\x00\x0e"_q);
		G(2);
		S("\x00\x1d\x00\x17\x00\x18\x00\x19\x01\x00\x01\x01"_q);
		S("\x00\x0b\x00\x02\x01\x00"_q);
		S("\x00\x23\x00\x00"_q);
		S(""
			"\x00\x10\x00\x0e\x00\x0c\x02\x68\x32\x08\x68\x74\x74\x70\x2f\x31"
			"\x2e\x31"_q);
		S("\x00\x05\x00\x05\x01\x00\x00\x00\x00"_q);
		S("\x00\x22\x00\x0a\x00\x08\x04\x03\x05\x03\x06\x03\x02\x03"_q);
		S("\x00\x33\x05\x2f\x05\x2d"_q);
		S("\x11\xec\x04\xc0"_q);
		M();
		K();
		S("\x00\x1d\x00\x20"_q);
		K();
		S("\x00\x17\x00\x41"_q);
		R(65);
		S("\x00\x2b\x00\x07\x06"_q);
		G(4);
		S("\x03\x04\x03\x03"_q);
		S(""
			"\x00\x0d\x00\x18\x00\x16\x04\x03\x05\x03\x06\x03\x08\x04\x08\x05"
			"\x08\x06\x04\x01\x05\x01\x06\x01\x02\x03\x02\x01"_q);
		S("\x00\x2d\x00\x02\x01\x01"_q);
		S("\x00\x1c\x00\x02\x40\x01"_q);
		S("\x00\x1b\x00\x07\x06\x00\x01\x00\x02\x00\x03"_q);
		S("\xfe\x0d\x01\x19"_q);
		S("\x00\x00\x01\x00\x01"_q);
		R(1);
		S("\x00\x20"_q);
		K();
		S("\x00\xef"_q);
		R(239);
		P();
		CloseScope();
		CloseScope();
		CloseScope();
		break;
	}
	case ProxyTlsProfile::FirefoxAndroid: {
		S("\x16\x03\x01"_q);
		OpenScope();
		S("\x01\x00"_q);
		OpenScope();
		S("\x03\x03"_q);
		Z(32);
		S("\x20"_q);
		R(32);
		S("\x00\x22"_q);
		S(""
			"\x13\x01\x13\x03\x13\x02\xc0\x2b\xc0\x2f\xcc\xa9\xcc\xa8\xc0\x2c"
			"\xc0\x30\xc0\x0a\xc0\x09\xc0\x13\xc0\x14\x00\x9c\x00\x9d\x00\x2f"
			"\x00\x35"_q);
		S("\x01\x00"_q);
		OpenScope();
		S("\x00\x00"_q);
		OpenScope();
		OpenScope();
		S("\x00"_q);
		OpenScope();
		D();
		CloseScope();
		CloseScope();
		CloseScope();
		S("\x00\x17\x00\x00"_q);
		S("\xff\x01\x00\x01\x00"_q);
		S(""
			"\x00\x0a\x00\x10\x00\x0e\x11\xec\x00\x1d\x00\x17\x00\x18\x00\x19"
			"\x01\x00\x01\x01"_q);
		S("\x00\x0b\x00\x02\x01\x00"_q);
		S(""
			"\x00\x10\x00\x0e\x00\x0c\x02\x68\x32\x08\x68\x74\x74\x70\x2f\x31"
			"\x2e\x31"_q);
		S("\x00\x05\x00\x05\x01\x00\x00\x00\x00"_q);
		S("\x00\x22\x00\x0a\x00\x08\x04\x03\x05\x03\x06\x03\x02\x03"_q);
		S("\x00\x33\x05\x2f\x05\x2d"_q);
		S("\x11\xec\x04\xc0"_q);
		M();
		K();
		S("\x00\x1d\x00\x20"_q);
		K();
		S("\x00\x17\x00\x41"_q);
		R(65);
		S("\x00\x2b\x00\x05\x04\x03\x04\x03\x03"_q);
		S(""
			"\x00\x0d\x00\x18\x00\x16\x04\x03\x05\x03\x06\x03\x08\x04\x08\x05"
			"\x08\x06\x04\x01\x05\x01\x06\x01\x02\x03\x02\x01"_q);
		S("\x00\x2d\x00\x02\x01\x01"_q);
		S("\x00\x1c\x00\x02\x40\x01"_q);
		S("\x00\x1b\x00\x07\x06\x00\x01\x00\x02\x00\x03"_q);
		S("\xfe\x0d\x01\xb9"_q);
		S("\x00\x00\x01\x00\x01"_q);
		R(1);
		S("\x00\x20"_q);
		K();
		S("\x01\x8f"_q);
		R(399);
		P();
		CloseScope();
		CloseScope();
		CloseScope();
		break;
	}
	case ProxyTlsProfile::AndroidOkHttp: {
		S("\x16\x03\x01"_q);
		OpenScope();
		S("\x01\x00"_q);
		OpenScope();
		S("\x03\x03"_q);
		Z(32);
		S("\x20"_q);
		R(32);
		S("\x00\x20"_q);
		G(0);
		S(""
			"\x13\x01\x13\x02\x13\x03\xc0\x2b\xc0\x2f\xc0\x2c\xc0\x30\xcc\xa9"
			"\xcc\xa8\xc0\x13\xc0\x14\x00\x9c\x00\x9d\x00\x2f\x00\x35\x01\x00"_q);
		OpenScope();
		G(2);
		S("\x00\x00"_q);
		S("\x00\x00"_q);
		OpenScope();
		OpenScope();
		S("\x00"_q);
		OpenScope();
		D();
		CloseScope();
		CloseScope();
		CloseScope();
		S("\x00\x0a\x00\x0a\x00\x08"_q);
		G(4);
		S("\x00\x1d\x00\x17\x00\x18"_q);
		S("\x00\x0b\x00\x02\x01\x00"_q);
		S(""
			"\x00\x0d\x00\x0e\x00\x0c\x04\x03\x05\x03\x04\x01\x05\x01\x02\x01"
			"\x02\x03"_q);
		S(""
			"\x00\x10\x00\x0e\x00\x0c\x02\x68\x32\x08\x68\x74\x74\x70\x2f\x31"
			"\x2e\x31"_q);
		S("\x00\x2b\x00\x07\x06"_q);
		G(6);
		S("\x03\x04\x03\x03"_q);
		S("\x00\x2d\x00\x02\x01\x01"_q);
		S("\x00\x33\x00\x26\x00\x24\x00\x1d\x00\x20"_q);
		K();
		G(3);
		S("\x00\x01\x00"_q);
		P();
		CloseScope();
		CloseScope();
		CloseScope();
		break;
	}
	case ProxyTlsProfile::Yandex: {
		S("\x16\x03\x01"_q);
		OpenScope();
		S("\x01\x00"_q);
		OpenScope();
		S("\x03\x03"_q);
		Z(32);
		S("\x20"_q);
		R(32);
		S("\x00\x20"_q);
		G(0);
		S(""
			"\x13\x01\x13\x02\x13\x03\xc0\x2b\xc0\x2f\xc0\x2c\xc0\x30\xcc\xa9"
			"\xcc\xa8\xc0\x13\xc0\x14\x00\x9c\x00\x9d\x00\x2f\x00\x35\x01\x00"_q);
		OpenScope();
		G(2);
		S("\x00\x00"_q);
		S("\x00\x17\x00\x00"_q);
		S(""
			"\x00\x0d\x00\x12\x00\x10\x04\x03\x08\x04\x04\x01\x05\x03\x08\x05"
			"\x05\x01\x08\x06\x06\x01"_q);
		S("\x00\x00"_q);
		OpenScope();
		OpenScope();
		S("\x00"_q);
		OpenScope();
		D();
		CloseScope();
		CloseScope();
		CloseScope();
		S("\x00\x0b\x00\x02\x01\x00"_q);
		S("\x00\x2d\x00\x02\x01\x01"_q);
		S("\x00\x1b\x00\x03\x02\x00\x02"_q);
		S(""
			"\x00\x10\x00\x0e\x00\x0c\x02\x68\x32\x08\x68\x74\x74\x70\x2f\x31"
			"\x2e\x31"_q);
		S("\xff\x01\x00\x01\x00"_q);
		S("\x00\x23\x00\x00"_q);
		S("\x00\x2b\x00\x07\x06"_q);
		G(6);
		S("\x03\x04\x03\x03"_q);
		S("\x00\x12\x00\x00"_q);
		S("\x00\x05\x00\x05\x01\x00\x00\x00\x00"_q);
		S("\x44\xcd\x00\x05\x00\x03\x02\x68\x32"_q);
		S("\x00\x0a\x00\x0c\x00\x0a"_q);
		G(4);
		S("\x11\xec\x00\x1d\x00\x17\x00\x18"_q);
		S("\xfe\x0d"_q);
		OpenScope();
		S("\x00\x00\x01\x00\x01"_q);
		R(1);
		S("\x00\x20"_q);
		K();
		OpenScope();
		E();
		CloseScope();
		CloseScope();
		S("\x00\x33\x04\xef\x04\xed"_q);
		G(4);
		S("\x00\x01\x00\x11\xec\x04\xc0"_q);
		M();
		K();
		S("\x00\x1d\x00\x20"_q);
		K();
		G(3);
		S("\x00\x00"_q);
		P();
		CloseScope();
		CloseScope();
		CloseScope();
		break;
	}
	case ProxyTlsProfile::ChromeModern: {
		S("\x16\x03\x01"_q);
		OpenScope();
		S("\x01\x00"_q);
		OpenScope();
		S("\x03\x03"_q);
		Z(32);
		S("\x20"_q);
		R(32);
		S("\x00\x20"_q);
		G(0);
		S(""
			"\x13\x01\x13\x02\x13\x03\xc0\x2b\xc0\x2f\xc0\x2c\xc0\x30\xcc\xa9"
			"\xcc\xa8\xc0\x13\xc0\x14\x00\x9c\x00\x9d\x00\x2f\x00\x35\x01\x00"
			""_q);
		OpenScope();
		G(2);
		S("\x00\x00"_q);
		OpenPermutation(); {
			StartPermutationElement(); {
				S("\x00\x00"_q);
				OpenScope();
				OpenScope();
				S("\x00"_q);
				OpenScope();
				D();
				CloseScope();
				CloseScope();
				CloseScope();
			}
			StartPermutationElement(); {
				S("\x00\x05\x00\x05\x01\x00\x00\x00\x00"_q);
			}
			StartPermutationElement(); {
				S("\x00\x0a\x00\x0c\x00\x0a"_q);
				G(4);
				S("\x11\xec\x00\x1d\x00\x17\x00\x18"_q);
			}
			StartPermutationElement(); {
				S("\x00\x0b\x00\x02\x01\x00"_q);
			}
			StartPermutationElement(); {
				S(""
					"\x00\x0d\x00\x12\x00\x10\x04\x03\x08\x04\x04\x01\x05\x03"
					"\x08\x05\x05\x01\x08\x06\x06\x01"_q);
			}
			StartPermutationElement(); {
				S(""
					"\x00\x10\x00\x0e\x00\x0c\x02\x68\x32\x08\x68\x74\x74\x70"
					"\x2f\x31\x2e\x31"_q);
			}
			StartPermutationElement(); {
				S("\x00\x12\x00\x00"_q);
			}
			StartPermutationElement(); {
				S("\x00\x17\x00\x00"_q);
			}
			StartPermutationElement(); {
				S("\x00\x1b\x00\x03\x02\x00\x02"_q);
			}
			StartPermutationElement(); {
				S("\x00\x23\x00\x00"_q);
			}
			StartPermutationElement(); {
				S("\x00\x2b\x00\x07\x06"_q);
				G(6);
				S("\x03\x04\x03\x03"_q);
			}
			StartPermutationElement(); {
				S("\x00\x2d\x00\x02\x01\x01"_q);
			}
			StartPermutationElement(); {
				S("\x00\x33\x04\xef\x04\xed"_q);
				G(4);
				S("\x00\x01\x00\x11\xec\x04\xc0"_q);
				M();
				K();
				S("\x00\x1d\x00\x20"_q);
				K();
			}
			StartPermutationElement(); {
				S("\x44\xcd\x00\x05\x00\x03\x02\x68\x32"_q);
			}
			StartPermutationElement(); {
				S("\xfe\x0d"_q);
				OpenScope();
				S("\x00\x00\x01\x00\x01"_q);
				R(1);
				S("\x00\x20"_q);
				R(32);
				OpenScope();
				E();
				CloseScope();
				CloseScope();
			}
			StartPermutationElement(); {
				S("\xff\x01\x00\x01\x00"_q);
			}
		} ClosePermutation();
		G(3);
		S("\x00\x01\x00"_q);
		P();
		CloseScope();
		CloseScope();
		CloseScope();
		break;
	}
	case ProxyTlsProfile::Auto: {
		return PrepareClientHelloRulesInternal(DefaultClientHelloProfile());
	}
	case ProxyTlsProfile::AndroidChrome: {
		S("\x16\x03\x01"_q);
		OpenScope();
		S("\x01\x00"_q);
		OpenScope();
		S("\x03\x03"_q);
		Z(32);
		S("\x20"_q);
		R(32);
		S("\x00\x20"_q);
		G(0);
		S(""
			"\x13\x01\x13\x02\x13\x03\xc0\x2b\xc0\x2f\xc0\x2c\xc0\x30\xcc\xa9"
			"\xcc\xa8\xc0\x13\xc0\x14\x00\x9c\x00\x9d\x00\x2f\x00\x35\x01\x00"
			""_q);
		OpenScope();
		G(2);
		S("\x00\x00"_q);
		OpenPermutation(); {
			StartPermutationElement(); {
				S("\x00\x00"_q);
				OpenScope();
				OpenScope();
				S("\x00"_q);
				OpenScope();
				D();
				CloseScope();
				CloseScope();
				CloseScope();
			}
			StartPermutationElement(); {
				S("\x00\x05\x00\x05\x01\x00\x00\x00\x00"_q);
			}
			StartPermutationElement(); {
				S("\x00\x0a\x00\x0c\x00\x0a"_q);
				G(4);
				S("\x11\xec\x00\x1d\x00\x17\x00\x18"_q);
			}
			StartPermutationElement(); {
				S("\x00\x0b\x00\x02\x01\x00"_q);
			}
			StartPermutationElement(); {
				S(""
					"\x00\x0d\x00\x12\x00\x10\x04\x03\x08\x04\x04\x01\x05\x03"
					"\x08\x05\x05\x01\x08\x06\x06\x01"_q);
			}
			StartPermutationElement(); {
				S(""
					"\x00\x10\x00\x0e\x00\x0c\x02\x68\x32\x08\x68\x74\x74\x70"
					"\x2f\x31\x2e\x31"_q);
			}
			StartPermutationElement(); {
				S("\x00\x12\x00\x00"_q);
			}
			StartPermutationElement(); {
				S("\x00\x17\x00\x00"_q);
			}
			StartPermutationElement(); {
				S("\x00\x1b\x00\x03\x02\x00\x02"_q);
			}
			StartPermutationElement(); {
				S("\x00\x23\x00\x00"_q);
			}
			StartPermutationElement(); {
				S("\x00\x2b\x00\x07\x06"_q);
				G(6);
				S("\x03\x04\x03\x03"_q);
			}
			StartPermutationElement(); {
				S("\x00\x2d\x00\x02\x01\x01"_q);
			}
			StartPermutationElement(); {
				S("\x00\x33\x04\xef\x04\xed"_q);
				G(4);
				S("\x00\x01\x00\x11\xec\x04\xc0"_q);
				M();
				K();
				S("\x00\x1d\x00\x20"_q);
				K();
			}
			StartPermutationElement(); {
				S("\x44\xcd\x00\x05\x00\x03\x02\x68\x32"_q);
			}
			StartPermutationElement(); {
				S("\xfe\x0d"_q);
				OpenScope();
				S("\x00\x00\x01\x00\x01"_q);
				R(1);
				S("\x00\x20"_q);
				R(32);
				OpenScope();
				E();
				CloseScope();
				CloseScope();
			}
			StartPermutationElement(); {
				S("\xff\x01\x00\x01\x00"_q);
			}
		} ClosePermutation();
		G(3);
		S("\x00\x01\x00"_q);
		P();
		CloseScope();
		CloseScope();
		CloseScope();
		break;
	}
	case ProxyTlsProfile::AutoRotate: {
		return PrepareClientHelloRulesInternal(DefaultClientHelloProfile());
	}
	}

	return MTP_tlsClientHello(MTP_vector<MTPTlsBlock>(Finish()));
}

[[nodiscard]] bytes::vector PrepareGreases(
		const ClientHelloGenerationOptions &options) {
	auto result = bytes::vector(kMaxGrease);
	if (options.deterministic) {
		for (auto i = 0; i != kMaxGrease; ++i) {
			result[i] = bytes::type((i << 4) + 0x0A);
		}
		return result;
	}
	bytes::set_random(result);
	for (auto &byte : result) {
		byte = bytes::type((uchar(byte) & 0xF0) + 0x0A);
	}
	static_assert(kMaxGrease % 2 == 0);
	for (auto i = 0; i != kMaxGrease; i += 2) {
		if (result[i] == result[i + 1]) {
			result[i + 1] = bytes::type(uchar(result[i + 1]) ^ 0x10);
		}
	}
	return result;
}

[[nodiscard]] bytes::vector GeneratePublicKey() {
	const auto context = EVP_PKEY_CTX_new_id(NID_ED25519, nullptr);
	if (!context) {
		return {};
	}
	const auto guardContext = gsl::finally([&] {
		EVP_PKEY_CTX_free(context);
	});

	if (EVP_PKEY_keygen_init(context) <= 0) {
		return {};
	}

	auto key = (EVP_PKEY*)nullptr;
	if (EVP_PKEY_keygen(context, &key) <= 0) {
		return {};
	}
	const auto guardKey = gsl::finally([&] {
		EVP_PKEY_free(key);
	});

	auto length = size_t(0);
	if (!EVP_PKEY_get_raw_public_key(key, nullptr, &length)) {
		return {};
	}
	Assert(length == 32);

	auto result = bytes::vector(length);
	const auto code = EVP_PKEY_get_raw_public_key(
		key,
		reinterpret_cast<unsigned char *>(result.data()),
		&length);
	if (!code) {
		return {};
	}
	return result;
}


struct ClientHelloRange {
	int offset = 0;
	int length = 0;

	[[nodiscard]] explicit operator bool() const {
		return length > 0;
	}
};

} // namespace

MTPTlsClientHello PrepareClientHelloRules(ProxyTlsProfile profile) {
	return PrepareClientHelloRulesInternal(profile);
}

namespace {

[[nodiscard]] bool ShouldPadBeforeSyntheticPsk(ProxyTlsProfile profile) {
	switch (profile) {
	case ProxyTlsProfile::Firefox:
	case ProxyTlsProfile::FirefoxAndroid:
	case ProxyTlsProfile::AndroidOkHttp:
	case ProxyTlsProfile::Yandex:
		return false;
	default:
		return true;
	}
}

class Generator {
public:
	Generator(
		const MTPTlsClientHello &rules,
		bytes::const_span domain,
		bytes::const_span key,
		bool padBeforeSyntheticPsk,
		std::optional<SyntheticPskOffer> pskOffer,
		ClientHelloGenerationOptions options);
	[[nodiscard]] ClientHello take();

private:
	class Part final {
	public:
		explicit Part(
			bytes::const_span domain,
			const bytes::vector &greases,
			bool padBeforeSyntheticPsk,
			const std::optional<SyntheticPskOffer> *pskOffer,
			ClientHelloGenerationOptions options);

		[[nodiscard]] bytes::span grow(int size);
		void writeBlocks(const QVector<MTPTlsBlock> &blocks);
		void writeBlock(const MTPTlsBlock &data);
		void writeBlock(const MTPDtlsBlockString &data);
		void writeBlock(const MTPDtlsBlockZero &data);
		void writeBlock(const MTPDtlsBlockGrease &data);
		void writeBlock(const MTPDtlsBlockRandom &data);
		void writeBlock(const MTPDtlsBlockDomain &data);
		void writeBlock(const MTPDtlsBlockPublicKey &data);
		void writeBlock(const MTPDtlsBlockScope &data);
		void writeBlock(const MTPDtlsBlockPermutation &data);
		void writeBlock(const MTPDtlsBlockM &data);
		void writeBlock(const MTPDtlsBlockE &data);
		void writeBlock(const MTPDtlsBlockPadding &data);
		void finalize(bytes::const_span key);
		[[nodiscard]] QByteArray extractDigest() const;

		[[nodiscard]] bool error() const;
		[[nodiscard]] QByteArray take();

	private:
		void writeSyntheticPskExtension();
		void writeDigest(bytes::const_span key);
		void injectTimestamp();

		bytes::const_span _domain;
		const bytes::vector &_greases;
		bool _padBeforeSyntheticPsk = false;
		const std::optional<SyntheticPskOffer> *_pskOffer = nullptr;
		ClientHelloGenerationOptions _options;
		QByteArray _result;
		const char *_data = nullptr;
		int _digestPosition = -1;
		bool _error = false;

	};

	bytes::vector _greases;
	std::optional<SyntheticPskOffer> _pskOffer;
	bool _padBeforeSyntheticPsk = false;
	ClientHelloGenerationOptions _options;
	Part _result;
	QByteArray _digest;

};

Generator::Part::Part(
	bytes::const_span domain,
	const bytes::vector &greases,
	bool padBeforeSyntheticPsk,
	const std::optional<SyntheticPskOffer> *pskOffer,
	ClientHelloGenerationOptions options)
: _domain(domain)
, _greases(greases)
, _padBeforeSyntheticPsk(padBeforeSyntheticPsk)
, _pskOffer(pskOffer)
, _options(options) {
	_result.reserve(kClientHelloLimit);
	_data = _result.constData();
}

bool Generator::Part::error() const {
	return _error;
}

QByteArray Generator::Part::take() {
	Expects(_error || _result.constData() == _data);

	return _error ? QByteArray() : std::move(_result);
}

bytes::span Generator::Part::grow(int size) {
	if (_error
		|| size <= 0
		|| _result.size() + size > kClientHelloLimit) {
		_error = true;
		return bytes::span();
	}

	const auto offset = _result.size();
	_result.resize(offset + size);
	return bytes::make_detached_span(_result).subspan(offset);
}

void Generator::Part::writeBlocks(const QVector<MTPTlsBlock> &blocks) {
	for (const auto &block : blocks) {
		writeBlock(block);
	}
}

void Generator::Part::writeBlock(const MTPTlsBlock &data) {
	data.match([&](const auto &data) {
		writeBlock(data);
	});
}

void Generator::Part::writeBlock(const MTPDtlsBlockString &data) {
	const auto &bytes = data.vdata().v;
	const auto storage = grow(bytes.size());
	if (storage.empty()) {
		return;
	}
	bytes::copy(storage, bytes::make_span(bytes));
}

void Generator::Part::writeBlock(const MTPDtlsBlockZero &data) {
	const auto length = data.vlength().v;
	const auto already = _result.size();
	const auto storage = grow(length);
	if (storage.empty()) {
		return;
	}
	if (length == kHelloDigestLength && _digestPosition < 0) {
		_digestPosition = already;
	}
	bytes::set_with_const(storage, bytes::type(0));
}

void Generator::Part::writeBlock(const MTPDtlsBlockGrease &data) {
	const auto seed = data.vseed().v;
	if (seed < 0 || seed >= _greases.size()) {
		_error = true;
		return;
	}
	const auto storage = grow(2);
	if (storage.empty()) {
		return;
	}
	bytes::set_with_const(storage, _greases[seed]);
}

void Generator::Part::writeBlock(const MTPDtlsBlockRandom &data) {
	const auto length = data.vlength().v;
	const auto storage = grow(length);
	if (storage.empty()) {
		return;
	}
	if (_options.deterministic) {
		bytes::set_with_const(storage, bytes::type(0));
	} else {
		bytes::set_random(storage);
	}
}

void Generator::Part::writeBlock(const MTPDtlsBlockDomain &data) {
	const auto storage = grow(_domain.size());
	if (storage.empty()) {
		return;
	}
	bytes::copy(storage, _domain);
}

void Generator::Part::writeBlock(const MTPDtlsBlockPublicKey &data) {
	if (_options.deterministic) {
		const auto storage = grow(32);
		if (!storage.empty()) {
			bytes::set_with_const(storage, bytes::type(0));
		}
		return;
	}
	const auto key = GeneratePublicKey();
	const auto storage = grow(key.size());
	if (storage.empty()) {
		return;
	}
	bytes::copy(storage, key);
}

void Generator::Part::writeBlock(const MTPDtlsBlockScope &data) {
	const auto storage = grow(kLengthSize);
	if (storage.empty()) {
		return;
	}
	const auto already = _result.size();
	writeBlocks(data.ventries().v);
	const auto length = qToBigEndian(uint16(_result.size() - already));
	bytes::copy(storage, bytes::object_as_span(&length));
}

void Generator::Part::writeBlock(const MTPDtlsBlockPermutation &data) {
	auto list = std::vector<QByteArray>();
	list.reserve(data.ventries().v.size());
	for (const auto &inner : data.ventries().v) {
		auto part = Part(
			_domain,
			_greases,
			_padBeforeSyntheticPsk,
			nullptr,
			_options);
		part.writeBlocks(inner.v);
		if (part.error()) {
			_error = true;
			return;
		}
		list.push_back(part.take());
	}
	if (!_options.deterministic) {
		ranges::shuffle(list);
	}
	for (const auto &element : list) {
		const auto storage = grow(element.size());
		if (storage.empty()) {
			return;
		}
		bytes::copy(storage, bytes::make_span(element));
	}
}

void Generator::Part::writeBlock(const MTPDtlsBlockM &data) {
	constexpr auto kElements = 384;
	constexpr auto kAdded = 32;

	const auto storage = grow(kElements * 3 + kAdded);
	if (storage.empty()) {
		return;
	}
	if (_options.deterministic) {
		bytes::set_with_const(storage, bytes::type(0));
		return;
	}

	auto random = bytes::vector(kElements * 8 + kAdded);
	bytes::set_random(random);

	auto out = storage;
	for (auto i = 0; i < kElements; ++i) {
		const auto a = int(binary::ReadAt<uint32>(
			bytes::make_span(random),
			i * 2 * int(sizeof(uint32))) % 3329);
		const auto b = int(binary::ReadAt<uint32>(
			bytes::make_span(random),
			(i * 2 + 1) * int(sizeof(uint32))) % 3329);
		out[0] = bytes::type(uchar(a & 255));
		out[1] = bytes::type(uchar((a >> 8) + ((b & 15) << 4)));
		out[2] = bytes::type(uchar(b >> 4));
		out = out.subspan(3);
	}
	bytes::set_random(storage.subspan(kElements * 3));
}

void Generator::Part::writeBlock(const MTPDtlsBlockE &data) {
	const auto lengths = std::array{ 144, 176, 208, 240 };
	const auto length = _options.deterministic
		? lengths.front()
		: lengths[base::RandomIndex(lengths.size())];
	writeBlock(MTP_tlsBlockRandom(MTP_int(length)));
}

void Generator::Part::writeBlock(const MTPDtlsBlockPadding &data) {
	const auto length = int(_result.size());
	if (_padBeforeSyntheticPsk && length < 513) {
		const auto zero = MTP_tlsBlockZero(MTP_int(513 - length));
		writeBlock(MTP_tlsBlockString(MTP_bytes("\x00\x15"_q)));
		writeBlock(MTP_tlsBlockScope(MTP_vector<MTPTlsBlock>(1, zero)));
	}
	writeSyntheticPskExtension();
}

void Generator::Part::writeSyntheticPskExtension() {
	if (!_pskOffer || !*_pskOffer) {
		return;
	}
	const auto &offer = **_pskOffer;
	const auto binderLengths = std::array{ 32, 48 };
	const auto identityLength = int(offer.identity.size());
	const auto binderLength = offer.binderLength;
	if (identityLength <= 0
		|| (binderLength != binderLengths[0]
			&& binderLength != binderLengths[1])) {
		_error = true;
		return;
	}
	const auto identitiesLength = identityLength + 6;
	const auto bindersLength = binderLength + 1;
	const auto extensionLength = identitiesLength + bindersLength + 4;
	const auto write16 = [&](uint16 value) {
		const auto big = qToBigEndian(value);
		const auto storage = grow(sizeof(big));
		if (storage.empty()) {
			return;
		}
		bytes::copy(storage, bytes::object_as_span(&big));
	};
	const auto write32 = [&](uint32 value) {
		const auto big = qToBigEndian(value);
		const auto storage = grow(sizeof(big));
		if (storage.empty()) {
			return;
		}
		bytes::copy(storage, bytes::object_as_span(&big));
	};
	const auto random = [&](int length) {
		const auto storage = grow(length);
		if (storage.empty()) {
			return;
		}
		if (_options.deterministic) {
			bytes::set_with_const(storage, bytes::type(0));
		} else {
			bytes::set_random(storage);
		}
	};
	write16(uint16(0x0029));
	write16(uint16(extensionLength));
	write16(uint16(identitiesLength));
	write16(uint16(identityLength));
	const auto identityStorage = grow(identityLength);
	if (identityStorage.empty()) {
		return;
	}
	bytes::copy(identityStorage, offer.identity);
	write32(offer.obfuscatedTicketAge);
	write16(uint16(bindersLength));
	const auto binderPrefix = grow(1);
	if (binderPrefix.empty()) {
		return;
	}
	binderPrefix[0] = bytes::type(binderLength);
	random(binderLength);
}

void Generator::Part::finalize(bytes::const_span key) {
	if (_error) {
		return;
	} else if (_digestPosition < 0) {
		_error = true;
		return;
	}
	writeDigest(key);
	if (!_options.deterministic) {
		injectTimestamp();
	}
}

QByteArray Generator::Part::extractDigest() const {
	if (_digestPosition < 0) {
		return {};
	}
	return _result.mid(_digestPosition, kHelloDigestLength);
}

void Generator::Part::writeDigest(bytes::const_span key) {
	Expects(_digestPosition >= 0);

	bytes::copy(
		bytes::make_detached_span(_result).subspan(_digestPosition),
		openssl::HmacSha256(key, bytes::make_span(_result)));
}

void Generator::Part::injectTimestamp() {
	Expects(_digestPosition >= 0);

	const auto storage = bytes::make_detached_span(_result).subspan(
		_digestPosition + kHelloDigestLength - sizeof(int32),
		sizeof(int32));
	auto already = int32();
	bytes::copy(bytes::object_as_span(&already), storage);
	already ^= qToLittleEndian(int32(base::unixtime::http_now()));
	bytes::copy(storage, bytes::object_as_span(&already));
}

Generator::Generator(
	const MTPTlsClientHello &rules,
	bytes::const_span domain,
	bytes::const_span key,
	bool padBeforeSyntheticPsk,
	std::optional<SyntheticPskOffer> pskOffer,
	ClientHelloGenerationOptions options)
: _greases(PrepareGreases(options))
, _pskOffer(std::move(pskOffer))
, _padBeforeSyntheticPsk(padBeforeSyntheticPsk)
, _options(options)
, _result(domain, _greases, _padBeforeSyntheticPsk, &_pskOffer, _options) {
	_result.writeBlocks(rules.data().vblocks().v);
	_result.finalize(key);
}

ClientHello Generator::take() {
	auto digest = _result.extractDigest();
	return { _result.take(), std::move(digest) };
}

[[nodiscard]] int ClientHelloRead16(const QByteArray &data, int offset) {
	if (offset < 0 || offset + 2 > data.size()) {
		return -1;
	}
	return (int(uchar(data[offset])) << 8)
		| int(uchar(data[offset + 1]));
}

[[nodiscard]] int ClientHelloRead24(const QByteArray &data, int offset) {
	if (offset < 0 || offset + 3 > data.size()) {
		return -1;
	}
	return (int(uchar(data[offset])) << 16)
		| (int(uchar(data[offset + 1])) << 8)
		| int(uchar(data[offset + 2]));
}

[[nodiscard]] ClientHelloRange ClientHelloSniHostRange(
		const QByteArray &data) {
	if (data.size() < 9 || uchar(data[0]) != 0x16) {
		return {};
	}
	const auto recordLength = ClientHelloRead16(data, 3);
	const auto recordEnd = 5 + recordLength;
	if (recordLength < 4 || recordEnd > data.size()) {
		return {};
	}
	auto position = 5;
	if (uchar(data[position]) != 0x01) {
		return {};
	}
	const auto handshakeLength = ClientHelloRead24(data, position + 1);
	position += 4;
	const auto handshakeEnd = position + handshakeLength;
	if (handshakeLength < 0 || handshakeEnd > recordEnd) {
		return {};
	}
	if (position + 34 > handshakeEnd) {
		return {};
	}
	position += 34;
	if (position + 1 > handshakeEnd) {
		return {};
	}
	const auto sessionIdLength = int(uchar(data[position++]));
	if (position + sessionIdLength > handshakeEnd) {
		return {};
	}
	position += sessionIdLength;
	const auto cipherSuitesLength = ClientHelloRead16(data, position);
	position += 2;
	if (cipherSuitesLength < 0
		|| position + cipherSuitesLength > handshakeEnd) {
		return {};
	}
	position += cipherSuitesLength;
	if (position + 1 > handshakeEnd) {
		return {};
	}
	const auto compressionLength = int(uchar(data[position++]));
	if (position + compressionLength > handshakeEnd) {
		return {};
	}
	position += compressionLength;
	const auto extensionsLength = ClientHelloRead16(data, position);
	position += 2;
	const auto extensionsEnd = position + extensionsLength;
	if (extensionsLength < 0 || extensionsEnd > handshakeEnd) {
		return {};
	}
	while (position + 4 <= extensionsEnd) {
		const auto type = ClientHelloRead16(data, position);
		const auto length = ClientHelloRead16(data, position + 2);
		const auto value = position + 4;
		const auto next = value + length;
		if (length < 0 || next > extensionsEnd) {
			return {};
		}
		if (type != 0x0000) {
			position = next;
			continue;
		}
		const auto listLength = ClientHelloRead16(data, value);
		auto listPosition = value + 2;
		const auto listEnd = listPosition + listLength;
		if (listLength < 0 || listEnd > next) {
			return {};
		}
		while (listPosition + 3 <= listEnd) {
			const auto nameType = uchar(data[listPosition]);
			const auto nameLength = ClientHelloRead16(data, listPosition + 1);
			const auto nameOffset = listPosition + 3;
			if (nameLength < 0 || nameOffset + nameLength > listEnd) {
				return {};
			}
			if (nameType == 0 && nameLength > 1) {
				return { nameOffset, nameLength };
			}
			listPosition = nameOffset + nameLength;
		}
		return {};
	}
	return {};
}

[[nodiscard]] int ClientHelloFragmentSplit(const QByteArray &data) {
	const auto range = ClientHelloSniHostRange(data);
	if (range) {
		return range.offset + 1 + base::RandomIndex(range.length - 1);
	}
	const auto size = int(data.size());
	const auto maxFirst = std::min(768, size - 96);
	const auto minFirst = std::min(224, maxFirst);
	const auto fallbackRange = (maxFirst > minFirst)
		? (maxFirst - minFirst + 1)
		: 1;
	return minFirst + base::RandomIndex(fallbackRange);
}

} // namespace

ClientHello PrepareClientHello(
		const MTPTlsClientHello &rules,
		bytes::const_span domain,
		bytes::const_span key,
		ProxyTlsProfile profile,
		std::optional<SyntheticPskOffer> pskOffer,
		ClientHelloGenerationOptions options) {
	return Generator(
		rules,
		domain,
		key,
		ShouldPadBeforeSyntheticPsk(profile),
		std::move(pskOffer),
		options).take();
}

ClientHelloFragmentationPlan PrepareClientHelloFragmentation(
		const QByteArray &data,
		ProxyClientHelloFragmentation mode) {
	const auto size = int(data.size());
	if (mode != ProxyClientHelloFragmentation::Soft || size < 384) {
		return {};
	}
	const auto delayRange = int(
		kClientHelloFragmentDelayMax - kClientHelloFragmentDelayMin + 1);
	return {
		ClientHelloFragmentSplit(data),
		kClientHelloFragmentDelayMin + base::RandomIndex(delayRange),
	};
}

} // namespace MTP::details

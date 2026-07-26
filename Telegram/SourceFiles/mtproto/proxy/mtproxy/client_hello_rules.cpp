/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/proxy/mtproxy/client_hello_builder.h"

#include "mtproto/proxy/mtproxy/client_hello_profile.h"

#include <variant>
#include <vector>

namespace MTP::details {
namespace {

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
		// Empty on purpose, and do not "fix" it to match a real capture. A
		// genuine Yandex Browser hello carries one zero byte here, and a
		// filtered network refuses exactly that shape: this template was
		// answered twelve times out of twelve where the byte-for-byte
		// browser capture was answered once out of six. Keeping the copy
		// imperfect is what makes it work. See client_hello_profile.cpp for
		// the measurement and test_mtproxy_profile_selection.py for the
		// guard on this line.
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
		// One zero byte, exactly as Chromium sends it - and exactly what a
		// filtered network refuses. This profile is withheld for that
		// reason, so these bytes are never sent; they stay here because the
		// template is still a correct capture and the JA4 guard checks it.
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


} // namespace

MTPTlsClientHello PrepareClientHelloRules(ProxyTlsProfile profile) {
	return PrepareClientHelloRulesInternal(profile);
}


} // namespace MTP::details

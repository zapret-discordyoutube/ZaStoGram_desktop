/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "logs.h"

#include <windows.h>
#include <wincrypt.h>
#include <delayimp.h>

#include <atomic>
#include <cstring>

namespace {

using CertGetCertificateChainMethod = decltype(&::CertGetCertificateChain);

std::atomic<CertGetCertificateChainMethod> RealCertGetCertificateChain;
std::atomic<bool> CachedRevocationLogged = false;

constexpr auto kRevocationFlags = DWORD(0)
	| CERT_CHAIN_REVOCATION_CHECK_END_CERT
	| CERT_CHAIN_REVOCATION_CHECK_CHAIN
	| CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT;

// Qt's Schannel backend builds every peer chain with a revocation check,
// synchronously on the socket's thread, and then ignores the revocation
// status. On a first launch the Let's Encrypt CRLs of the Cloudflare fronts
// are not cached yet; where *.c.lencr.org is slow each new front stopped
// every MTP session thread for cryptnet's 15 s, connect budgets and proxy
// switches included (desktop log 02.10, the VM stack dump showed a session
// thread inside CertVerifyRevocation). Revocation is answered from the cache
// only, so a handshake never waits for a CRL download.
BOOL WINAPI CertGetCertificateChainCachedRevocation(
		HCERTCHAINENGINE engine,
		PCCERT_CONTEXT context,
		LPFILETIME time,
		HCERTSTORE additionalStore,
		PCERT_CHAIN_PARA parameters,
		DWORD flags,
		LPVOID reserved,
		PCCERT_CHAIN_CONTEXT *chain) {
	if (flags & kRevocationFlags) {
		flags |= CERT_CHAIN_REVOCATION_CHECK_CACHE_ONLY;
		if (!CachedRevocationLogged.exchange(true)) {
			LOG(("TLS: certificate revocation is checked from cache only."));
		}
	}
	return RealCertGetCertificateChain.load()(
		engine,
		context,
		time,
		additionalStore,
		parameters,
		flags,
		reserved,
		chain);
}

// crypt32.dll is delay-loaded, so the import used by the statically linked
// Qt resolves through this hook and other modules keep the real function.
FARPROC WINAPI DelayLoadNotify(unsigned notify, PDelayLoadInfo info) {
	if (notify != dliNotePreGetProcAddress
		|| !info->dlp.fImportByName
		|| _stricmp(info->szDll, "crypt32.dll")
		|| strcmp(info->dlp.szProcName, "CertGetCertificateChain")) {
		return nullptr;
	}
	const auto real = reinterpret_cast<CertGetCertificateChainMethod>(
		GetProcAddress(info->hmodCur, info->dlp.szProcName));
	if (!real) {
		return nullptr;
	}
	RealCertGetCertificateChain = real;
	return reinterpret_cast<FARPROC>(&CertGetCertificateChainCachedRevocation);
}

} // namespace

extern "C" const PfnDliHook __pfnDliNotifyHook2 = DelayLoadNotify;

/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "base/bytes.h"
#include "base/assertion.h"
#include "mtproto/core_types.h"

#include <type_traits>

namespace MTP::details::binary {

template <typename Type>
[[nodiscard]] bytes::span AsBytes(Type *value) {
	return bytes::object_as_span(value);
}

template <typename Type>
[[nodiscard]] bytes::const_span AsBytes(const Type *value) {
	return bytes::object_as_span(value);
}

template <typename Type>
[[nodiscard]] Type Read(bytes::const_span source) {
	static_assert(std::is_trivially_copyable_v<Type>);

	Expects(source.size() >= sizeof(Type));

	auto result = Type();
	bytes::copy(bytes::object_as_span(&result), source.subspan(0, sizeof(Type)));
	return result;
}

template <typename Type>
[[nodiscard]] Type Read(const void *source) {
	return Read<Type>(bytes::make_span(
		static_cast<const bytes::type*>(source),
		sizeof(Type)));
}

template <typename Type>
void Write(bytes::span destination, const Type &value) {
	static_assert(std::is_trivially_copyable_v<Type>);

	Expects(destination.size() >= sizeof(Type));

	bytes::copy(destination.subspan(0, sizeof(Type)), bytes::object_as_span(&value));
}

template <typename Type>
void Write(void *destination, const Type &value) {
	Write(bytes::make_span(
		static_cast<bytes::type*>(destination),
		sizeof(Type)), value);
}

template <typename Type>
[[nodiscard]] Type ReadAt(bytes::const_span source, int offset) {
	Expects(offset >= 0);

	return Read<Type>(source.subspan(offset));
}

template <typename Type>
void WriteAt(bytes::span destination, int offset, const Type &value) {
	Expects(offset >= 0);

	Write(destination.subspan(offset), value);
}

inline void Copy(bytes::span destination, bytes::const_span source) {
	bytes::copy(destination, source);
}

inline void Copy(void *destination, bytes::const_span source) {
	Copy(bytes::make_span(
		static_cast<bytes::type*>(destination),
		source.size()), source);
}

inline void Copy(bytes::span destination, const void *source, int size) {
	Expects(size >= 0);

	Copy(destination, bytes::make_span(
		static_cast<const bytes::type*>(source),
		size));
}

inline void AppendBytes(mtpBuffer &to, bytes::const_span source) {
	const auto size = to.size();
	const auto primes = (source.size() / sizeof(mtpPrime))
		+ ((source.size() % sizeof(mtpPrime)) ? 1 : 0);
	to.resize(size + int(primes));
	Copy(
		bytes::make_span(to).subspan(size * sizeof(mtpPrime)),
		source);
}

inline void AppendPrimes(mtpBuffer &to, gsl::span<const mtpPrime> source) {
	const auto size = to.size();
	to.resize(size + source.size());
	Copy(
		bytes::make_span(to).subspan(size * sizeof(mtpPrime)),
		bytes::make_span(source));
}

} // namespace MTP::details::binary

/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "zsg_naive/zsg_naive_links.h"

#include <QtCore/QRegularExpression>

#include <algorithm>

namespace Zsg::Naive {
namespace {

[[nodiscard]] const QRegularExpression &NaiveLinkExpression() {
	static const auto result = [] {
		auto expression = QRegularExpression(
			QString::fromLatin1("(?<![\\w\\$\\-\\_%=\\.\\+])"
				"naive\\+https://[^\\s<>\"']+"),
			QRegularExpression::CaseInsensitiveOption
				| QRegularExpression::UseUnicodePropertiesOption);
		expression.optimize();
		return expression;
	}();
	return result;
}

[[nodiscard]] bool IsLinkEntity(EntityType type) {
	return (type == EntityType::Url)
		|| (type == EntityType::Email)
		|| (type == EntityType::Mention)
		|| (type == EntityType::Hashtag)
		|| (type == EntityType::Cashtag)
		|| (type == EntityType::BotCommand);
}

} // namespace

void MarkNaiveLinks(TextWithEntities &text) {
	if (!text.text.contains(u"naive+"_q, Qt::CaseInsensitive)) {
		return;
	}
	auto found = std::vector<std::pair<int, int>>();
	auto matches = NaiveLinkExpression().globalMatch(text.text);
	while (matches.hasNext()) {
		const auto match = matches.next();
		const auto from = int(match.capturedStart());
		auto till = int(match.capturedEnd());
		while (till > from + 1
			&& QStringView(u".,;:!?)]}").contains(text.text[till - 1])) {
			--till;
		}
		found.emplace_back(from, till - from);
	}
	for (const auto &[offset, length] : found) {
		const auto end = offset + length;
		auto explicitLink = false;
		auto entities = EntitiesInText();
		entities.reserve(text.entities.size() + 1);
		for (const auto &entity : text.entities) {
			const auto overlaps = (entity.offset() < end)
				&& (entity.offset() + entity.length() > offset);
			if (!overlaps) {
				entities.push_back(entity);
			} else if (entity.type() == EntityType::CustomUrl) {
				// The sender made this piece a link to somewhere else on
				// purpose: leave it alone.
				explicitLink = true;
			} else if (!IsLinkEntity(entity.type())) {
				// Formatting (bold, spoiler, ...) stays.
				entities.push_back(entity);
			}
		}
		if (explicitLink) {
			continue;
		}
		entities.push_back(EntityInText(EntityType::Url, offset, length));
		std::stable_sort(
			entities.begin(),
			entities.end(),
			[](const EntityInText &a, const EntityInText &b) {
				return a.offset() < b.offset();
			});
		text.entities = std::move(entities);
	}
}

} // namespace Zsg::Naive

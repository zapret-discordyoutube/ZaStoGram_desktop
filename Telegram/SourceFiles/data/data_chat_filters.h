/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "base/flags.h"
#include "base/timer.h"

#include <iterator>

class History;

namespace Dialogs {
class MainList;
class Key;
} // namespace Dialogs

namespace Ui {
struct MoreChatsBarContent;
} // namespace Ui

namespace Api {
class LocalFoldersSync;
} // namespace Api

namespace Data {

class Session;
class LocalFolders;

// ZaStoGram's own folders live above this id, Telegram's own ids are small.
inline constexpr auto kLocalFilterIdBase = FilterId(0x10000000);

[[nodiscard]] inline bool IsLocalFilterId(FilterId id) {
	return id >= kLocalFilterIdBase;
}

struct ChatFilterTitle {
	TextWithEntities text;
	bool isStatic = false;

	[[nodiscard]] bool empty() const {
		return text.empty();
	}
};

[[nodiscard]] TextWithEntities ForceCustomEmojiStatic(TextWithEntities text);

class ChatFilter final {
public:
	enum class Flag : ushort {
		Contacts    = (1 << 0),
		NonContacts = (1 << 1),
		Groups      = (1 << 2),
		Channels    = (1 << 3),
		Bots        = (1 << 4),
		NoMuted     = (1 << 5),
		NoRead      = (1 << 6),
		NoArchived  = (1 << 7),
		RulesMask   = ((1 << 8) - 1),

		Chatlist    = (1 << 8),
		HasMyLinks  = (1 << 9),
		StaticTitle = (1 << 10),

		NewChats      = (1 << 11), // Telegram Business exceptions.
		ExistingChats = (1 << 12),
	};
	friend constexpr inline bool is_flag_type(Flag) { return true; };
	using Flags = base::flags<Flag>;

	ChatFilter() = default;
	ChatFilter(
		FilterId id,
		ChatFilterTitle title,
		QString iconEmoji,
		std::optional<uint8> colorIndex,
		Flags flags,
		base::flat_set<not_null<History*>> always,
		std::vector<not_null<History*>> pinned,
		base::flat_set<not_null<History*>> never);

	[[nodiscard]] ChatFilter withId(FilterId id) const;
	[[nodiscard]] ChatFilter withTitle(ChatFilterTitle title) const;
	[[nodiscard]] ChatFilter withColorIndex(std::optional<uint8>) const;
	[[nodiscard]] ChatFilter withChatlist(
		bool chatlist,
		bool hasMyLinks) const;
	[[nodiscard]] ChatFilter withoutAlways(not_null<History*>) const;

	[[nodiscard]] static ChatFilter FromTL(
		const MTPDialogFilter &data,
		not_null<Session*> owner);
	[[nodiscard]] MTPDialogFilter tl(FilterId replaceId = 0) const;

	[[nodiscard]] FilterId id() const;
	[[nodiscard]] ChatFilterTitle title() const;
	[[nodiscard]] const TextWithEntities &titleText() const;
	[[nodiscard]] QString iconEmoji() const;
	[[nodiscard]] std::optional<uint8> colorIndex() const;
	[[nodiscard]] Flags flags() const;
	[[nodiscard]] bool staticTitle() const;
	[[nodiscard]] bool chatlist() const;
	[[nodiscard]] bool hasMyLinks() const;
	[[nodiscard]] const base::flat_set<not_null<History*>> &always() const;
	[[nodiscard]] const std::vector<not_null<History*>> &pinned() const;
	[[nodiscard]] const base::flat_set<not_null<History*>> &never() const;

	[[nodiscard]] bool contains(
		not_null<History*> history,
		bool ignoreFakeUnread = false) const;

private:
	FilterId _id = 0;
	TextWithEntities _title;
	QString _iconEmoji;
	std::optional<uint8> _colorIndex;
	base::flat_set<not_null<History*>> _always;
	std::vector<not_null<History*>> _pinned;
	base::flat_set<not_null<History*>> _never;
	Flags _flags;

};

inline bool operator==(const ChatFilter &a, const ChatFilter &b) {
	return (a.titleText() == b.titleText())
		&& (a.iconEmoji() == b.iconEmoji())
		&& (a.colorIndex() == b.colorIndex())
		&& (a.flags() == b.flags())
		&& (a.always() == b.always())
		&& (a.never() == b.never());
}

inline bool operator!=(const ChatFilter &a, const ChatFilter &b) {
	return !(a == b);
}

struct ChatFilterLink {
	FilterId id = 0;
	QString url;
	QString title;
	std::vector<not_null<History*>> chats;

	friend inline bool operator==(
		const ChatFilterLink &a,
		const ChatFilterLink &b) = default;
};

struct SuggestedFilter {
	ChatFilter filter;
	QString description;
};

struct TagColorChanged final {
	FilterId filterId = 0;
	bool colorExistenceChanged = false;
};

class ChatFilters final {
public:
	// What the folder tabs show: Telegram's folders and ZaStoGram's
	// top-level ones. Nested ZaStoGram folders are reached from their parent.
	class Tabs final {
	public:
		explicit Tabs(not_null<const ChatFilters*> owner) : _owner(owner) {
		}

		[[nodiscard]] int size() const;
		[[nodiscard]] bool empty() const {
			return !size();
		}
		[[nodiscard]] const ChatFilter &operator[](int index) const;

		class iterator final {
		public:
			using iterator_category = std::forward_iterator_tag;
			using value_type = ChatFilter;
			using difference_type = std::ptrdiff_t;
			using pointer = const ChatFilter*;
			using reference = const ChatFilter&;

			iterator() = default;
			iterator(not_null<const ChatFilters*> owner, int index)
			: _owner(owner)
			, _index(index) {
			}

			[[nodiscard]] reference operator*() const;
			[[nodiscard]] pointer operator->() const {
				return &**this;
			}
			iterator &operator++() {
				++_index;
				return *this;
			}
			iterator operator++(int) {
				auto result = *this;
				++_index;
				return result;
			}
			[[nodiscard]] friend bool operator==(
					const iterator &a,
					const iterator &b) {
				return a._index == b._index;
			}

		private:
			const ChatFilters *_owner = nullptr;
			int _index = 0;

		};
		[[nodiscard]] iterator begin() const {
			return iterator(_owner, 0);
		}
		[[nodiscard]] iterator end() const {
			return iterator(_owner, size());
		}

	private:
		not_null<const ChatFilters*> _owner;

	};

	explicit ChatFilters(not_null<Session*> owner);
	~ChatFilters();

	void setPreloaded(
		const QVector<MTPDialogFilter> &result,
		bool tagsEnabled);

	void load();
	void reload();
	void apply(const MTPUpdate &update);
	void set(ChatFilter filter);
	void remove(FilterId id);
	void moveAllToFront();
	[[nodiscard]] const std::vector<ChatFilter> &list() const;
	[[nodiscard]] Tabs tabs() const {
		return Tabs(this);
	}
	[[nodiscard]] int tabsCount() const;
	// The tab that shows this folder: the folder itself, or for a nested
	// ZaStoGram folder the top-level folder it is inside of.
	[[nodiscard]] FilterId tabIdFor(FilterId id) const;
	[[nodiscard]] const ChatFilter &tabAt(int index) const;
	[[nodiscard]] LocalFolders &local();
	[[nodiscard]] const LocalFolders &local() const;
	[[nodiscard]] rpl::producer<> changed() const;
	[[nodiscard]] rpl::producer<FilterId> isChatlistChanged() const;
	[[nodiscard]] rpl::producer<TagColorChanged> tagColorChanged() const;
	[[nodiscard]] bool loaded() const;
	[[nodiscard]] bool has() const;
	// Telegram's own folders (with the default one), not ZaStoGram's.
	[[nodiscard]] int serverCount() const;

	[[nodiscard]] FilterId defaultId() const;
	[[nodiscard]] FilterId lookupId(int index) const;

	bool loadNextExceptions(bool chatsListLoaded);

	void refreshHistory(not_null<History*> history);

	[[nodiscard]] not_null<Dialogs::MainList*> chatsList(FilterId filterId);
	void clear();

	const ChatFilter &applyUpdatedPinned(
		FilterId id,
		const std::vector<Dialogs::Key> &dialogs);
	void saveOrder(
		const std::vector<FilterId> &order,
		mtpRequestId after = 0);

	[[nodiscard]] bool archiveNeeded() const;

	void requestSuggested();
	[[nodiscard]] bool suggestedLoaded() const;
	[[nodiscard]] auto suggestedFilters() const
		-> const std::vector<SuggestedFilter> &;
	[[nodiscard]] rpl::producer<> suggestedUpdated() const;

	ChatFilterLink add(
		FilterId id,
		const MTPExportedChatlistInvite &update);
	void edit(
		FilterId id,
		const QString &url,
		const QString &title);
	void destroy(FilterId id, const QString &url);
	rpl::producer<std::vector<ChatFilterLink>> chatlistLinks(
		FilterId id) const;
	void reloadChatlistLinks(FilterId id);

	[[nodiscard]] rpl::producer<Ui::MoreChatsBarContent> moreChatsContent(
		FilterId id);
	[[nodiscard]] const std::vector<not_null<PeerData*>> &moreChats(
		FilterId id) const;
	void moreChatsHide(FilterId id, bool localOnly = false);

	[[nodiscard]] bool tagsEnabled() const;
	[[nodiscard]] rpl::producer<bool> tagsEnabledValue() const;
	[[nodiscard]] rpl::producer<bool> tagsEnabledChanges() const;
	void requestToggleTags(bool value, Fn<void()> fail);

private:
	struct MoreChatsData {
		std::vector<not_null<PeerData*>> missing;
		crl::time lastUpdate = 0;
		mtpRequestId requestId = 0;
		std::weak_ptr<bool> watching;
	};

	void load(bool force);
	void received(const QVector<MTPDialogFilter> &list);
	bool applyOrder(const QVector<MTPint> &order);
	bool applyChange(ChatFilter &filter, ChatFilter &&updated);
	void applyInsert(ChatFilter filter, int position);
	void applyRemove(int position);

	void checkLoadMoreChatsLists();
	void loadMoreChatsList(FilterId id);

	// ZaStoGram's own folders live at the tail of _list, after Telegram's.
	void refreshLocal();
	void ensureTabs() const;

	const not_null<Session*> _owner;

	std::vector<ChatFilter> _list;
	base::flat_map<FilterId, std::unique_ptr<Dialogs::MainList>> _chatsLists;
	rpl::event_stream<> _listChanged;
	rpl::event_stream<FilterId> _isChatlistChanged;
	rpl::event_stream<TagColorChanged> _tagColorChanged;
	mtpRequestId _loadRequestId = 0;
	mtpRequestId _saveOrderRequestId = 0;
	mtpRequestId _saveOrderAfterId = 0;
	mtpRequestId _toggleTagsRequestId = 0;
	bool _loaded = false;
	bool _reloading = false;

	mtpRequestId _suggestedRequestId = 0;
	std::vector<SuggestedFilter> _suggested;
	rpl::event_stream<> _suggestedUpdated;
	crl::time _suggestedLastReceived = 0;

	rpl::variable<bool> _tagsEnabled = false;

	std::deque<FilterId> _exceptionsToLoad;
	mtpRequestId _exceptionsLoadRequestId = 0;

	base::flat_map<FilterId, std::vector<ChatFilterLink>> _chatlistLinks;
	rpl::event_stream<FilterId> _chatlistLinksUpdated;
	mtpRequestId _linksRequestId = 0;

	const std::unique_ptr<LocalFolders> _local;
	std::unique_ptr<Api::LocalFoldersSync> _sync;
	rpl::lifetime _localLifetime;
	mutable std::vector<int> _tabIndices;
	mutable bool _tabsDirty = true;

	base::flat_map<FilterId, MoreChatsData> _moreChatsData;
	rpl::event_stream<FilterId> _moreChatsUpdated;
	base::Timer _moreChatsTimer;

};

[[nodiscard]] bool CanRemoveFromChatFilter(
	const ChatFilter &filter,
	not_null<History*> history);

} // namespace Data

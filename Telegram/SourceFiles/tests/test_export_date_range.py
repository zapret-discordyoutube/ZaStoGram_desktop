from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def source(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def test_export_start_uses_the_visible_settings_snapshot() -> None:
    view = source("export/view/export_view_settings.cpp")
    panel = source("export/view/export_view_panel_controller.cpp")

    assert "rpl::producer<Settings> SettingsWidget::startClicks() const" in view
    assert "return base::duplicate(readData());" in view
    assert "rpl::on_next([=](Settings data)" in panel
    assert "*_settings = std::move(data);" in panel


def test_message_range_is_enforced_by_api_and_writer() -> None:
    api = source("export/export_api_wrap.cpp")
    data = source("export/data/export_data_types.cpp")

    assert "const auto useSearch = onlyMyMessages || dateRange.hasLimits();" in api
    assert api.count("MTP_int(dateRange.searchMinDate())") >= 2
    assert api.count("MTP_int(dateRange.searchMaxDate())") >= 2
    assert "MTP_flags(Flag::f_top_msg_id)" in api
    assert "settings.singlePeerDateRange.contains(message.date)" in data


def test_message_range_has_half_open_semantics() -> None:
    date_range = source("export/export_date_range.h")

    assert "date >= from" in date_range
    assert "date < till" in date_range
    assert "till > from" in date_range
    assert "hasFrom() ? (from - 1) : 0" in date_range

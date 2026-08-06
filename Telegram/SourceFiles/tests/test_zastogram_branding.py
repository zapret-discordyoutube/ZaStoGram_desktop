#!/usr/bin/env python3

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
FORK_RELEASES = "https://git.zapret.moe/zapretdiscordyoutube/ZaStoGram_desktop/releases"
UPSTREAM_CHANGELOG = "https://telegramdesktop.github.io/tdesktop/changelog/"


def source(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def require(path: str, *needles: str) -> None:
    text = source(path)
    missing = [needle for needle in needles if needle not in text]
    if missing:
        raise AssertionError(
            f"{path} lost ZaStoGram fork markers: {', '.join(missing)}")


def main() -> None:
    application = source("SourceFiles/core/application.cpp")
    if UPSTREAM_CHANGELOG in application:
        raise AssertionError("the upstream Telegram changelog URL was restored")
    if FORK_RELEASES not in application:
        raise AssertionError("the ZaStoGram release history URL is missing")

    require(
        "SourceFiles/core/version.h",
        'constexpr auto AppName = "ZaStoGram"_cs;',
        "constexpr auto AppBetaVersion = false;",
    )
    require(
        "SourceFiles/core/launcher.cpp",
        'QApplication::setApplicationName(u"ZaStoGram"_q);',
    )
    require(
        "SourceFiles/boxes/about_box.cpp",
        "box->setTitle(AppName.utf16());",
        'u" (build %1)"_q.arg(ZsgBuildId.utf16())',
    )
    require(
        "SourceFiles/core/update_checker.cpp",
        "kZaStoGramReleasesApi",
        'release.value("prerelease").toBool()',
        "ZaStoGramDevBuildNumber()",
        "versionNum == AppVersion && !IsZaStoGramDevBuild()",
    )
    require(
        "SourceFiles/window/window_main_menu.cpp",
        "AppName.utf16()",
        FORK_RELEASES,
    )
    require(
        "SourceFiles/storage/localstorage.cpp",
        FORK_RELEASES + "/latest/download",
    )
    require(
        "Resources/winrc/Telegram.rc",
        'VALUE "FileDescription", "ZaStoGram"',
        'VALUE "ProductName", "ZaStoGram"',
    )
    require(
        "../.github/workflows/win.yml",
        'BUILD_ID="stable-${GITHUB_RUN_NUMBER}"',
        'BUILD_ID="dev-${GITHUB_RUN_NUMBER}"',
        "Generate dev update map (current4).",
    )


if __name__ == "__main__":
    main()

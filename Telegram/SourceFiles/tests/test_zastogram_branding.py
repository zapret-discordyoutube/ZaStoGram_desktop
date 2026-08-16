#!/usr/bin/env python3

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
FORK_RELEASES = "https://git.zapret.moe/zastogram/ZaStoGram_desktop/releases"


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
        "https://git.zapret.moe/api/v1/repos/",
        "zastogram/ZaStoGram_desktop/releases?limit=100",
        "if (IsZaStoGramDevBuild())",
        "ResponseType::DevReleases",
        'release.value("prerelease").toBool()',
        "ZaStoGramDevBuildNumber()",
        'name == "current4"',
        "_dev%2",
        "versionNum == AppVersion && !IsZaStoGramDevBuild()",
    )
    require(
        "SourceFiles/window/window_main_menu.cpp",
        "AppName.utf16()",
        FORK_RELEASES,
    )
    localstorage = source("SourceFiles/storage/localstorage.cpp")
    if FORK_RELEASES + "/download/latest" not in localstorage:
        raise AssertionError("the native Forgejo latest-asset prefix is missing")
    if FORK_RELEASES + "/latest/download" in localstorage:
        raise AssertionError("the GitHub latest-asset path order returned")
    require(
        "Resources/winrc/Telegram.rc",
        'VALUE "FileDescription", "ZaStoGram"',
        'VALUE "ProductName", "ZaStoGram"',
    )
    require(
        "../.forgejo/workflows/source-guards.yml",
        "release_guards.txt",
        "Run canonical release source guards",
    )


if __name__ == "__main__":
    main()

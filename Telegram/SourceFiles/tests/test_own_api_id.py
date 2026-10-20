from pathlib import Path


BUILD_SCRIPT = (
    Path(__file__).resolve().parents[2]
    / "build" / "zastogram" / "build-telegram.bat"
)


def test_build_uses_own_api_identity_not_the_public_test_pair():
    script = BUILD_SCRIPT.read_text(encoding="utf-8")

    # The public tdesktop pair is flagged by Telegram: login fails with
    # API_ID_PUBLISHED_FLOOD for every user of such a build.
    assert "TDESKTOP_API_TEST=ON" not in script
    # A cached ON from an earlier configure would override the id below.
    assert "-D TDESKTOP_API_TEST=OFF" in script
    assert "-D TDESKTOP_API_ID=%ZSG_API_ID%" in script
    assert "-D TDESKTOP_API_HASH=%ZSG_API_HASH%" in script


def test_build_refuses_missing_or_public_api_identity():
    script = BUILD_SCRIPT.read_text(encoding="utf-8")

    assert "DesktopPrivate\\telegram_api.txt" in script
    assert 'if not exist "%ZSG_API_FILE%"' in script
    assert 'if "%ZSG_API_ID%"=="4"' in script
    assert 'if "%ZSG_API_ID%"=="17349"' in script
    assert script.index("ZSG_API_ID%\"==\"17349\"") < script.index("configure.bat")


def test_api_identity_is_not_committed():
    script = BUILD_SCRIPT.read_text(encoding="utf-8")

    assert "344583e45741c457fe1862106095a5eb" not in script


if __name__ == "__main__":
    for name, value in list(globals().items()):
        if name.startswith("test_") and callable(value):
            value()

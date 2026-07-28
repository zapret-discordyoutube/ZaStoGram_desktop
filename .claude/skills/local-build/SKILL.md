---
name: local-build
description: >
  Собрать ZaStoGram локально в Windows-VM на этом хосте и, если нужно,
  выложить dev-пререлиз — вместо ожидания GitHub Actions. Использовать после
  изменений в исходниках, когда нужен проверенный компиляцией результат или
  тестируемый бинарь ("собери", "проверь что компилируется", "выложи сборку",
  "дай exe"). НЕ использовать для публикации обновления пользователям —
  для этого есть скилл release-update.
---

# Локальная сборка ZaStoGram

Сборка идёт не на этой машине, а в соседней VM. Хост — Proxmox (Debian), сам
он собирать Windows-бинарь не может; всё делается в гостевой Windows через SSH.

## Инфраструктура

| Что | Где |
|---|---|
| Сборочная машина | VM 100 `win10-workstation` (28 vCPU, 20 ГБ RAM), `qm` на хосте |
| Канал | `ssh win10` (пользователь `privacy`, ключ `~/.ssh/id_ed25519_win10`) |
| PowerShell-обёртка | `/home/codex-pve/winps.sh` — скрипт на stdin, без мучений с экранированием |
| Аварийный канал | `/home/codex-pve/winexec.sh` — через QEMU guest agent, работает даже если SSH лёг |
| BuildPath | `C:\TBuild` |
| Репозиторий | `C:\TBuild\ZaStoGram_desktop` |
| Библиотеки | `C:\TBuild\Libraries\win64` |
| Ключи подписи | `C:\TBuild\DesktopPrivate\packer_private.h` (копия на хосте: `/home/codex-pve/DesktopPrivate`, права 600) |
| Кеш компиляции | `C:\TBuild\sccache`, 20 ГБ |
| Скрипт релиза | `/home/codex-pve/zsg-release.sh` |

Тулчейн подобран под CI, не под «посвежее»:

- **MSVC 14.44** из VS 2022 Build Tools (`C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools`).
  В VS 2026 этого toolset нет — её установщик отвечает кодом 87. Дефолтный v145 из
  VS 2026 не поддерживает Windows 7, поэтому не подходит.
- **Windows SDK 10.0.26100.0** — версия зашита в `docs/building-win.md`, CI читает её оттуда.
- **CMake 3.31.6**, не 4.x. CMake 4 удалил совместимость с `cmake_minimum_required(VERSION < 3.5)`,
  а рецепты зависимостей в `Telegram/build/prepare/prepare.py` под него не адаптированы
  (обход `-DCMAKE_POLICY_VERSION_MINIMUM=3.5` прописан лишь в одном месте).
- Python 3.12, Git, Ninja, sccache — в PATH.

## Собрать

```bash
ssh win10 'cmd /c C:\TBuild\build-telegram.bat > C:\TBuild\build.log 2>&1'
```

Аргумент `lto` включает `DESKTOP_APP_ENABLE_LTO=ON` — так CI собирает теги и nightly.
Без него сборка быстрее и легче по памяти; для обычной проверки LTO не нужен.

`build-telegram.bat` повторяет шаг «Telegram Desktop build» из `.github/workflows/win.yml`:
генератор Ninja Multi-Config, Qt 6, `TDESKTOP_API_TEST=ON`, `ZASTOGRAM_PACKER=ON`,
`CMAKE_MSVC_DEBUG_INFORMATION_FORMAT=` (пусто — иначе sccache не кеширует),
цели `Telegram Packer`, параллелизм 16.

Результат: `C:\TBuild\ZaStoGram_desktop\out\Release\Telegram.exe` (+ `Updater.exe`, `Packer.exe`).

Смотреть прогресс:

```bash
/home/codex-pve/winps.sh <<'PS'
Get-Content 'C:\TBuild\build.log' -Tail 30
PS
```

## Выложить сборку

```bash
/home/codex-pve/zsg-release.sh --ref dev --publish
```

Это создаёт **пререлиз** `local-<sha>` с `ZaStoGram-x64.exe` и portable-zip. Пререлиз
не помечается `latest`, `current4` не трогается — установленные клиенты ничего не получают.
Без `--publish` файлы просто складываются в `~/zsg-release-work/release`.

Скрипт сам синхронизирует клон в VM с origin, гоняет source-гарды (те же, что CI),
собирает, забирает артефакты по scp и проверяет, что это непустой 64-битный PE.

## Границы

- **Не публикуй обновление пользователям из этого скилла.** Флаг `--release` делает релиз
  `latest` с подписанным `current4`, после чего все установленные клиенты обновятся в
  течение 8–16 часов, и откатить это нельзя. Такой выпуск — только по явной просьбе,
  через скилл `release-update`.
- Не бампай версию в `Telegram/build/version` ради обычной сборки.
- Не коммить и не пуш ничего из VM — она только собирает. Источник правды остаётся в
  `/home/codex-pve/tdesktop` и на origin.
- GitHub Actions продолжает собирать на каждый push и работает независимо. Не жди его,
  не отменяй и не перезапускай.

## Первичная подготовка

Библиотеки (Qt 6.11.1, ffmpeg, openssl, tg_owt — 32 стадии) собираются один раз:

```bash
ssh win10 'cmd /c C:\TBuild\build-libs.bat > C:\TBuild\libs.log 2>&1'
```

Это часы работы. `prepare.py` идемпотентен — держит `cache_keys` по стадиям, поэтому
обрыв не смертелен: повторный запуск продолжит с незавершённой стадии. Пересобирать
нужно только после изменений в `Telegram/build/prepare/prepare.py` или смены toolset.

## Если что-то сломалось

- **`Make sure to run from Native Tools Command Prompt`** — не выставлена переменная
  `Platform`. `VsDevCmd.bat`, в отличие от `vcvarsall.bat`, её не ставит; `C:\TBuild\env.bat`
  делает `set Platform=x64` именно поэтому.
- **`LNK1104` / `access denied` на `Telegram.exe`** — запущен собранный клиент или отладчик.
  Останови процесс, не retry вслепую.
- **Кончается место на `C:`** — диск 200 ГБ, свободного около 100 ГБ. Отдельный диск
  под сборку не заводить: в thin-пуле Proxmox это раздувает allocated, а уменьшить
  его потом нельзя. Чистить: `C:\TBuild\sccache`, `out\Release`, дерево библиотек по
  фильтру из шага «Free up some disk space» в `win.yml`.
- **SSH не отвечает** — работай через `/home/codex-pve/winexec.sh` (guest agent) и проверь
  `sudo qm agent 100 ping` на хосте.

---
name: tdesktop-local-release
description: Build and package a local ZaStoGram Release immediately after delivering product-source changes, while GitHub Actions continues independently. Use for ordinary development deliveries that need a testable binary without waiting for CI. Do not use for signed production auto-update releases or version tags.
---

# Ship a local ZaStoGram Release

Treat "local release" as an unsigned development package built from the exact
committed revision. Produce it immediately and leave GitHub Actions running in
the background.

## Keep the release boundary safe

- Follow the repository `AGENTS.md` and inspect the existing configured build
  tree before choosing a command.
- Do not bump the application version, create or push a tag, create a GitHub
  Release, generate `current4`, or claim that an auto-update is live.
- Use `.claude/skills/release-update/SKILL.md` only when the user explicitly
  requests a signed production update or a new public version.
- Do not wait for, poll, cancel, or retry GitHub Actions. A single read-only
  lookup to report the run URL is allowed.
- Skip this workflow when the user explicitly asks not to build or package.

## Deliver and start CI

1. Complete the requested source change and the strongest applicable fast
   checks.
2. Confirm that the intended diff is committed and push the current branch.
   This starts the remote workflow; continue locally without waiting for it.
3. Record the commit SHA. Build and package only that committed revision.

## Build locally

1. Inspect `out/CMakeCache.txt` and use only a toolchain compatible with that
   build tree. Do not reconfigure the project merely to switch platforms.
2. For a configured Windows tree, run from the matching Visual Studio Native
   Tools environment:

   ```text
   cmake --build out --config Release --target Telegram --parallel
   ```

   The `Telegram` target also builds `Updater` when auto-update support is
   enabled.
3. From WSL, invoke the matching native Windows toolchain only for a Windows
   build tree. Never run native Windows CMake against a Linux or Docker tree.
   For a Linux tree, use the repository Docker environment and build the
   `Release` configuration only when that environment is already available.
4. Do not substitute a Debug binary or an older successful output. If no
   compatible local Release toolchain or configured tree exists, report that
   concrete blocker immediately; do not wait for Actions as a fallback.
5. If the build reports `C1041`, `LNK1104`, an inaccessible output executable,
   `access denied`, or `file in use`, stop after the first failure and ask the
   user to close Telegram and any debugger. Do not retry.

## Package the result

1. Verify that the Release executable exists, is non-empty, has the expected
   platform format, and is newer than the build start time.
2. Create an ignored staging directory at
   `out/local-release/<short-commit>/`.
3. Copy the executable there with a `ZaStoGram-local-<short-commit>-<arch>`
   filename. For Windows, also create a portable ZIP containing the freshly
   built `Telegram.exe` and `Updater.exe` when the updater exists.
4. Compute SHA-256 hashes for every delivered file. Keep build and package
   output out of Git.

## Report completion

Provide the exact absolute package paths, commit SHA, architecture, and
SHA-256 hashes. State that GitHub Actions is continuing independently and
include its URL only if it was obtained without waiting. Do not call the task
complete when no fresh local Release package was produced; report the local
toolchain blocker instead.

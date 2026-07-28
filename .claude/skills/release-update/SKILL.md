---
name: release-update
description: >
  Release a new ZaStoGram auto-update: bump the app version, build it locally
  and publish the signed update package on GitHub Releases.
  Use ONLY when the user explicitly asks to release/publish an update or a
  new version ("выпусти обновление", "зарелизь", "выпусти новую версию",
  "release an update", "ship a new version"). Do NOT use for ordinary
  commits, dev builds, CI fixes or version questions — for an ordinary local
  build or a test binary use the local-build skill instead.
---

# Release a ZaStoGram update

Auto-updates work like this: the client polls
`https://github.com/youtubediscord/ZaStoGram_desktop/releases/latest/download/current4`
and installs the signed package listed there **only if its version is greater
than the client's baked-in `AppVersion`**. `releases/latest` resolves only to a
published non-prerelease release, and the update file itself must be an asset of
that same release — the client fetches `<latest>/download/<link>`.

So a release reaches nobody unless the version was bumped, and it breaks every
client if `current4` points at a file that is not attached to that release.

## Two ways to publish

**Local build (default, minutes).** Builds x64 in the Windows VM and publishes
from this host. Fast, free, signing key already in place. Limitation: only x64 is
built, so the 32-bit channel freezes at its current version — the release script
carries the old `tupdate*` file and its `win` entry forward, so 32-bit clients keep
a working (older) channel instead of losing updates entirely.

**Tag + CI (1–3 hours).** Push a `zsg-<X.Y.Z>` tag and let
`.github/workflows/win.yml` build both x64 and x64_x86. Use this when 32-bit
clients must also receive the update, or when the local toolchain is broken.

## Steps (local build)

1. **Preconditions.** Working tree clean, on `dev`, synced with `origin/dev`
   (`git status`, `git pull --ff-only`). The signing key must be present at
   `C:\TBuild\DesktopPrivate\packer_private.h` in the VM (host backup:
   `/home/codex-pve/DesktopPrivate`, mode 600). Without it Packer cannot sign.

2. **Pick the new version.** Use the version the user named, otherwise bump the
   patch part of `AppVersionStr` in [Telegram/build/version](../../../Telegram/build/version)
   (e.g. 7.0.6 → 7.0.7). The numeric form is `major*1000000 + minor*1000 + patch`
   (7.0.7 → 7000007) and must strictly increase, or clients ignore the release.

3. **Bump.** Run `python Telegram/build/set_version.py <X.Y.Z>` from the repo
   root. Verify both `Telegram/build/version` and
   `Telegram/SourceFiles/core/version.h` show the new version.

4. **Commit and push.** Commit as `Version <X.Y.Z>` and push `dev`. Do not create
   the tag by hand — the release script creates it together with the release.

5. **Build and publish.**

   ```bash
   /home/codex-pve/zsg-release.sh --ref dev --release --lto --publish
   ```

   The script refuses to publish if `AppVersion` is not greater than the version
   currently served by `current4`, runs the source guards, builds Release x64,
   signs with `Packer.exe`, carries the 32-bit channel forward, writes `current4`
   and creates the release marked `--latest`.

   Run it once without `--publish` if you want to inspect the artifacts in
   `~/zsg-release-work/release` before anything becomes public.

6. **Verify.** `gh release view zsg-<X.Y.Z> --repo youtubediscord/ZaStoGram_desktop --json assets,isLatest,isPrerelease`
   must show `isLatest: true`, `isPrerelease: false`, and assets including
   `current4`, `tx64upd<AppVersion>` plus the user-facing exe/zip files. Then
   confirm the endpoint serves the new map:
   `curl -sL https://github.com/youtubediscord/ZaStoGram_desktop/releases/latest/download/current4`

7. **Report.** Tell the user the release is live and which version; that it is
   x64-only and 32-bit clients stay on the previous version; and that clients pick
   it up on their next update check (every 8–16 hours, or immediately via
   Settings → Advanced → Check for updates).

## Steps (tag + CI)

Versioning steps 1–4 are the same, then
`git tag zsg-<X.Y.Z> && git push origin zsg-<X.Y.Z>`. The `zsg-` prefix is
required: plain `v<X.Y.Z>` tags collide with upstream Telegram's tags that came
along with the fork (v6.9.3 etc. already exist and point at official commits).
Find the run with
`gh run list --repo youtubediscord/ZaStoGram_desktop --workflow win.yml --json databaseId,headBranch,status`
(the tag run has `headBranch` = the tag name) and poll with a background Monitor
every ~90s; a full build takes 1–3 hours. If it fails, read
`gh run view <id> --log-failed`, fix the cause, then redo the tag:
`git tag -d zsg-<X.Y.Z>`, `git push origin :refs/tags/zsg-<X.Y.Z>`, delete the
half-made release (`gh release delete zsg-<X.Y.Z> --yes`), and re-tag.

## Failure notes

- "Could not read RSA private key" in the Pack step → the key file is missing or
  corrupt; restore it from `/home/codex-pve/DesktopPrivate/packer_private.h`
  (never commit that file). The same content lives in the `PACKER_PRIVATE_H`
  GitHub secret, which cannot be read back — that host copy and the user's own
  backup are the only readable ones.
- "No signed update packages found" → Packer ran without a key, or the build
  produced no `Packer.exe` (check that the configure step kept `ZASTOGRAM_PACKER=ON`).
- A published release whose `current4` names a file not attached to it leaves every
  client failing the download. Upload the missing asset to that same release rather
  than publishing another one.
- Linker errors mentioning symbols that exist in the sources → stale build cache;
  clear `C:\TBuild\sccache` locally, or bump `TELEGRAM_BUILD_CACHE_VERSION` in
  [.github/workflows/win.yml](../../../.github/workflows/win.yml) for CI.

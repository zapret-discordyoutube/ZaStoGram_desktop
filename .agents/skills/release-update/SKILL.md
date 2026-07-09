---
name: release-update
description: >
  Release a new ZaStoGram auto-update: bump the app version, push a release
  tag and watch CI publish the signed update packages on GitHub Releases.
  Use ONLY when the user explicitly asks to release/publish an update or a
  new version ("выпусти обновление", "зарелизь", "выпусти новую версию",
  "release an update", "ship a new version"). Do NOT use for ordinary
  commits, dev builds, CI fixes or version questions — regular pushes to dev
  only produce dev-N prereleases which are never served as auto-updates.
---

# Release a ZaStoGram update

Auto-updates work like this: the client polls
`https://github.com/youtubediscord/ZaStoGram_desktop/releases/latest/download/current4`
and installs the signed package listed there **only if its version is greater
than the client's baked-in `AppVersion`**. `releases/latest` resolves only to
a published non-prerelease release, and signed packages are built only on tag
pushes — so nothing is released until you push a `v*` tag, and a release
without a version bump reaches nobody.

## Steps

1. **Preconditions.** Working tree clean, on `dev`, synced with `origin/dev`
   (`git status`, `git pull --ff-only`). Confirm the secret exists:
   `gh secret list --repo youtubediscord/ZaStoGram_desktop` must show
   `PACKER_PRIVATE_H` — without it the Packer cannot sign and the tag build
   fails.

2. **Pick the new version.** Use the version the user named, otherwise bump
   the patch part of `AppVersionStr` in [Telegram/build/version](../../../Telegram/build/version)
   (e.g. 6.9.3 → 6.9.4). The numeric form is `major*1000000 + minor*1000 + patch`
   (6.9.4 → 6009004) and must strictly increase, or clients will ignore the
   release.

3. **Bump.** Run `python Telegram/build/set_version.py <X.Y.Z>` from the repo
   root. Verify both `Telegram/build/version` and
   `Telegram/SourceFiles/core/version.h` now show the new version.

4. **Commit, push, tag.** Commit as `Version <X.Y.Z>`, push `dev`, then
   `git tag zsg-<X.Y.Z> && git push origin zsg-<X.Y.Z>`. The `zsg-` prefix is
   required: plain `v<X.Y.Z>` tags collide with upstream Telegram's tags that
   came along with the fork (v6.9.3 etc. already exist and point at official
   commits). The tag build runs in its own concurrency group, so tagging
   immediately is fine. Note: any push to `dev` cancels the in-progress dev
   build for that branch — that is expected.

5. **Watch the tag build.** Find the run:
   `gh run list --repo youtubediscord/ZaStoGram_desktop --workflow win.yml --json databaseId,headBranch,status`
   (the tag run has `headBranch` = the tag name). Poll with a background
   Monitor every ~90s until it completes; a full build takes 1–3 hours. If it
   fails, read `gh run view <id> --log-failed`, fix the cause, then redo the
   tag: `git tag -d zsg-<X.Y.Z>`, `git push origin :refs/tags/zsg-<X.Y.Z>`,
   delete the half-made release if any (`gh release delete zsg-<X.Y.Z> --yes`),
   and re-tag the fixed commit.

6. **Verify the release.** `gh release view zsg-<X.Y.Z> --json assets,isLatest,isPrerelease`
   must show `isLatest: true`, `isPrerelease: false`, and assets including
   `current4`, `tupdate<AppVersion>`, `tx64upd<AppVersion>` plus the
   user-facing exe/zip files. Then confirm the update endpoint serves the new
   map: `curl -sL https://github.com/youtubediscord/ZaStoGram_desktop/releases/latest/download/current4`
   must contain the new version number.

7. **Report.** Tell the user the release is live, which version, and remind
   that clients pick it up on their next update check (every 8–16 hours, or
   immediately via Settings → Advanced → Check for updates).

## Failure notes

- "Could not read RSA private key" in the Pack step → the
  `PACKER_PRIVATE_H` secret is missing/corrupt; restore it from the local
  `J:\privacy\DesktopPrivate\packer_private.h` (never commit that file).
- "No signed update packages found" in the release job → the Pack step was
  skipped or failed upstream; check the windows job logs.
- Linker errors mentioning symbols that exist in the sources → stale CI build
  cache; bump `TELEGRAM_BUILD_CACHE_VERSION` in
  [.github/workflows/win.yml](../../../.github/workflows/win.yml).

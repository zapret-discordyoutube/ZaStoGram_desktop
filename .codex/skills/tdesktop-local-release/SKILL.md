---
name: tdesktop-local-release
description: Build and package a local ZaStoGram Release immediately after delivering product-source changes, while GitHub Actions continues independently. Use for ordinary development deliveries that need a testable binary without waiting for CI. Do not use for signed production auto-update releases or version tags.
---

# Ship a local ZaStoGram Release

Treat "local release" as a development package built from the exact committed
revision. Produce it immediately and leave GitHub Actions running in the
background.

On the Proxmox host this is fully automated — the Windows toolchain lives in
VM 100 `win10-workstation` and the whole sequence is one command. The Claude
counterpart of this workflow, with infrastructure details and troubleshooting,
is `.claude/skills/local-build/SKILL.md`; keep the two consistent.

## Keep the release boundary safe

- Do not bump the application version, generate `current4`, mark a release
  `latest`, or claim that an auto-update is live. A prerelease is the ceiling
  for this workflow.
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

## Build and publish locally

```bash
/home/codex-pve/zsg-release.sh --ref dev --publish
```

That syncs the build clone in the VM, runs the same source guards as CI, builds
Release x64 with MSVC 14.44, verifies the artifact is a non-empty 64-bit PE,
packages `ZaStoGram-x64.exe` plus a portable zip, and publishes them as the
prerelease `local-<sha>`. A prerelease is never served as an auto-update.

Drop `--publish` to leave the packages in `~/zsg-release-work/release` without
touching GitHub.

If the host has no such VM (a different machine, or a Windows/WSL checkout),
fall back to the manual route: inspect `out/CMakeCache.txt`, build only with a
toolchain matching that tree, and package by hand under
`out/local-release/<short-commit>/`. Never run native Windows CMake against a
Linux or Docker build tree.

## When the build cannot run

Stop after the first failure and report the concrete blocker — do not retry
blindly and do not fall back to waiting for Actions:

- `C1041`, `LNK1104`, inaccessible output executable, `access denied`, or
  `file in use` → a running client or debugger holds the binary; ask the user
  to close it.
- Missing libraries or an unconfigured tree → the one-time
  `C:\TBuild\build-libs.bat` run has not completed; that takes hours.
- No compatible local toolchain at all → say so instead of substituting a Debug
  binary or an older successful output.

## Report completion

Provide the exact package paths (or the release URL), the commit SHA,
architecture, and SHA-256 hashes. State that GitHub Actions is continuing
independently and include its URL only if it was obtained without waiting. Do
not call the task complete when no fresh local Release package was produced.

#!/usr/bin/env python3
"""Every library the build reads after a strip must be classified.

Telegram/build/zastogram/clean-libs.ps1 strips Libraries/win64 after each
successful prepare down to headers and libraries, except the directories that
Telegram/build/zastogram/libs-keep.json keeps whole. A stage whose other files
are read later (crate sources, generated .cpp) and is not kept leaves a valid
cache key over missing files: prepare skips it and the next consumer fails far
away from the cause (16.10.26: tdesktop_rust over a stripped tlottie, the client
configure over a stripped tdesktop_rust/out).

This guard derives the consumers itself, so an upstream merge that adds one
fails here, at the merge, with the stage to classify:

- prepare.py: a Libraries stage referenced by another stage's commands
  (../name, %LIBS_DIR%\\name, $LIBS_DIR/name);
- the client CMake (cmake/, Telegram/cmake/, when the submodule is checked
  out): a ${libs_loc}/... path to anything but headers and libraries, after
  expanding set() variables.
"""

import itertools
import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
REPO = ROOT.parent
PREPARE = ROOT / "build/prepare/prepare.py"
KEEP = ROOT / "build/zastogram/libs-keep.json"
STRIP_SURVIVORS = {".lib", ".a", ".exe", ".h", ".hpp", ".inc", ".cmake", ".pc"}
STAGE_RE = re.compile(r"^stage\('([^']+)',", re.M)
LOCATION_RE = re.compile(r'"""\s*,\s*\'([A-Za-z]+)\'\)')
SET_RE = re.compile(r"\bset\(\s*([A-Za-z0-9_]+)\s+([^\s)]+)", re.I)
VAR_RE = re.compile(r"\$\{([A-Za-z0-9_]+)\}")


def stages() -> dict[str, tuple[str, str]]:
    """name -> (location, body) for every stage() of prepare.py."""
    text = PREPARE.read_text(encoding="utf-8")
    starts = [(m.group(1), m.start()) for m in STAGE_RE.finditer(text)]
    result = {}
    for index, (name, start) in enumerate(starts):
        end = starts[index + 1][1] if index + 1 < len(starts) else len(text)
        body = text[start:end]
        match = LOCATION_RE.search(body)
        result[name] = (match.group(1) if match else "Libraries", body)
    return result


def stage_consumers(all_stages) -> dict[str, set[str]]:
    consumers = {}
    for name, (location, _) in all_stages.items():
        if location != "Libraries":
            continue
        pattern = re.compile(
            r"(?:\.\.[\\/]+|LIBS_DIR%?[\\/]+|\$LIBS_DIR/)" + re.escape(name)
            + r"(?![A-Za-z0-9_.+-])")
        for other, (_, body) in all_stages.items():
            if other != name and pattern.search(body):
                consumers.setdefault(name, set()).add(other)
    return consumers


def cmake_library_paths() -> list[tuple[str, str]] | None:
    """(path under libs_loc, cmake file) that a strip would delete."""
    roots = [REPO / "cmake", ROOT / "cmake"]
    if not (REPO / "cmake/external").is_dir():
        return None  # submodule not checked out (host checkout without submodules)
    files = []
    for root in roots:
        files += [p for p in root.rglob("*") if p.is_file()
                  and (p.name == "CMakeLists.txt" or p.suffix == ".cmake")]
    definitions: dict[str, set[str]] = {}
    sets = []
    for path in files:
        text = path.read_text(encoding="utf-8", errors="replace")
        for match in SET_RE.finditer(text):
            name, value = match.group(1), match.group(2).strip('"')
            definitions.setdefault(name, set()).add(value)
            sets.append((value, path))
    definitions.pop("libs_loc", None)

    def expand(value: str, depth: int = 0) -> set[str]:
        names = [n for n in VAR_RE.findall(value) if n != "libs_loc" and n in definitions]
        if not names or depth > 6:
            return {value}
        name = names[0]
        out = set()
        for replacement in itertools.islice(definitions[name], 8):
            out |= expand(value.replace("${" + name + "}", replacement), depth + 1)
        return out

    found = []
    for value, path in sets:
        for expanded in expand(value):
            if not expanded.startswith("${libs_loc}/"):
                continue
            rel = expanded[len("${libs_loc}/"):]
            if "${" in rel or "/include/" in f"/{rel}/" or "/objects-" in f"/{rel}":
                continue
            suffix = Path(rel).suffix.lower()
            if suffix and suffix not in STRIP_SURVIVORS:
                found.append((rel, str(path.relative_to(REPO))))
    return found


def kept(path: str, keep_whole) -> bool:
    return any(path == k or path.startswith(k + "/") for k in keep_whole)


def main() -> None:
    keep = json.loads(KEEP.read_text(encoding="utf-8"))
    keep_whole = set(keep["keep_whole"])
    headers = set(keep["headers_and_libraries"])
    all_stages = stages()
    errors = []

    for name, users in sorted(stage_consumers(all_stages).items()):
        if not kept(name, keep_whole) and name not in headers:
            errors.append(
                f"стадию {name} читают стадии {', '.join(sorted(users))}: впиши её в "
                f"{KEEP.relative_to(REPO)} — в keep_whole, если они компилируют её "
                "исходники или читают другие файлы, или в headers_and_libraries, если "
                "берут только заголовки и .lib")

    paths = cmake_library_paths()
    if paths is None:
        print("cmake/ не развёрнут: проверка путей CMake пропущена")
    else:
        for rel, where in sorted(set(paths)):
            if not kept(rel, keep_whole):
                errors.append(
                    f"{where} берёт ${{libs_loc}}/{rel}, а уборка его удалит: добавь "
                    f"каталог в keep_whole файла {KEEP.relative_to(REPO)}")

    for name in sorted(keep_whole | headers):
        stage = name.split("/")[0]
        if stage not in all_stages:
            errors.append(f"{KEEP.relative_to(REPO)}: стадии {stage} в prepare.py больше нет")

    if errors:
        raise SystemExit("libs-keep:\n- " + "\n- ".join(errors))
    print(f"libs-keep: {len(keep_whole)} целиком, {len(headers)} по заголовкам — ok")


if __name__ == "__main__":
    main()

# ---------------------------------------------------------
# Copyright (C) 2026 krvstek
#
# DO NOT REMOVE OR ALTER THIS COPYRIGHT HEADER.
# This file is part of uni-apks.
# Canonical source: https://github.com/krvstek/uni-apks
#
# Licensed under the GNU GPLv3. You may modify this file,
# but you MUST keep this original copyright notice intact
# and prominently state any changes made.
# See the AUTHORS file in the root directory for details.
# ---------------------------------------------------------

import re
import sys
from pathlib import Path

from src.core.logger import IS_GITHUB, abort


def _require_ci(script: str) -> None:
    if not IS_GITHUB:
        abort(f"'{script}' is only available in GitHub Actions")


def _parse_log_file(log: Path, green_lines: list[str], collected: list[str]) -> str:
    microg_line = ""
    lines = [
        s for ln in log.read_text(encoding="utf-8").splitlines() if (s := ln.strip())
    ]
    for i, line in enumerate(lines):
        if line.startswith("- 🟢"):
            green_lines.append(f"{line}  ")
        elif not microg_line and line.startswith("▶️") and "MicroG" in line:
            microg_line = line
        elif line.startswith("> ⚙️ » CLI:"):
            collected.append(f"{line}  ")
        elif line.startswith("> ⚙️ » Patches:"):
            next_line = lines[i + 1] if i + 1 < len(lines) else ""
            collected.append(f"{line}  \n{next_line}  ")
    return microg_line


def get_title(logs_dir: Path | str, default: str = "") -> str:
    logs = sorted(Path(logs_dir).rglob("build*.md"))
    titles: list[str] = []
    for log in logs:
        for line in log.read_text(encoding="utf-8").splitlines():
            m = re.search(
                r"-\s*🟢\s*»\s*([^(]+?)\s*\([^)]+\):\s*\[`?v?([^`\]]+)`?\]", line
            )
            if m:
                app_name = m.group(1).strip()
                version = m.group(2).strip().lstrip("v")
                t = f"{app_name} v{version}"
                if t not in titles:
                    titles.append(t)
    return ", ".join(titles) if titles else default


def get_version(logs_dir: Path | str, default: str = "") -> str:
    logs = sorted(Path(logs_dir).rglob("build*.md"))
    versions: list[str] = []
    for log in logs:
        for line in log.read_text(encoding="utf-8").splitlines():
            m = re.search(
                r"-\s*🟢\s*»\s*([^(]+?)\s*\([^)]+\):\s*\[`?v?([^`\]]+)`?\]", line
            )
            if m:
                version = m.group(2).strip().lstrip("v")
                if version not in versions:
                    versions.append(version)
    return ", ".join(versions) if versions else default


def combine_logs(logs_dir: Path | str) -> None:
    logs = sorted(Path(logs_dir).rglob("build*.md"))
    if not logs:
        return

    green_lines: list[str] = []
    collected: list[str] = []
    microg_line = ""
    for log in logs:
        m_line = _parse_log_file(log, green_lines, collected)
        if not microg_line:
            microg_line = m_line

    if green_lines:
        print("\n".join(green_lines), end="\n\n")

    if microg_line:
        print(microg_line, end="\n\n")

    if unique := list(dict.fromkeys(collected)):
        print("\n\n".join(unique))


def main() -> None:
    _require_ci("logs.py")
    match sys.argv[1:]:
        case ["get-title", *args]:
            logs_p = Path(args[0]) if args else Path("logs")
            d_val = args[1] if len(args) > 1 else ""
            print(get_title(logs_dir=logs_p, default=d_val))
        case ["get-version", *args]:
            logs_p = Path(args[0]) if args else Path("logs")
            d_val = args[1] if len(args) > 1 else ""
            print(get_version(logs_dir=logs_p, default=d_val))
        case ["combine-logs", *args]:
            combine_logs(logs_dir=Path(args[0] if args else "logs"))
        case _:
            abort("Usage: logs.py combine-logs [dir] | get-title [dir] [default] | get-version [dir] [default]")


if __name__ == "__main__":
    main()

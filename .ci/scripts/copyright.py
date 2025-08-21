#!/usr/bin/env -S uv run --script
# PEP 723 Inline Script Metadata
# /// script
# requires-python = ">=3.13"
# dependencies = [
#     "rich",
# ]#
# ///
import logging
import os
import subprocess
from functools import cache
from pathlib import Path

from rich.logging import RichHandler

__self__ = Path(__file__)

ci_scripts_dir = __self__.parent
ci_templates_dir = ci_scripts_dir.parent / "templates"
copyright_template_path = ci_templates_dir / "copyright.txt"

copyright_check_words = ["Copyright", "copyright", "License", "license"]
copyright_skip_words = ["CPY", "CPY001"]

log = logging.getLogger(__self__.stem)

skip_copyright_prefixes = [
    Path(".ci/scripts"),
]

HEAD_CHARS_LENGTH = 1000


@cache
def git_root() -> Path:
    git_toplevel = subprocess.check_output(
        "git rev-parse --show-toplevel",
        shell=True,
        text=True,
        cwd=str(__self__.parent),
    )

    return Path(git_toplevel.strip())


@cache
def get_copyright() -> str:
    text = copyright_template_path.read_text()
    lines = text.splitlines()
    for i, line in enumerate(list(lines)):
        lines[i] = f"# {line}".strip()
    text = "\n".join(lines)
    log.info(f"Copyright Header:\n{text}")
    return text


@cache
def copyright_length() -> int:
    return len(get_copyright().strip())


def main():
    git_toplevel = git_root()
    os.chdir(str(git_toplevel))

    base_dirs: list[Path] = []
    python_files: list[Path] = []

    for d in Path().glob("*"):
        if d.stem.startswith("."):
            continue
        if str(d) in ["dist"]:
            continue
        if d.is_dir():
            base_dirs.append(d)

    for base_dir in base_dirs:
        python_files.extend(list(base_dir.rglob("*.py")))

    files_to_add_copyright: list[Path] = []
    files_to_strip_copyright: list[Path] = []
    for f in python_files:
        if is_empty_file(f):
            continue
        if not f.is_absolute():
            f = f.absolute()
        file_text = f.read_text()
        search_chunk = file_text[:HEAD_CHARS_LENGTH]

        has_cw = has_copyright(f, text=search_chunk)
        needs_cw = needs_copyright(f, search_chunk=search_chunk)

        if has_cw and not needs_cw:
            files_to_strip_copyright.append(f)
            continue
        elif not needs_cw:
            continue
        elif has_cw:
            continue
        files_to_add_copyright.append(f)

    copyright_text = get_copyright()
    # No copyright found, inject copyright
    for f in files_to_add_copyright:
        insert_copyright(f, copyright_text=copyright_text)
    # Has copyright but shouldn't, strip copyright
    for f in files_to_strip_copyright:
        strip_copyright(f, text=None, copyright_text=copyright_text)


@cache
def is_empty_file(f: Path) -> bool:
    if f.is_file() and f.stat().st_size == 0:
        log.debug(f"file={f} is_empty=True")
        return True
    return False


@cache
def has_copyright(f: Path, text: str | None = None) -> bool:
    if text is None:
        text = f.read_text()
    search_chunk = text[:HEAD_CHARS_LENGTH]
    # check if the words "Copyright" or "License are in the first 50 bytes
    for cw in copyright_check_words:
        if cw in search_chunk:
            log.debug(f"file={f} has_copyright=True check_word={cw}")
            return True
    log.debug(f"file={f} has_copyright=False")
    return False


@cache
def needs_copyright(f: Path, search_chunk: str | None = None) -> bool:
    for prefix in skip_copyright_prefixes:
        try:
            if f.relative_to(git_root(), walk_up=True).is_relative_to(prefix):
                log.debug(f"file={f} needs_copyright=False relative_to={prefix}")
                return False
        except ValueError:
            log.exception(f"Failed to determine if prefix {prefix} should be ignored")
            return False
    if search_chunk is None:
        text = f.read_text()
        search_chunk = text[:HEAD_CHARS_LENGTH]
    for cw in copyright_skip_words:
        if "noqa" in search_chunk and cw in search_chunk:
            log.debug(f"file={f} needs_copyright=False check_word={cw}")
            return False
    return True


def has_shebang(f: Path, lines: list[str] | None = None, text: str | None = None) -> bool:
    """Determine if the given file has a POSIX Shebang (#!) on the first line."""
    if not text:
        text = f.read_text()
    if not lines:
        lines = text.splitlines()

    if not text and not lines:
        return False
    line1 = lines[0]
    if line1.startswith("#!"):
        return True

    return False


def remove_trailing_whitespace(lines: list[str]) -> list[str]:
    return [line.rstrip(" ") for line in lines]


def strip_coding_header(lines: list[str]) -> list[str]:
    new_lines: list[str] = []
    strip_to_content = False
    for i, line in enumerate(list(lines)):
        rstripline = line.rstrip()
        if i > 5:
            new_lines.extend(lines[i:])
            break
        if strip_to_content:
            if rstripline != "":
                strip_to_content = False
            elif rstripline == "":
                continue
        if rstripline == "# coding: utf-8":
            strip_to_content = True
            continue
        new_lines.append(line)
    return new_lines


def joinlines(lines: list[str]) -> str:
    if lines[-1] != "":
        lines.append("")
    return "\n".join(lines)


def insert_copyright(f: Path, copyright_text: str | None = None):
    if not copyright_text:
        copyright_text = get_copyright()
    text = f.read_text()
    lines: list[str] = text.splitlines()
    lines = strip_coding_header(lines)
    lines = remove_trailing_whitespace(lines)

    if has_shebang(f, lines, text):
        line1: str = lines[0]
        lines = lines[1:]

        log.debug(f"file={f} preserving_shebang")
        new_text = joinlines([line1, copyright_text, "", *lines])
    else:
        new_text = joinlines([copyright_text, "", *lines])

    log.info(f"file={f} inserted_copyright")
    f.write_text(new_text)


def strip_copyright(f: Path, text: str | None, copyright_text: str | None = None):
    if not text:
        text = f.read_text()
    if not copyright_text:
        copyright_text = get_copyright()
    new_text = text.replace(copyright_text, "")
    log.info(f"file={f} removed_copyright")
    f.write_text(new_text)


if __name__ == "__main__":
    logging.basicConfig(
        format="%(message)s",
        level=logging.DEBUG,
        handlers=[RichHandler(rich_tracebacks=True, tracebacks_show_locals=True)],
    )
    main()

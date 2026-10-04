#!/usr/bin/env python3
"""Install this skill into Claude Code's skills directory (``~/.claude/skills/ipa-analyzer``).

macOS / Linux: a symlink to this checkout (edits and ``git pull`` show up immediately).
Windows: a copy (creating symlinks needs elevated rights); re-run the script to update the copy.

    python scripts/install_skill.py                 # install; asks before replacing an existing install
    python scripts/install_skill.py --force         # replace without asking
    python scripts/install_skill.py --copy          # copy instead of linking (any OS)
    python scripts/install_skill.py --dry-run       # show what would happen
    python scripts/install_skill.py --target DIR    # use DIR instead of ~/.claude/skills
    python scripts/install_skill.py --uninstall     # remove an install made by this script

Only ``<target>/ipa-analyzer`` is ever created or removed. Standard library only (Python >= 3.9).
"""
from __future__ import annotations

import argparse
import os
import shutil
import sys
from pathlib import Path
from typing import Callable, Optional, Sequence

SKILL_NAME = "ipa-analyzer"
SKILL_ROOT = Path(__file__).resolve().parent.parent
COPY_IGNORE = shutil.ignore_patterns("__pycache__", "*.pyc", ".pytest_cache", ".git", "*.egg-info", "build", "dist",
                                     "tests", "out", ".venv", "venv", ".DS_Store")


def default_target() -> Path:
    return Path.home() / ".claude" / "skills"


def _same_location(a: Path, b: Path) -> bool:
    try:
        return a.resolve() == b.resolve()
    except OSError:
        return False


def _inside(child: Path, parent: Path) -> bool:
    try:
        child.resolve().relative_to(parent.resolve())
        return True
    except (ValueError, OSError):
        return False


def _remove(dst: Path) -> None:
    if dst.is_symlink() or dst.is_file():
        dst.unlink()
    elif dst.is_dir():
        shutil.rmtree(str(dst))


def install(source: Path, target_dir: Path, *, force: bool = False, copy: Optional[bool] = None, dry_run: bool = False,
            ask: Optional[Callable[[str], bool]] = None, out=None) -> int:
    """Returns a process exit code: 0 ok, 1 refused / nothing done, 2 failed."""
    out = out or sys.stdout
    say = lambda msg: print(msg, file=out)  # noqa: E731
    if not (source / "SKILL.md").is_file():
        say("error: %s does not contain SKILL.md (is this the skill directory?)" % source)
        return 2
    dst = target_dir / SKILL_NAME
    if copy is None:
        copy = os.name == "nt"
    if dst.is_symlink() and not copy and _same_location(dst, source):
        say("already installed: %s -> %s" % (dst, source))
        return 0
    if _same_location(dst, source) or _inside(target_dir, source) or _inside(source, dst):
        say("error: refusing to install onto itself (%s <-> %s)" % (source, dst))
        return 1
    if dst.exists() or dst.is_symlink():
        what = "a symlink to %s" % os.readlink(str(dst)) if dst.is_symlink() else "an existing directory/file"
        if not force:
            if ask is None or not ask("%s already exists (%s). Replace it? [y/N] " % (dst, what)):
                say("%s already exists (%s); nothing changed. Use --force to replace it." % (dst, what))
                return 1
        say("replacing %s" % dst)
        if not dry_run:
            _remove(dst)
    mode = "copy" if copy else "symlink"
    say("%s: %s -> %s" % (mode, source, dst))
    if dry_run:
        say("dry run: nothing was written")
        return 0
    try:
        target_dir.mkdir(parents=True, exist_ok=True)
        if not copy:
            try:
                os.symlink(str(source), str(dst), target_is_directory=True)
            except (OSError, NotImplementedError) as exc:
                say("symlink failed (%s); falling back to a copy" % exc)
                copy = True
        if copy:
            shutil.copytree(str(source), str(dst), ignore=COPY_IGNORE)
    except OSError as exc:
        say("error: could not install: %s" % exc)
        return 2
    say("installed. Check it with:  python %s doctor" % (dst / "scripts" / "ipa_analyze.py"))
    say("Restart Claude Code (or start a new session) so that it picks up the skill.")
    return 0


def uninstall(target_dir: Path, *, dry_run: bool = False, out=None) -> int:
    out = out or sys.stdout
    dst = target_dir / SKILL_NAME
    if not (dst.exists() or dst.is_symlink()):
        print("nothing to remove: %s does not exist" % dst, file=out)
        return 0
    if not dst.is_symlink() and not (dst / "SKILL.md").is_file():
        print("refusing to remove %s: it does not look like this skill (no SKILL.md)" % dst, file=out)
        return 1
    print("removing %s" % dst, file=out)
    if not dry_run:
        _remove(dst)
    return 0


def _ask_tty(prompt: str) -> bool:
    if not (sys.stdin and sys.stdin.isatty()):
        return False
    try:
        return input(prompt).strip().lower() in ("y", "yes")
    except EOFError:
        return False


def main(argv: Optional[Sequence[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Install the ipa-analyzer skill for Claude Code.")
    ap.add_argument("--target", metavar="DIR", help="skills directory (default: ~/.claude/skills)")
    ap.add_argument("--force", action="store_true", help="replace an existing install without asking")
    ap.add_argument("--copy", action="store_true", help="copy the files instead of creating a symlink")
    ap.add_argument("--dry-run", action="store_true", help="only show what would be done")
    ap.add_argument("--uninstall", action="store_true", help="remove the installed skill")
    args = ap.parse_args(argv)
    target = Path(args.target).expanduser() if args.target else default_target()
    if args.uninstall:
        return uninstall(target, dry_run=args.dry_run)
    return install(SKILL_ROOT, target, force=args.force, copy=True if args.copy else None, dry_run=args.dry_run,
                   ask=_ask_tty)


if __name__ == "__main__":
    sys.exit(main())

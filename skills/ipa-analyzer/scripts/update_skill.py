#!/usr/bin/env python3
"""Update the git checkout this skill lives in, and (optionally) do it automatically at every Claude Code start.

    python scripts/update_skill.py                  # git pull --ff-only now (+ refresh the copy on Windows)
    python scripts/update_skill.py --enable-auto    # add a SessionStart hook to ~/.claude/settings.json
    python scripts/update_skill.py --disable-auto   # remove that hook again
    python scripts/update_skill.py --dry-run        # show what would happen

macOS / Linux: ``install_skill.py`` linked ``~/.claude/skills/ipa-analyzer`` to the checkout, so a pull is the whole update.
Windows: the install is a copy, so after a successful pull the copy is refreshed with ``install_skill.py``'s logic.

The update never touches local work: it refuses on uncommitted changes, only fast-forwards, and gives every git call a
timeout, so a missing network can never hang a Claude Code session. With ``--quiet`` it prints only when something
changed or went wrong and always exits 0 (suitable for a hook). Standard library only (Python >= 3.9).
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import List, Optional, Sequence, Tuple

SKILL_NAME = "ipa-analyzer"
SKILL_ROOT = Path(__file__).resolve().parent.parent
HOOK_MARK = "update_skill.py"            # identifies the hook entry this script manages in settings.json
STAMP_NAME = "ipa-analyzer-last-update"  # stored inside the repo's git dir, so it is per checkout
GIT_TIMEOUT = 60


def default_settings() -> Path:
    return Path.home() / ".claude" / "settings.json"


def _git(root: Path, *args: str, timeout: int = GIT_TIMEOUT) -> Tuple[int, str]:
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0")          # never block on a credential prompt
    try:
        p = subprocess.run(["git", "-C", str(root)] + list(args), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           universal_newlines=True, timeout=timeout, env=env)
    except FileNotFoundError:
        return 127, "git is not installed or not on PATH"
    except subprocess.TimeoutExpired:
        return 124, "git %s timed out after %ss" % (args[0], timeout)
    return p.returncode, p.stdout.strip()


def _load_installer():
    spec = importlib.util.spec_from_file_location("install_skill", str(Path(__file__).with_name("install_skill.py")))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _throttled(stamp: Path, hours: float) -> bool:
    try:
        return hours > 0 and (time.time() - stamp.stat().st_mtime) < hours * 3600
    except OSError:
        return False


def update(source: Path = SKILL_ROOT, target_dir: Optional[Path] = None, *, dry_run: bool = False,
           throttle_hours: float = 0.0, out=None) -> int:
    """Returns 0 (up to date / updated / skipped on purpose), 1 (could not update), 2 (not a git checkout)."""
    out = out or sys.stdout
    say = lambda msg: print(msg, file=out)  # noqa: E731
    code, top = _git(source, "rev-parse", "--show-toplevel")
    if code != 0:
        say("not a git checkout (%s): nothing to update. Re-clone the repository to get a pullable copy." % source)
        return 2
    root = Path(top)
    code, gitdir = _git(root, "rev-parse", "--absolute-git-dir")
    stamp = Path(gitdir) / STAMP_NAME if code == 0 else None
    if stamp is not None and _throttled(stamp, throttle_hours):
        return 0
    code, dirty = _git(root, "status", "--porcelain", "--untracked-files=no")
    if code != 0:
        say("cannot read git status: %s" % dirty)
        return 1
    if dirty:
        say("local changes in %s; not updating (commit or stash them, then re-run)." % root)
        return 1
    code, upstream = _git(root, "rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}")
    if code != 0:
        say("the current branch of %s has no upstream; not updating (git branch --set-upstream-to=origin/main)." % root)
        return 1
    code, msg = _git(root, "fetch", "--quiet")
    if code != 0:
        say("fetch failed (offline?): %s" % msg)
        return 1
    if stamp is not None and not dry_run:
        try:
            stamp.write_text(str(int(time.time())), encoding="utf-8")
        except OSError:
            pass
    code, behind = _git(root, "rev-list", "--count", "HEAD..@{u}")
    if code != 0:
        say("cannot compare with %s: %s" % (upstream, behind))
        return 1
    if behind == "0":
        say("already up to date (%s)." % upstream)
        return 0
    if dry_run:
        say("dry run: %s commit(s) behind %s; would run git pull --ff-only" % (behind, upstream))
        return 0
    code, before = _git(root, "rev-parse", "--short", "HEAD")
    code, msg = _git(root, "merge", "--ff-only", "--quiet", "@{u}")
    if code != 0:
        say("cannot fast-forward (local commits diverge from %s): %s" % (upstream, msg))
        return 1
    _, after = _git(root, "rev-parse", "--short", "HEAD")
    say("updated %s: %s -> %s (%s commit(s))" % (SKILL_NAME, before, after, behind))
    inst = _load_installer()
    dst = (target_dir or inst.default_target()) / SKILL_NAME
    if dst.exists() and not dst.is_symlink() and (dst / "SKILL.md").is_file():      # a copy install: refresh it
        rc = inst.install(source, dst.parent, force=True, copy=True, out=out)
        return 0 if rc == 0 else 1
    return 0


def _hook_command() -> str:
    exe = sys.executable or "python3"
    return '"%s" "%s" --quiet --throttle 12' % (exe, Path(__file__).resolve())


def _read_settings(path: Path) -> dict:
    if not path.exists():
        return {}
    data = json.loads(path.read_text(encoding="utf-8") or "{}")
    if not isinstance(data, dict):
        raise ValueError("top level is not a JSON object")
    return data


def _is_ours(entry) -> bool:
    return isinstance(entry, dict) and any(isinstance(h, dict) and HOOK_MARK in str(h.get("command", ""))
                                           for h in entry.get("hooks", []) if isinstance(h, dict))


def set_auto(enable: bool, settings: Path, *, dry_run: bool = False, out=None) -> int:
    out = out or sys.stdout
    say = lambda msg: print(msg, file=out)  # noqa: E731
    try:
        data = _read_settings(settings)
    except (ValueError, OSError) as exc:
        say("error: cannot use %s (%s); fix it by hand first, nothing was changed." % (settings, exc))
        return 2
    hooks = data.get("hooks") if isinstance(data.get("hooks"), dict) else {}
    entries: List = hooks.get("SessionStart") if isinstance(hooks.get("SessionStart"), list) else []
    rest = [e for e in entries if not _is_ours(e)]
    had = len(rest) != len(entries)
    if enable:
        rest.append({"hooks": [{"type": "command", "command": _hook_command()}]})
    elif not had:
        say("auto-update is not enabled in %s." % settings)
        return 0
    if dry_run:
        say("dry run: would %s the SessionStart hook in %s" % ("write" if enable else "remove", settings))
        return 0
    if rest:
        hooks["SessionStart"] = rest
    else:
        hooks.pop("SessionStart", None)
    if hooks:
        data["hooks"] = hooks
    else:
        data.pop("hooks", None)
    try:
        settings.parent.mkdir(parents=True, exist_ok=True)
        settings.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    except OSError as exc:
        say("error: could not write %s: %s" % (settings, exc))
        return 2
    say("auto-update %s in %s (checks at most every 12 h at Claude Code start; other settings left as they were)."
        % ("enabled" if enable else "disabled", settings))
    return 0


class _Quiet:
    """Collects output; ``flush_if`` prints it only when the update did something or failed."""

    def __init__(self) -> None:
        self.lines: List[str] = []

    def write(self, s: str) -> int:
        self.lines.append(s)
        return len(s)

    def flush(self) -> None:
        pass


def main(argv: Optional[Sequence[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Update the ipa-analyzer skill (git pull), optionally at every Claude Code start.")
    ap.add_argument("--enable-auto", action="store_true", help="add a SessionStart hook that runs this script")
    ap.add_argument("--disable-auto", action="store_true", help="remove that hook")
    ap.add_argument("--settings", metavar="FILE", help="Claude Code settings file (default: ~/.claude/settings.json)")
    ap.add_argument("--target", metavar="DIR", help="skills directory of a copy install (default: ~/.claude/skills)")
    ap.add_argument("--throttle", metavar="HOURS", type=float, default=0.0,
                    help="skip when the last check was less than HOURS ago (default: always check)")
    ap.add_argument("--quiet", action="store_true", help="print only when updated or on error; always exit 0 (for hooks)")
    ap.add_argument("--dry-run", action="store_true", help="only show what would be done")
    args = ap.parse_args(argv)
    settings = Path(args.settings).expanduser() if args.settings else default_settings()
    if args.enable_auto or args.disable_auto:
        if args.enable_auto and args.disable_auto:
            ap.error("--enable-auto and --disable-auto are mutually exclusive")
        return set_auto(args.enable_auto, settings, dry_run=args.dry_run)
    target = Path(args.target).expanduser() if args.target else None
    if not args.quiet:
        return update(target_dir=target, dry_run=args.dry_run, throttle_hours=args.throttle)
    buf = _Quiet()
    try:
        rc = update(target_dir=target, dry_run=args.dry_run, throttle_hours=args.throttle, out=buf)
    except Exception as exc:  # noqa: BLE001 - a hook must never break session start
        print("ipa-analyzer update failed: %s" % exc)
        return 0
    text = "".join(buf.lines)
    if rc != 0 or text.startswith("updated"):
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())

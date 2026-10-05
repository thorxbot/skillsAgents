"""scripts/update_skill.py: every test works on throw-away git repos and a temporary settings file; ``~/.claude`` is never touched."""
from __future__ import annotations

import importlib.util
import io
import json
import os
import subprocess
from pathlib import Path

import pytest

from conftest import SKILL_ROOT

spec = importlib.util.spec_from_file_location("update_skill", str(SKILL_ROOT / "scripts" / "update_skill.py"))
upd = importlib.util.module_from_spec(spec)
spec.loader.exec_module(upd)

ENV = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@t", GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@t")


def git(cwd: Path, *args: str) -> str:
    return subprocess.run(["git"] + list(args), cwd=str(cwd), env=ENV, check=True, stdout=subprocess.PIPE,
                          universal_newlines=True).stdout.strip()


def commit(repo: Path, name: str, text: str) -> None:
    (repo / name).write_text(text, encoding="utf-8")
    git(repo, "add", name)
    git(repo, "commit", "-q", "-m", "c " + name)


@pytest.fixture()
def repos(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("USERPROFILE", str(tmp_path / "home"))
    origin = tmp_path / "origin"
    origin.mkdir()
    git(origin, "init", "-q", "-b", "main")
    commit(origin, "SKILL.md", "v1\n")
    clone = tmp_path / "clone"
    git(tmp_path, "clone", "-q", str(origin), str(clone))
    return origin, clone


def run(clone: Path, **kw):
    buf = io.StringIO()
    return upd.update(clone, target_dir=kw.pop("target_dir", clone.parent / "skills"), out=buf, **kw), buf.getvalue()


def test_up_to_date_then_fast_forward(repos):
    origin, clone = repos
    code, text = run(clone)
    assert code == 0 and "already up to date" in text
    commit(origin, "SKILL.md", "v2\n")
    code, text = run(clone)
    assert code == 0 and text.startswith("updated") and (clone / "SKILL.md").read_text(encoding="utf-8") == "v2\n"


def test_dry_run_changes_nothing(repos):
    origin, clone = repos
    commit(origin, "SKILL.md", "v2\n")
    code, text = run(clone, dry_run=True)
    assert code == 0 and "dry run" in text and (clone / "SKILL.md").read_text(encoding="utf-8") == "v1\n"


def test_refuses_with_local_changes(repos):
    origin, clone = repos
    commit(origin, "SKILL.md", "v2\n")
    (clone / "SKILL.md").write_text("mine\n", encoding="utf-8")
    code, text = run(clone)
    assert code == 1 and "local changes" in text and (clone / "SKILL.md").read_text(encoding="utf-8") == "mine\n"


def test_refuses_when_history_diverged(repos):
    origin, clone = repos
    commit(origin, "SKILL.md", "v2\n")
    commit(clone, "local.txt", "x\n")
    code, text = run(clone)
    assert code == 1 and "cannot fast-forward" in text and (clone / "local.txt").exists()


def test_not_a_git_checkout(tmp_path):
    plain = tmp_path / "plain"
    plain.mkdir()
    code, text = run(plain)
    assert code == 2 and "not a git checkout" in text


def test_throttle_skips_a_second_check(repos):
    origin, clone = repos
    assert run(clone, throttle_hours=12)[0] == 0
    commit(origin, "SKILL.md", "v2\n")
    code, text = run(clone, throttle_hours=12)                    # checked a moment ago: silent no-op
    assert code == 0 and text == "" and (clone / "SKILL.md").read_text(encoding="utf-8") == "v1\n"
    assert run(clone)[1].startswith("updated")                    # no throttle: updates


def test_copy_install_is_refreshed_after_a_pull(repos, tmp_path):
    origin, clone = repos
    target = tmp_path / "skills"
    inst = upd._load_installer()                                  # noqa: SLF001
    assert inst.install(clone, target, copy=True, out=io.StringIO()) == 0
    commit(origin, "SKILL.md", "v2\n")
    code, text = run(clone, target_dir=target)
    assert code == 0 and (target / "ipa-analyzer" / "SKILL.md").read_text(encoding="utf-8") == "v2\n"


def test_enable_and_disable_auto_keep_other_settings(tmp_path):
    settings = tmp_path / "settings.json"
    other = {"hooks": {"SessionStart": [{"hooks": [{"type": "command", "command": "echo hi"}]}]}, "model": "x"}
    settings.write_text(json.dumps(other), encoding="utf-8")
    assert upd.set_auto(True, settings, out=io.StringIO()) == 0
    assert upd.set_auto(True, settings, out=io.StringIO()) == 0           # idempotent: still one entry of ours
    data = json.loads(settings.read_text(encoding="utf-8"))
    cmds = [h["command"] for e in data["hooks"]["SessionStart"] for h in e["hooks"]]
    assert cmds[0] == "echo hi" and len(cmds) == 2 and "update_skill.py" in cmds[1] and data["model"] == "x"
    assert upd.set_auto(False, settings, out=io.StringIO()) == 0
    assert json.loads(settings.read_text(encoding="utf-8")) == other


def test_enable_auto_creates_missing_settings_and_disable_cleans_up(tmp_path):
    settings = tmp_path / ".claude" / "settings.json"
    assert upd.set_auto(True, settings, out=io.StringIO()) == 0 and settings.is_file()
    assert upd.set_auto(False, settings, out=io.StringIO()) == 0
    assert json.loads(settings.read_text(encoding="utf-8")) == {}


def test_broken_settings_are_left_alone(tmp_path):
    settings = tmp_path / "settings.json"
    settings.write_text("{not json", encoding="utf-8")
    buf = io.StringIO()
    assert upd.set_auto(True, settings, out=buf) == 2 and "nothing was changed" in buf.getvalue()
    assert settings.read_text(encoding="utf-8") == "{not json"


def test_quiet_mode_prints_only_on_change_or_error_and_exits_0(repos, monkeypatch, capsys):
    origin, clone = repos
    real = upd.update
    monkeypatch.setattr(upd, "update", lambda **kw: real(clone, **kw))
    assert upd.main(["--quiet"]) == 0 and capsys.readouterr().out == ""            # up to date: silent
    commit(origin, "SKILL.md", "v2\n")
    assert upd.main(["--quiet"]) == 0 and capsys.readouterr().out.startswith("updated")
    (clone / "SKILL.md").write_text("mine\n", encoding="utf-8")
    commit(origin, "SKILL.md", "v3\n")
    assert upd.main(["--quiet"]) == 0 and "local changes" in capsys.readouterr().out     # error: shown, still exit 0

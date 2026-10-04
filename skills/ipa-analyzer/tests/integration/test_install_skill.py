"""scripts/install_skill.py: every test installs into a temporary ``--target``; the real ``~/.claude`` is never touched."""
from __future__ import annotations

import importlib.util
import io
import os
import subprocess
import sys
from pathlib import Path

import pytest

from conftest import SKILL_ROOT

SCRIPT = SKILL_ROOT / "scripts" / "install_skill.py"
spec = importlib.util.spec_from_file_location("install_skill", str(SCRIPT))
inst = importlib.util.module_from_spec(spec)
spec.loader.exec_module(inst)

can_symlink = hasattr(os, "symlink") and os.name != "nt"


@pytest.fixture(autouse=True)
def _no_real_home(monkeypatch, tmp_path):
    """Belt and braces: even a bug that ignores ``--target`` would land in a temporary home."""
    home = tmp_path / "fake-home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))


def run(source: Path, target: Path, **kw):
    buf = io.StringIO()
    code = inst.install(source, target, out=buf, **kw)
    return code, buf.getvalue()


def make_source(tmp_path: Path) -> Path:
    src = tmp_path / "checkout"
    (src / "scripts").mkdir(parents=True)
    (src / "SKILL.md").write_text("---\nname: ipa-analyzer\n---\n", encoding="utf-8")
    (src / "scripts" / "ipa_analyze.py").write_text("print(1)\n", encoding="utf-8")
    (src / "tests").mkdir()
    (src / "tests" / "t.py").write_text("x\n", encoding="utf-8")
    (src / "__pycache__").mkdir()
    (src / "__pycache__" / "x.pyc").write_bytes(b"0")
    return src


def test_default_target_is_the_claude_skills_dir():
    assert inst.default_target() == Path.home() / ".claude" / "skills"
    assert Path.home().name == "fake-home"                     # the fixture above really redirected it


@pytest.mark.skipif(not can_symlink, reason="symlinks: macOS / Linux")
def test_symlink_install_and_idempotence(tmp_path):
    src, target = make_source(tmp_path), tmp_path / "skills"
    code, text = run(src, target)
    assert code == 0 and (target / "ipa-analyzer").is_symlink()
    assert (target / "ipa-analyzer").resolve() == src.resolve() and "symlink" in text
    code, text = run(src, target)                                # same link again: no-op
    assert code == 0 and "already installed" in text


def test_copy_install_excludes_tests_and_caches(tmp_path):
    src, target = make_source(tmp_path), tmp_path / "skills"
    code, _ = run(src, target, copy=True)
    dst = target / "ipa-analyzer"
    assert code == 0 and (dst / "SKILL.md").is_file() and (dst / "scripts" / "ipa_analyze.py").is_file()
    assert not dst.is_symlink() and not (dst / "tests").exists() and not (dst / "__pycache__").exists()


def test_existing_install_needs_force_or_confirmation(tmp_path):
    src, target = make_source(tmp_path), tmp_path / "skills"
    (target / "ipa-analyzer").mkdir(parents=True)
    (target / "ipa-analyzer" / "keep.txt").write_text("mine", encoding="utf-8")
    code, text = run(src, target, copy=True)                     # no ask callback = non-interactive
    assert code == 1 and "--force" in text and (target / "ipa-analyzer" / "keep.txt").exists()
    code, _ = run(src, target, copy=True, ask=lambda prompt: False)                    # user says no
    assert code == 1 and (target / "ipa-analyzer" / "keep.txt").exists()
    asked = []
    code, _ = run(src, target, copy=True, ask=lambda prompt: asked.append(prompt) or True)   # user says yes
    assert code == 0 and asked and "already exists" in asked[0]
    assert not (target / "ipa-analyzer" / "keep.txt").exists() and (target / "ipa-analyzer" / "SKILL.md").is_file()


def test_force_replaces_without_asking(tmp_path):
    src, target = make_source(tmp_path), tmp_path / "skills"
    (target / "ipa-analyzer").mkdir(parents=True)
    code, text = run(src, target, copy=True, force=True)
    assert code == 0 and "replacing" in text and (target / "ipa-analyzer" / "SKILL.md").is_file()


@pytest.mark.skipif(not can_symlink, reason="symlinks: macOS / Linux")
def test_force_replaces_a_foreign_symlink_without_touching_its_target(tmp_path):
    src, target = make_source(tmp_path), tmp_path / "skills"
    other = tmp_path / "other"
    other.mkdir()
    (other / "precious.txt").write_text("x", encoding="utf-8")
    target.mkdir()
    os.symlink(str(other), str(target / "ipa-analyzer"))
    assert run(src, target)[0] == 1                                          # asks first (no callback -> refuses)
    code, _ = run(src, target, force=True)
    assert code == 0 and (other / "precious.txt").exists()                   # only the link was replaced
    assert (target / "ipa-analyzer").resolve() == src.resolve()


def test_dry_run_writes_nothing(tmp_path):
    src, target = make_source(tmp_path), tmp_path / "skills"
    code, text = run(src, target, dry_run=True)
    assert code == 0 and "dry run" in text and not target.exists()
    (tmp_path / "skills" / "ipa-analyzer").mkdir(parents=True)
    code, _ = run(src, target, dry_run=True, force=True)
    assert code == 0 and (tmp_path / "skills" / "ipa-analyzer").is_dir()      # not even removed


def test_refuses_to_install_into_itself_or_without_skill_md(tmp_path):
    src = make_source(tmp_path)
    assert run(src, src)[0] == 1                                              # target = the checkout itself
    assert run(src, src / "nested")[0] == 1                                   # target inside the checkout
    empty = tmp_path / "empty"
    empty.mkdir()
    code, text = run(empty, tmp_path / "skills")
    assert code == 2 and "SKILL.md" in text


def test_uninstall_removes_only_this_skill(tmp_path):
    src, target = make_source(tmp_path), tmp_path / "skills"
    run(src, target, copy=True)
    (target / "other-skill").mkdir()
    buf = io.StringIO()
    assert inst.uninstall(target, out=buf) == 0
    assert not (target / "ipa-analyzer").exists() and (target / "other-skill").is_dir()
    assert inst.uninstall(target, out=io.StringIO()) == 0                     # nothing to remove
    (target / "ipa-analyzer").mkdir()                                         # a foreign directory without SKILL.md
    assert inst.uninstall(target, out=io.StringIO()) == 1 and (target / "ipa-analyzer").is_dir()


def test_cli_entry_point_with_target(tmp_path):
    target = tmp_path / "skills"
    env = dict(os.environ, HOME=str(tmp_path / "fake-home"), USERPROFILE=str(tmp_path / "fake-home"))
    p = subprocess.run([sys.executable, str(SCRIPT), "--target", str(target), "--copy"], capture_output=True, text=True,
                       encoding="utf-8", env=env, timeout=60)
    assert p.returncode == 0, p.stderr
    dst = target / "ipa-analyzer"
    assert (dst / "SKILL.md").is_file() and (dst / "src" / "ipa_analyzer" / "cli.py").is_file()
    assert (dst / "data").is_dir() and (dst / "schemas" / "report.schema.json").is_file() and not (dst / "tests").exists()
    # the installed copy runs without installing anything else
    v = subprocess.run([sys.executable, str(dst / "scripts" / "ipa_analyze.py"), "--version"], capture_output=True, text=True,
                       encoding="utf-8", timeout=60)
    assert v.returncode == 0 and "ipa-analyzer" in v.stdout
    again = subprocess.run([sys.executable, str(SCRIPT), "--target", str(target), "--copy"], capture_output=True, text=True,
                           encoding="utf-8", env=env, timeout=60, stdin=subprocess.DEVNULL)
    assert again.returncode == 1 and "--force" in again.stdout                   # non-interactive: refuses, does not hang
    assert not (tmp_path / "fake-home" / ".claude").exists()

"""SKILL.md / README.md / references are part of the product: they must stay short, complete and runnable."""
from __future__ import annotations

import re
import shlex
from pathlib import Path

import pytest

from conftest import SKILL_ROOT
from ipa_analyzer.cli import build_parser

SKILL = (SKILL_ROOT / "SKILL.md").read_text(encoding="utf-8")
README = (SKILL_ROOT / "README.md").read_text(encoding="utf-8")
REFS = SKILL_ROOT / "references"


def frontmatter(text: str):
    assert text.startswith("---\n")
    head, _, body = text[4:].partition("\n---\n")
    return dict(ln.split(":", 1) for ln in head.splitlines() if ":" in ln), body


def test_skill_md_is_short_with_valid_frontmatter():
    assert len(SKILL.splitlines()) <= 150
    meta, body = frontmatter(SKILL)
    assert meta["name"].strip() == "ipa-analyzer"
    desc = meta["description"]
    for word in ("ipa", "unity", "il2cpp", "assetbundle", "拆包", "逆向摸底", "引擎"):
        assert word.lower() in desc.lower(), word
    assert len(desc) < 1024


@pytest.mark.parametrize("needle", [
    "doctor", "analyze", "--offline", "== 执行摘要 ==", "report.json", "summary",                      # flow
    "FairPlay", "do not retry with `--force-dump`", "do not look for or run decryption tools",             # FairPlay rule
    "Ask first", "tools install", ".NET", "explicit \"yes\"",                                           # consent
    "libs.user.json", "summary.libs.unknown", "engines.user.d", "references/custom-engine-playbook.md",  # write-backs
    "engine.custom", "block_encrypted_suspected", "压缩 ≠ 加密", "字节码 ≠ 加密",                         # encryption reading
    "never paste", "--no-redact", "redacted",                                                          # privacy
    "E_TOOL_DOWNLOAD_FAILED", "E_DOTNET_MISSING",
])
def test_skill_md_covers_the_required_instructions(needle):
    assert needle.lower() in SKILL.lower(), needle


def test_every_referenced_file_exists_and_is_listed():
    refs = set(re.findall(r"references/([A-Za-z0-9_.-]+\.md)", SKILL + README))
    assert refs and all((REFS / r).is_file() for r in refs), sorted(r for r in refs if not (REFS / r).is_file())
    for needed in ("report-fields.md", "macho-fairplay.md", "faq.md", "custom-engine-playbook.md"):
        assert needed in refs or needed in SKILL
    listed = SKILL.split("## References", 1)[1]
    for f in sorted(p.name for p in REFS.glob("*.md")):
        assert f.replace(".md", "") in listed or f in listed, "%s not listed in SKILL.md" % f


def _flags(parser):
    out = {}
    for action in parser._actions:                       # noqa: SLF001
        for o in action.option_strings:
            out[o] = action
    return out


def test_every_cli_flag_in_the_docs_exists():
    parser = build_parser()
    sub = next(a for a in parser._actions if a.dest == "command")      # noqa: SLF001
    known = set()
    for p in [parser] + list(sub.choices.values()):
        known |= set(_flags(p))
        for a in p._actions:                                           # noqa: SLF001
            if hasattr(a, "choices") and isinstance(a.choices, dict):
                for sp in a.choices.values():
                    known |= set(_flags(sp))
    used = set(re.findall(r"(?<![\w-])(--[a-z][a-z0-9-]+)", SKILL + README))
    ignore = {"--target", "--force", "--copy", "--dry-run", "--uninstall", "--runslow",
              "--enable-auto", "--disable-auto", "--throttle", "--quiet", "--settings", "--ff-only"}      # install_skill.py / update_skill.py / git / pytest
    assert not (used - known - ignore), sorted(used - known - ignore)


def test_cheat_sheet_commands_parse():
    parser = build_parser()
    block = SKILL.split("## Command cheat sheet", 1)[1].split("```")[1]
    n = 0
    for ln in block.splitlines():
        ln = ln.split("#", 1)[0].strip()
        if not ln:
            continue
        for cmd in ln.split(" | "):
            argv = shlex.split(cmd.replace("X.ipa", "app.ipa"))
            if argv[:1] == ["IA"]:
                argv = argv[1:]
            ns = parser.parse_args(argv)
            assert ns.command in ("analyze", "tools", "doctor", "decrypt", "probe")
            n += 1
    assert n >= 7


def test_readme_is_chinese_and_has_the_required_sections():
    for head in ("## 能力矩阵", "## 安装", "## 用法", "## 环境要求", "## 常见问题", "## 合规声明", "## 局限"):
        assert head in README, head
    assert "pip install -e ." in README and "install_skill.py" in README and "scripts/ipa_analyze.py" in README
    for topic in ("FairPlay", "dotnet", "离线", "metadata 版本"):
        assert topic in README


def test_readme_example_numbers_match_the_synthetic_fixtures(runs):
    """The sample report excerpts in README come from the fixtures: keep them true."""
    enc = runs.cli("unity_il2cpp_encrypted_binary")
    assert enc.report["summary"]["fairplay"]["encrypted"] == 2 and enc.report["summary"]["dump"]["error_code"] == "E_BINARY_FAIRPLAY"
    assert enc.report["summary"]["unity"]["version"] == "2021.3.16f1"
    x = runs.cli("unity_xlua_lua53").details["unity"]["hotfix"]
    assert x["lua"]["bytecode"]["by_version"] == {"5.3": 2} and x["lua"]["runtime_versions"][0]["version"] == "5.3.6"
    assert runs.cli("custom_engine").details["detect"]["custom"]["confidence"] == pytest.approx(0.8, abs=0.005)


@pytest.mark.parametrize("f", sorted(p.name for p in REFS.glob("*.md")))
def test_reference_files_are_non_trivial_utf8(f):
    text = (REFS / f).read_text(encoding="utf-8")
    assert len(text) > 200 and "\r" not in text and "TODO" not in text

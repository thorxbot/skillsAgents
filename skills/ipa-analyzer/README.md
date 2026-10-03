# ipa-analyzer

Claude Code Skill + cross-platform Python CLI that analyzes an iOS IPA: structure, resources,
libraries, encryption / protection (FairPlay, code signing, engine resource protection) and, for
Unity games, IL2CPP / AssetBundle encryption checks with automatic Il2CppDumper runs.

Status: **WP0 skeleton**. The pipeline, contracts and CLI exist; all analysis stages are stubs that
report `skipped: not implemented`. See `../../docs/CONTRACT-FREEZE.md` for the frozen contracts.

## Quick start (no install)

```
python scripts/ipa_analyze.py --help
python scripts/ipa_analyze.py doctor
python scripts/ipa_analyze.py analyze app.ipa -o out
```

## Install

```
pip install -e .[dev]
ipa-analyze doctor
python -m pytest -q
```

Requirements: Python >= 3.9, no runtime dependencies (optional: `lief` via `.[full]`).

The full user documentation (capability matrix, FAQ, limitations) is written in WP9.

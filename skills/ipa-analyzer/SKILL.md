---
name: ipa-analyzer
description: Analyze iOS IPA files (structure, resources, libraries, encryption/protection, game engine, Unity IL2CPP dump). Placeholder until WP9 finalises this file.
---

# ipa-analyzer (placeholder)

The final instructions are written in WP9. Until then:

1. `python scripts/ipa_analyze.py doctor`
2. `python scripts/ipa_analyze.py analyze <file.ipa> -o out`
3. Read `out/<name>-<sha12>/report.json`.

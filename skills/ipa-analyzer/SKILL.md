---
name: ipa-analyzer
description: Analyze iOS IPA / .app files - 分析 ipa、ipa 结构、ipa 报告、拆包、逆向摸底. Detects the game engine (Unity IL2CPP/Mono, Cocos, Unreal, Egret, Laya, Flutter, in-house engines), Unity hot-update (HybridCLR/xLua/ToLua/puerts/Addressables), IL2CPP metadata and AssetBundle encryption, FairPlay, third-party SDKs, permissions and resource layout; runs Il2CppDumper when allowed (il2cpp dump). Use for "unity ipa", "assetbundle 加密", "il2cpp dump", "这个包用的什么引擎", "IPA 里有哪些 SDK".
---

# ipa-analyzer

Static, read-only analysis of an IPA. Output: `report.md` (Chinese by default) + `report.json` in `<out>/<name>-<sha12>/`.
It never executes anything from the IPA and never decrypts anything.

Below, `IA` means `python3 <SKILL_DIR>/scripts/ipa_analyze.py` (`<SKILL_DIR>` = the folder holding this file; Windows: `python` or `py -3`).
If `ipa-analyze` is on PATH it is the same program. Python >= 3.9, no other packages needed.

## Workflow

1. **Doctor** (once per session): `IA doctor --offline`
   Python must be OK; `dotnet` WARN is fine (only the dumper needs it). Do not install anything because of a WARN.
2. **Analyze**: `IA analyze "<file.ipa>" -o ./ipa-out --offline`
   - Always pass `--offline` on the first run: without it the tool may download Il2CppDumper on its own, which you must not do unasked (see "Ask first").
   - Input can be `.ipa`, `.zip`, an `.app` folder or an extracted folder. Add `--lang en` for an English report.
   - Exit codes: 0 ok, 1 bad arguments, 2 input unusable (report still written), 3 some stage failed (report written), 4 fatal.
3. **Read the summary, not the whole report.** The command prints `== 执行摘要 ==` (about 12 lines). For details read
   `report.json` -> `summary` (keys: `name bundle_id version category engine fairplay dump unity libs risks problem_stages`)
   and the chapters of `report.md` you need. Field meanings: `references/report-fields.md`.
4. **Tell the user**, in the user's language: what the app is, engine (+ confidence), FairPlay yes/no, Unity details if any,
   whether a dump was produced, the top risks, and every stage that was skipped or failed *with its reason*.
5. **Follow-ups** below, only when they apply.

## How to talk about results
- Finding IDs named in this file (`unity.il2cpp.dump`, `protect.fairplay`, ...) are `findings[].id` in `report.json`; their data sits in `engine_details.*`, `protection.*`, `libraries`.
- Verdicts are `yes / no / suspected / unknown / n/a`. Repeat them as is. `no` means "not found", never "proven absent". `suspected` stays `suspected`.
- Compressed is not encrypted (压缩 ≠ 加密). Compiled bytecode (Lua `.luac`, Hermes, `.jsc`) is not encrypted either (字节码 ≠ 加密). High entropy alone is not proof.
- Anti-debug / jailbreak-detection hits are "feature hits", not conclusions. Findings from a sample say how many were sampled.
- If a stage is `skipped`/`partial`/`failed`, say why (`stages[].reason`) and what would fix it. Never silently omit it.

## FairPlay (protect.fairplay = yes, or scope all / partial)
- Say plainly: the main binary is App Store (FairPlay) encrypted, so binary-based checks (ObjC classes, symbols, strings, Lua runtime version) and any il2cpp dump are limited or impossible.
- **Stop there for the dump**: do not retry with `--force-dump`, do not look for or run decryption tools, do not suggest bypasses.
  The tool does not decrypt (and this skill must not try). If the user owns the app and needs the dump, ask them to supply an IPA
  they obtained lawfully in decrypted form; then run the analysis again on that file.
- Everything that is a plain file (metadata, AssetBundles, Lua/JS/DLL files, resources, plist, SDK frameworks) is still analysed. Report those results.
- Details: `references/macho-fairplay.md`.

## Ask first (never do these without an explicit "yes" from the user)
- Downloading Il2CppDumper / Cpp2IL / any tool: `tools install ...`, or running `analyze` without `--offline`.
- Installing .NET (`tools install dotnet --yes`, `--yes` on analyze, or any package manager install).
When the report shows `unity.il2cpp.dump` failed with `E_TOOL_DOWNLOAD_FAILED` (tool missing) or `E_DOTNET_MISSING` and the pre-check is ready
(`unity.il2cpp.precheck` = yes), ask, naming what and where from: "Il2CppDumper 6.7.x from github.com (SHA256-pinned, ~0.4 MB), and a
user-level .NET 8 runtime from dot.net if you do not have one (no admin rights, installed under the tool cache). Download?"
See `tools list --offline` for versions. If yes: `IA tools install il2cppdumper` (and `IA tools install dotnet --yes` only if you asked about .NET above), then re-run step 2
(still with `--offline`; the cached tool is used). If no: leave it, report the failure with its remediation text.
Other dump errors (`E_METADATA_ENCRYPTED`, `E_METADATA_VERSION_UNSUPPORTED`, `E_REGISTRATION_NOT_FOUND`, `E_TIMEOUT`): see `references/il2cpp-troubleshooting.md`.

## Follow-ups
- **Unknown libraries** (`summary.libs.unknown` not empty): the tool never guesses their purpose. For each one, search the web (vendor docs, CocoaPods, GitHub).
  Add only what you can cite to `libs.user.json` (format: `references/libs-kb-format.md`: `id name vendor category purpose_zh purpose_en tags match sources`),
  then re-run analyze with `--libs-user <path>` (or put the file in the default folder: macOS `~/Library/Application Support/ipa-analyzer/`,
  Linux `${XDG_CONFIG_HOME:-~/.config}/ipa-analyzer/`, Windows `%APPDATA%\ipa-analyzer\`, or `$IPA_ANALYZER_HOME`). Tell the user what you added. No source -> do not add.
- **In-house engine** (`engine.custom` = yes/suspected): read `references/custom-engine-playbook.md`, follow `engine_details.detect.custom.next_steps` and the
  profile (`engine_details.fingerprint`). Do not name an engine or vendor from a guess. When the user confirms a trait, write it to
  `<user data dir>/engines.user.d/<id>.json` (format: `references/engines-detection.md`: needs `id name kind signals sources`; Mach-O symbols are written without the leading `_`), re-run with `--engines-user <dir>` if you used another folder.
- **Encrypted resources / scripts** (`unity.assetbundle.encryption`, `unity.metadata.encrypted`, `engine.*.encrypted`, `unity.hotfix.script_protection`):
  - `block_encrypted_suspected` (bundle header standard, BlocksInfo readable, first data block does not decompress; sometimes a repeated marker): block-level
    encryption is suspected. Report the evidence, state it is unconfirmed, do not claim a vendor scheme. See `references/unity-assetbundle.md`.
  - `high_entropy_unknown` / `xor_simple` / `offset_prefix`: whole-file encryption, XOR or a prefix; counts and sample paths are in the report.
  - Hot-update scripts: Lua version profile, bytecode vs plain, "mismatch" notes, `custom_lua_suspected` (see `references/unity-hotfix.md`). Bytecode is `no`, tampered/XOR/random is `suspected`.
  - The tool only reports. Never decrypt, extract keys or recover scripts.
- **Unity metadata**: `unity.metadata.encrypted` suspected/yes blocks the dump (`E_METADATA_ENCRYPTED`); see `references/unity-il2cpp-metadata.md`.

## Privacy
- Purchaser fields of `iTunesMetadata.plist` (Apple ID, name, ...) are redacted (`<redacted>`, `[REDACTED-...]`, `[user]`). Never paste or reconstruct them,
  never run with `--no-redact` unless the user asks for it explicitly, and do not copy `report.json` content around beyond what the user needs.

## Command cheat sheet
```
IA analyze X.ipa -o out --offline                  # default run (md + json)
IA analyze X.ipa -o out --offline --lang en        # English report
IA analyze X.ipa -o out --offline --stages meta,libs   # only some stages (+ dependencies)
IA analyze X.ipa -o out --offline --extract metadata,bundles   # also copy those files to out/.../split/
IA analyze X.ipa -o out --offline --il2cpp-tool /path/Il2CppDumper.dll   # use a tool you already have
IA analyze X.ipa -o out --offline --no-il2cpp      # never dump
IA tools list --offline | IA tools path il2cppdumper --offline
```
Stage names: ingest inventory macho meta engine.fingerprint engine.detect engine.other engine.unity engine.unity.hotfix libs classify protect report.

## References (read only when needed)
`references/report-fields.md` (report layout) - `macho-fairplay.md` - `faq.md` - `il2cpp-troubleshooting.md` - `unity-il2cpp-metadata.md` -
`unity-assetbundle.md` - `unity-hotfix.md` - `engines-detection.md` - `custom-engine-playbook.md` - `cocos-family.md` - `egret-laya.md` -
`engine-resource-protection.md` - `libs-kb-format.md` -
`public-crypto-schemes.md` (what a public protection scheme is, what key material it needs, how to validate; knowledge only - the tool still does not decrypt or look for keys)

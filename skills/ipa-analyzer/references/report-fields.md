# report.json / report.md field guide

Schema: `schemas/report.schema.json` (`schema_version` "1.0"). Stable apart from `generated_at` and `duration_s`.
Everything the tool concludes is a **Finding**: `{id, verdict, confidence, title, summary, params, evidence[], remediation, tags}`.

| verdict | meaning |
|---|---|
| `yes` | the property was positively established |
| `no` | looked for and not found (never "proven absent") |
| `suspected` | indicators point to it, not confirmed (the cap for container / script / resource encryption) |
| `unknown` | could not be determined (missing input, encrypted binary, stage skipped) |
| `n/a` | does not apply (for example il2cpp dump on a Mono app) |

`confidence` is 0..1 (>=0.8 high, 0.5-0.8 medium, below low). `evidence[]` items: `{kind, ref, detail}`, `ref` is an archive path or `Info.plist:Key`.

## Top level
| key | content |
|---|---|
| `input` | `path` (home folder redacted), `sha256`, `size`, `kind` (`ipa zip app_dir payload_dir dir`) |
| `app` | name candidates + `selected_name`, `bundle_id`, `version`, `build`, `min_os`, `devices`, `distribution` (`appstore adhoc enterprise development unsigned_or_repackaged unknown`), `provision`, `extensions`, `sdk` |
| `classification` | `category` (`game media lifestyle social utility finance education health_fitness shopping travel news_reading other unknown`), `subcategory`, `confidence`, `evidence` |
| `structure` | `tree`, `nested_units`, `binaries` (per Mach-O: archs, `slices[].encrypted/cryptid/cryptsize`, signing, dylibs), `languages`, `engine` |
| `resources` | `by_category`, `by_ext`, `top_files`, `archives`, `localizations`; full table in `inventory.json` |
| `libraries` | identified libs `{id name vendor category purpose_zh purpose_en tags confidence evidence}` |
| `protection` | `fairplay`, `codesign`, `hardening`, `antidebug`, `jailbreak_detect`, plus `findings[]` (all protection related Findings) |
| `engine_details` | `fingerprint` (capability profile), `detect` (primary, candidates, wrapper, `custom`), `unity` (+ `unity.hotfix`), and one key per engine checker (`cocos`, `egret`, `laya`, `unreal`, `godot`, `flutter`, ...) |
| `privacy` | `permissions` (+ sensitivity), `url_schemes`, `query_schemes`, `ats`, `trackers` |
| `stages[]` | per stage `{name, status, duration_s, reason|error, warnings, finding_ids}`; status `ok partial skipped failed` |
| `findings[]` | every Finding in execution order |
| `warnings[]` | non fatal problems, prefixed with the stage name |
| `redaction` | `{applied, fields, counts}` |
| `summary` | executive summary data (below) |
| `artifacts` | produced files relative to the output folder (`report.md`, `inventory.json`, `il2cpp/dump.cs`, ...) |

Large lists are cut in `report.json` and written to `details/*.json` with `*_total` / `*_file` fields next to them (namespaces, bundle path samples).

## `summary` (read this first)
`name bundle_id version build category{id,subcategory,confidence}` - `engine{primary,candidates,custom,wrapper_host,known}` - `languages[]` -
`fairplay{verdict,scope,encrypted,total}` - `signing{signed,signature_type,team_id,distribution}` - `unity_state` (`unity | not_unity | unknown`) and `unity{backend,version,metadata_verdict,assetbundle_verdict,hotfix_frameworks,script_protection}` -
`dump{state,error_code,ok}` (`state`: `dumped failed ready blocked disabled not_unity unknown`) - `risks[]` - `problem_stages[]` (skipped / failed stages with reason) - `libs{unknown,by_category,privacy_tags}`.

## Finding IDs by stage
`meta.*` identity, distribution, permissions, fairplay_container, signature_integrity - `macho.summary` - `engine.fingerprint`, `engine.container.unknown` -
`engine.primary|language|custom|wrapper` - `engine.pak|script|resource.encrypted`, `engine.hermes`, `engine.flutter_aot`, `engine.cocos.variant` (tag `engine:<checker>`) -
`unity.detected|version|backend|metadata.present|metadata.encrypted|binary.fairplay|il2cpp.precheck|il2cpp.dump|il2cpp.names_obfuscated|assetbundle.encryption|mono.dll_encrypted` -
`unity.hotfix.framework|lua|lua_version|csharp_dll|js|resource_update|script_protection` - `libs.summary|unknown` - `protect.fairplay|codesign|stripped|antidebug|jailbreak_detect|obfuscation|packer` - `classify.category` - `inventory.summary`.
Conventions: `unity.il2cpp.dump` = `no` means "no dump was produced" (error code in `params.error_code`); `engine.*.encrypted` = `no` always means "no encryption found"
(compressed / compiled is not encrypted); `protect.antidebug` / `jailbreak_detect` never exceed `suspected`.

## report.md chapters
1 Executive summary - 2 Basic info - 3 Project type - 4 Structure (tree, nested units, Mach-O list, languages) - 5 Resources - 6 Libraries (incl. unknown) -
7 Encryption and protection - 8 Engine details (8.1 engine and profile, 8.2 Unity incl. 8.2.1 hot update, 8.3 other engines) - 9 Privacy and permissions -
10 Appendix (10.1 stage status with skip / failure reasons, 10.2 warnings, 10.3 tool versions, 10.4 limits, 10.5 heuristics).

## Stage statuses
`ok` complete - `partial` usable result but something was missing (see `reason` / `warnings`) - `skipped` a prerequisite was not met (`reason` says which; a stage whose dependency was
skipped is skipped too) - `failed` the stage itself broke (`error`). `report` always runs. A stage failure never removes the other stages' results.

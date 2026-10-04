# Engine detection reference (engine.fingerprint / engine.detect)

Read this when a report shows an engine verdict you want to understand, extend or challenge.

## Three layers
1. **engine.fingerprint** - engine-independent capability profile: `render` (metal/gles/vulkan/angle), `shader_formats`,
   `script_vms`, `physics`, `audio`, `animation`, `network`, `asset_formats`, `containers`, `host`, `summary_text`.
   Rules: `data/fingerprint.json`.
2. **engine.detect** - known engines (`data/engines/<id>.json`, one file per engine) -> `primary` / `candidates` /
   `wrapper`, plus `languages` and the `custom` (in-house / modified engine) block.
3. **engine.other** (separate work package) - per-engine checkers for script / resource protection.

## Scoring
Each matching signal adds its `weight` once. `score = sum(weights)`; the engine is *confirmed* when a verified
`strong` signal matched or `score >= confirm_threshold`; `confidence = min(0.99, score)` (>= 0.9 for a strong hit).
Every matched signal is listed in `signals_matched` and in the evidence (`weight 0.50 ...`).
* `exclusive_with` pairs: the better supported engine stays, the other gets `extra.suppressed_by` and
  `confirmed=false` (Cocos variants exclude each other).
* `role: "family"` (`cocos_family`): used when only family-level evidence exists (e.g. CCZ textures); suppressed by any
  confirmed variant of the same family.
* `role: "fallback"` (`native_*`): never beats a real engine; may be primary when nothing else matched.
* Primary selection: kind rank (game engine / cross-platform / web hybrid, then open-source library, then native), then
  confidence, number of signals, id.
* `wrapper` = host + embedded engines (hosts: Cordova / Capacitor, Flutter, React Native; embedded: engines with
  `embeddable`, e.g. Unity).

## Signal grammar (`SignalSpec.type` -> `pattern`)
| type | pattern |
|---|---|
| `file` | case-insensitive glob on the app-relative path. No `/`: base name anywhere. With `/` (leading `/` anchors a bare name at the .app root): whole path. `*` inside a segment, `**` across segments. `magic:<id>` = inventory magic id; `head:<ASCII>` = unknown-magic file starting with that text; trailing `#<n>` = at least n files |
| `dir` | glob on directory paths (same anchoring rules) |
| `string` | literal in readable `__cstring`-type sections; `re:<regex>` for a regex |
| `symbol` | exact / `prefix*` / `*substr*`, written without the single Mach-O leading underscore (`luaL_newstate`, `_ZN7cocos2d*`); `re:` allowed |
| `objc_prefix` | class-name prefix (`__objc_classname` and `OBJC_CLASS_$_` symbols) |
| `dylib` | case-insensitive substring of a linked library's install name |
| `plist_key` | `Key` or `Key=value` in the top-level Info.plist |
| `binary_section` | `SEGMENT,section` present in a parsed Mach-O |

## Adding or overriding an engine (no code)
Drop a JSON file in `<IPA_ANALYZER_HOME>/engines.user.d/` or pass `--engines-user DIR`. A file may hold one object or a list;
the same `id` replaces a built-in definition; malformed files only produce warnings.
```json
{"id": "my_engine", "name": "My Engine", "family": "mine", "kind": "game_engine",
 "confirm_threshold": 0.7,
 "signals": [{"type": "file", "pattern": "/data/main.pkg", "weight": 0.9, "strong": true}],
 "sources": ["how you verified this"]}
```
Required: `id` (`[a-z0-9_]`), `name`, `kind` (`game_engine|cross_platform_ui|web_hybrid|native|open_source_lib`),
non-empty `signals`, non-empty `sources`. Optional: `confirm_threshold`, `exclusive_with`, `language_hints`, `notes` and the extras
`embeddable`, `wrapper_host`, `open_source_base`, `layout_expected`, `version_regex`, `role`.
**Verification policy**: a signal you could not check against a primary source must carry `"unverified": true`; the loader then
forbids `strong` and caps the weight at 0.4, so unverified knowledge can only confirm an engine through several signals.

## FairPlay-encrypted binaries
Mach-O code inside `cryptoff..cryptoff+cryptsize` is ciphertext. Strings, ObjC class names and symbol names are read with
`skip_encrypted=True`; the linked-library list, imported symbols (the symbol table lives in `__LINKEDIT`), files, directories
and `Info.plist` stay usable. Consequences visible in the output: both stages are `partial`
(`binary encrypted: binary-based detection limited`), `engine.detect.extra.visibility.limited = true`, the findings carry the
remediation "provide a decrypted IPA", and engines that only have binary signals are simply not matched (no noise).
This tool never decrypts.

## Container analysis (engines/containers.py)
Candidates: unknown magic and >= 1 MiB, or a container-like extension. Per file: offset table in the header, size field, ASCII tag,
compression streams validated by inflating (zlib checksum, gzip, LZMA-alone; zstd / LZ4 by magic), block entropy, known-plaintext XOR
probe (hypothesis only), sibling index files. Verdicts: `compressed`, `custom_format`, `encrypted_suspected`, `plain`, `unknown`;
confidence never above 0.8. **Compressed is not encrypted**: structure outranks entropy. Families of small files with a shared
4-byte header (many `.json` / `.png` files that are not JSON / PNG) are reported once as `header-cluster:<TAG>` with the
payload profile; no vendor is ever asserted from a header tag.

## Engines in the built-in library and how they were checked
See each file's `sources`. Engines whose signals could only be recalled from memory are flagged per signal (`unverified`).
Not included (no verifiable iOS-side traits): Messiah, QuickSilver, Angelica, Luminous / Fox / Anvil / Snowdrop / Frostbite,
CryEngine / O3DE, Unigine, Buildbox, GameSalad, Codea, Japanese / Korean in-house engines.

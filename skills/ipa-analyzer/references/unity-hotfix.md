# Unity hot-update analysis (stage `engine.unity.hotfix`)

Goal: which mechanism (C# DLL / Lua / JS / resources only), where the scripts live (loose files / AssetBundles /
SerializedFiles), in what format (plain / bytecode / compressed / suspected encrypted) and which Lua version.
Analysis only: nothing is executed, decrypted, repaired or extracted as a key.

## Evidence channels (cheapest first)
1. **Metadata identifier pool** (`global-metadata.dat`): NUL-separated type / namespace / method / assembly names are
   matched against `data/hotfix.json`. Needs no dumper and is not affected by FairPlay. The pool is taken from
   `engine.unity.metadata.string_region` when it looks like an identifier pool, otherwise located again from the header
   `(offset, size)` pairs (the header layout differs between metadata versions, e.g. v31 vs v39). Skipped when the
   metadata verdict is `yes` / `suspected`.
2. **il2cpp dump namespaces** (optional, `engine.unity.dump`).
3. **Native code**: Lua version strings (`Lua 5.3.6  Copyright (C) 1994-2020 Lua.org, PUC-Rio`, `LuaJIT 2.1.0-beta3`,
   `luaJIT_version_2_1_0_beta3`), Lua API symbols, framework symbols (`xlua_*`, `luaopen_xlua`, `N9hybridclr`), QuickJS /
   V8 / Node.js symbols. Only bytes **outside the FairPlay-encrypted range** are scanned; on an encrypted binary the stage
   says so (`limited_by_encryption`) and degrades to the other channels.
4. **Files and containers**: inventory candidates, a deterministic sample of bundles (`Config.unity.hotfix_scan_bundles`,
   default 100; at most `hotfix_scan_bytes_per_bundle`, default 64 MiB, decompressed per bundle) and the raw
   SerializedFiles (`resources.assets`, `sharedassets*`, `level*`, `globalgamemanagers`). The decompressed stream is
   signature-scanned; the SerializedFile is not parsed.

## Decision matrix
| Observation | Reading | Verdict wording |
|---|---|---|
| framework namespace + type + native symbol | framework present | `yes` (confidence from the weights) |
| namespace only (package compiled in) | framework present or merely linked | `yes` for strong signals, lower for unverified rules |
| identifier names such as `HotFixManager` only | custom logic, unattributed | capped at 0.45, `suspected` |
| Lua/DLL/JS files found, no known binding | mechanism known, binding unknown | `*_unattributed` framework entry |
| `1B 4C 75 61` / `1B 4C 4A` with a valid header | Lua / LuaJIT bytecode, version from the header | `bytecode` (not encrypted) |
| zlib/gzip/LZ4/... magic | compressed | `compressed` (not encrypted) |
| header valid under a 1-4 byte XOR key | obfuscated Lua / PE header | `encrypted_suspected` + key as evidence |
| high entropy, no magic / base64-looking text | possibly encrypted | `encrypted_suspected` (only a suspicion) |
| bundle not UnityFS and high entropy | file-level bundle protection | counted as `encrypted_suspected` bundle |
| UnityFS header and BlocksInfo fine, first data block fails | block-level protection (see `unity-assetbundle.md`) | counted as `block_decompress_failed` |
| nothing found but bundles unreadable / binary encrypted / metadata unreadable | cannot tell | `unknown`, never `no` |

`no` is only reported when the metadata pool was scanned, every bundle was sampled and readable, the binary is not
encrypted and no script was found; even then the summary says it is a sample-based result.

## Lua version profile
* `bytecode.by_version` counts valid headers (`5.1`..`5.5`, `luajit_2.0`, `luajit_2.1`); `invalid` counts headers with
  tamper signals (unusual sizeof, wrong `LUAC_DATA` / `LUAC_INT` / `LUAC_NUM`, unknown version byte, private LuaJIT dump
  version). `arch_bits` and `stripped_count` come from the header (32/64-bit, stripped debug info) where it carries them.
* `runtime_versions` come from native strings and symbols. `lua_newuserdatauv` / `lua_setiuservalue` imply 5.4;
  `luaJIT_setmode` / `luaopen_jit` imply LuaJIT. LuaJIT also reports `Lua 5.1` as `LUA_VERSION`.
* `consistency.ok = false` when bytecode versions disagree with each other or with the runtime (a 5.1 chunk cannot run on a
  5.3 VM, LuaJIT bytecode needs LuaJIT). Framework defaults (tolua# on iOS: LuaJIT 2.1-beta3 per its README; xLua ships
  5.3.5 by default with 5.1.5, 5.4.1 and LuaJIT 2.1.0-beta3 build trees) are only side evidence; measured data wins and a
  conflict is written out.
* `custom_lua_suspected` is raised for tampered headers and XOR-able headers. **A clean header never proves stock Lua**:
  opcode re-mapping is invisible from the header.
* Known documented variant: xLua built with `LUAC_COMPATIBLE_FORMAT` omits the `sizeof(size_t)` byte of the 5.3 header; such
  chunks are reported as 5.3 with `bytecode.variants.xlua_compat_header`, not as tampered.
* Plain sources: the minimum Lua version is inferred lexically (`goto` / `::label::` -> 5.2, `//` and bit operators -> 5.3,
  `<const>` / `<close>` -> 5.4; `setfenv`, `module(` are 5.1 style hints), with comments and strings stripped first.

## C# assemblies
`formats.pe_cli` gives assembly name, CLR version string, TypeDef count and AssemblyRef names. Name-based split:
`aot_meta` (AOT assembly names such as `mscorlib`, `System*`, `UnityEngine*`, anything in the metadata pool) vs `hot`
(Unity/BCL references under another name, or a `.dll.bytes` with Unity references when a C# hot-update runtime is present).
Compressed, XOR-able and high-entropy candidates are classified without decoding them. Being able to read a DLL does not
mean it can be run.

## Resource updates and CDN hosts
Addressables (`aa/settings.json`: version, catalog update flag; `catalog*.json|bin|hash`), YooAsset (`yoo/` folder,
`PackageManifest_*`; binary manifest magic `0x594F4F`), generic `version` / `filelist` / `*manifest*` files and Unity
BuildPipeline `.manifest` files. Hosts are collected from those files and from URL literals in the metadata file; **only
the domain** is kept (no path, port, user-info or token), at most 20, SDK / schema / licence domains filtered, and hosts that
come only from metadata literals must look like content-delivery names.

## Known limits
* Sampling: only `sampled/total` bundles are inspected. Encrypted or block-encrypted bundles cannot be inspected, so scripts
  inside them are invisible; this is reported (`scanned.unreadable_by_reason`) and turns verdicts into `unknown`.
* Plain Lua inside bundles is only counted through text hints (`local function`, `require(`) and container script paths.
* JS bytecode formats (QuickJS / V8) are not identified; non-text binaries are reported as such.
* Unverified rules in `data/hotfix.json` (flag `unverified`) are down-weighted; see the file for sources.

## Manual verification
* Lua version: take a script from the container, read bytes 0-12 (`1B 4C 75 61 5x` = PUC 5.x, `1B 4C 4A 0x` = LuaJIT) and
  compare with the runtime string reported in `lua.runtime_versions`.
* Hot DLL list: `csharp.assemblies` lists name / source / refs / kind; confirm the same names in the bundle's asset list.
* Protection: a high-entropy script with no magic is a suspicion only; compare several files and check whether the game's
  loader code (identifier hints such as `*Decrypt*`, `SignatureLoader`) exists in the metadata.

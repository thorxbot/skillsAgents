# Engine resource / script protection checkers (WP7b)

Common principles: bytecode is not encryption; compression is not encryption; high entropy alone is not proof; sampling is reported ("N of M"); detection only (no decryption, no key extraction). Thresholds and patterns: `data/engines_checks.json`. Shared helpers: `engines/formats/common.py`.

| Checker | Reads | Finding(s) | Sources / grade |
|---|---|---|---|
| `cocos` | layout, ccz headers, script heads, binary strings | `engine.cocos.variant`, `engine.script.encrypted`, `engine.resource.encrypted` | see `cocos-family.md` |
| `egret`, `laya` | markers, script / resource heads | script + resource | U (see `egret-laya.md`) |
| `unreal` | pak footer (last 320 bytes), IoStore `.utoc` header | `engine.pak.encrypted` | repak `footer.rs` / `Version::size` (pak footer, v1-v11) and retoc `FIoStoreTocHeader` / `EIoContainerFlags` (V against these open re-implementations; not against Epic's source). Only the index-encryption flag; entries inside an unencrypted index are not examined. |
| `godot` | `.pck` header and (unencrypted) directory, `.gdc` / `.gde` heads | `engine.pak.encrypted`, `engine.script.encrypted` | godot `file_access_pack.{h,cpp}` (3.5, 4.2, 4.3, master), `file_access_encrypted.h` ("GDEC"), `gdscript_tokenizer_buffer.cpp` ("GDSC"): V. iOS `.pck` placement U. |
| `flutter` | `Frameworks/Flutter.framework`, `App.framework/{App,flutter_assets,kernel_blob.bin}` | `engine.flutter_aot` | flutter/engine `FlutterDartProject.mm` (names V); AOT symbol names / Dart version strings U |
| `react_native` | `main.jsbundle` / `*.jsbundle` heads | `engine.hermes`, `engine.script.encrypted` | hermes `BytecodeFileFormat.h` (V, magic `0x1F1903C103BC1FC6`, header through `fileLength`); Metro prelude markers U |
| `lua` | `.lua` / `.luac` / Lua magic files | `engine.script.encrypted` + Lua profile | `ipa_analyzer.formats.lua_bytecode` / `lua_source` (WP3b) |
| `defold` | `game.arci` index | `engine.pak.encrypted` | defold `resource_archive.h/.cpp` (V: version 6, 16-byte big-endian entries, flag bits); bundle file names `game.projectc` / `game.dmanifest` U |
| `gamemaker` | `game.ios` / `data.win` FORM chunks | `engine.pak.encrypted` | community-documented IFF layout, U |
| `solar2d_love` | `resource.car` scan, `.love` zip flags | `engine.resource.encrypted` | `resource.car` plain-container claim is a single secondary source (U); zip flag bit 0 is APPNOTE |
| `xamarin` | `*.dll` PE + CLI | `engine.script.encrypted` | ECMA-335 via `formats.pe_cli` |
| `web_hybrid` | web root `.html/.js/.css` | `engine.script.encrypted` | informational |
| `generic_scripts` | script-like files, custom 4-byte header clusters | `engine.script.encrypted`, `engine.resource.encrypted` | heuristics; never names a vendor |

Not implemented (not verifiable here): NeoX `.npk` index structure and Supercell `.sc` headers (the only sources were secondary blog / README summaries; see `docs/03-ENGINE-RESEARCH.md`, grade C).

## Custom wrapper clusters

Files whose extension names a standard format (`.json .png .js .astc ...`) but whose inventory magic is unknown and whose first four bytes are the same printable tag are clustered (`common.find_wrapper_clusters`). Per cluster: file count, extensions, whether u32 LE at offset 4 equals the file size, constant u32 fields, payload entropy, payload probe (compression container / text at a fixed offset), and a constant-single-byte-XOR relation to the PNG signature (count only, the byte is not reported). A cluster makes the resource / script verdict `suspected` (confidence 0.7), never `yes`, and the vendor is never asserted.

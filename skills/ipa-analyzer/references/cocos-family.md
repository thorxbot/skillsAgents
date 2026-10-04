# Cocos family: variants, layouts and protection (WP7b checker `cocos`)

Grade: **V** = verified against source / a real sample in this project, **U** = UNVERIFIED (memory or single secondary source).
Detection only: the `cocos` checker never decrypts, never extracts keys. Decryption is a separate, opt-in capability —
see [Decryption and key recovery](#decryption-and-key-recovery-opt-in-cocosdecrypt-stage) — gated behind
`--cocos-decrypt` for apps you own or are authorised to assess.

## Variants and the markers used (`engines/checkers/cocos.py`, `data/engines_checks.json` section `cocos`)

| Variant id | Markers | Grade |
|---|---|---|
| `cocos_creator_3x` | `application.js`, `src/settings.json`, `src/import-map.json`, `src/system.bundle.js`, `jsb-adapter/`, `assets/<bundle>/{import,native}/`, per-bundle `index.js`, `cc.config.json` / `config.<hash>.json` | V (cocos-engine v3.8.9 sources for the asset-bundle config fields and the CCON format; layout confirmed on a real sample) |
| `cocos_creator_2x` | `src/settings.js(c)`, `src/project.js(c)`, `res/import/`, `res/raw-assets/`, `jsb-adapter/`, `main.js(c)`; 2.4+ also uses `assets/<bundle>/` | U |
| `cocos2dx_lua` | `src/main.lua(c)`, `src/config.lua(c)`, `src/app/`, `src/64bit/` (from the cocos2d-x v3 lua template), `src/cocos/init.lua`, `cocos/cocos2d/Cocos2d.lua` (framework script dir `cocos/scripting/lua-bindings/script`) | V (repo templates) |
| `cocos2dx_js` | `script/jsb_boot.js(c)` (`AppDelegate::runScript("script/jsb_boot.js")`), `main.js`, `project.json` with `jsList` / `modules` | V (repo template) |
| `cocos2d_iphone` | `Published-iOS/`, `.ccbi` ("ibcc" header, derived from `CCBReader.cpp`) | U (directory names) |
| `cocos2dx_cpp` | `.ccz` (CCZ!/CCZp), `.csb`, `.ExportJson`, `.tmx`; binary strings `cocos2d::` | V for `.ccz`, U for the rest |

A plist + png only app never triggers the checker (`quick_signals` needs `.ccz`, `.csb`, `.ExportJson`, `.ccbi` or a script layout).

## Facts (sources)

* **CCZ header** (cocos2d-x v3 `ZipUtils.h`/`ZipUtils.cpp`): `sig[4]` ("CCZ!" plain, "CCZp" encrypted), u16 BE compression type (must be 0 = zlib), u16 BE version (<= 2 plain, <= 0 encrypted), u32 BE reserved (checksum for CCZp), u32 BE uncompressed length; the encrypted form is a TEA variant keyed with `ZipUtils::setPvrEncryptionKey(4 x u32)`. V.
  A real sample used the "CCZp" signature with other header values (`comp=0 ver=1`, `comp=3 ver=0`) that stock `inflateCCZBuffer` rejects: reported as `ccz_header_deviates_from_stock` (modified format), still counted as encrypted by signature plus entropy.
* **XXTEA for Lua** (`CCLuaStack.cpp`): a chunk is decrypted when it starts with the configured sign; the lua template calls `setXXTEAKeyAndSign("2dxLua", 6, "XXTEA", 5)`, so "XXTEA" is the sign of unmodified projects. V.
* **xxtea-c** (`xxtea.c`): ciphertext length is `(ceil(len/4)+1)*4`: multiple of 4, at least 8. V for xxtea-c; cocos' bundled copy being identical is U.
* **Creator `.jsc`** (cocos-engine `ScriptEngine.cpp` comment "jsc file isn't bytecode format anymore, it's a xxtea encrypted binary format instead"; `jsb_global_init.cpp`: `xxtea_decrypt` of the whole file with `jsb_set_xxtea_key`, gunzip when `ZipUtils::isGZipBuffer`): no sign prefix, optional gzip inside. V.
* **cocos2d-x JS `.jsc`** (`ScriptingCore.cpp`): `JS_DecodeScript`, i.e. SpiderMonkey bytecode. The byte format is U, so content alone cannot tell it from ciphertext -> reported `suspected`, with the note that bytecode would not be encryption.
* **CCON** (`cocos/serialization/ccon.ts`): "CCON" magic, u32 LE version (1 or 2), u32 LE total length (must equal the file size). V. `.bin` files with it are counted in `resources.ccon`.
* **Asset bundle `config.json` fields** (`asset-manager/config.ts`): `name`, `importBase`, `nativeBase`, `deps`, `uuids`, `paths`, `scenes`, `packs`, `versions`, `redirect`, `types`, `extensionMap`. V.
* **Version hints**: `cocos2dVersion()` returns "cocos2d-x-3.17.2" (v3 branch) / "cocos2d-x-4.0" (v4 branch) -> string in the binary (V); Creator 3.x `cc.ENGINE_VERSION` (`global-exports.ts`) -> `src/settings.json` key `CocosEngine` (U key name, read only when plain text); Creator 2.x `cc.ENGINE_VERSION = engineVersion` (V in `predefine.js`; minified form U).
* Lua runtime strings: `lua.h` `LUA_RELEASE` + `LUA_COPYRIGHT` (V for 5.1.5 / 5.3.6 / 5.4.x); `LuaJIT 2.x.y` format U.

## Judgement rules

scripts: plain `.lua`/`.js` -> `no`; Lua bytecode -> `no` ("compiled", bytecode is not encryption); Creator `.jsc` -> `yes` (documented XXTEA); high entropy / custom header / Lua-after-XOR -> `suspected` (XXTEA footprint = shared sign prefix + size shape + symbols). Resources: `CCZp` -> `yes`; custom header clusters on standard extensions -> `suspected`; otherwise `no` at moderate confidence or `n/a`.

## Not reliably detectable (stated limits)

* Whether a `suspected` script is really XXTEA (vs another cipher / obfuscation) without the key.
* Creator 2.x layout details (U) and `cocos2d_iphone` names (U).
* Binary-based hints (xxtea symbols, `setXXTEAKey` strings, Lua runtime version) on FairPlay-encrypted binaries: C strings are ciphertext; only the symbol table is read, and release builds are usually stripped. The result says so (`xxtea_hint.binary.status`).

## Decryption and key recovery (opt-in, `cocos.decrypt` stage)

For apps you own or are authorised to assess. Off by default; enabled with `--cocos-decrypt`. Implemented by
`analyzers/cocos_decrypt.py` + `crypto/xxtea.py` + `crypto/cocos.py`; the detection `cocos` checker is unchanged.

Cocos ships the XXTEA key inside its own binary so it can decrypt its own scripts at run time, so "decryption" here
is key *recovery* plus the standard xxtea-c transform, not breaking cryptography:

* **Key recovery** (`crypto/cocos.recover_key`): try, in order, any `--xxtea-key` you pass, the template default
  `XXTEA`, then every printable-ASCII run (4..32 bytes) harvested from the main binary. A candidate is accepted only
  if it decrypts a sample to valid script (Lua bytecode magic `\x1bLua` / mostly-printable source for Lua; UTF-8 /
  gzip-then-UTF-8 for `.jsc`). On a FairPlay-encrypted binary the key strings are ciphertext, so recovery usually
  fails — pass `--xxtea-key` from an authorised source, or analyse a decrypted IPA.
* **Lua** (`decrypt_lua`): require the sign prefix (`--xxtea-sign`, default `XXTEA`), then `xxtea_decrypt` the rest.
* **Creator `.jsc`** (`decrypt_jsc`): `xxtea_decrypt` the whole file, then gunzip when the plaintext is gzip.
* **XXTEA format** (`crypto/xxtea.py`): xxtea-c compatible — little-endian word packing, a trailing length word,
  key zero-padded to 16 bytes, `DELTA=0x9E3779B9`, `rounds=6+52//n`. Verified byte-for-byte against the authoritative
  `xxtea` reference library (pinned vectors in `tests/unit/crypto/test_xxtea.py`).

Output: decrypted scripts under `<out>/decrypted/` (mirroring the in-app path) and `decrypted/manifest.json`
(recovered key, per-file result). Not yet covered: `CCZp` / PVR textures (`setPvrEncryptionKey`, a 4×u32 key passed
in code, not a string) and custom-wrapper resources — these still report as detection only.

Flags: `--cocos-decrypt` (enable), `--xxtea-key KEY` (repeatable; tried first), `--xxtea-sign SIGN` (default `XXTEA`,
`''` for none), `--no-xxtea-key-scan` (do not harvest candidates from the binary; use only `--xxtea-key`).

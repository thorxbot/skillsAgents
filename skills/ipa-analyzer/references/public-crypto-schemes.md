# Publicly documented engine protection schemes (catalogue)

Purpose: explain *what a finding means* (which public scheme a flag / header / extension points to, what key material
it needs, what is and is not verifiable) and give implementers ground truth to test against.
Scope and limits:
* Only schemes whose algorithm is public (open-source implementations, official documentation). No vendor-private
  formats, no keys of real applications are listed or shipped.
* The analyzer itself stays **detection only**: it does not decrypt, does not search for keys. Keys are operator
  supplied (an app you own or are authorised to assess). FairPlay / App Store DRM is out of scope and not covered here.
* Grades: **V** = reproduced in this repo by a test against third-party ground truth; **S** = read in the cited source
  code, not reproduced; **D** = official documentation only; **U** = secondary description (blog / README / search
  result), treat as a lead.

Ground truth in this repo: `tests/fixtures/public/` (README there lists sources and licenses) -
`unreal_pak/` (15 real `UnrealPak` outputs + manifest), `vectors.json` (XXTEA / AES-256 / UnityCN-signature vectors).
Tests: `tests/unit/engine_checkers/test_public_unreal_pak.py`, `tests/unit/test_public_vectors.py`.

| # | Scheme | Seen in | Algorithm | Key material | Grade |
|---|---|---|---|---|---|
| 1 | XXTEA scripts | cocos2d-x Lua (`.luac`/`.lua`), Cocos Creator `.jsc` | XXTEA, 128-bit key | string baked into the native library; optional "sign" prefix | V (algorithm), S/U (container) |
| 2 | UnityCN AssetBundle encryption | Unity China builds (`AssetBundle.SetAssetBundleDecryptKey`) | AES-ECB-derived mask + nibble substitution over LZ4 control bytes | 16-byte key | S (UnityPy), V (signature relation, synthetic key) |
| 3 | UE pak encryption | Unreal Engine 4.20+ `.pak` | AES-256-ECB over index and/or entries | 32-byte key (Crypto.json / runtime delegate) | V (15 real paks) |
| 4 | Godot PCK / script encryption | Godot 3/4 | AES-256 (key compiled into custom export templates) | 32-byte key at template build | D |
| 5 | IL2CPP metadata | Unity IL2CPP | none standard; custom / commercial obfuscators | n/a | U |

## 1. XXTEA scripts (Cocos)

**Algorithm (V).** Corrected Block TEA, 32-bit words little-endian, `DELTA = 0x9e3779b9`, rounds `6 + 52/n`, key = first 16
bytes (zero-padded when shorter, extra bytes ignored). Pinned by 9 vectors from the `xxtea-c` reference implementation
(MIT, github.com/xxtea/xxtea-c) that a second, independent implementation also reproduces (`vectors.json`).

**Two incompatible conventions exist - confirm per target.**
* `xxtea-c` style: plaintext is zero-padded to words and a **trailing length word** is appended before encrypting; on
  decrypt the length word must satisfy `len-3 <= value <= len` - a wrong key almost always fails this check, which is
  the cheapest "is this the right key" test (`test_xxtea_wrong_key_is_detectable_via_the_length_word`).
* "no padding" style: the Python `xxtea` package with `padding=False` (what the public `Mas0nShi/jsc-Decryption`
  script uses, S) has no length word; the plaintext is validated by content instead (below).
Do not assume one from the other; try both and accept only output that validates.

**Containers.**
* cocos2d-x Lua (S/U): encrypted file = optional ASCII *sign* prefix + XXTEA ciphertext. The sign is stripped before
  decrypting. Plaintext validates as Lua source or Lua bytecode (`\x1bLua` + known version byte, see `lua_bytecode`).
* Cocos Creator `.jsc` (S, jsc-Decryption): XXTEA, then **gzip** (`zlib.decompress(data, 16 + MAX_WBITS)`), result is
  UTF-8 JavaScript. Validation = gzip magic `1f 8b` after decrypt.
* Key placement (U, several public write-ups): the key and sign are ordinary string constants handed to the engine's
  `setXXTEAKey...` call at start-up, so they live in the native binary - which is why a FairPlay-encrypted main binary
  blocks the whole line of analysis (see `macho-fairplay.md`).
* Public key-recovery tooling exists (e.g. `zboralski/reverse`, static analysis of ARM64 builds). It is mentioned only
  so you can tell the user the key is *recoverable by the app owner*; this skill does not run it.

**Recognition in this tool.** `engine.script.encrypted` from the `cocos` checker (script heads without a valid
Lua/JS header, `xxtea_*` symbols) - evidence only, `suspected` at most. See `cocos-family.md`.

## 2. UnityCN AssetBundle encryption (S)

Source: UnityPy `UnityPy/helpers/ArchiveStorageManager.py` (based on PGRStudio), flags in `enums/BundleFile.py`.
* **Flag**: `UsesAssetBundleEncryption` = `0x400` (older Unity) or `0x1000` (newer) in the UnityFS header flags - this is
  what `formats.unityfs` reads (`FLAG_ENCRYPTION_OLD/NEW`). Only data blocks are encrypted; header and BlocksInfo parse
  normally, which is exactly the `block_encrypted_suspected` class in `unity-assetbundle.md`.
* **Extra header** when the flag is set: `u32` unknown, then two (data[16], key[16], 1 pad byte) vectors - the second is
  the *signature check* pair `(data_sig, key_sig)`.
* **Key check (V with a synthetic key)**: `signature = data_sig XOR AES-128-ECB(key).encrypt(key_sig)` must equal the
  ASCII string `#$unity3dchina!@`. A candidate 16-byte key is therefore verifiable in one block operation without
  touching any bundle data. UnityPy documents that candidates are typically 16-character `\w` strings found in
  `global-metadata.dat` or a memory dump. Vector: `vectors.json` -> `unitycn_signature_check`.
* **Block cipher (S)**: the same AES-ECB mask is derived for a 16-byte `data`/`key` pair, split into nibbles; the first
  16 nibbles become an index table and the rest a 4x4 substitution table. Per byte the table is indexed with a position
  counter. It is applied only to the **LZ4 control bytes** (token, literal-length extension, match offset, match-length
  extension); literal bytes are skipped. Consequence for analysis: literals stay readable in encrypted bundles, which is
  why strings may still be visible while decompression fails.
* Not covered: other vendors' private bundle encryptions (custom XOR, whole-file AES, header rewriting) - no public
  reference was verified; they remain `xor_simple` / `high_entropy_unknown` heuristics.

## 3. Unreal Engine pak (V)

Verified against 15 real `UnrealPak` outputs (repak `tests/packs`, versions 5, 7, 8b, 9, 11; 48 more variants checked
locally across compress/encrypt combinations, all footers parsed correctly).
* **Footer** (little-endian, at end of file): `[encryption GUID 16B if v>=7] [encrypted-index flag 1B if v>=4] magic
  0x5A6F12E1, version u32, index offset u64, index size u64, SHA-1 20B, [frozen flag v9] [compression names 4/5 x 32B if
  v>=8]`. `engines/formats/pak_ue.py` implements this; the tests pin version and flag for every sample.
* **Two independent switches** (`UnrealPak -encrypt`, `-encryptindex`): entry data and the index are encrypted separately.
  The footer flag describes the **index only**.
* **Cipher (V)**: AES-256-ECB, no padding (size is a multiple of 16), applied to the whole index blob. Correct key =>
  the decrypted index starts with an FString (`i32` length incl. NUL + ASCII), the mount point (e.g. `../mount/point/root/`).
  That is a one-block validity test for a candidate key (`test_public_test_key_decrypts_index_to_a_mount_point`; the key
  is repak's public *test* key, not an application key).
* **Key source (D)**: project Crypto.json (`EncryptionKey`, base64 32 bytes, `bEnablePakIndexEncryption`, ...) at packaging
  time; at runtime the game registers it (`FPakPlatformFile::RegisterEncryptionKey` / key delegate), so it is in the app.
* **Known limit, now demonstrated**: a pak packed with `-encrypt` but not `-encryptindex` has `index_encrypted = false`;
  the checker reports `no` although entry data is encrypted (`test_known_limit_entry_only_encryption_is_not_reported`).
  The per-entry flag is inside the (readable) index; parsing it requires the version-specific index layouts (v10+ uses
  path-hash / encoded entries) and is not implemented. Say so in reports instead of claiming "not encrypted".
* IoStore `.utoc` flags: unchanged (V against retoc, see `engine-resource-protection.md`).

## 4. Godot (D)

Official docs (`compiling_with_script_encryption_key`): a 256-bit AES key (`openssl rand -hex 32`) is exported as
`SCRIPT_AES256_ENCRYPTION_KEY` when **building custom export templates**; the export dialog then encrypts the PCK
(directory and/or files) and scripts with it. Stock templates cannot decrypt such packs. Consequence: an encrypted
Godot app always carries its own key in its custom engine binary. Header-level recognition (`GDPC` flags, `GDEC`,
`GDSC`) is already implemented and graded V in `engine-resource-protection.md`.

## 5. IL2CPP metadata (U)

`global-metadata.dat` has no standard encryption. The standard header magic is `AF 1B B1 FA`; its absence or a modified
header, plus a loader that decrypts at runtime, is the common public picture (secondary sources; commercial protectors
such as DexGuard/iXGuard, BitMono-style string encryption are named). Treat `unity.metadata.encrypted` as
"cannot parse", never as a scheme name. See `unity-il2cpp-metadata.md`.

## Public sample sources

Vendored (small, permissive, generated from synthetic input): repak test packs (MIT / Apache-2.0).
Candidates deliberately **not** vendored, because they are third-party game assets or real application files with
unclear redistribution rights: UnityPy `tests/samples` (game bundles), `zboralski/reverse` `samples`. Reference them by
URL in your own working notes if you need real-world checks, and keep them out of the repo.
Good sources for further *synthetic* ground truth: the generator scripts of the same projects (`repak/tests/generate.sh`
needs UnrealPak binaries; xxtea-c `example/test.c` is the vector source used here).

## Leads not verified here (do not state as fact)
Cocos CCZ/CCZp texture wrappers, cocos2d-x default sign/key values in project templates, Egret/Laya resource ciphers,
NeoX `.npk`, Supercell `.sc`. Verify against source before adding to a report; see also `custom-engine-playbook.md`.

# Unity AssetBundle protection: classes, verdict matrix, limits

Produced by the `engine.unity` stage (finding `unity.assetbundle.encryption`, data `engine.unity.bundles`).
Every conclusion is a **heuristic**: nothing is decrypted, compression is not encryption, and sampling is not a
full scan (the report always says how many bundles were deep-checked).

## Discovery
Candidates come from the inventory: files with a UnityFS/UnityWeb/UnityRaw/UnityArchive magic; files with a bundle
extension (`.bundle .ab .unity3d .assetbundle .b`) or category `assetbundle`; unknown-magic files under
`Data/Raw/` (StreamingAssets) or `aa/` (Addressables) that are not obviously text/media; `.bytes` files are
examined but never count against the verdict. `catalog*.bin|json|hash` and `aa/settings.json` are reported under
`addressables` instead (`catalog_found`, `catalogs`, `settings_found`, `aa_files`).

## Classes (`by_class`)
| class | meaning |
|---|---|
| `standard` | known signature at offset 0 (UnityFS normally; UnityWeb/Raw/Archive are classified but not deep-checkable) |
| `offset_prefix` | a signature with a plausible header inside the first 4 KiB, not at offset 0 (wrapped bundle) |
| `xor_simple` | the first bytes XOR `UnityFS\0` give a constant / 2-4 byte repeating key and the header then decodes: the key is recorded as a **hypothesis** (`xor_hypotheses`), never applied |
| `high_entropy_unknown` | no known magic, no compression container, head entropy >= 7.5 (7.0 for files < 4 KiB) |
| `block_encrypted_suspected` | standard header, BlocksInfo decodes, but the first LZ4/LZ4HC data block does not decompress (Htp-style block encryption). Optional key added to `by_class` by WP5 |
| `other` | claims to be a bundle (extension) but is a known format or a compression container |
| `unknown` | unrecognised, low entropy |

## Deep check (sampled, `Config.unity.bundle_deep_sample`, default 200)
For header-standard UnityFS bundles: header sizes, BlocksInfo (decompressed with `formats.unityfs`), then the first
and (when seeking is cheap) the last data block are decompressed with a bounded LZ4/LZMA decoder. Outcomes:
`ok`, `block_encrypted`, `fail` (with the `UnityFSError` kind), `unsupported`, `skipped` (block larger than 16 MiB).
For block-encrypted candidates the first 256 bytes of up to 8 LZ4 blocks are searched for a byte sequence (>= 6
bytes) that recurs in >= 75% of them (`block_markers`: hex, length, positions). The marker is *evidence only*; its
meaning is unknown.

## Aggregate verdict
Population = standard + offset_prefix + xor_simple + high_entropy_unknown + block_encrypted_suspected + files that
claim to be bundles by extension. Sample outcomes are extrapolated to all header-standard bundles.

| situation | verdict |
|---|---|
| no candidate files | `unknown` |
| >= 50% xor_simple / high_entropy_unknown | `yes` |
| >= 95% standard and deep-checked fine, nothing else | `no` |
| >= 50% block_encrypted_suspected / deep failures, otherwise mixed | `suspected` |
| anything else (e.g. 80% standard + 20% high entropy, offset prefixes) | `suspected` |

## Known limits
* UnityCN and other vendor variants: header-standard bundles whose BlocksInfo or data blocks fail to decode are
  reported as deep failures / `block_encrypted_suspected`; whether they are truly encrypted needs a manual check.
* Header flag bits >= 0x200 and the Unity-version cut-offs that choose their meaning come from UnityPy only
  (see `formats.unityfs`).
* Only the first 4 KiB prefix is searched for offset-prefixed signatures; prefixed bundles are not deep-checked.
* Entropy is taken from the first 16 KiB; localised encryption deeper in a file is invisible.
* Custom loaders that decrypt after reading (typical for `high_entropy_unknown`) cannot be distinguished from
  random-looking but legitimate formats (encrypted archives, custom containers).

## How to verify manually
1. `xxd -l 64 <file>`: a standard bundle starts with `UnityFS\0`, a big-endian format version (5-8) and two version strings.
2. For `high_entropy_unknown`: look for the same first 4-16 bytes across many files (a shared header/IV), check the
   size modulo 16, and compare with `catalog.bin`/manifest sizes.
3. For `block_encrypted_suspected`: parse the header and BlocksInfo with a bundle reader (they work) and try to
   decompress block 0 yourself; compare the first 256 bytes of several blocks.
4. For `xor_simple`: XOR the first bytes with the recorded key and check for `UnityFS\0`.

# Public reference fixtures

Real, third-party, openly licensed material used to check this tool against ground truth that **we did not write**.
No application binaries, no third-party game assets, no keys of real applications.

| Path | What | Source | License |
|---|---|---|---|
| `unreal_pak/*.pak` (15 files) | Unreal Engine pak v5/v7/v8b/v9/v11 written by Epic's own `UnrealPak`, plain / entry-encrypted / index-encrypted. Content is repak's synthetic `tests/pack` (a PNG, two text files, a zero file). | [trumank/repak](https://github.com/trumank/repak) `repak/tests/packs/` @ `355b5f6` (`generate.sh` documents how they were produced) | MIT or Apache-2.0 (`unreal_pak/LICENSE-*`) |
| `unreal_pak/MANIFEST.json` | Ground truth (version / index-encrypted / entries-encrypted) and the public *test* AES key | derived from the generator's file naming + repak `tests/crypto.json` | same |
| `vectors.json` | XXTEA reference vectors, AES-256 FIPS-197 vector, UnityCN signature relation (synthetic key) | [xxtea/xxtea-c](https://github.com/xxtea/xxtea-c) (MIT) output; NIST FIPS-197 App. C.3; [UnityPy](https://github.com/K0lb3/UnityPy) `ArchiveStorageManager` | see file comment |

Used by `tests/integration/test_public_unreal_pak.py` and `tests/unit/test_public_vectors.py`.

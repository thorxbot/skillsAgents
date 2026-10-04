# IL2CPP `global-metadata.dat`: layout, verdict matrix, limits

Produced by the `engine.unity` stage (findings `unity.metadata.present`, `unity.metadata.encrypted`,
`unity.il2cpp.precheck`; data `engine.unity.metadata`). Heuristic evidence only; nothing is decrypted.

## Facts used (checked 2026-10-04)
* Magic `0xFAB11BAF` (bytes `AF 1B B1 FA`), then `int32 version`.
* Versions <= 35: `(int32 offset, int32 size)` pairs in the order of Il2CppDumper's `Il2CppGlobalMetadataHeader`
  (version-conditional fields). The stored version does not identify sub-versions (24.x, 27.x), so the variant is
  chosen by comparing the computed header size with the first section offset. Real v31 sample: 31 pairs, header
  256 bytes, sections contiguous, last section ends at the end of the file.
* Versions >= 38: `(offset, size, count)` triples (Il2CppInspectorRedux `Il2CppSectionMetadata`). Real v39 sample:
  31 triples, header 380 bytes. Layouts for >= 104 come from Redux's source only (not seen in a real file).
* The third section is the identifier string table (NUL separated: `mscorlib`, `System`, `UnityEngine`,
  `Assembly-CSharp`, `<Module>`, ...).
* Accepted version range = union of `data/il2cpp_backends.json` `metadata_versions` (16-110 today). A version the
  *dumper* cannot read (Il2CppDumper stops at 31) is **not** evidence of encryption; the precheck lists which
  backends support the version so the runner can fall back (Cpp2IL needs the Unity version).

## Checks
1. magic; 2. version inside any backend range; 3. header self-consistency (sections inside the file, no overlap,
no section inside the header; soft notes: non-monotonic order, unaligned offsets, trailing gap); 4. sampled entropy
(plain files measured 4.7-5.9 bits/byte, threshold 7.5); 5. string table readable (>= 85% printable tokens and a
known marker); 6. on failure, XOR hypotheses (single-byte key for the string table; key derived from the first four
bytes for the header) - recorded, never applied to the file.

## Verdict matrix
| situation | verdict | confidence |
|---|---|---|
| magic ok, version known, header ok, strings readable, entropy < 7.5 | `no` | 0.9 (verified layout) / 0.8 / 0.65 |
| magic ok but header inconsistent / strings unreadable / entropy >= 7.5 | `suspected` | 0.6-0.9 |
| magic ok but version outside every backend range | `suspected` (`version_out_of_range`) | 0.45; precheck reports `E_METADATA_VERSION_UNSUPPORTED` |
| wrong magic, XOR of the header with a short key validates | `suspected` (`xor_header`) | 0.85 |
| wrong magic, bytes 4.. still form a valid header (`magic_modified`) or magic found at offset > 0 | `suspected` | 0.8 |
| wrong magic, high entropy | `yes` | 0.85 |
| wrong magic, low entropy, nothing else matches | `suspected` | 0.6 |
| empty / shorter than 16 bytes | `suspected` | 0.5 |

## Pre-check (`unity.il2cpp.precheck`)
Ready only when: backend is il2cpp; metadata present; the Unity binary slice is not FairPlay-encrypted
(`E_BINARY_FAIRPLAY`, never overridable); metadata verdict is `no` (otherwise `E_METADATA_ENCRYPTED`, overridable
with `--force-dump`); at least one backend supports the version (otherwise `E_METADATA_VERSION_UNSUPPORTED`,
overridable) and, if only Cpp2IL does, the Unity version is known. A binary without `il2cpp_*` strings only warns.

## Known limits
* Vendor-modified headers that keep the section table valid but change a struct layout are not detectable here.
* Metadata encrypted *and* re-written with a plausible header would pass; the string-table check catches
  string-level encryption only.
* v36/v37 and >= 111 have unknown layouts: `header_ok` is `null` and the verdict relies on the other checks.
* The obfuscation estimate from the string table (`identifier_stats`) is calibrated on two real samples only.

## How to verify manually
`xxd -l 64 global-metadata.dat` (magic and version), compare the first section offset with 8 + 8*N (or 12*N for
>= 38), `strings -n 8 global-metadata.dat | head` should show .NET names, `ent`-style entropy of the file should be
about 5-6 bits/byte.

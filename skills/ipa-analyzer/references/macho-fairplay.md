# Mach-O and FairPlay (what the tool checks, what it concludes)

## What is read
For every Mach-O in the app (main binary, frameworks, dylibs, app extensions, watch apps), each architecture slice of a universal (fat) file, in pure Python:
header (cpu, filetype), load commands, `LC_ENCRYPTION_INFO` / `LC_ENCRYPTION_INFO_64`, `LC_BUILD_VERSION` / `LC_VERSION_MIN_*` (platform, min OS, SDK), `LC_UUID`,
the dylib list (`LC_LOAD_DYLIB` and variants), rpaths, symbol table counts (stripped or not), code signature blob (`LC_CODE_SIGNATURE`: team id, entitlements keys, CodeDirectory hash type, ad-hoc or CMS).

## FairPlay rule
`slice.encrypted = (cryptid != 0 and cryptsize > 0)`. `cryptoff` / `cryptsize` is the byte range of the code that Apple encrypted for the buyer's device.
A decrypted slice usually keeps the command with `cryptid = 0`; some binaries have the command with `cryptsize = 0` (empty stubs) - these are *not* encrypted.
`protect.fairplay`: `yes` if the main binary is encrypted, `scope` = `all` (every Mach-O) / `partial` / `none` / `unknown`. `meta.fairplay_container` is a separate hint
(`SC_Info/*.sinf|*.supp` present): an App Store container, which says nothing about whether the binary was already decrypted.

## Consequences for the analysis
| depends on | when the binary is encrypted |
|---|---|
| Mach-O headers, load commands, dylib list, code signature, `cryptid` | still readable (they are outside the encrypted range) |
| ObjC class names, `__cstring` strings, symbols inside the encrypted range, Lua runtime version strings, `UNITY` version string | noise or missing: those detections are skipped (`skip_encrypted`) and the report says "binary based detection limited" |
| files in the bundle (`global-metadata.dat`, AssetBundles, Lua / JS / DLL files, plists, resources) | unaffected, fully analysed |
| il2cpp dump | impossible: blocked with `E_BINARY_FAIRPLAY` (never attempted) |

Engine and library results on an encrypted app therefore come mostly from files, directories, framework names and imported symbols; confidence is lower and the report states it.

## What the tool does not do
No decryption, no dumping from a device, no key handling, no bypass of any protection. To analyse the code of an encrypted app the user has to supply an IPA that is already
decrypted (for an app they are entitled to analyse). The tool treats it like any other IPA.

## Fat binaries and arm64
Every slice is parsed separately and reported. For il2cpp the arm64 slice is cut out in pure Python (no `lipo`). `arm64e` and `arm64_32` (Watch) are recognised.

## Other protection hints (heuristics, low confidence)
Stripped symbols, PIE, stack canary, ARC, anti-debug / jailbreak-detection strings and symbols (`ptrace`, `sysctl`, `/Applications/Cydia.app`, ...). These are *feature hits*
(`suspected` at most); they do not prove that the protection is active at runtime. Commercial packers / obfuscators are not detected yet (`protect.packer` = `n/a`).

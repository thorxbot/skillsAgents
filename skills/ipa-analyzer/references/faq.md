# FAQ

**The report says FairPlay `yes`. Can the tool still tell me the engine?** Usually yes (from files, frameworks, imported symbols), with lower confidence. Binary strings / classes /
symbols inside the encrypted range are not used. See `macho-fairplay.md`. A dump is not possible until a decrypted IPA is supplied.

**Why was the il2cpp dump not produced?** Read `unity.il2cpp.dump` (`params.error_code` + `remediation`): `E_BINARY_FAIRPLAY` encrypted binary; `E_METADATA_ENCRYPTED` metadata modified or encrypted;
`E_METADATA_VERSION_UNSUPPORTED` the tool does not read this metadata version (another backend may); `E_REGISTRATION_NOT_FOUND`; `E_DOTNET_MISSING`; `E_TOOL_DOWNLOAD_FAILED` (tool not installed / offline);
`E_TIMEOUT`; `E_UNKNOWN`. Details: `il2cpp-troubleshooting.md`.

**.NET / dotnet is missing.** Only Il2CppDumper needs it (version 6 or newer). Install a .NET runtime yourself (`brew install dotnet`, `apt install dotnet-runtime-8.0`, `winget install Microsoft.DotNet.Runtime.8`),
or let the tool install a user-level copy into its cache with `tools install dotnet --yes` (downloads from dot.net; ask before doing it). Cpp2IL does not need .NET.

**Offline.** `--offline` never touches the network. Tools must already be cached (`tools list --offline`) or given with `--il2cpp-tool`. `doctor --offline` skips the network probe.
An offline run is complete apart from the dump; the dump failure carries the instruction for what to prepare.

**"metadata version not supported".** New Unity versions (2022.3+ / Unity 6) use newer `global-metadata.dat` versions (for example 31, 39). Il2CppDumper reads versions 16-31 only; the
tool then tries Cpp2IL / Il2CppInspectorRedux (they are experimental and are downloaded only after consent). The compatibility table is `data/il2cpp_backends.json`.

**"Compressed is not encrypted" - what does `no` mean for `engine.script.encrypted`?** No encryption was found: files are plain or compiled bytecode or ordinarily compressed. High entropy, a custom header on every
file, or an `xxtea`-style sign + length pattern make it `suspected`. The tool never says `yes` for scripts / containers without a decryptable proof, and never decrypts.

**`block_encrypted_suspected` on AssetBundles.** The bundle header and BlocksInfo are standard, but the first LZ4 data block does not decompress; often a repeated 8-byte marker sits near the start of the blocks.
This matches a block-level encryption scheme; it is *not confirmed* until the decryption routine of that game is known.

**Are real names in `iTunesMetadata.plist` shown?** No. Purchaser fields are redacted by default; `--no-redact` is an explicit opt-out.

**Which platforms?** macOS, Linux, Windows 10+, Python >= 3.9, standard library only. The tool never needs `otool`, `lipo`, `codesign`, `unzip`. It never executes anything from the IPA.

**How do I add a library or an engine?** Unknown libraries: `libs.user.json` (`libs-kb-format.md`). Engines: `engines.user.d/<id>.json` (`engines-detection.md`). No code change needed.

**Where is the output?** `<out>/<name>-<sha12>/report.md`, `report.json`, `inventory.json`, `il2cpp/` (dump files), `split/` (with `--extract`). The scratch folder `work/` is removed after the run (`--keep-workdir` keeps it).

**Large IPAs.** The archive is read through its central directory; nothing is unpacked unless `--extract` is given (limit `--max-extract-size`, default 8G). Entropy and magic checks sample files.

**Legal / scope.** For your own apps, authorised security research, compliance audits and learning. The tool detects and reports; it does not break protections.

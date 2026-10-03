# IL2CPP dump troubleshooting

Facts below were checked on 2026-10-03 against the upstream sources named in `data/il2cpp_backends.json`
(`sources` per backend). Items marked **UNVERIFIED** could not be exercised (no successful real dump was run
on a decrypted sample; Windows/Linux were not tried).

## Quick map: error code -> what to do

| Code | Meaning | Action |
|---|---|---|
| `E_BINARY_FAIRPLAY` | The il2cpp Mach-O slice has `LC_ENCRYPTION_INFO(_64)` with `cryptid != 0`. | Nothing can read its code. This tool never decrypts. Ask for an IPA already decrypted by its owner. The runner refuses before starting any tool (checked on two real App Store samples: both gave this code in 0 s). |
| `E_METADATA_ENCRYPTED` | `global-metadata.dat` does not start with `AF 1B B1 FA` (0xFAB11BAF), or Il2CppDumper printed `Metadata file supplied is not valid metadata file` / `Metadata file not found or encrypted`. | Game-specific encryption or obfuscation. Out of scope. Supply a plain file if you are authorised to obtain one. |
| `E_METADATA_VERSION_UNSUPPORTED` | Metadata version outside the backend range (Il2CppDumper 6.7.46: 16..31). | Let the chain fall back: Cpp2IL (23..108, needs the Unity version) or Il2CppInspectorRedux (16..110, needs .NET 10). Real samples seen: v31 (fine for Il2CppDumper), v39 (Unity 6000.3+, Il2CppDumper cannot read it). |
| `E_REGISTRATION_NOT_FOUND` | Il2CppDumper's auto search failed (`Can't use auto mode to process file`, `Input CodeRegistration:` prompt, `An error occurred while processing`). | Check that the binary is the il2cpp one (UnityFramework on Unity 2019.3+, else the main executable) and matches the metadata. Packed/stripped/modified il2cpp needs a manual address pair, which non-interactive mode cannot give. Try another backend. |
| `E_DOTNET_MISSING` | No `Microsoft.NETCore.App` at the required major (or the host printed `You must install or update .NET`, exit code 150). | Install .NET, or re-run with `--yes` to allow a user-level install into the cache (no admin rights), or `--dotnet PATH`. `ipa-analyze tools install dotnet` does the same explicitly. |
| `E_TOOL_DOWNLOAD_FAILED` | Offline, blocked by proxy, SHA256 mismatch (file discarded), no pinned hash, or unusable `--il2cpp-tool`. | Check `HTTPS_PROXY`; or download the release yourself, verify its SHA256 against `data/il2cpp_backends.json` and pass `--il2cpp-tool PATH` (or `IL2CPPDUMPER_PATH`). |
| `E_TIMEOUT` | Global timeout (`--il2cpp-timeout`, default 900 s) or no output for 300 s (`req.extra['idle_timeout_s']`). | Raise the timeout; large games need several GB RAM; check `il2cpp-run.log` in the output folder. |
| `E_UNKNOWN` | Anything else (non-zero exit, truncated dump, unexpected prompt). | Read `stdout_tail` / `il2cpp-run.log`. |

## Il2CppDumper v6.7.46 facts that shape the runner

* Command line: `Il2CppDumper <executable-file> <global-metadata> <output-directory>`; arguments are classified by
  content (a file starting with 0xFAB11BAF is the metadata). The output directory must already exist, otherwise
  files are written into the tool directory.
* `config.json` is read from the **tool directory** (`AppDomain.BaseDirectory`), not the cwd. The runner therefore
  copies the tool directory per run and rewrites `config.json` (`RequireAnyKey=false`, `DumpAttribute=false`,
  other fields as shipped). Your cached tool is never modified.
* The process exit code is **0 even when the dump failed**. Success = `dump.cs` exists, is non-empty and the
  console printed `Done!`; failures are classified from the console text.
* With `RequireAnyKey=true` and redirected stdin the tool dies in `Console.ReadKey` (exit 134). Fat Mach-O input
  triggers `Select Platform:` + `ReadKey` (also impossible to answer through a pipe), so the runner always passes a
  thin arm64 slice (cut out in pure Python).
* Prompts that exist: `Press any key to exit...`, `Select Platform:`, `Input CodeRegistration:` /
  `Input MetadataRegistration:` (after `Can't use auto mode...`), `Input il2cpp dump address` (ELF only). None can
  usefully be answered, so the supervisor stops the process tree when it sees one (also without trailing newline).
* Outputs: `dump.cs`, `script.json`, `il2cpp.h`, `stringliteral.json`, `DummyDll/`. The `ida.py`/`ghidra.py` helper
  scripts stay in the tool directory.
* .NET: the release zips `net6` and `net7` are framework-dependent. With `DOTNET_ROLL_FORWARD=Major` the net6
  build runs on .NET 8 (VERIFIED on 8.0.25; without it: exit 150). Windows also has a self-contained
  `Il2CppDumper-win-*.zip` that needs no runtime (**UNVERIFIED** on a real Windows machine); it is preferred on
  Windows when no .NET is installed.

## Fallback backends (experimental)

* **Cpp2IL** `2022.1.0-pre-release.21`: single-file native binaries (no .NET). Needs all of `--force-binary-path`,
  `--force-metadata-path`, `--force-unity-version`. Emits a C# tree (`diffable-cs`, `dummydll`), not `dump.cs`;
  `summarize_dump` falls back to a coarser scan of that tree. On Apple Silicon the unsigned download is killed
  (exit 137) until `codesign -s - --force` is run; `tools install` does that automatically.
* **Il2CppInspectorRedux** `2026.2`: framework-dependent, **needs the .NET 10 runtime** (checked: refuses to start
  on 8.0.25). Same macOS signing caveat. Output file names under `cs/` and `dll/` are **UNVERIFIED**. AGPL-3.0:
  only downloaded and run as an external process.

## Manual checks

```
ipa-analyze tools list                 # what is cached, .NET runtimes
ipa-analyze tools install il2cppdumper # download + SHA256 verification
ipa-analyze tools path il2cppdumper
ipa-analyze doctor
```

Environment: `IPA_ANALYZER_HOME` (cache root), `IL2CPPDUMPER_PATH`, `CPP2IL_PATH`, `IL2CPPINSPECTOR_PATH`,
`DOTNET_ROOT`. Re-running with identical inputs reuses the previous result (`.il2cpp-cache.json` in the output
folder, keyed by SHA256 of binary and metadata plus backend and version).

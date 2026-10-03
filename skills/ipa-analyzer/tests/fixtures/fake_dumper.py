"""Fake Il2CppDumper for tests: ``python fake_dumper.py <binary> <metadata> <outdir>``.

Behaviour is selected with ``FAKE_DUMPER_MODE`` (passed through ``Il2CppRunRequest.extra['env']``):

success            write a small valid dump (dump.cs, script.json, il2cpp.h, stringliteral.json, DummyDll/), exit 0
fail_nonzero       print an unrecognised error, exit 3
metadata_encrypted print Il2CppDumper's "Metadata file not found or encrypted." and exit 0 (like the real tool)
unsupported_version print the NotSupportedException line for metadata v35, exit 0
registration       "Can't use auto mode..." then the "Input CodeRegistration: " prompt (no newline), wait on stdin
prompt             "Press any key to exit..." and wait on stdin
fat_prompt         "Select Platform: 1.64bit " (no newline) and wait on stdin
hang               print once, spawn a long-lived child (pid file ``FAKE_DUMPER_PIDFILE``), then sleep forever
silent             print nothing and sleep forever
truncated          write dump.cs but never print "Done!"
dotnet_missing     print the .NET host's "You must install or update .NET" message, exit 150

``FAKE_DUMPER_CONFIG_AWARE=1``: like the real tool, read ``config.json`` next to this script and, when
``RequireAnyKey`` is true, finish with "Press any key to exit..." and wait for stdin.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

DUMP_CS = """// Image 0: Assembly-CSharp.dll - 0
// Image 1: UnityEngine.CoreModule.dll - 3

// Namespace: Game.Core
public class PlayerController : MonoBehaviour // TypeDefIndex: 0
{
\t// Fields
\tprivate int health; // 0x18
\tpublic float speed; // 0x1C

\t// Methods

\t// RVA: 0x1000 Offset: 0x1000 VA: 0x1000
\tpublic void Update() { }
\t// RVA: 0x1100 Offset: 0x1100 VA: 0x1100
\tpublic int GetHealth() { }
}

// Namespace: HybridCLR
public static class RuntimeApi // TypeDefIndex: 1
{
\t// Methods

\t// RVA: 0x2000 Offset: 0x2000 VA: 0x2000
\tpublic static void LoadMetadataForAOTAssembly() { }
}

// Namespace: Game.Core
public enum State // TypeDefIndex: 2
{
\t// Fields
\tpublic const State Idle = 0;
\tpublic const State Run = 1;
}
"""


def _write_outputs(out: Path, *, with_dump: bool = True) -> None:
    out.mkdir(parents=True, exist_ok=True)
    if with_dump:
        (out / "dump.cs").write_text(DUMP_CS, encoding="utf-8")
    (out / "script.json").write_text(json.dumps({"ScriptMethod": []}), encoding="utf-8")
    (out / "il2cpp.h").write_text("typedef struct Il2CppObject {} Il2CppObject;\n", encoding="utf-8")
    (out / "stringliteral.json").write_text(
        '[\n  {\n    "value": "hello",\n    "address": "0x1"\n  },\n  {\n    "value": "world",\n    "address": "0x2"\n  }\n]',
        encoding="utf-8")
    (out / "DummyDll").mkdir(exist_ok=True)
    (out / "DummyDll" / "Assembly-CSharp.dll").write_bytes(b"MZ" + b"\0" * 64)


def _wait_stdin() -> None:
    try:
        sys.stdin.readline()
    except (OSError, ValueError):
        pass


def main(argv) -> int:
    mode = os.environ.get("FAKE_DUMPER_MODE", "success")
    if argv[:1] in (["--help"], ["-h"]) or len(argv) < 3:
        print("usage: fake_dumper <executable-file> <global-metadata> <output-directory>")
        return 0
    binary, metadata, outdir = argv[0], argv[1], Path(argv[2])
    if not Path(binary).is_file() or not Path(metadata).is_file():
        print("ERROR: input file missing")
        return 2
    sys.stdout.reconfigure(line_buffering=True)  # type: ignore[attr-defined]
    require_any_key = False
    if os.environ.get("FAKE_DUMPER_CONFIG_AWARE") == "1":
        try:
            cfg = json.loads((Path(__file__).resolve().parent / "config.json").read_text(encoding="utf-8"))
            require_any_key = bool(cfg.get("RequireAnyKey", True))
        except (OSError, ValueError):
            require_any_key = True
    if mode == "dotnet_missing":
        print("You must install or update .NET to run this application.")
        return 150
    if mode == "silent":
        time.sleep(600)
        return 0
    print("Initializing metadata...")
    print("Metadata Version: 24")
    if mode == "hang":
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(600)"])
        pidfile = os.environ.get("FAKE_DUMPER_PIDFILE")
        if pidfile:
            Path(pidfile).write_text("%d %d" % (os.getpid(), child.pid), encoding="utf-8")
        time.sleep(600)
        return 0
    if mode == "metadata_encrypted":
        print("ERROR: Metadata file not found or encrypted.")
        return 0
    if mode == "unsupported_version":
        print("System.NotSupportedException: ERROR: Metadata file supplied is not a supported version[35].")
        return 0
    if mode == "fail_nonzero":
        print("something exploded in an unknown way")
        return 3
    if mode == "fat_prompt":
        sys.stdout.write("Select Platform: 1.64bit ")
        sys.stdout.flush()
        _wait_stdin()
        return 0
    print("Initializing il2cpp file...")
    print("Searching...")
    if mode == "registration":
        print("ERROR: Can't use auto mode to process file, try manual mode.")
        sys.stdout.write("Input CodeRegistration: ")
        sys.stdout.flush()
        _wait_stdin()
        return 0
    print("Dumping...")
    if mode == "truncated":
        _write_outputs(outdir, with_dump=True)
        return 0
    if mode == "prompt":
        sys.stdout.write("Press any key to exit...")
        sys.stdout.flush()
        _wait_stdin()
        return 0
    _write_outputs(outdir)
    print("Done!")
    print("Generate struct...")
    print("Done!")
    print("Generate dummy dll...")
    print("Done!")
    if require_any_key:
        print("Press any key to exit...")
        _wait_stdin()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

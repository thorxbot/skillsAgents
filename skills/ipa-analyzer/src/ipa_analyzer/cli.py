"""Command line interface: ``analyze``, ``doctor``, ``tools``.

Exit codes: 0 success (no failed stage); 1 usage error; 2 invalid input; 3 some stage failed (a
report was still written); 4 fatal error.
"""
from __future__ import annotations

import argparse
import importlib
import json
import logging
import platform
import shutil
import socket
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from . import TOOL_NAME, __version__
from .config import EXTRACT_CATEGORIES, FORMATS, Config, parse_size
from .errors import CycleError, InvalidInput, RegistryError, UsageError
from .models import Status

EXIT_OK, EXIT_USAGE, EXIT_INVALID_INPUT, EXIT_PARTIAL, EXIT_FATAL = 0, 1, 2, 3, 4

log = logging.getLogger("ipa_analyzer")


class _Parser(argparse.ArgumentParser):
    """argparse variant that exits with code 1 (not 2) on usage errors."""

    def error(self, message: str):  # type: ignore[override]
        self.print_usage(sys.stderr)
        self.exit(EXIT_USAGE, "%s: error: %s\n" % (self.prog, message))


def _csv(value: str) -> List[str]:
    return [p.strip() for p in value.split(",") if p.strip()]


def build_parser() -> argparse.ArgumentParser:
    p = _Parser(prog="ipa-analyze", description="Analyze an iOS IPA / .app: structure, resources, libs, "
                "protection, engine (Unity IL2CPP dump). Analysis only; never executes app code.")
    p.add_argument("--version", action="version", version="%s %s" % (TOOL_NAME, __version__))
    sub = p.add_subparsers(dest="command", metavar="{analyze,doctor,tools}", parser_class=_Parser)

    a = sub.add_parser("analyze", help="analyze an .ipa / .zip / .app directory")
    a.add_argument("input", help="path to .ipa, .zip, .app directory, Payload/ or extracted directory")
    a.add_argument("-o", "--output", default="out", metavar="DIR",
                   help="base output directory (default: ./out); results go to DIR/<name>-<sha12>/")
    a.add_argument("--lang", choices=["zh", "en"], default="zh", help="report language (default: zh)")
    a.add_argument("--format", default="md,json", metavar="LIST",
                   help="comma list of md,json,html (default: md,json); report.json is always written")
    a.add_argument("--stages", metavar="LIST", help="run only these stages (+ their hard dependencies)")
    a.add_argument("--skip", metavar="LIST", help="skip these stages")
    a.add_argument("--no-il2cpp", action="store_true", help="never run the IL2CPP dumper")
    a.add_argument("--force-dump", action="store_true", help="try the dump even if pre-checks suspect encryption")
    a.add_argument("--il2cpp-tool", metavar="PATH", help="path to an Il2CppDumper executable / dll")
    a.add_argument("--dotnet", metavar="PATH", help="path to the dotnet executable")
    a.add_argument("--il2cpp-timeout", type=int, default=900, metavar="SEC", help="dumper timeout (default 900)")
    a.add_argument("--offline", action="store_true", help="never use the network")
    a.add_argument("--yes", action="store_true", help="assume yes for tool/.NET download prompts")
    a.add_argument("--no-redact", action="store_true", help="do not redact purchaser info in the report")
    a.add_argument("--extract", metavar="LIST",
                   help="physically extract categories to <out>/split/: %s" % ",".join(EXTRACT_CATEGORIES))
    a.add_argument("--max-extract-size", metavar="SIZE", help="total extraction limit, e.g. 4G (default 8G)")
    a.add_argument("--libs-user", metavar="PATH", help="user library knowledge base (libs.user.json)")
    a.add_argument("--engines-user", metavar="DIR", help="directory with extra engine signature *.json files")
    a.add_argument("--no-signature-integrity", action="store_true", help="skip CodeResources hash verification")
    a.add_argument("--cocos-decrypt", action="store_true",
                   help="decrypt Cocos XXTEA Lua/.jsc scripts to <out>/decrypted/ (apps you own or are authorised "
                        "to assess); recovers the key from the app binary unless --no-xxtea-key-scan")
    a.add_argument("--xxtea-key", metavar="KEY", action="append", dest="xxtea_key",
                   help="candidate XXTEA key for --cocos-decrypt (repeatable); tried before binary strings")
    a.add_argument("--xxtea-sign", metavar="SIGN", default="XXTEA",
                   help="Cocos Lua chunk sign prefix (default: XXTEA); use '' for none")
    a.add_argument("--no-xxtea-key-scan", action="store_true",
                   help="with --cocos-decrypt, do not harvest key candidates from the app binary")
    a.add_argument("--keep-workdir", action="store_true", help="keep the scratch directory after the run")
    a.add_argument("-v", "--verbose", action="count", default=0, help="-v info, -vv debug logging")
    a.set_defaults(func=cmd_analyze)

    d = sub.add_parser("doctor", help="check the environment (Python, dotnet, cache dir, network, tools)")
    d.add_argument("--offline", action="store_true", help="skip the network probe")
    d.add_argument("--dotnet", metavar="PATH", help="path to the dotnet executable")
    d.add_argument("--json", action="store_true", help="machine-readable output")
    d.add_argument("-v", "--verbose", action="count", default=0)
    d.set_defaults(func=cmd_doctor)

    t = sub.add_parser("tools", help="manage external tools (Il2CppDumper, ...)")
    tsub = t.add_subparsers(dest="tools_command", metavar="{list,install,path}", parser_class=_Parser)
    tl = tsub.add_parser("list", help="list known/cached tools")
    tl.add_argument("--offline", action="store_true")
    tl.add_argument("-v", "--verbose", action="count", default=0)
    tl.set_defaults(func=cmd_tools_list_dispatch)
    ti = tsub.add_parser("install", help="download and cache a tool")
    ti.add_argument("name")
    ti.add_argument("--offline", action="store_true")
    ti.add_argument("--yes", action="store_true")
    ti.add_argument("--dotnet", metavar="PATH")
    ti.add_argument("-v", "--verbose", action="count", default=0)
    ti.set_defaults(func=cmd_tools_install_dispatch)
    tp = tsub.add_parser("path", help="print the resolved path of a tool")
    tp.add_argument("name")
    tp.add_argument("--offline", action="store_true")
    tp.add_argument("-v", "--verbose", action="count", default=0)
    tp.set_defaults(func=cmd_tools_path_dispatch)
    t.set_defaults(func=lambda args: (t.print_help(sys.stderr), EXIT_USAGE)[1])
    return p


def config_from_args(args: argparse.Namespace) -> Config:
    cfg = Config()
    cfg.output_dir = Path(args.output)
    cfg.lang = args.lang
    cfg.formats = tuple(_csv(args.format))
    cfg.stages = tuple(_csv(args.stages)) if args.stages else None
    cfg.skip = tuple(_csv(args.skip)) if args.skip else ()
    cfg.il2cpp.enabled = not args.no_il2cpp
    cfg.il2cpp.force_dump = args.force_dump
    cfg.il2cpp.tool_path = args.il2cpp_tool
    cfg.il2cpp.dotnet_path = args.dotnet
    cfg.il2cpp.timeout_s = args.il2cpp_timeout
    cfg.offline = args.offline
    cfg.assume_yes = args.yes
    cfg.redact = not args.no_redact
    cfg.extract = tuple(_csv(args.extract)) if args.extract else ()
    if args.max_extract_size:
        cfg.limits.max_total_extract = parse_size(args.max_extract_size)
    cfg.libs_user_path = Path(args.libs_user) if args.libs_user else None
    cfg.engines_user_dir = Path(args.engines_user) if args.engines_user else None
    cfg.signature_integrity = not args.no_signature_integrity
    cfg.cocos.enabled = args.cocos_decrypt
    cfg.cocos.keys = tuple(args.xxtea_key) if args.xxtea_key else ()
    cfg.cocos.sign = args.xxtea_sign
    cfg.cocos.scan_binary_for_key = not args.no_xxtea_key_scan
    cfg.keep_workdir = args.keep_workdir
    cfg.verbose = args.verbose
    return cfg.validate()


def _setup_logging(verbose: int) -> None:
    level = logging.WARNING if verbose <= 0 else (logging.INFO if verbose == 1 else logging.DEBUG)
    logging.basicConfig(level=level, format="%(levelname)s %(name)s: %(message)s", stream=sys.stderr, force=True)


def _reconfigure_streams() -> None:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
        except (AttributeError, ValueError, OSError):
            pass


# --- analyze --------------------------------------------------------------------------------------
def cmd_analyze(args: argparse.Namespace) -> int:
    from . import pipeline
    from .context import AnalysisContext
    from .util.hashing import sha256_stream

    try:
        cfg = config_from_args(args)
    except UsageError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return EXIT_USAGE
    _setup_logging(cfg.verbose)

    input_path = Path(args.input)
    if not input_path.exists():
        print("error: input does not exist: %s" % input_path, file=sys.stderr)
        return EXIT_INVALID_INPUT
    if input_path.is_file() and input_path.stat().st_size == 0:
        print("error: input file is empty: %s" % input_path, file=sys.stderr)
        return EXIT_INVALID_INPUT

    try:
        reg = pipeline.ensure_analyzers_loaded()
        ctx = AnalysisContext(cfg, input_path)
        try:
            outcome = pipeline.run(ctx, reg)
        finally:
            ctx.close()
        if not ctx.is_bound:   # ingest did not bind (stub or failure): derive the output dir ourselves
            digest = "unhashed"
            if input_path.is_file():
                try:
                    digest = sha256_stream(input_path)
                except OSError:
                    pass
            ctx.bind_input(digest)
        report_path = _ensure_report_json(ctx, outcome)
        if not cfg.keep_workdir:
            _cleanup_workdir(ctx)
    except UsageError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return EXIT_USAGE
    except (RegistryError, CycleError) as exc:
        print("fatal: invalid stage registry: %s" % exc, file=sys.stderr)
        return EXIT_FATAL
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return EXIT_FATAL
    except Exception as exc:  # noqa: BLE001
        log.debug("fatal", exc_info=True)
        print("fatal: %s: %s" % (type(exc).__name__, exc), file=sys.stderr)
        return EXIT_FATAL

    _print_summary(ctx, outcome, report_path)
    if outcome.invalid_input:
        return EXIT_INVALID_INPUT
    if outcome.failed:
        return EXIT_PARTIAL
    return EXIT_OK


def _ensure_report_json(ctx: Any, outcome: Any) -> Path:
    """Guarantee ``report.json`` exists: the report stage writes it; otherwise write the basic report."""
    from . import pipeline

    rel = ctx.artifacts.get("report.json")
    if rel and (ctx.out_dir / rel).is_file():
        return ctx.out_dir / rel
    report = pipeline.build_report(ctx, outcome.stage_results)
    path = ctx.artifact_path("report.json")
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(report.to_json())
    ctx.register_artifact("report.json", "report.json")
    return path


def _cleanup_workdir(ctx: Any) -> None:
    from .util.paths import is_within

    wd = getattr(ctx, "_workdir", None)
    if wd is not None and Path(wd).exists() and ctx.is_bound and is_within(ctx.out_dir, wd) and Path(wd) != ctx.out_dir:
        shutil.rmtree(wd, ignore_errors=True)
    elif wd is not None and not ctx.is_bound:
        shutil.rmtree(wd, ignore_errors=True)


def _print_summary(ctx: Any, outcome: Any, report_path: Path) -> None:
    out = sys.stdout
    print("%s %s -- %s" % (TOOL_NAME, __version__, ctx.input_path), file=out)
    for r in outcome.stage_results:
        extra = r.reason or r.error or ""
        print("  %-22s %-8s %6.2fs  %s" % (r.name, r.status.value, r.duration_s, extra), file=out)
    n = {s: sum(1 for r in outcome.stage_results if r.status == s) for s in Status}
    print("stages: %d ok, %d partial, %d skipped, %d failed" % (
        n[Status.OK], n[Status.PARTIAL], n[Status.SKIPPED], n[Status.FAILED]), file=out)
    print("report: %s" % report_path, file=out)


# --- doctor ---------------------------------------------------------------------------------------
def _check_dotnet(explicit: Optional[str]) -> Dict[str, Any]:
    from .util import procs

    exe = explicit or procs.which_safe("dotnet")
    if not exe:
        return {"name": "dotnet", "level": "warn", "detail": "not found (only needed for Il2CppDumper)"}
    r = procs.run([exe, "--list-runtimes"], timeout=15)
    if not r.ok:
        return {"name": "dotnet", "level": "warn", "detail": "%s found but --list-runtimes failed: %s" % (
            exe, r.error or r.stderr.strip()[:120])}
    runtimes = [ln.split(" [")[0] for ln in r.stdout.splitlines() if ln.strip()]
    return {"name": "dotnet", "level": "ok", "detail": "%s; runtimes: %s" % (exe, "; ".join(runtimes) or "none")}


def _check_cache_writable() -> Dict[str, Any]:
    import tempfile

    from .util.paths import cache_dir

    d = cache_dir()
    try:
        d.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=str(d), prefix=".doctor-", delete=True):
            pass
        return {"name": "cache dir", "level": "ok", "detail": "%s (writable)" % d}
    except OSError as exc:
        return {"name": "cache dir", "level": "warn", "detail": "%s not writable: %s" % (d, exc)}


def _check_network() -> Dict[str, Any]:
    try:
        with socket.create_connection(("github.com", 443), timeout=3):
            pass
        return {"name": "network", "level": "ok", "detail": "github.com:443 reachable"}
    except OSError as exc:
        return {"name": "network", "level": "warn", "detail": "github.com:443 unreachable (%s); use --offline" % exc}


def _check_cached_tools() -> Dict[str, Any]:
    from .util.paths import tools_dir

    d = tools_dir()
    try:
        entries = sorted(p.name for p in d.iterdir()) if d.is_dir() else []
    except OSError:
        entries = []
    return {"name": "cached tools", "level": "ok", "detail": ", ".join(entries) if entries else "none (%s)" % d}


def collect_doctor(args: argparse.Namespace) -> List[Dict[str, Any]]:
    from . import pipeline
    from .engines import api as engines_api

    checks: List[Dict[str, Any]] = []
    ok = sys.version_info >= (3, 9)
    checks.append({"name": "python", "level": "ok" if ok else "error",
                   "detail": "%s (%s)%s" % (platform.python_version(), sys.executable,
                                            "" if ok else " -- Python >= 3.9 required")})
    checks.append({"name": "platform", "level": "ok",
                   "detail": "%s %s (%s)" % (platform.system(), platform.release(), platform.machine())})
    checks.append(_check_dotnet(getattr(args, "dotnet", None)))
    checks.append(_check_cache_writable())
    if getattr(args, "offline", False):
        checks.append({"name": "network", "level": "skip", "detail": "skipped (--offline)"})
    else:
        checks.append(_check_network())
    checks.append(_check_cached_tools())
    try:
        reg = pipeline.ensure_analyzers_loaded()
        reg.validate()
        bad = sorted(reg.import_failures)
        checks.append({"name": "stages", "level": "warn" if bad else "ok",
                       "detail": "%d registered%s" % (len(reg), ("; import failures: " + ", ".join(bad)) if bad else "")})
    except Exception as exc:  # noqa: BLE001
        checks.append({"name": "stages", "level": "error", "detail": "%s: %s" % (type(exc).__name__, exc)})
    try:
        n = len(engines_api.get_checkers())
        fails = sorted(engines_api.checker_import_failures())
        checks.append({"name": "engine checkers", "level": "warn" if fails else "ok",
                       "detail": "%d registered%s" % (n, ("; import failures: " + ", ".join(fails)) if fails else "")})
    except Exception as exc:  # noqa: BLE001
        checks.append({"name": "engine checkers", "level": "error", "detail": "%s: %s" % (type(exc).__name__, exc)})
    try:
        import lief  # noqa: F401
        checks.append({"name": "lief (optional)", "level": "ok", "detail": "available"})
    except ImportError:
        checks.append({"name": "lief (optional)", "level": "skip", "detail": "not installed (not required)"})
    return checks


def cmd_doctor(args: argparse.Namespace) -> int:
    _setup_logging(getattr(args, "verbose", 0))
    checks = collect_doctor(args)
    if getattr(args, "json", False):
        print(json.dumps({"tool": TOOL_NAME, "version": __version__, "checks": checks}, ensure_ascii=False, indent=2))
    else:
        marks = {"ok": "[ OK ]", "warn": "[WARN]", "error": "[FAIL]", "skip": "[SKIP]"}
        print("%s %s doctor" % (TOOL_NAME, __version__))
        for c in checks:
            print("%s %-16s %s" % (marks.get(c["level"], "[ ?? ]"), c["name"], c["detail"]))
    return EXIT_FATAL if any(c["level"] == "error" for c in checks) else EXIT_OK


# --- tools (wiring points for WP6) ------------------------------------------------------------------
def _tools_impl(fn_name: str):
    """Return ``ipa_analyzer.il2cpp.tools.<fn_name>`` if WP6 provides it, else None."""
    try:
        mod = importlib.import_module("ipa_analyzer.il2cpp.tools")
    except ImportError:
        return None
    return getattr(mod, fn_name, None)


def cmd_tools_list_dispatch(args: argparse.Namespace) -> int:
    fn = _tools_impl("cmd_tools_list")
    if fn is not None:
        return int(fn(args))
    from .util.paths import tools_dir

    print("no tools are registered in this build yet (tool provisioning not implemented)")
    print("cache directory: %s" % tools_dir())
    return EXIT_OK


def cmd_tools_install_dispatch(args: argparse.Namespace) -> int:
    fn = _tools_impl("cmd_tools_install")
    if fn is not None:
        return int(fn(args))
    print("error: 'tools install' is not implemented yet", file=sys.stderr)
    return EXIT_FATAL


def cmd_tools_path_dispatch(args: argparse.Namespace) -> int:
    fn = _tools_impl("cmd_tools_path")
    if fn is not None:
        return int(fn(args))
    print("error: 'tools path' is not implemented yet", file=sys.stderr)
    return EXIT_FATAL


# --- entry point ------------------------------------------------------------------------------------
def main(argv: Optional[Sequence[str]] = None) -> int:
    _reconfigure_streams()
    parser = build_parser()
    try:
        args = parser.parse_args(list(argv) if argv is not None else None)
    except SystemExit as exc:   # --help / --version / usage errors
        return int(exc.code) if isinstance(exc.code, int) else EXIT_OK
    if not getattr(args, "command", None):
        parser.print_help(sys.stderr)
        return EXIT_USAGE
    try:
        return int(args.func(args))
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return EXIT_FATAL
    except InvalidInput as exc:
        print("error: %s" % exc, file=sys.stderr)
        return EXIT_INVALID_INPUT


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())

"""Flutter checker: framework layout, AOT vs JIT (debug) form -> ``engine.flutter_aot``.

Layout (``Frameworks/Flutter.framework`` = engine, ``Frameworks/App.framework`` = the app: ``App`` Mach-O holding the
AOT snapshot in release builds, ``flutter_assets/`` data).  Verified against flutter/engine
``FlutterDartProject.mm``: it looks for ``Frameworks/App.framework``, ``flutter_assets`` and ``kernel_blob.bin``
(a kernel snapshot, i.e. JIT / debug) and reads the ``FLTLibraryPath`` Info.plist key.  UNVERIFIED: AOT symbol
names in ``App`` (``kDartVmSnapshotData`` ...), Dart version strings.

``engine.flutter_aot``: ``yes`` = ``App`` binary present and no ``kernel_blob.bin``; ``no`` = ``kernel_blob.bin``
present (debug / JIT build); otherwise ``unknown``.  Dart code is compiled, not encrypted; obfuscation of
symbols cannot be judged from the layout.  Detection only.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from ...models import Evidence, Status, Verdict
from ..api import CheckerResult, DetectResult, register_checker
from ..formats import common
from ..formats.common import FileIndex

FRAMEWORK = "Frameworks/Flutter.framework/"
APP_FW = "Frameworks/App.framework/"


@register_checker("flutter")
class FlutterChecker:
    engine_id = "flutter"

    def applies(self, ctx: Any, detect: DetectResult) -> bool:
        if detect.has("flutter"):
            return True
        idx = FileIndex(ctx)
        return idx.has_dir(FRAMEWORK) or idx.has_dir(APP_FW + "flutter_assets")

    def run(self, ctx: Any, detect: DetectResult) -> CheckerResult:
        cfg = common.checks("flutter")
        idx = FileIndex(ctx)
        has_engine = idx.has_dir(FRAMEWORK) and idx.exists(FRAMEWORK + "Flutter")
        app_bin = idx.get(APP_FW + "App")
        assets = APP_FW + "flutter_assets/"
        kernel = idx.get(assets + "kernel_blob.bin")
        vm_snap = idx.get(assets + "vm_snapshot_data")
        iso_snap = idx.get(assets + "isolate_snapshot_data")
        manifests = [n for n in ("AssetManifest.json", "AssetManifest.bin", "FontManifest.json", "NOTICES", "NOTICES.Z")
                     if idx.exists(assets + n)]
        n_assets = sum(1 for r in idx.recs if r.rel.startswith(assets))
        encrypted_bin: Optional[bool] = None
        macho = ctx.results.get("macho")
        if isinstance(macho, dict) and app_bin is not None:
            for b in macho.get("binaries") or []:
                if b.get("rel") == APP_FW + "App":
                    encrypted_bin = any(s.get("encrypted") for s in b.get("slices") or [])
        hits: Dict[str, List[str]] = {}
        scan_status = "not_scanned"
        if app_bin is not None and encrypted_bin is False:
            scan = common.scan_binary(ctx, app_bin.path, cfg["binary_patterns"])
            hits, scan_status = scan.hits, scan.status
        elif encrypted_bin:
            scan_status = "skipped_encrypted"
        dart = None
        for t in hits.get("dart_version", []):
            m = re.search(r"(\d+\.\d+\.\d+)", t)
            if m:
                dart = m.group(1)
                break
        info_plist_hint = None
        fw_plist = idx.get(FRAMEWORK + "Info.plist")
        if fw_plist is not None:
            info_plist_hint = {"path": fw_plist.rel, "size": fw_plist.size}
        data: Dict[str, Any] = {
            "engine_framework": has_engine, "app_framework_binary": app_bin.rel if app_bin else None,
            "flutter_assets": {"present": idx.has_dir(assets), "files": n_assets, "manifests": manifests},
            "kernel_blob_present": kernel is not None, "snapshot_files": [r.rel for r in (vm_snap, iso_snap) if r],
            "app_binary_encrypted": encrypted_bin, "binary_scan": {"status": scan_status, "hits": {k: v[:3] for k, v in hits.items()}},
            "dart_version_hint": dart, "framework_info_plist": info_plist_hint,
        }
        ev: List[Evidence] = []
        if kernel is not None:
            verdict, conf = Verdict.NO, 0.9
            note = "kernel_blob.bin is present: a debug / JIT build, not an AOT snapshot."
            ev.append(Evidence("file", kernel.rel, "kernel snapshot (JIT)"))
        elif app_bin is not None:
            verdict, conf = Verdict.YES, 0.85 if has_engine else 0.7
            note = "App.framework/App is present without kernel_blob.bin: the Dart code is an AOT snapshot (compiled, not encrypted)."
            ev.append(Evidence("file", app_bin.rel, "AOT snapshot container"))
            if has_engine:
                ev.append(Evidence("file", FRAMEWORK + "Flutter", "Flutter engine framework"))
        else:
            verdict, conf = Verdict.UNKNOWN, 0.2
            note = "No App.framework/App binary was found, so the Dart code form is unknown."
        if encrypted_bin:
            note += " The App binary is FairPlay-encrypted, so snapshot symbols / version strings were not read."
        summary = "Flutter: %s" % note
        f = common.make_finding("engine.flutter_aot", verdict, conf, "flutter", "Flutter AOT snapshot", summary,
                                {"engine": "Flutter", "aot": verdict.value, "dart_version": dart or "unknown",
                                 "assets": n_assets}, ev)
        return CheckerResult(findings=[f], data=data, status=Status.OK)

"""Xamarin / .NET iOS checker: are the managed assemblies intact PE + CLI files? -> ``engine.script.encrypted``.

Every ``*.dll`` in the app (outside SDK frameworks) is parsed with ``ipa_analyzer.formats.pe_cli`` (PE header, CLI
data directory and the ``BSJB`` metadata root, ECMA-335 II.24).  Intact assemblies are compiled IL (``no``,
labelled compiled); a ``.dll`` that is not a PE image and looks like random data is ``suspected``; a PE that is
not a managed assembly is just reported (native / ReadyToRun-only images exist).  Detection only.
"""
from __future__ import annotations

from typing import Any, Dict, List

from ...formats import pe_cli
from ...models import Evidence, Status
from ..api import CheckerResult, DetectResult, register_checker
from ..formats import common
from ..formats.common import BlobInfo, FileIndex, ScriptTally


@register_checker("xamarin")
class XamarinChecker:
    engine_id = "xamarin"

    def applies(self, ctx: Any, detect: DetectResult) -> bool:
        if detect.has("xamarin_maui") or detect.has("xamarin"):
            return True
        idx = FileIndex(ctx)
        return any(idx.find(rx) for rx in common.checks("xamarin")["key_assemblies"])

    def run(self, ctx: Any, detect: DetectResult) -> CheckerResult:
        cfg = common.checks("xamarin")
        idx = FileIndex(ctx)
        dlls = idx.not_vendor(idx.with_ext(".dll"))
        sample, total = common.evenly_sample(dlls, cfg["max_dlls"])
        tally = ScriptTally()
        items: List[Dict[str, Any]] = []
        for r in sample:
            data = common.read_head(ctx, r.path, cfg["max_read_bytes"])
            info = pe_cli.parse(data)
            item: Dict[str, Any] = {"path": r.rel, "size": r.size, "is_pe": info.is_pe, "is_dotnet": info.is_dotnet}
            if info.is_dotnet:
                item.update(assembly=info.assembly_name, clr=info.clr_version, typedefs=info.typedef_count)
                tally.add(r.rel, r.ext, BlobInfo(common.K_ASSEMBLY, {}))
            elif info.is_pe:
                item["note"] = "PE image without CLI metadata"
                tally.add(r.rel, r.ext, BlobInfo(common.K_BINARY, {}))
            else:
                blob = common.classify_blob(data[:cfg["head_bytes"]], r.size, r.entropy)
                item["kind"] = blob.kind
                tally.add(r.rel, r.ext, blob if blob.bucket == "suspected_encrypted" else BlobInfo(common.K_BINARY, {}))
            items.append(item)
        scripts = tally.to_dict(sampled=len(sample), of=total)
        verdict, conf, state = common.verdict_from_tally(tally, total)
        ev: List[Evidence] = []
        for kk in (common.K_HIGH_ENTROPY, common.K_CUSTOM_HEADER, common.K_ASSEMBLY):
            ev.extend(common.file_evidence(tally.samples.get(kk, []), kk, 2))
        note = "Managed assemblies are compiled IL, not encryption." if tally.count("bytecode") else ""
        f = common.script_finding("xamarin", "Xamarin / .NET", scripts, verdict, conf, state, ev, note)
        return CheckerResult(findings=[f], data={"assemblies": items[:cfg["max_listed"]], "scripts": scripts},
                             status=Status.OK)

"""In-house / modified-engine judgement (``engine.custom``, WP7).

Input: the capability profile (``FingerprintResult``) plus the known-engine result (``DetectResult``).
Output: the ``custom`` block of ``engine.detect`` (verdict, confidence, evidence, per-condition table,
next steps, deviations, open-source base).

Design (anti false-positive):
* A pure native app that merely uses Metal (map / video apps do) is *never* called a custom engine: the
  judgement needs a render API **and** a game signal **and** at least two of {own script VM, custom
  container, physics library, C++-heavy code}.
* When a known engine is confirmed the verdict is ``no`` -- unless the engine shows the "modified open-source
  engine" pattern: its code traces are present while all of its standard layout files are missing.
* When the binary is FairPlay-encrypted and no known engine matched, evidence is missing, so the verdict
  is ``unknown`` rather than ``no``.
Weights below are heuristics (no external source); the result is always an inference (<= ``MAX_CONFIDENCE``).
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence

from ..models import Evidence, Verdict
from .api import DetectResult, FingerprintHit, FingerprintResult
from .signatures import SignatureSet

MAX_CONFIDENCE = 0.8
YES_SCORE = 0.9
SUSPECTED_SCORE = 0.5
CPP_HEAVY_RATIO = 0.4
KNOWN_KINDS = ("game_engine", "cross_platform_ui", "web_hybrid")
OWN_VMS = frozenset({"lua", "luajit", "quickjs", "duktape", "python", "squirrel", "angelscript", "wren", "mruby",
                     "mozjs", "v8", "hashlink"})
GAME_AUDIO = frozenset({"fmod", "wwise", "openal", "bass", "soloud", "miniaudio", "sdl_mixer"})
GAME_TEXTURES = frozenset({"ccz", "pvr", "astc", "ktx", "dds"})
GAME_LOOP_HINTS = frozenset({"CADisplayLink", "GCController", "MTKView", "GLKView"})
_W = {"render": 0.25, "script_vm": 0.2, "custom_container": 0.2, "physics": 0.1, "cpp_heavy": 0.15,
      "game_signal": 0.1, "thin_shell": 0.1}


def _conf(hits: Sequence[FingerprintHit], minimum: float = 0.4) -> List[FingerprintHit]:
    return [h for h in hits if h.confidence >= minimum]


def next_steps(fp: FingerprintResult, binary_limited: bool, vm_ids: Sequence[str]) -> List[Dict[str, Any]]:
    """Concrete follow-ups (localisable through ``engines.next.*`` keys)."""
    steps: List[Dict[str, Any]] = []
    for h in fp.containers:
        v = h.extra.get("verdict")
        if v not in ("custom_format", "encrypted_suspected"):
            continue
        if h.extra.get("kind") == "header_cluster":
            steps.append({"key": "engines.next.header_cluster",
                          "params": {"header": h.extra.get("magic_ascii") or h.extra.get("magic"), "count": h.extra.get("count")},
                          "text": "%d files share the custom header %s: read one small and one large sample and check "
                                  "whether the bytes after the header are a standard format (see the payload evidence)."
                                  % (h.extra.get("count", 0), h.extra.get("magic_ascii") or h.extra.get("magic"))})
        else:
            tbl = (h.extra.get("header") or {}).get("offset_table")
            where = "offset table in the first %d bytes (stride %d)" % (
                (tbl["start_index"] + tbl["run"] * tbl["stride"]) * (tbl["width"]), tbl["stride"]) if tbl else "header"
            steps.append({"key": "engines.next.container", "params": {"path": h.id, "verdict": v, "where": where},
                          "text": "Inspect %s (%s): custom container; %s." % (h.id, v, where)})
        if len([s for s in steps if s["key"].startswith("engines.next.c")]) >= 3:
            break
    for vm in vm_ids[:2]:
        steps.append({"key": "engines.next.script_vm", "params": {"vm": vm},
                      "text": "Focus on the %s bindings / loader in the main binary and check whether scripts on disk "
                              "are plain text, bytecode or encrypted." % vm})
    py = next((h for h in fp.script_vms if h.id == "python" and (h.extra.get("pyc") or {}).get("opcode_scramble_suspected")), None)
    if py is not None:
        steps.append({"key": "engines.next.python_opcodes", "params": {},
                      "text": "Python bytecode headers are non-standard: expect a customised interpreter (shuffled "
                              "opcodes); standard disassemblers will not work."})
    if fp.render and not any(h.id == "metallib" for h in fp.shader_formats):
        steps.append({"key": "engines.next.shader", "params": {},
                      "text": "No shader files were recognised: confirm the shader format manually (embedded source, "
                              "runtime-compiled MSL/GLSL or a custom binary)."})
    if binary_limited:
        steps.append({"key": "engines.next.decrypted_ipa", "params": {},
                      "text": "The main binary is FairPlay-encrypted, so symbol / string evidence is missing: provide a "
                              "decrypted IPA to continue. This tool never decrypts."})
    steps.append({"key": "engines.next.record_signature", "params": {},
                  "text": "Once traits are confirmed, record them in <user data dir>/engines.user.d/<id>.json so the "
                          "next run identifies the engine directly."})
    return steps


def _modified_open_source(detect: DetectResult, sigset: Optional[SignatureSet], visible: bool) -> Optional[Dict[str, Any]]:
    """Code traces of an open-source engine without any of its standard layout files."""
    if sigset is None or not visible:
        return None
    best: Optional[Dict[str, Any]] = None
    for c in detect.candidates:
        base = sigset.extras.get(c.id, {}).get("open_source_base")
        sig = sigset.signatures.get(c.id)
        if not base or sig is None or not sigset.extras.get(c.id, {}).get("layout_expected"):
            continue
        has_layout = any(s.type in ("file", "dir") for s in sig.signals)
        code, layout = float(c.extra.get("code_score", 0.0)), float(c.extra.get("layout_score", 0.0))
        if has_layout and code >= 0.4 and layout <= 0.15:
            cand = {"base": base, "engine": c.id, "name": c.name, "code": code, "layout": layout,
                    "evidence": [e for e in c.evidence if e.kind in ("symbol", "string", "macho")][:3]}
            if best is None or code > best["code"]:
                best = cand
    return best


def judge_custom(fp: FingerprintResult, detect: DetectResult, *, binary_limited: bool = False,
                 binaries_scanned: int = 0, sigset: Optional[SignatureSet] = None) -> Dict[str, Any]:
    """Return the ``custom`` block (see CONTRACT-FREEZE 4.6)."""
    primary = detect.primary
    known = primary is not None and primary.kind in KNOWN_KINDS
    vms = _conf(fp.script_vms)
    own_vms = [h for h in vms if h.id in OWN_VMS]
    containers = [h for h in fp.containers if h.extra.get("verdict") in ("custom_format", "encrypted_suspected")
                  and h.confidence >= 0.4]
    physics = _conf(fp.physics)
    host = fp.host or {}
    cpp_ratio = host.get("cpp_ratio")
    cpp_heavy = bool(cpp_ratio is not None and cpp_ratio >= CPP_HEAVY_RATIO)
    thin = bool(host.get("thin_uikit_shell"))
    game_signal = bool(physics or [h for h in fp.audio if h.id in GAME_AUDIO and h.confidence >= 0.4]
                       or [h for h in fp.asset_formats if h.id in GAME_TEXTURES]
                       or (set(host.get("main_loop_hints") or []) & GAME_LOOP_HINTS and fp.render
                           and set(host.get("main_loop_hints") or []) - {"CAMetalLayer", "CAEAGLLayer"}))
    cond: Dict[str, Any] = {
        "known_engine_confirmed": known, "render_api": bool(fp.render), "script_vm": bool(own_vms),
        "custom_container": bool(containers), "physics_lib": bool(physics), "cpp_heavy": cpp_heavy,
        "game_signals": game_signal, "thin_uikit_shell": thin, "binary_limited": binary_limited,
    }
    score = (_W["render"] * bool(fp.render) + _W["script_vm"] * bool(own_vms) + _W["custom_container"] * bool(containers)
             + _W["physics"] * bool(physics) + _W["cpp_heavy"] * cpp_heavy + _W["game_signal"] * game_signal
             + _W["thin_shell"] * thin)
    cond["score"] = round(score, 3)
    structure = sum([bool(own_vms), bool(containers), bool(physics), cpp_heavy])
    evidence: List[Evidence] = []
    if fp.render:
        evidence.append(Evidence("heuristic", "render", "render API: %s" % ", ".join(sorted(fp.render))))
    for h in own_vms[:2]:
        evidence.append(Evidence("heuristic", h.id, "own script VM: %s (confidence %.2f)" % (h.name or h.id, h.confidence)))
    for h in containers[:2]:
        evidence.append(Evidence("heuristic", h.id, "custom container: %s (%s)" % (h.extra.get("verdict"), h.id)))
    for h in physics[:1]:
        evidence.append(Evidence("heuristic", h.id, "physics library: %s" % (h.name or h.id)))
    out: Dict[str, Any] = {"verdict": Verdict.UNKNOWN.value, "confidence": 0.2, "evidence": [], "profile_ref": "engine.fingerprint",
                           "conditions": cond, "next_steps": [], "deviations": [], "open_source_base": []}

    modified = _modified_open_source(detect, sigset, binaries_scanned > 0 and not binary_limited)
    if known and modified is None:
        out.update(verdict=Verdict.NO.value, confidence=0.85)
        out["evidence"] = [e.to_dict() for e in [Evidence("heuristic", primary.id, "known engine confirmed: %s (%.2f)" % (primary.name, primary.confidence))]]
        return out
    if modified is not None:
        out.update(verdict=Verdict.SUSPECTED.value, confidence=min(0.6, 0.3 + modified["code"] * 0.4),
                   kind="modified_open_source", open_source_base=[modified["base"]])
        out["deviations"] = ["%s code traces present but none of its standard layout files (directories / scripts / resources) were found" % modified["name"]]
        out["evidence"] = [e.to_dict() for e in modified["evidence"]] + [e.to_dict() for e in evidence[:2]]
        out["next_steps"] = next_steps(fp, binary_limited, [h.id for h in own_vms])
        return out

    if fp.render and game_signal and structure >= 2:
        verdict = Verdict.YES if score >= YES_SCORE else Verdict.SUSPECTED
        conf = min(MAX_CONFIDENCE, 0.35 + score * 0.5)
        out.update(verdict=verdict.value, confidence=conf, kind="in_house")
        out["evidence"] = [e.to_dict() for e in evidence]
        out["next_steps"] = next_steps(fp, binary_limited, [h.id for h in own_vms])
        if detect.candidates:
            out["deviations"] = ["no known engine reached its confirmation threshold (best: %s %.2f)" % (
                detect.candidates[0].name, detect.candidates[0].confidence)]
        return out
    if binary_limited or binaries_scanned == 0:
        out.update(verdict=Verdict.UNKNOWN.value, confidence=0.2)
        out["evidence"] = [e.to_dict() for e in evidence]
        out["next_steps"] = next_steps(fp, binary_limited, [])[-2:]
        return out
    out.update(verdict=Verdict.NO.value, confidence=0.6 if not fp.render else 0.5)
    out["evidence"] = [e.to_dict() for e in evidence]
    return out

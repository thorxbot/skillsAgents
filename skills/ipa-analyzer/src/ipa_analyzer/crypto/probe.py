"""Decryptability probe: for each encryption the detectors flagged, say whether this tool can decrypt it now,
and if not, what the next step is.

This is read-only and key-free. It consumes the analysis findings (frozen ids, see ``docs/CONTRACT-FREEZE.md``)
plus whether the main binary is FairPlay-encrypted, and returns one :class:`Assessment` per encrypted artifact:

* ``supported``        -- the built-in decryptor can do it now (e.g. Cocos XXTEA scripts on a readable binary).
* ``needs_key``        -- the scheme is supported but you must supply the key (``--pvr-key``, ``--xxtea-key``, or
                          the ``decrypt`` subcommand).
* ``blocked_fairplay`` -- the binary (hence the embedded key/strings) is ciphertext; supply a decrypted IPA first.
* ``unsupported``      -- the scheme is recognised but there is no built-in decryptor yet; the next step names the
                          key location / external tool.
* ``unknown``          -- encryption is only suspected and the scheme is undetermined; the next step is triage.

``feasibility`` is advisory: it reflects what the detectors saw, not a guarantee a specific key exists.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional

SUPPORTED = "supported"
NEEDS_KEY = "needs_key"
BLOCKED_FAIRPLAY = "blocked_fairplay"
UNSUPPORTED = "unsupported"
UNKNOWN = "unknown"

# Display / sorting priority (most actionable first).
_ORDER = {SUPPORTED: 0, NEEDS_KEY: 1, BLOCKED_FAIRPLAY: 2, UNSUPPORTED: 3, UNKNOWN: 4}
_ACTIVE_VERDICTS = {"yes", "suspected"}


@dataclass
class Assessment:
    artifact: str                 # what is encrypted (engine + kind)
    scheme: str                   # best-known cipher / container
    feasibility: str              # one of the constants above
    next_step: str                # concrete action
    finding_id: str = ""
    evidence: List[str] = field(default_factory=list)   # sample in-app paths, if the finding carried any

    def to_dict(self) -> Dict[str, Any]:
        return {"artifact": self.artifact, "scheme": self.scheme, "feasibility": self.feasibility,
                "next_step": self.next_step, "finding_id": self.finding_id, "evidence": self.evidence}


def _norm(f: Any) -> Dict[str, Any]:
    if isinstance(f, dict):
        return {"id": f.get("id", ""), "verdict": str(f.get("verdict", "")),
                "tags": list(f.get("tags", [])), "params": dict(f.get("params", {}))}
    verdict = getattr(f, "verdict", "")
    verdict = getattr(verdict, "value", verdict)
    return {"id": getattr(f, "id", ""), "verdict": str(verdict),
            "tags": list(getattr(f, "tags", [])), "params": dict(getattr(f, "params", {}))}


def _engine(tags: List[str]) -> str:
    for t in tags:
        if t.startswith("engine:"):
            return t.split(":", 1)[1]
    return ""


def _evidence(params: Dict[str, Any]) -> List[str]:
    out: List[str] = []
    for key in ("samples", "examples", "paths", "files"):
        v = params.get(key)
        if isinstance(v, list):
            out.extend(str(x) for x in v[:3])
    return out[:3]


def _assess_one(fid: str, verdict: str, engine: str, params: Dict[str, Any], fairplay: bool) -> Optional[Assessment]:
    ev = _evidence(params)

    if fid == "engine.script.encrypted":
        if engine == "cocos":
            if fairplay:
                return Assessment("Cocos scripts (Lua/.jsc)", "XXTEA (xxtea-c)", BLOCKED_FAIRPLAY,
                                  "Main binary is FairPlay-encrypted, so the embedded XXTEA key is ciphertext. "
                                  "Supply a decrypted IPA, or pass a known key: analyze --cocos-decrypt --xxtea-key <key>.",
                                  fid, ev)
            return Assessment("Cocos scripts (Lua/.jsc)", "XXTEA (xxtea-c)", SUPPORTED,
                              "Run: analyze --cocos-decrypt (recovers the XXTEA key from the binary and writes "
                              "decrypted/). If recovery fails, add --xxtea-key <key> / --xxtea-sign <sign>.", fid, ev)
        return Assessment("Scripts (%s)" % (engine or "unknown engine"), "unknown cipher", UNKNOWN,
                          "Identify the cipher and key (check the binary for key setters / constants), then: "
                          "decrypt <file> --scheme xxtea|xor --key <key> [--sign <sign>].", fid, ev)

    if fid == "engine.resource.encrypted":
        if engine == "cocos":
            return Assessment("Cocos resources (CCZp textures / wrappers)", "CCZp PVR (XXTEA keystream) or custom",
                              NEEDS_KEY,
                              "For CCZp supply the 4-part PVR key: analyze --cocos-decrypt --pvr-key <32hex>, or "
                              "decrypt <file.ccz> --scheme ccz --key <...>. For a custom wrapper, identify the "
                              "scheme first, then use the decrypt subcommand.", fid, ev)
        return Assessment("Resources (%s)" % (engine or "unknown engine"), "unknown container", UNKNOWN,
                          "Identify the container/cipher, then: decrypt <file> --scheme xor|xxtea --key <key>.", fid, ev)

    if fid == "engine.pak.encrypted":
        if engine == "unreal":
            return Assessment("Unreal .pak / IoStore", "AES-256 (UE)", UNSUPPORTED,
                              "Recover the 32-byte UE AES key (embedded in the binary / build). No built-in AES "
                              "decryptor yet: run UnrealPak or retoc with the key to extract, then re-run analyze on "
                              "the output.", fid, ev)
        if engine == "godot":
            return Assessment("Godot .pck", "AES-256-CBC (script key)", UNSUPPORTED,
                              "Recover the 256-bit script encryption key from the app. No built-in support yet: use "
                              "gdsdecomp with the key, then re-run analyze on the extracted project.", fid, ev)
        return Assessment("Package (%s)" % (engine or "unknown engine"), "unknown", UNSUPPORTED,
                          "Identify the packaging cipher and key; use the engine's own repacker/extractor.", fid, ev)

    if fid == "unity.metadata.encrypted":
        return Assessment("Unity global-metadata.dat", "whole-file XOR / custom (varies)", UNSUPPORTED,
                          "Find the metadata key in UnityFramework (inspect load commands & strings). If it is a "
                          "simple XOR: decrypt global-metadata.dat --scheme xor --key <hex:..>. Then re-run analyze "
                          "with --il2cpp-tool against the decrypted metadata.", fid, ev)

    if fid == "unity.assetbundle.encryption":
        return Assessment("Unity AssetBundle", "whole-file XOR/AES or block-level", UNSUPPORTED,
                          "See references/unity-assetbundle.md to pin the scheme. Whole-file XOR: decrypt <bundle> "
                          "--scheme xor --key <...>. Block-level encryption needs bundle-aware tooling (not built in).",
                          fid, ev)

    if fid == "unity.mono.dll_encrypted":
        return Assessment("Unity Mono assemblies (.dll)", "whole-file (varies)", UNSUPPORTED,
                          "Find the key on the libmono load path, then: decrypt Managed/*.dll --scheme xor|xxtea "
                          "--key <...>.", fid, ev)

    if fid == "unity.hotfix.script_protection":
        return Assessment("Unity hot-update scripts (Lua/JS/DLL)", "XXTEA or custom", NEEDS_KEY,
                          "If XXTEA: decrypt <file> --scheme xxtea --key <key> [--sign <sign>]. Otherwise identify "
                          "the cipher first (see references/unity-hotfix.md).", fid, ev)

    return None


def assess(findings: Iterable[Any], *, fairplay: bool = False) -> List[Assessment]:
    """Build the decryptability assessment from analysis findings and the FairPlay state of the main binary."""
    rows = [_norm(f) for f in findings]
    out: List[Assessment] = []
    for r in rows:
        if r["verdict"] not in _ACTIVE_VERDICTS:
            continue
        a = _assess_one(r["id"], r["verdict"], _engine(r["tags"]), r["params"], fairplay)
        if a is not None:
            out.append(a)
    out.sort(key=lambda a: (_ORDER.get(a.feasibility, 9), a.artifact))
    return out


def fairplay_encrypted(findings: Iterable[Any]) -> bool:
    """True if a finding says the main binary is FairPlay-encrypted (``protect.fairplay`` / ``unity.binary.fairplay``)."""
    for r in (_norm(f) for f in findings):
        if r["id"] in ("protect.fairplay", "unity.binary.fairplay") and r["verdict"] == "yes":
            return True
    return False

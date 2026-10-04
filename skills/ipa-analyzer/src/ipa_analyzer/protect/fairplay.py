"""FairPlay summary from the per-slice ``encrypted`` flags recorded by the ``macho`` stage."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from ..models import Verdict


@dataclass
class FairplayInfo:
    verdict: Verdict
    confidence: float
    scope: str                                   # all | partial | none | unknown
    encrypted_binaries: List[str] = field(default_factory=list)
    total_binaries: int = 0
    main_encrypted: Optional[bool] = None
    sc_info_present: Optional[bool] = None
    case: str = "unknown"
    text_en: str = ""
    text_zh: str = ""
    remediation: str = ""

    def to_data(self) -> Dict[str, Any]:
        return {"verdict": self.verdict.value, "scope": self.scope, "encrypted_binaries": list(self.encrypted_binaries),
                "total_binaries": self.total_binaries, "main_encrypted": self.main_encrypted,
                "sc_info_present": self.sc_info_present}


_REMEDIATION = ("Provide a decrypted IPA (obtained by the owner from their own device); this tool never decrypts "
                "FairPlay-protected code.")


def summarize_fairplay(macho: Optional[Dict[str, Any]], sc_info_present: Optional[bool]) -> FairplayInfo:
    """Combine per-binary encryption flags with the SC_Info container presence (``meta.fairplay_container``)."""
    binaries = [b for b in (macho or {}).get("binaries") or [] if isinstance(b, dict) and b.get("slices")]
    if not binaries:
        return FairplayInfo(Verdict.UNKNOWN, 0.2, "unknown", [], 0, None, sc_info_present, "unknown",
                            "No Mach-O data is available, so FairPlay encryption could not be assessed.",
                            "缺少 Mach-O 解析结果,无法判断 FairPlay 加密状态。", "")
    enc = sorted(b["path"] for b in binaries if any(s.get("encrypted") for s in b["slices"]))
    main = next((b for b in binaries if b.get("role") == "main"), None)
    main_enc = any(s.get("encrypted") for s in main["slices"]) if main else None
    total = len(binaries)
    if enc and len(enc) == total:
        scope = "all"
    elif enc:
        scope = "partial"
    else:
        scope = "none"
    if scope == "none":
        if sc_info_present:
            return FairplayInfo(Verdict.NO, 0.9, scope, [], total, main_enc, True, "decrypted_container",
                                "No Mach-O binary is FairPlay-encrypted (cryptid=0), although the SC_Info container is still "
                                "present: typically a decrypted IPA that kept its original container.",
                                "没有任何 Mach-O 被 FairPlay 加密(cryptid=0),但仍保留 SC_Info 容器:通常是已解密后重打包的 IPA。", "")
        return FairplayInfo(Verdict.NO, 0.9, scope, [], total, main_enc, sc_info_present, "plain",
                            "No Mach-O binary is FairPlay-encrypted; binary-level analysis and il2cpp dumping are possible.",
                            "没有任何 Mach-O 被 FairPlay 加密,可以直接做二进制分析与 il2cpp dump。", "")
    if scope == "all" or main_enc:
        n = "all %d" % total if scope == "all" else "%d of %d" % (len(enc), total)
        nz = "全部 %d" % total if scope == "all" else "%d/%d" % (len(enc), total)
        return FairplayInfo(Verdict.YES, 0.95, scope, enc, total, main_enc, sc_info_present, "main_encrypted",
                            "The main executable is FairPlay-encrypted (%s binaries encrypted): its code, ObjC class names and "
                            "strings cannot be analysed and il2cpp dump is blocked. Unity metadata and resource files are ordinary "
                            "files and are judged by the Unity stage." % n,
                            "主程序被 FairPlay 加密(%s 个二进制已加密):其代码、ObjC 类名与字符串无法分析,il2cpp dump 被阻断;"
                            "Unity 的 metadata 与资源文件是普通文件,由 Unity 阶段单独判断。" % nz, _REMEDIATION)
    return FairplayInfo(Verdict.YES, 0.85, scope, enc, total, main_enc, sc_info_present, "partial_other",
                        "The main executable is readable but %d of %d binaries (e.g. frameworks) are FairPlay-encrypted; "
                        "those cannot be analysed at code level." % (len(enc), total),
                        "主程序未加密,但 %d/%d 个二进制(如 Framework)被 FairPlay 加密,这些文件无法做代码级分析。" % (len(enc), total),
                        _REMEDIATION)

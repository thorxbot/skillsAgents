"""IL2CPP error taxonomy: remediation texts, output classification and log redaction.

The English strings here are the fallback; the report layer overrides them through the i18n keys
``il2cpp.error.<CODE>`` / ``il2cpp.remediation.<CODE>`` (see ``data/i18n/*/il2cpp.json``).
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence

from . import Il2CppErrorCode

__all__ = ["Il2CppToolError", "ToolDownloadError", "ERROR_TITLES", "REMEDIATIONS", "remediation_for",
           "title_for", "ClassifiedFailure", "classify_output", "redact_text", "redact_lines", "tail_lines",
           "i18n_error_key", "i18n_remediation_key"]


class Il2CppToolError(Exception):
    """A classified failure raised by the provisioning helpers (never by the supervised run)."""

    def __init__(self, code: Il2CppErrorCode, message: str, remediation: str = "") -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.remediation = remediation or remediation_for(code)


class ToolDownloadError(Il2CppToolError):
    """Download / verification failure. ``reason`` is one of policy|network|http|sha256|size|unpinned|offline."""

    def __init__(self, message: str, reason: str = "network") -> None:
        super().__init__(Il2CppErrorCode.E_TOOL_DOWNLOAD_FAILED, message)
        self.reason = reason


ERROR_TITLES: Dict[Il2CppErrorCode, str] = {
    Il2CppErrorCode.E_BINARY_FAIRPLAY: "The IL2CPP binary is FairPlay-encrypted",
    Il2CppErrorCode.E_METADATA_ENCRYPTED: "global-metadata.dat is encrypted or modified",
    Il2CppErrorCode.E_METADATA_VERSION_UNSUPPORTED: "The metadata version is not supported by the dumper",
    Il2CppErrorCode.E_REGISTRATION_NOT_FOUND: "CodeRegistration / MetadataRegistration were not found",
    Il2CppErrorCode.E_DOTNET_MISSING: "A suitable .NET runtime is not available",
    Il2CppErrorCode.E_TOOL_DOWNLOAD_FAILED: "The dumper could not be obtained",
    Il2CppErrorCode.E_TIMEOUT: "The dumper timed out",
    Il2CppErrorCode.E_UNKNOWN: "The dumper failed for an unclassified reason",
}

REMEDIATIONS: Dict[Il2CppErrorCode, str] = {
    Il2CppErrorCode.E_BINARY_FAIRPLAY: (
        "The Mach-O is encrypted with FairPlay (LC_ENCRYPTION_INFO cryptid != 0), so no dumper can read its "
        "code. This tool never decrypts it. Provide an IPA that its owner has already decrypted and re-run."),
    Il2CppErrorCode.E_METADATA_ENCRYPTED: (
        "The file is not a plain IL2CPP metadata file (wrong magic 0xFAB11BAF or unreadable structures); the "
        "game most likely encrypts or obfuscates it. Deobfuscation is out of scope. If you are authorised and "
        "can obtain a plain global-metadata.dat (for example the game's own loader output), pass it in and retry."),
    Il2CppErrorCode.E_METADATA_VERSION_UNSUPPORTED: (
        "The metadata version is newer or older than the selected dumper supports. Install/allow a fallback "
        "backend (Cpp2IL needs the Unity version; Il2CppInspectorRedux needs .NET 10) with "
        "'ipa-analyze tools install cpp2il' or 'tools install redux', or upgrade the dumper."),
    Il2CppErrorCode.E_REGISTRATION_NOT_FOUND: (
        "The dumper could not locate CodeRegistration/MetadataRegistration in the binary (stripped, packed or "
        "modified il2cpp, or a metadata/binary mismatch). Check that the binary is the il2cpp one "
        "(UnityFramework on Unity 2019.3+) and matches the metadata; try another backend; a manually supplied "
        "address pair is not supported in non-interactive mode."),
    Il2CppErrorCode.E_DOTNET_MISSING: (
        "No .NET runtime that satisfies the tool was found. Install one (macOS: 'brew install dotnet' or the "
        "Microsoft pkg; Linux: your package manager, e.g. 'apt install dotnet-runtime-8.0'; Windows: "
        "'winget install Microsoft.DotNet.Runtime.8'), or re-run with --yes to allow a user-level install "
        "into the cache (no admin rights needed), or pass --dotnet PATH."),
    Il2CppErrorCode.E_TOOL_DOWNLOAD_FAILED: (
        "The tool could not be downloaded or verified. Check your network/proxy (HTTPS_PROXY), or download the "
        "release manually, verify its SHA256 against data/il2cpp_backends.json and pass it with --il2cpp-tool "
        "(or set IL2CPPDUMPER_PATH). In --offline mode the tool must already be cached."),
    Il2CppErrorCode.E_TIMEOUT: (
        "The dumper did not finish in time (or stopped producing output). Increase --il2cpp-timeout, make sure "
        "the machine has enough free memory (large games need several GB), or try another backend."),
    Il2CppErrorCode.E_UNKNOWN: (
        "See the captured stdout/stderr tail for the dumper's own message and consult "
        "references/il2cpp-troubleshooting.md."),
}


def i18n_error_key(code: Il2CppErrorCode) -> str:
    return "il2cpp.error.%s" % code.value


def i18n_remediation_key(code: Il2CppErrorCode) -> str:
    return "il2cpp.remediation.%s" % code.value


def remediation_for(code: Optional[Il2CppErrorCode]) -> str:
    if code is None:
        return ""
    return REMEDIATIONS.get(code, REMEDIATIONS[Il2CppErrorCode.E_UNKNOWN])


def title_for(code: Optional[Il2CppErrorCode]) -> str:
    if code is None:
        return ""
    return ERROR_TITLES.get(code, ERROR_TITLES[Il2CppErrorCode.E_UNKNOWN])


# --- classification --------------------------------------------------------------------------------------
@dataclass
class ClassifiedFailure:
    code: Il2CppErrorCode
    message: str
    pattern: str = ""
    groups: Dict[str, str] = field(default_factory=dict)
    matched_line: str = ""


def classify_output(lines: Iterable[str], patterns: Sequence[Mapping[str, Any]], *,
                    returncode: Optional[int] = None, prompt: Optional[str] = None,
                    missing_framework_markers: Sequence[str] = (), missing_framework_rc: Optional[int] = None,
                    ) -> Optional[ClassifiedFailure]:
    """Map a tool's console output to an error code.

    Priority: missing .NET framework markers (or the host's exit code) > ``patterns`` in list order
    (the first pattern that matches any line wins) > a detected interactive prompt. Returns ``None`` when
    nothing matched (the caller then decides between ``E_UNKNOWN`` and success).
    """
    text_lines = [ln for ln in lines]
    for marker in missing_framework_markers:
        for ln in text_lines:
            if marker in ln:
                return ClassifiedFailure(Il2CppErrorCode.E_DOTNET_MISSING,
                                         "The .NET host reported a missing framework", marker, {}, ln)
    if missing_framework_rc is not None and returncode == missing_framework_rc:
        return ClassifiedFailure(Il2CppErrorCode.E_DOTNET_MISSING,
                                 "The .NET host exited with the missing-framework code %d" % returncode)
    for pat in patterns:
        try:
            rx = re.compile(str(pat["pattern"]))
            code = Il2CppErrorCode(pat["code"])
        except (re.error, KeyError, ValueError):
            continue
        for ln in text_lines:
            m = rx.search(ln)
            if m:
                msg = _message_for(code, m.groupdict(), ln)
                return ClassifiedFailure(code, msg, str(pat["pattern"]), {k: v for k, v in m.groupdict().items() if v},
                                         ln)
    if prompt:
        return ClassifiedFailure(Il2CppErrorCode.E_UNKNOWN,
                                 "The tool is waiting for interactive input: %r" % prompt.strip(), "prompt", {}, prompt)
    return None


def _message_for(code: Il2CppErrorCode, groups: Mapping[str, Optional[str]], line: str) -> str:
    line = line.strip()
    if code is Il2CppErrorCode.E_METADATA_VERSION_UNSUPPORTED and groups.get("ver"):
        return "Metadata version %s is not supported by this backend" % groups["ver"]
    return line[:300] if line else title_for(code)


# --- redaction / tails --------------------------------------------------------------------------------------
_USER_PATH_RE = re.compile(
    r"(?P<prefix>(?:[A-Za-z]:)?[\\/](?:Users|home)[\\/])(?P<user>[^\\/\s\"':]+)", re.IGNORECASE)


def redact_text(text: str, *, home: Optional[Path] = None) -> str:
    """Replace the user's home directory and ``/Users/<name>`` / ``C:\\Users\\<name>`` segments."""
    if not text:
        return text
    out = text
    try:
        h = str(home if home is not None else Path.home())
    except (RuntimeError, OSError):
        h = ""
    if h and len(h) > 3:
        out = out.replace(h, "~")
    out = _USER_PATH_RE.sub(lambda m: m.group("prefix") + "<user>", out)
    user = os.environ.get("USERNAME") or os.environ.get("USER") or ""
    if user and len(user) >= 3:
        out = re.sub(r"(?<![A-Za-z0-9_])%s(?![A-Za-z0-9_])" % re.escape(user), "<user>", out)
    return out


def redact_lines(lines: Iterable[str], *, home: Optional[Path] = None) -> List[str]:
    return [redact_text(ln, home=home) for ln in lines]


def tail_lines(lines: Sequence[str], n: int = 200) -> List[str]:
    return list(lines[-n:]) if n > 0 else []

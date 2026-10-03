"""ToolManager: catalog, resolution order, offline guarantee, verified download/install against a local HTTP server."""
from __future__ import annotations

import hashlib
import http.server
import io
import json
import os
import socketserver
import sys
import threading
import time
import urllib.request
import zipfile

import pytest

from ipa_analyzer.config import Config
from ipa_analyzer.il2cpp import Il2CppErrorCode as E
from ipa_analyzer.il2cpp import tools as T
from ipa_analyzer.il2cpp.errors import ToolDownloadError

def local_policy(**kw):
    base = dict(allowed_hosts=("127.0.0.1",), require_https=False, retries=1, timeout_s=3.0, backoff_s=0.0)
    base.update(kw)
    return T.DownloadPolicy(**base)


@pytest.fixture(autouse=True)
def _no_proxy(monkeypatch):
    monkeypatch.setenv("NO_PROXY", "127.0.0.1,localhost")
    monkeypatch.setenv("no_proxy", "127.0.0.1,localhost")
    for k in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "ALL_PROXY", "all_proxy"):
        monkeypatch.delenv(k, raising=False)


class _Server:
    def __init__(self, routes):
        outer = self
        self.hits = []

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):  # silence
                pass

            def do_GET(self):
                outer.hits.append(self.path)
                route = routes.get(self.path)
                if route is None:
                    self.send_response(404)
                    self.end_headers()
                    return
                kind = route[0]
                if kind == "redirect":
                    self.send_response(302)
                    self.send_header("Location", route[1].replace("{port}", str(outer.port)))
                    self.end_headers()
                elif kind == "sleep":
                    time.sleep(route[1])
                    self.send_response(200)
                    self.end_headers()
                elif kind == "trunc":
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(route[1]) + 100))
                    self.end_headers()
                    self.wfile.write(route[1])
                else:
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(route[1])))
                    self.end_headers()
                    self.wfile.write(route[1])

        self.httpd = socketserver.ThreadingTCPServer(("127.0.0.1", 0), H)
        self.httpd.daemon_threads = True
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def url(self, path):
        return "http://127.0.0.1:%d%s" % (self.port, path)

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture
def server():
    made = []

    def make(routes):
        s = _Server(routes)
        made.append(s)
        return s
    yield make
    for s in made:
        s.close()


def sha(b):
    return hashlib.sha256(b).hexdigest()


def make_zip(members: dict) -> bytes:
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    return bio.getvalue()


# --- catalog -------------------------------------------------------------------------------------------------------
def test_shipped_catalog_is_consistent():
    cat = T.load_catalog()
    assert cat["default_order"] == ["il2cppdumper", "cpp2il", "redux"]
    allowed = set(cat["download"]["allowed_hosts"])
    assert "github.com" in allowed and "release-assets.githubusercontent.com" in allowed
    for name, b in cat["backends"].items():
        assert b["version"] and b["sources"], name
        ids = [a["id"] for a in b["assets"]]
        assert len(ids) == len(set(ids)), name
        for a in b["assets"]:
            assert len(a["sha256"]) == 64 and int(a["sha256"], 16) >= 0, (name, a["id"])
            assert a["url"].startswith("https://github.com/"), a["url"]
            assert a["url"].endswith(a["filename"]) and a["size"] > 0
            assert a["archive"] in ("zip", "none") and a["entry"]
    d = cat["backends"]["il2cppdumper"]
    assert d["metadata_versions"] == {"min": 16, "max": 31, "note": d["metadata_versions"]["note"]}
    assert d["config"]["applied"]["RequireAnyKey"] is False
    assert cat["dotnet"]["roll_forward"] == "Major"


def test_pinned_il2cppdumper_hashes():
    # computed locally from the release assets on 2026-10-03
    cat = T.load_catalog()
    by_id = {a["id"]: a for a in cat["backends"]["il2cppdumper"]["assets"]}
    assert by_id["net6"]["sha256"] == "db9bbbc538e33abfb057c7757ae5d6c1f16a05fdc0d13af8a5a67ea31faaba0c"
    assert by_id["win_selfcontained"]["sha256"] == "f5fc60dfc5c034c1ff3fc651514416ebd47658a63493207734537fd25fa2dea2"


@pytest.mark.parametrize("platforms,system,machine,ok", [
    (["any"], "Linux", "x86_64", True), (["windows"], "Windows", "AMD64", True), (["windows"], "Linux", "x86_64", False),
    (["darwin-arm64"], "Darwin", "arm64", True), (["darwin-arm64"], "Darwin", "x86_64", False),
    (["linux-aarch64"], "Linux", "arm64", True), (["linux-x86_64"], "Linux", "amd64", True),
    (["windows-arm64"], "Windows", "ARM64", True), (["windows-x86_64"], "Windows", "ARM64", False)])
def test_platform_matches(platforms, system, machine, ok):
    assert T.platform_matches(platforms, system, machine) is ok


def test_asset_choice_per_platform():
    mgr = T.ToolManager(Config(), offline=True)
    dumper, cpp = mgr.spec("il2cppdumper"), mgr.spec("cpp2il")
    assert T.preferred_asset_ids(dumper, system="Linux", machine="x86_64")[0] == "net6"
    assert T.preferred_asset_ids(dumper, system="Windows", machine="AMD64", dotnet_available=True)[0] == "net6"
    # Windows without .NET: the self-contained build needs no runtime at all
    assert T.preferred_asset_ids(dumper, system="Windows", machine="AMD64", dotnet_available=False)[0] == "win_selfcontained"
    mac = T.preferred_asset_ids(dumper, system="Darwin", machine="arm64", dotnet_available=False)
    assert mac[0] == "net6" and "win_selfcontained" not in mac
    assert T.preferred_asset_ids(cpp, system="Darwin", machine="arm64") == ["osx-arm64"]
    assert T.preferred_asset_ids(cpp, system="Linux", machine="aarch64") == ["linux-arm64"]
    assert T.preferred_asset_ids(cpp, system="Windows", machine="AMD64") == ["win-x64"]


def test_aliases():
    assert T.canonical_name("Il2CppDumper") == "il2cppdumper" and T.canonical_name("Il2CppInspectorRedux") == "redux"
    mgr = T.ToolManager(Config(), offline=True)
    with pytest.raises(KeyError):
        mgr.spec("nope")


# --- resolution order --------------------------------------------------------------------------------------------------
def test_resolve_explicit_python_script(fake_tool, mgr):
    r = mgr.resolve("il2cppdumper", explicit=str(fake_tool))
    assert r.ok and r.kind == "python" and r.source == "explicit"
    assert r.command == [sys.executable, str(fake_tool)] and r.tool_dir == fake_tool.parent and r.min_dotnet == 0


def test_resolve_explicit_missing_path_is_actionable(mgr, tmp_path):
    r = mgr.resolve("il2cppdumper", explicit=str(tmp_path / "nope.dll"))
    assert not r.ok and "does not exist" in r.message and "--il2cpp-tool" in r.remediation


def test_resolve_cfg_tool_path_applies_only_to_dumper(fake_tool, tmp_path):
    cfg = Config()
    cfg.il2cpp.tool_path = str(fake_tool)
    mgr = T.ToolManager(cfg, cache_root=tmp_path / "c", offline=True, env={"PATH": ""})
    assert mgr.resolve("il2cppdumper").source == "explicit"
    assert not mgr.resolve("cpp2il").ok


def test_resolution_order_explicit_env_path_cache(tmp_path, fake_tool):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    exe = bindir / ("Il2CppDumper.cmd" if os.name == "nt" else "Il2CppDumper")
    exe.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    exe.chmod(0o755)
    envfile = tmp_path / "envtool" / "dumper.py"
    envfile.parent.mkdir()
    envfile.write_text("print(1)", encoding="utf-8")
    env = {"PATH": str(bindir), "IL2CPPDUMPER_PATH": str(envfile)}
    mgr = T.ToolManager(Config(), cache_root=tmp_path / "c", offline=True, env=env)
    assert mgr.resolve("il2cppdumper", explicit=str(fake_tool)).source == "explicit"
    assert mgr.resolve("il2cppdumper").source == "env"
    mgr2 = T.ToolManager(Config(), cache_root=tmp_path / "c", offline=True, env={"PATH": str(bindir)})
    if os.name != "nt":
        r = mgr2.resolve("il2cppdumper")
        assert r.source == "path" and r.kind == "native" and r.uses_dotnet_env
    # a broken env var falls through instead of failing
    mgr3 = T.ToolManager(Config(), cache_root=tmp_path / "c", offline=True,
                         env={"PATH": "", "IL2CPPDUMPER_PATH": str(tmp_path / "missing")})
    r = mgr3.resolve("il2cppdumper")
    assert not r.ok and "not installed" in r.message


def test_dll_beside_exe_preferred_off_windows(tmp_path):
    d = tmp_path / "t"
    d.mkdir()
    (d / "Il2CppDumper.dll").write_bytes(b"x")
    (d / "Il2CppDumper.exe").write_bytes(b"MZ")
    (d / "Il2CppDumper.runtimeconfig.json").write_text(
        json.dumps({"runtimeOptions": {"framework": {"name": "Microsoft.NETCore.App", "version": "7.0.0"}}}), encoding="utf-8")
    linux = T.ToolManager(Config(), cache_root=tmp_path / "c", offline=True, system="Linux", env={"PATH": ""})
    r = linux.resolve("il2cppdumper", explicit=str(d / "Il2CppDumper.exe"))
    assert r.ok and r.kind == "dotnet_dll" and r.entry.name == "Il2CppDumper.dll" and r.min_dotnet == 7
    r = linux.resolve("il2cppdumper", explicit=str(d))      # directory -> finds the dll first
    assert r.entry.name == "Il2CppDumper.dll"


def test_windows_exe_resolution_is_pure(tmp_path):
    d = tmp_path / "t"
    d.mkdir()
    (d / "Il2CppDumper.exe").write_bytes(b"MZ")
    win = T.ToolManager(Config(), cache_root=tmp_path / "c", offline=True, system="Windows", env={"PATH": ""})
    r = win.resolve("il2cppdumper", explicit=str(d / "Il2CppDumper.exe"))
    assert r.ok and r.kind == "native" and r.min_dotnet == 0 and r.uses_dotnet_env
    assert r.command == [str(d / "Il2CppDumper.exe")]


def test_unknown_tool_name():
    r = T.ToolManager(Config(), offline=True).resolve("nonexistent")
    assert not r.ok and "unknown IL2CPP tool" in r.message


# --- offline ------------------------------------------------------------------------------------------------------------
def test_offline_never_touches_the_network(tmp_path, monkeypatch):
    def boom(*a, **k):
        raise AssertionError("network access attempted in offline mode")
    monkeypatch.setattr(urllib.request, "build_opener", boom)
    monkeypatch.setattr(urllib.request, "urlopen", boom)
    monkeypatch.setattr(T.socket, "create_connection", boom)
    mgr = T.ToolManager(Config(), cache_root=tmp_path / "c", offline=True, env={"PATH": ""})
    r = mgr.resolve("il2cppdumper", install=True)
    assert not r.ok and r.error_code == E.E_TOOL_DOWNLOAD_FAILED
    assert "offline" in r.message and "not cached" in r.message and "tools install" in r.remediation
    r = mgr.install("il2cppdumper")
    assert not r.ok and "offline" in r.message and "online" in r.remediation
    from ipa_analyzer.il2cpp import dotnet
    d = dotnet.ensure_runtime(99, offline=True, cache_root=tmp_path / "c", env={"PATH": ""},
                              runtimes_fn=lambda p: [], install_fn=boom)
    assert not d.ok and d.error_code == E.E_DOTNET_MISSING


def test_unpinned_catalog_entry_refuses_download(tmp_path):
    cat = json.loads(json.dumps(T.load_catalog()))
    for a in cat["backends"]["il2cppdumper"]["assets"]:
        a["sha256"] = None

    def boom(*a, **k):
        raise AssertionError("must not download")
    mgr = T.ToolManager(Config(), cache_root=tmp_path / "c", catalog=cat, downloader=boom, env={"PATH": ""})
    r = mgr.install("il2cppdumper")
    assert not r.ok and r.error_code == E.E_TOOL_DOWNLOAD_FAILED and "SHA256" in r.message
    assert "manually" in r.remediation


# --- download -----------------------------------------------------------------------------------------------------------
def test_download_success_and_sha_check(server, tmp_path):
    payload = b"hello world" * 1000
    s = server({"/f.bin": ("ok", payload)})
    p = T.download_file(s.url("/f.bin"), tmp_path / "d", sha256=sha(payload), policy=local_policy(), expected_size=len(payload))
    assert p.read_bytes() == payload and p.name == "f.bin"
    assert [x.name for x in (tmp_path / "d").iterdir()] == ["f.bin"]


def test_download_sha_mismatch_is_rejected_and_cleaned(server, tmp_path):
    s = server({"/f.bin": ("ok", b"evil")})
    with pytest.raises(ToolDownloadError) as ei:
        T.download_file(s.url("/f.bin"), tmp_path / "d", sha256=sha(b"good"), policy=local_policy(retries=3))
    assert ei.value.reason == "sha256" and ei.value.code == E.E_TOOL_DOWNLOAD_FAILED
    assert list((tmp_path / "d").iterdir()) == []
    assert len(s.hits) == 1    # integrity failures are not retried


def test_download_refuses_without_pinned_hash(server, tmp_path):
    s = server({"/f.bin": ("ok", b"x")})
    with pytest.raises(ToolDownloadError) as ei:
        T.download_file(s.url("/f.bin"), tmp_path, sha256=None, policy=local_policy())
    assert ei.value.reason == "unpinned" and s.hits == []


def test_download_timeout_then_failure(server, tmp_path):
    s = server({"/slow": ("sleep", 3)})
    t0 = time.monotonic()
    with pytest.raises(ToolDownloadError) as ei:
        T.download_file(s.url("/slow"), tmp_path / "d", sha256="0" * 64, policy=local_policy(timeout_s=0.5, retries=2),
                        sleep=lambda s_: None)
    assert ei.value.reason == "network" and "2 attempt" in ei.value.message
    assert time.monotonic() - t0 < 6
    assert not list((tmp_path / "d").iterdir())


def test_download_truncated_body_is_retried_then_fails(server, tmp_path):
    s = server({"/t": ("trunc", b"abc")})
    with pytest.raises(ToolDownloadError) as ei:
        T.download_file(s.url("/t"), tmp_path / "d", sha256="0" * 64, policy=local_policy(retries=2), sleep=lambda s_: None)
    assert ei.value.reason == "network" and len(s.hits) == 2


def test_download_404_is_not_retried(server, tmp_path):
    s = server({})
    with pytest.raises(ToolDownloadError) as ei:
        T.download_file(s.url("/missing"), tmp_path, sha256="0" * 64, policy=local_policy(retries=3), sleep=lambda s_: None)
    assert ei.value.reason == "http" and len(s.hits) == 1


def test_redirect_to_non_whitelisted_host_is_rejected(server, tmp_path):
    s = server({"/r": ("redirect", "http://localhost:{port}/f.bin"), "/f.bin": ("ok", b"data")})
    with pytest.raises(ToolDownloadError) as ei:
        T.download_file(s.url("/r"), tmp_path / "d", sha256=sha(b"data"), policy=local_policy())
    assert ei.value.reason == "policy" and "allow-list" in ei.value.message
    assert "/f.bin" not in s.hits      # the redirect target was never contacted


def test_redirect_to_whitelisted_host_is_followed(server, tmp_path):
    s = server({"/r": ("redirect", "http://127.0.0.1:{port}/f.bin"), "/f.bin": ("ok", b"data")})
    p = T.download_file(s.url("/r"), tmp_path / "d", sha256=sha(b"data"), policy=local_policy(), filename="out.bin")
    assert p.read_bytes() == b"data"


def test_redirect_loop_is_bounded(server, tmp_path):
    s = server({"/a": ("redirect", "http://127.0.0.1:{port}/b"), "/b": ("redirect", "http://127.0.0.1:{port}/a")})
    with pytest.raises(ToolDownloadError):
        T.download_file(s.url("/a"), tmp_path, sha256="0" * 64, policy=local_policy(max_redirects=3))


def test_https_is_required_by_default(tmp_path):
    with pytest.raises(ToolDownloadError) as ei:
        T.download_file("http://github.com/x", tmp_path, sha256="0" * 64)
    assert ei.value.reason == "policy" and "non-HTTPS" in ei.value.message
    with pytest.raises(ToolDownloadError) as ei:
        T.download_file("https://evil.example.com/x", tmp_path, sha256="0" * 64)
    assert "allow-list" in ei.value.message


def test_download_size_limit(server, tmp_path):
    s = server({"/big": ("ok", b"x" * 5000)})
    with pytest.raises(ToolDownloadError) as ei:
        T.download_file(s.url("/big"), tmp_path, sha256="0" * 64, policy=local_policy(max_bytes=1000))
    assert ei.value.reason == "size"


# --- install ------------------------------------------------------------------------------------------------------------
def _catalog_for(server, files: dict, *, archive="zip", entry="Il2CppDumper.dll", kind="dotnet_dll", sha_override=None):
    blob = make_zip(files) if archive == "zip" else files["raw"]
    s = server({"/tool.zip": ("ok", blob)})
    cat = json.loads(json.dumps(T.load_catalog()))
    b = cat["backends"]["il2cppdumper"]
    b["assets"] = [{"id": "net6", "filename": "tool.zip", "url": s.url("/tool.zip"), "size": len(blob),
                    "sha256": sha_override or sha(blob), "archive": archive, "kind": kind, "platforms": ["any"],
                    "min_dotnet": 6, "entry": entry}]
    b["asset_selection"] = {"default": "net6"}
    return cat, s


def test_install_extracts_atomically_and_resolves_from_cache(server, tmp_path):
    cat, s = _catalog_for(server, {"sub/Il2CppDumper.dll": b"dll", "sub/config.json": b"{}",
                                   "sub/Il2CppDumper.runtimeconfig.json": json.dumps(
                                       {"runtimeOptions": {"framework": {"version": "6.0.0"}}})})
    mgr = T.ToolManager(Config(), cache_root=tmp_path / "c", catalog=cat, policy=local_policy(), env={"PATH": ""})
    r = mgr.install("il2cppdumper")
    assert r.ok and r.source == "download" and r.kind == "dotnet_dll" and r.version == "6.7.46"
    assert r.entry.name == "Il2CppDumper.dll" and r.tool_dir == r.entry.parent and r.min_dotnet == 6
    root = tmp_path / "c" / "tools"
    assert (root / "il2cppdumper" / "6.7.46" / "net6" / T.INSTALL_MARKER).is_file()
    assert not [p for p in root.iterdir() if p.name.startswith(".staging")]
    assert not list((root / ".downloads").iterdir())
    # now cached: a second resolve does not hit the server again
    hits = len(s.hits)
    r2 = T.ToolManager(Config(), cache_root=tmp_path / "c", catalog=cat, policy=local_policy(), env={"PATH": ""}).resolve("il2cppdumper")
    assert r2.ok and r2.source == "cache" and len(s.hits) == hits


def test_install_sha_mismatch_leaves_no_trace(server, tmp_path):
    cat, _s = _catalog_for(server, {"Il2CppDumper.dll": b"dll"}, sha_override="0" * 64)
    mgr = T.ToolManager(Config(), cache_root=tmp_path / "c", catalog=cat, policy=local_policy(), env={"PATH": ""})
    r = mgr.install("il2cppdumper")
    assert not r.ok and r.error_code == E.E_TOOL_DOWNLOAD_FAILED and "SHA256 mismatch" in r.message
    assert "discarded" in r.remediation
    root = tmp_path / "c" / "tools"
    assert not (root / "il2cppdumper").exists()
    assert not [p for p in root.rglob("*") if p.is_file()]


def test_install_rejects_zip_slip(server, tmp_path):
    cat, _s = _catalog_for(server, {"../evil.txt": b"x", "Il2CppDumper.dll": b"dll"})
    mgr = T.ToolManager(Config(), cache_root=tmp_path / "c", catalog=cat, policy=local_policy(), env={"PATH": ""})
    r = mgr.install("il2cppdumper")
    assert not r.ok and "unsafe path" in r.message
    assert not (tmp_path / "c" / "evil.txt").exists() and not (tmp_path / "evil.txt").exists()


def test_install_missing_entry_in_archive(server, tmp_path):
    cat, _s = _catalog_for(server, {"readme.txt": b"x"})
    mgr = T.ToolManager(Config(), cache_root=tmp_path / "c", catalog=cat, policy=local_policy(), env={"PATH": ""})
    r = mgr.install("il2cppdumper")
    assert not r.ok and "does not contain" in r.message


def test_install_raw_binary_gets_exec_bit(server, tmp_path):
    cat, _s = _catalog_for(server, {"raw": b"\x7fELF-ish"}, archive="none", entry="Cpp2IL", kind="native")
    # reuse the il2cppdumper slot but make it look like a native tool
    cat["backends"]["il2cppdumper"]["assets"][0]["entry"] = "Il2CppDumper"
    cat["backends"]["il2cppdumper"]["executable_names"] = ["Il2CppDumper"]
    mgr = T.ToolManager(Config(), cache_root=tmp_path / "c", catalog=cat, policy=local_policy(), system="Linux",
                        machine="x86_64", env={"PATH": ""})
    r = mgr.install("il2cppdumper")
    assert r.ok and r.kind == "native"
    if os.name != "nt":
        assert os.access(str(r.entry), os.X_OK)


def test_adhoc_codesign_only_on_macos(monkeypatch, tmp_path):
    calls = []

    class R:
        ok = True
        stderr = error = ""
    monkeypatch.setattr(T._procs, "run", lambda cmd, timeout, **k: (calls.append(cmd), R())[1])
    monkeypatch.setattr(T.shutil, "which", lambda n: "/usr/bin/codesign")
    assert T.adhoc_codesign(tmp_path / "x", system="Linux") is None and calls == []
    assert T.adhoc_codesign(tmp_path / "x", system="Darwin") is None
    assert calls[0][:4] == ["/usr/bin/codesign", "-s", "-", "--force"]


# --- archive safety ---------------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("name,unsafe", [
    ("a/b.txt", False), ("./a.txt", False), ("../a", True), ("a/../../b", True), ("/abs", True), ("C:\\x", True),
    ("C:/x", True), ("a\\..\\..\\b", True), ("\\\\server\\share", True), ("", True)])
def test_unsafe_member_names(name, unsafe):
    assert T._unsafe_member(name) is unsafe


def test_zip_bomb_limits(tmp_path):
    z = tmp_path / "b.zip"
    z.write_bytes(make_zip({"big.bin": b"\0" * (3 * 1024 * 1024)}))
    with pytest.raises(ToolDownloadError):
        T.safe_extract_zip(z, tmp_path / "o", max_total=1024 * 1024)
    with pytest.raises(ToolDownloadError):
        T.safe_extract_zip(z, tmp_path / "o2", max_ratio=10.0)
    z2 = tmp_path / "many.zip"
    z2.write_bytes(make_zip({"f%d" % i: b"x" for i in range(10)}))
    with pytest.raises(ToolDownloadError):
        T.safe_extract_zip(z2, tmp_path / "o3", max_files=5)


def test_windows_illegal_names_are_sanitised(tmp_path):
    z = tmp_path / "w.zip"
    z.write_bytes(make_zip({"dir/CON.txt": b"x", "dir/a:b.txt": b"y"}))
    out = T.safe_extract_zip(z, tmp_path / "o")
    names = sorted(p.name for p in out)
    assert "CON.txt" not in names and all(":" not in n for n in names)


def test_bad_zip(tmp_path):
    z = tmp_path / "x.zip"
    z.write_bytes(b"not a zip")
    with pytest.raises(ToolDownloadError):
        T.safe_extract_zip(z, tmp_path / "o")


# --- CLI ------------------------------------------------------------------------------------------------------------
class _Args:
    def __init__(self, **kw):
        self.offline, self.yes, self.dotnet, self.verbose, self.name = True, False, None, 0, ""
        self.__dict__.update(kw)


def test_cli_list_and_path(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("IPA_ANALYZER_HOME", str(tmp_path / "home"))
    monkeypatch.delenv("IL2CPPDUMPER_PATH", raising=False)
    assert T.cmd_tools_list(_Args()) == 0
    out = capsys.readouterr().out
    assert "il2cppdumper" in out and "cpp2il" in out and "redux" in out and str(tmp_path / "home") in out
    assert T.cmd_tools_path(_Args(name="nonexistent")) == T.EXIT_USAGE
    rc = T.cmd_tools_path(_Args(name="il2cppdumper"))
    err = capsys.readouterr().err
    assert rc in (0, T.EXIT_FAIL)     # PATH may contain a real Il2CppDumper on the developer machine
    assert rc == 0 or "not installed" in err
    assert T.cmd_tools_install(_Args(name="il2cppdumper")) == T.EXIT_FAIL    # offline
    assert "offline" in capsys.readouterr().err
    assert T.cmd_tools_install(_Args(name="bogus")) == T.EXIT_USAGE

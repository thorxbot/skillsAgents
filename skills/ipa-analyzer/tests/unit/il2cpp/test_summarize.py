"""summarize_dump: streaming counts, namespaces, framework hits and obfuscation scoring."""
from __future__ import annotations

import json
import random
import tracemalloc
from pathlib import Path

import pytest

from ipa_analyzer.il2cpp import summarize as S


def write_dump(path: Path, types, *, ns_prefix="Game", images=("Assembly-CSharp.dll", "UnityEngine.CoreModule.dll")):
    """types: iterable of (namespace, kind, name, fields, methods)."""
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        for i, im in enumerate(images):
            fh.write("// Image %d: %s - %d\n" % (i, im, i * 10))
        for idx, (ns, kind, name, fields, methods) in enumerate(types):
            fh.write("\n// Namespace: %s\n" % ns)
            fh.write("public %s%s : System.Object // TypeDefIndex: %d\n{\n" % ("" if kind == "enum" else "sealed ", kind + " " + name, idx))
            if fields:
                fh.write("\t// Fields\n")
                for f in fields:
                    fh.write("\tprivate int %s; // 0x10\n" % f)
            if methods:
                fh.write("\n\t// Methods\n")
                for m in methods:
                    fh.write("\n\t// RVA: 0x1000 Offset: 0x1000 VA: 0x1000\n\tpublic void %s() { }\n" % m)
            fh.write("}\n")


def normal_types(n=200):
    rnd = random.Random(1)
    words = ["Player", "Enemy", "Weapon", "Inventory", "Manager", "Controller", "Health", "Score", "Level", "Camera"]
    acts = ["Update", "GetHealth", "SetScore", "OnEnable", "LoadLevel", "Spawn", "Reset"]
    out = []
    for i in range(n):
        name = "%s%s%d" % (rnd.choice(words), rnd.choice(words), i)
        out.append(("Game.Core" if i % 2 else "Game.UI", "class", name,
                    ["health", "speed", "m_count"], [rnd.choice(acts) for _ in range(3)]))
    return out


def junk_types(n=200, *, style="short"):
    rnd = random.Random(2)
    out = []
    for i in range(n):
        if style == "short":
            mk = lambda: "".join(rnd.choice("abcdefgh") for _ in range(rnd.choice((1, 2))))
        elif style == "garbled":
            mk = lambda: "".join(chr(rnd.choice([1, 2, 0x200B, 0xE000, 0x2588, 0x25A0])) for _ in range(6))
        else:   # random-looking alphanumerics
            mk = lambda: "".join(rnd.choice("bcdfghjklmnpqrstvwxz") for _ in range(10))
        out.append(("", "class", mk() + str(i % 3), [mk(), mk()], [mk(), mk(), mk()]))
    return out


def test_counts_and_namespaces(tmp_path):
    write_dump(tmp_path / "dump.cs", [
        ("Game.Core", "class", "Player", ["health", "speed"], ["Update", "GetHealth"]),
        ("HybridCLR", "class", "RuntimeApi", [], ["Load"]),
        ("Game.Core", "enum", "State", ["Idle", "Run"], []),
        ("Game.Core", "interface", "IThing", [], []),
        ("Game.Core", "struct", "Vec", ["x"], []),
        ("", "class", "GlobalThing", [], []),
    ])
    (tmp_path / "stringliteral.json").write_text(
        '[\n  {\n    "value": "a \\"address\\": b",\n    "address": "0x1"\n  },\n  {\n    "value": "c",\n    "address": "0x2"\n  }\n]',
        encoding="utf-8")
    s = S.summarize_dump(tmp_path)
    assert s.source == "dump.cs" and s.assemblies == 2 and s.assembly_names == ["Assembly-CSharp.dll", "UnityEngine.CoreModule.dll"]
    assert (s.classes, s.structs, s.enums, s.interfaces) == (3, 1, 1, 1)
    assert s.methods == 3 and s.fields == 5 and s.string_literals == 2
    assert s.namespaces_total == 3 and s.namespaces[0] == "Game.Core"
    assert S.GLOBAL_NAMESPACE in s.namespaces
    assert (tmp_path / "namespaces.txt").read_text(encoding="utf-8").splitlines() == ["1\t(global)", "4\tGame.Core", "1\tHybridCLR"]
    assert s.namespaces_file == "namespaces.txt"
    assert "HybridCLR" in s.framework_namespaces and {h["id"] for h in s.framework_hits} == {"hybridclr"}
    d = s.to_dict()
    for key in ("assemblies", "classes", "interfaces", "enums", "methods", "fields", "string_literals",
                "framework_namespaces", "obfuscation"):
        assert key in d
    assert set(d["obfuscation"]) >= {"score", "non_standard_ratio", "short_ratio", "non_ascii_ratio"}
    json.dumps(d)       # JSON-able


def test_member_parsing_edge_cases(tmp_path):
    (tmp_path / "dump.cs").write_text(
        "// Image 0: A.dll - 0\n\n// Namespace: N\n[Serializable]\npublic class Foo<T> : Bar<T> // TypeDefIndex: 0\n{\n"
        "\t// Fields\n\t[CompilerGenerated]\n\tpublic const int K = 5;\n\tprivate static readonly string S = \"a = b\"; // 0x0\n"
        "\tprivate Dictionary<string, int> map; // 0x20\n\n\t// Properties\n\tpublic int P { get; set; }\n\n"
        "\t// Methods\n\n\t// RVA: -1 Offset: -1\n\tpublic abstract void Abs();\n\n\t// RVA: 0x10 Offset: 0x10 VA: 0x10\n"
        "\tpublic T Gen<U>(U a, ref int b) { }\n\t// RVA: 0x20 Offset: 0x20 VA: 0x20\n\tpublic void .ctor() { }\n}\n",
        encoding="utf-8")
    s = S.summarize_dump(tmp_path, write_namespaces=False)
    assert (s.classes, s.fields, s.properties, s.methods) == (1, 3, 1, 3)
    assert s.namespaces_file is None and not (tmp_path / "namespaces.txt").exists()
    assert s.obfuscation.names_considered == 1 + 3 + 1 + 2     # Foo, K/S/map, P, Abs/Gen (.ctor ignored)


def test_missing_and_malformed_inputs(tmp_path):
    s = S.summarize_dump(tmp_path / "nothing")
    assert s.source == "none" and s.warnings and s.classes == 0
    (tmp_path / "dump.cs").write_bytes(b"\xff\xfe\x00garbage\x00\n\t// Fields\n\t\n{{{\n")
    s = S.summarize_dump(tmp_path)
    assert s.source == "dump.cs" and s.classes == 0
    (tmp_path / "dump.cs").write_text("", encoding="utf-8")
    assert S.summarize_dump(tmp_path).obfuscation.score == 0.0


def test_obfuscation_scores_separate_normal_from_junk(tmp_path):
    scores = {}
    for label, types in (("normal", normal_types()), ("short", junk_types(style="short")),
                         ("garbled", junk_types(style="garbled")), ("random", junk_types(style="random"))):
        d = tmp_path / label
        d.mkdir()
        write_dump(d / "dump.cs", types)
        scores[label] = S.summarize_dump(d).obfuscation
    assert scores["normal"].score < 0.1 and scores["normal"].level == "none"
    assert scores["normal"].short_ratio < 0.05 and scores["normal"].non_standard_ratio == 0
    for k in ("short", "garbled", "random"):
        assert scores[k].score > 0.5 and scores[k].level in ("medium", "high"), (k, scores[k])
        assert scores[k].score > scores["normal"].score + 0.4
    assert scores["short"].short_ratio > 0.4
    assert scores["garbled"].garbled_ratio > 0.9 and scores["garbled"].non_standard_ratio > 0.9
    assert scores["random"].random_like_ratio > 0.5
    assert scores["garbled"].examples


def test_legit_cjk_identifiers_do_not_look_obfuscated(tmp_path):
    names = ["玩家", "背包系统", "战斗管理", "关卡数据", "角色控制器"]
    write_dump(tmp_path / "dump.cs", [("Game", "class", n + str(i), ["生命值"], ["开始战斗"]) for i, n in enumerate(names * 20)])
    ob = S.summarize_dump(tmp_path).obfuscation
    assert ob.non_ascii_ratio > 0.9 and ob.garbled_ratio == 0 and ob.score < 0.35


def test_compiler_generated_names_are_ignored(tmp_path):
    write_dump(tmp_path / "dump.cs", [("N", "class", "<>c__DisplayClass1_0", ["<Name>k__BackingField"], ["<Start>b__0"]),
                                      ("N", "class", "<Module>", [], [])])
    assert S.summarize_dump(tmp_path).obfuscation.names_considered == 0


def test_framework_rules_builtin_and_libs_json(tmp_path):
    ns = ["XLua", "Cysharp.Threading.Tasks.Linq", "DG.Tweening.Core", "Newtonsoft.Json.Linq", "Mirrorsomething", "Game.XLuaFake"]
    assert {h["id"] for h in S.match_frameworks(ns, [], S.load_framework_rules([tmp_path / "none.json"])[0])} == \
        {"xlua", "unitask", "dotween", "newtonsoft"}
    libs = tmp_path / "libs.json"
    libs.write_text(json.dumps({"libs": [{"id": "acme", "name": "Acme SDK", "match": {"namespace": ["Acme.Sdk", "AcmeCore.*"]}},
                                         {"id": "nomatch", "match": {"symbol": "x"}}, "junk", {"id": "x"}]}), encoding="utf-8")
    rules, warns = S.load_framework_rules([libs])
    hits = S.match_frameworks(["Acme.Sdk.Net", "AcmeCore.Util"], [], rules)
    assert {(h["id"], h["namespace"]) for h in hits} == {("acme", "Acme.Sdk"), ("acme", "AcmeCore")} and not warns
    (tmp_path / "bad.json").write_text("{not json", encoding="utf-8")
    rules, warns = S.load_framework_rules([tmp_path / "bad.json"])
    assert len(rules) == len(S.BUILTIN_FRAMEWORKS) and warns       # degrades to the built-in table
    assert S.load_framework_rules([libs.parent / "list.json"])[0]  # missing file is fine
    (tmp_path / "list.json").write_text(json.dumps([{"id": "l", "name": "L", "match": {"namespace": "L.Ns"}}]), encoding="utf-8")
    assert any(r["id"] == "l" for r in S.load_framework_rules([tmp_path / "list.json"])[0])


def test_framework_matching_by_assembly_name():
    hits = S.match_frameworks([], ["UniTask.dll", "Other.dll"], [{"id": "u", "name": "U", "namespaces": ["UniTask"]}])
    assert hits and hits[0]["namespace"] == "UniTask"


def test_cs_tree_fallback(tmp_path):
    t = tmp_path / "DiffableCs" / "Assembly-CSharp" / "Game"
    t.mkdir(parents=True)
    (t / "Player.cs").write_text("namespace Game;\n\npublic class Player : MonoBehaviour\n{\n}\n", encoding="utf-8")
    (t / "State.cs").write_text("namespace Game;\n\n[Flags]\npublic enum State\n{\n}\n", encoding="utf-8")
    s = S.summarize_dump(tmp_path)
    assert s.source == "cs_tree" and (s.classes, s.enums) == (1, 1) and s.assemblies == 1
    assert s.namespaces == ["Game"] and s.methods == 0 and any("not available" in w for w in s.warnings)


def _dump_with_size(path: Path, target_bytes: int):
    rnd = random.Random(3)
    acts = ["Update", "GetHealth", "SetScore", "OnEnable", "LoadLevel"]
    written, i = 0, 0
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("// Image 0: Assembly-CSharp.dll - 0\n")
        while written < target_bytes:
            block = ["\n// Namespace: Game.Ns%d\n" % (i % 50), "public class Type%d : MonoBehaviour // TypeDefIndex: %d\n{\n" % (i, i),
                     "\t// Fields\n"]
            block += ["\tprivate int field%d; // 0x%X\n" % (j, 16 + j * 4) for j in range(6)]
            block.append("\n\t// Methods\n")
            for j in range(8):
                block.append("\n\t// RVA: 0x%X Offset: 0x%X VA: 0x%X\n\tpublic void %s%d() { }\n" % (i, i, i, rnd.choice(acts), j))
            block.append("}\n")
            data = "".join(block)
            fh.write(data)
            written += len(data)
            i += 1
    return i


def test_streaming_memory_is_flat(tmp_path):
    n = _dump_with_size(tmp_path / "dump.cs", 6 * 1024 * 1024)
    tracemalloc.start()
    s = S.summarize_dump(tmp_path)
    _cur, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert s.classes == n and s.methods == n * 8
    assert peak < 8 * 1024 * 1024, "peak %d bytes for a 6 MB dump" % peak


@pytest.mark.slow
def test_streaming_50mb_dump(tmp_path):
    import time
    n = _dump_with_size(tmp_path / "dump.cs", 50 * 1024 * 1024)
    tracemalloc.start()
    t0 = time.monotonic()
    s = S.summarize_dump(tmp_path)
    dt = time.monotonic() - t0
    _cur, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert s.classes == n and s.namespaces_total == 50
    assert peak < 16 * 1024 * 1024, peak        # dictionary of 50 namespaces + counters only
    assert dt < 120

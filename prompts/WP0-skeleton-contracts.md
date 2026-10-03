# WP0 — 项目骨架 + 公共契约(Wave 0,所有人的前置)

先读 `prompts/_common.md`。你是整个项目的"地基",**产出会被冻结,其他 8 个 agent 并行依赖它**,所以宁可小而稳。

## 目标
搭出可运行的空流水线:`ipa-analyze <任意 zip>` 能跑完所有(桩)阶段并输出合法的 `report.json`;冻结公共 API 与数据契约。

## 文件归属
`pyproject.toml`、`README.md`(骨架)、`SKILL.md`(占位)、`scripts/ipa_analyze.py`、
`src/ipa_analyzer/{__init__,__main__,cli,models,context,pipeline,registry,errors,config}.py`、
`src/ipa_analyzer/util/{__init__,hashing,entropy,paths,procs,plist_utils}.py`、
`src/ipa_analyzer/analyzers/__init__.py`(自动发现)以及 **所有阶段的桩文件**(见下)、`src/ipa_analyzer/engines/{__init__,api}.py`、`engines/checkers/{__init__,_example}.py`、
`src/ipa_analyzer/ingest/__init__.py`(仅 `ArchiveSource` Protocol)、`il2cpp/__init__.py`(仅 Protocol/类型)、
`schemas/report.schema.json`、`tests/conftest.py`、`tests/unit/test_pipeline_smoke.py`、`.github/workflows/ci.yml`(放在项目根 `.github/`)、`docs/CONTRACT-FREEZE.md`。

## 要做的事
1. **models.py**:按 `02-ARCHITECTURE.md` §3 实现 `Verdict/Status/Evidence/Finding/StageResult/Report` 等 dataclass,带 `to_dict()`(稳定键序)与 `from_dict()`。`Config` dataclass(输出目录、语言、格式、阶段开关、限额、`offline`、`redact`、`assume_yes` 等)。子配置必须包含:`il2cpp{enabled, force_dump, timeout_s=900, tool_path, dotnet_path, backend_order}`、`unity{bundle_deep_sample=200}`、`limits{max_total_extract, max_file_size, max_files, max_ratio}`、`libs_user_path`、`signature_integrity`(bool)。
2. **registry / pipeline**:
   - `@register(name=..., requires=[...], after=[...])` 装饰器,Analyzer 接口 `run(ctx) -> StageResult`。
   - `pipeline.run(ctx)`:拓扑排序;硬依赖失败 / 跳过 ⇒ 下游标 `skipped(reason="dependency X failed")`;软依赖 `after` 仅影响顺序;每阶段 try/except 隔离、计时;循环依赖启动时报错。
   - `analyzers/__init__.py` 用 `pkgutil.iter_modules` 自动导入本包下全部模块(导入失败的模块记录为一个 `failed` 的伪阶段而不是崩溃)。
3. **引擎检查器插件接口** `src/ipa_analyzer/engines/api.py`(WP0 只定义接口与注册器,不写业务):`EngineChecker` Protocol(`engine_id`、`applies(ctx, detect) -> bool`、`run(ctx, detect) -> CheckerResult{findings, data}`)、`@register_checker(engine_id)`、`engines/checkers/__init__.py` 用 `pkgutil` 自动导入该包下所有模块(单个导入失败只记录,不崩溃)、`engines/checkers/_example.py` 示例。另定义 `EngineSignature / FingerprintResult / DetectResult` dataclass(字段见 `02-ARCHITECTURE.md` §4.7),并在 `CONTRACT-FREEZE.md` 写明 `ctx.results["engine.fingerprint"]`、`["engine.detect"]`、`["engine.other"]` 的形状(`engine.detect` 至少含 `primary{id,name,confidence}`、`candidates[{id,confidence}]`、`custom{verdict,confidence}`、`wrapper`、`is_game_engine`)。
4. **桩阶段**(每个文件只含 `@register` + 返回 `Status.SKIPPED, reason="not implemented"`,**名字与依赖必须与下表完全一致**,下游 WP 会替换文件内容):

   | 文件 | name | requires | after |
   |---|---|---|---|
   | analyzers/ingest_stage.py (WP1) | `ingest` | – | – |
   | analyzers/inventory.py (WP1) | `inventory` | ingest | – |
   | analyzers/meta.py (WP2) | `meta` | ingest | – |
   | analyzers/macho_stage.py (WP3) | `macho` | inventory | – |
   | analyzers/engine_fingerprint.py (WP7) | `engine.fingerprint` | inventory | macho, meta |
   | analyzers/engine_detect.py (WP7) | `engine.detect` | inventory | macho, meta, engine.fingerprint |
   | analyzers/engines_other.py (WP7b) | `engine.other` | engine.detect | – |
   | analyzers/unity.py (WP5) | `engine.unity` | engine.detect, inventory | macho, meta |
   | analyzers/unity_hotfix.py (WP5b) | `engine.unity.hotfix` | engine.unity | inventory, macho |
   | analyzers/libs.py (WP4) | `libs` | inventory | macho, engine.fingerprint, engine.unity, engine.unity.hotfix, engine.other |
   | analyzers/protect.py (WP4) | `protect` | inventory | macho, engine.unity, engine.unity.hotfix, engine.other, libs |
   | analyzers/classify.py (WP4) | `classify` | – | meta, engine.detect, engine.fingerprint, libs |
   | analyzers/report_stage.py (WP8) | `report` | – | 所有其他阶段 |

   `report` 阶段:无论其他阶段成败都要运行。
5. **ArchiveSource Protocol**(`ingest/__init__.py`):`kind`、`namelist() -> list[EntryInfo]`、`stat(name)`、`open(name)`、`read_head(name, n)`、`extract_to(name, dest)`;`EntryInfo(name, size, compressed_size, is_dir, is_symlink, crc, mode)`。另给一个**最小**的 `ZipSource` 仅供冒烟测试(WP1 会重写替换,接口不变)。
6. **Il2CPP 契约**(`il2cpp/__init__.py`):`Il2CppRunRequest / Il2CppRunResult / Il2CppErrorCode(Enum: E_BINARY_FAIRPLAY, E_METADATA_ENCRYPTED, E_METADATA_VERSION_UNSUPPORTED, E_REGISTRATION_NOT_FOUND, E_DOTNET_MISSING, E_TOOL_DOWNLOAD_FAILED, E_TIMEOUT, E_UNKNOWN) / Il2CppBackend Protocol / run_il2cpp_dump 函数签名(抛 NotImplementedError)`。
7. **util 最小集**:`hashing.sha256_stream`、`entropy.shannon(data)` 与 `sampled_entropy(fileobj, size)`(头 64KB + 均匀抽样若干块)、`paths`(缓存目录解析:macOS/Linux/Windows + `IPA_ANALYZER_HOME`、`is_within(base, p)`、`sanitize_component` 处理 Windows 保留名 / 非法字符 / 末尾点空格)、`procs.run(cmd, timeout, env, cwd) -> ProcResult` 与 `kill_tree(proc)`(POSIX 进程组 / Windows `taskkill /T /F`)、`plist_utils.load_plist(bytes)`(二进制 + XML,损坏时返回 None 并记录)。每个都要有单测。
8. **CLI**(`argparse`,子命令):
   - `analyze <input> [-o DIR] [--lang zh|en] [--format md,json,html] [--stages a,b] [--skip a,b] [--no-il2cpp] [--il2cpp-tool PATH] [--dotnet PATH] [--offline] [--yes] [--no-redact] [--extract cat1,cat2] [--max-extract-size N] [--keep-workdir] [-v]`
   - `doctor`(检查 Python、OS/架构、dotnet、缓存目录可写、可选联网探测、已缓存工具);
   - `tools list|install <name>|path <name>`(先桩);
   - 退出码:0 全部 ok;1 用法错误;2 输入无效;3 部分阶段失败(有 report);4 致命错误。
   - 启动时 `sys.stdout.reconfigure(encoding="utf-8", errors="replace")`。
9. **`scripts/ipa_analyze.py`**:免安装入口,把 `../src` 插入 `sys.path` 后调用 `cli.main()`。`pyproject.toml`:setuptools,`console_scripts: ipa-analyze`,`python_requires>=3.9`,**无运行时依赖**,`extras: dev(pytest), full(lief)`;`package-data` 包含 `data/`、`schemas/`。
10. **`schemas/report.schema.json`**:JSON Schema draft-07,覆盖 `02-ARCHITECTURE.md` §3.2 顶层与 Finding/StageResult/Evidence;`additionalProperties` 在 `engine_details`、`data` 等扩展点放开。
11. **CI**:`.github/workflows/ci.yml`:矩阵 `{ubuntu,macos,windows}-latest × {3.9,3.12,3.13}`,`pip install -e .[dev]`,`pytest -q`。
12. **`docs/CONTRACT-FREEZE.md`**:列出全部冻结的公共 API(签名 + 一句话语义)、阶段表、Finding ID 表、`ctx.results` 各键的**数据形状约定**(每个阶段写入什么键,例如 `ctx.results["macho"]["binaries"][i]` 至少含 `path, kind, slices[{arch, cryptid_encrypted, ...}]`)。这份文档是下游唯一依据,务必精确。

## 验收标准
- ✅ `python scripts/ipa_analyze.py --help`、`doctor`、`analyze <随手造的空 zip>` 在本机成功;`report.json` 通过 `schemas/report.schema.json` 校验(用最小自写校验器或 `jsonschema` 若已装)。
- ✅ 13 个桩阶段全部被发现并按依赖顺序执行;人为让某阶段抛异常 → 下游被标 skipped,`report` 仍运行,退出码 3。
- ✅ 循环依赖 / 重名阶段 → 启动即报清晰错误(单测)。
- ✅ 全部标准库,`pip install -e .` 后 `ipa-analyze` 可用。
- ✅ `docs/CONTRACT-FREEZE.md` 完整,另一个 agent 仅凭它即可编写阶段实现。
- ✅ 单测通过;`python -W error` 导入无警告。

## 注意
- 这是契约,不是实现:不要提前实现 WP1–WP8 的业务逻辑。
- 想清楚 `ctx.results` 的形状再冻结——这是并行开发能否合拢的关键。拿不准的字段允许 `extra: dict` 扩展位,但核心字段要定死。

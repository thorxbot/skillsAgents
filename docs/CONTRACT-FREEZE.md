# CONTRACT-FREEZE v1.0(WP0 产出,Wave 1/2/3 唯一依据)

状态:**已冻结**。任何字段、签名、Finding ID、阶段名的**改名/删除/语义变更**必须走 "Contract change request"(在回报里写,由总监裁决)。**新增**可选字段 / 新增 Finding ID 允许(加 i18n 即可)。
本文与 `02-ARCHITECTURE.md` 冲突时以本文为准;与各 WP 提示词冲突时以本文为准(冲突点见 §12"裁决记录")。

Skill 根 = `skills/ipa-analyzer/`;下文路径相对于它,除非写明 `docs/`。

---

## 1. 通用约定

| 项 | 约定 |
|---|---|
| 路径(archive 名) | **`ctx.results` 里所有 `path` 字段都是 archive 全名**(`ArchiveSource.namelist()` 的 `EntryInfo.name`,POSIX `/`,不以 `/` 开头),例如 `Payload/Foo.app/Frameworks/UnityFramework.framework/UnityFramework`。可直接用于 `ctx.source.open/stat/read_head` 与 `ctx.extract`。需要相对 .app 根的路径时用 `ctx.rel(name)`(app 外返回 `None`);规则匹配(`data/engines/*.json` 的 `Frameworks/...` 等)一律在 **相对路径** 上做。唯一例外:`inventory.tree` 以 .app 为根,节点名是相对名。 |
| `ctx.app_root` | `""`(源根即 .app,如 `.app` 目录输入)或以 `/` 结尾的前缀,如 `Payload/Foo.app/`。`ctx.app_path("Info.plist")` 拼出 archive 名。 |
| 输出文件路径 | 凡写入 `ctx.results` / 报告的输出目录内文件路径,**一律相对 `ctx.out_dir`**、POSIX 分隔符(如 `il2cpp/dump.cs`)。 |
| JSON 化 | `StageResult.data` 在 pipeline 中被 `to_jsonable` 规范化:只允许 `None/bool/int/float/str/list/dict`(`Path`→posix str,`tuple`→list,`set`→排序 list,`bytes`→hex,`Enum`→value,NaN/Inf→null);其他类型 ⇒ 该阶段 `failed`。dict 键必须是 str(int 键会转 str)。 |
| 三态 | `Verdict`: `yes / no / suspected / unknown / n/a`。没把握**绝不报 `no`**。 |
| 置信度 | 0..1 浮点,越界会被 clamp。 |
| `ctx.results` 键 | **规范键 = 阶段名**(含点号,如 `"engine.unity.hotfix"`)。仅 `ok`/`partial` 的阶段有键;`skipped`/`failed` 无键(读取用 `ctx.results.get(...)`;阶段状态用 `ctx.stage_status(name)` / `ctx.stage_results[name]`)。**只读别人的键,不改**。 |
| 读别名 | `ctx.results["unity"]` 是 `ctx.results["engine.unity"]` 的**只读别名**(WP4/WP5b 提示词用的是 `unity`)。迭代只会看到规范键。新代码请写规范键。 |
| i18n 文件 | `data/i18n/{zh,en}/<模块>.json`,顶层对象。键分两类:① Finding ID → `{"title": "...", "summary": "...", "remediation": "..."}`;② 其他展示文案,键必须以模块名为前缀(`"inventory.category.executable": "可执行代码"`)。插值语法 `{param}`(`str.format_map`,字面花括号写 `{{ }}`),参数来自 `Finding.params`。zh 必须有,en 缺失回退 Finding 自带英文兜底。 |
| 资源目录 | 代码里一律 `util.paths.resource_dir("data" \| "schemas" \| "references")` 取目录(源码树 / editable / skill 拷贝 / wheel 都适用);环境变量 `IPA_ANALYZER_DATA_DIR` 可覆盖。 |
| 用户数据 | `util.paths.user_data_dir()`(`IPA_ANALYZER_HOME` 优先)下放 `libs.user.json`、`engines.user.d/*.json`。缓存 / 工具 / .NET 在 `util.paths.cache_dir()`(`IPA_ANALYZER_HOME` 优先,直接作为缓存根)。 |
| 阶段互不 import | 阶段模块只允许 import:`models/context/config/errors/registry/ingest(Protocol)/util/*/engines.api/il2cpp(契约)`、库子包 `macho` 与 `formats`(WP3 / WP3b 产出的纯库,可被任意阶段 import)与**自己的子包**。读取其他阶段只通过 `ctx.results`。 |
| 日志 | 库代码 `logging.getLogger(__name__)`;不 `print`。 |
| 警告 | 阶段内非致命问题:放进 `StageResult.warnings`(pipeline 自动加 `[阶段名]` 前缀汇入 `ctx.warnings` / `report.warnings`),不要抛异常。 |
| 状态语义 | `ok` 全部完成;`partial` 有部分失败但产出了可用结果(须在 `warnings`/`reason` 写明);`skipped` 前置不满足(必须写 `reason`,面向用户的英文兜底);`failed` 阶段自身出错(`error`)。**依赖被 `skipped` 的阶段也会被 skip**,所以"可选上游"必须声明为 `after`,不是 `requires`。 |
| 唯一例外异常 | 阶段只有在输入根本无法分析时才抛 `errors.InvalidInput`(仅 `ingest`);pipeline 把它记为 `failed` 并使 CLI 退出码为 2。其他意外异常自动隔离为 `failed`,退出码 3。 |

## 2. 阶段表(13 个,名字与依赖冻结)

`requires` = 硬依赖(失败 / 跳过 ⇒ 本阶段 `skipped`,`reason="dependency X failed"` 或 `"dependency X skipped"`)。`after` = 软依赖(仅排序)。同层按阶段名字母序执行(确定性)。`report` 带 `always_run=True`:不受依赖失败影响、排在所有非 always_run 阶段之后。

| 阶段名 | 文件(analyzers/) | 负责 | requires | after |
|---|---|---|---|---|
| `ingest` | ingest_stage.py | WP1 | – | – |
| `inventory` | inventory.py | WP1 | ingest | – |
| `meta` | meta.py | WP2 | ingest | – |
| `macho` | macho_stage.py | WP3 | inventory | – |
| `engine.fingerprint` | engine_fingerprint.py | WP7 | inventory | macho, meta |
| `engine.detect` | engine_detect.py | WP7 | inventory | macho, meta, engine.fingerprint |
| `engine.other` | engines_other.py | WP7b | engine.detect | – |
| `engine.unity` | unity.py | WP5 | engine.detect, inventory | macho, meta |
| `engine.unity.hotfix` | unity_hotfix.py | WP5b | engine.unity | inventory, macho |
| `libs` | libs.py | WP4 | inventory | macho, engine.fingerprint, engine.unity, engine.unity.hotfix, engine.other |
| `protect` | protect.py | WP4 | inventory | macho, engine.unity, engine.unity.hotfix, engine.other, libs |
| `classify` | classify.py | WP4 | – | meta, engine.detect, engine.fingerprint, libs |
| `report` | report_stage.py | WP8 | – | 以上全部 12 个(`always_run=True`) |

替换桩时**原样保留 `@register(...)` 参数**(单测 `test_stub_stage_table_matches_contract` 会校验)。`classify` 无硬依赖,因此上游缺数据时必须自己降级为 `partial` / `unknown`,不得崩溃。

## 3. 公共 Python API(签名冻结)

### 3.1 `ipa_analyzer.models`
```python
class Verdict(str, Enum): YES="yes"; NO="no"; SUSPECTED="suspected"; UNKNOWN="unknown"; NA="n/a"
class Status(str, Enum):  OK="ok"; PARTIAL="partial"; SKIPPED="skipped"; FAILED="failed"

@dataclass Evidence(kind: str, ref: str, detail: str = "")      # kind 建议值: file|plist_key|macho|string|symbol|heuristic|tool_output
@dataclass Finding(id: str, verdict: Verdict, confidence: float, title: str, summary: str = "",
                   params: dict = {}, evidence: list[Evidence] = [], remediation: str = "", tags: list[str] = [])
    # verdict 接受字符串;confidence 被 clamp 到 [0,1];to_dict()/from_dict()
@dataclass StageResult(name, status, duration_s=0.0, error=None, reason=None, findings=[], data={}, warnings=[])
    # 构造器: StageResult.ok(name, data=None, findings=(), warnings=()) / .partial(name, data, findings, warnings, reason=None)
    #         .skipped(name, reason, findings=()) / .failed(name, error, data=None)
    # .to_dict() / .summary_dict()(不含 data,含 finding_ids) / from_dict()
@dataclass Report(...)   # 顶层字段见 §7;.to_dict()(稳定键序) / .to_json() / from_dict()
to_jsonable(obj, *, sort_keys=False) -> Any ;  dumps_json(obj, *, indent=2, sort_keys=False) -> str
SCHEMA_VERSION = "1.0"
```
`Config` 从 `ipa_analyzer.config` 导入(`models` 也再导出)。

### 3.2 `ipa_analyzer.config`
```python
@dataclass Il2cppConfig(enabled=True, force_dump=False, timeout_s=900, tool_path=None, dotnet_path=None, backend_order=[])
@dataclass UnityConfig(bundle_deep_sample=200, hotfix_scan_bundles=100, hotfix_scan_bytes_per_bundle=64*MiB)
@dataclass LimitsConfig(max_total_extract=8GiB, max_file_size=2GiB, max_files=200_000, max_ratio=200.0)
@dataclass Config(output_dir=Path("out"), lang="zh", formats=("md","json"), stages=None, skip=(), il2cpp, unity, limits,
                  libs_user_path=None, engines_user_dir=None, signature_integrity=True, offline=False, redact=True,
                  assume_yes=False, extract=(), keep_workdir=False, verbose=0)
    .validate() -> Config (UsageError) ; .to_dict() ; Config.from_dict(d)
EXTRACT_CATEGORIES = ("binary","frameworks","metadata","bundles","plists","all")   # --extract 的合法值(WP1 实现提取)
parse_size("64M") -> int
```
`--max-extract-size` 映射到 `limits.max_total_extract`;`--libs-user` → `libs_user_path`;`--engines-user` → `engines_user_dir`。

### 3.3 `ipa_analyzer.errors`
`IpaAnalyzerError` ← `UsageError`(退出码 1)、`InvalidInput`(2) ← `LimitExceeded`、`UnsafePath`;`RegistryError` ← `CycleError(cycle: list[str])`。

### 3.4 `ipa_analyzer.registry`
```python
register(name, requires=(), after=(), *, always_run=False, description="", registry=None)   # 装饰 class(无参构造,方法 run(self, ctx)->StageResult)或函数 run(ctx)
get_registry() -> Registry ;  Registry.validate() / .order(selected=None) / .closure(names) / .names() / .specs() / .get(name)
StageSpec(name, run, requires, after, always_run, module, description)
```
重名 ⇒ 注册时立即 `RegistryError`;循环依赖 ⇒ `CycleError`(`validate()`/`pipeline.run` 开始前);未知硬依赖 ⇒ `RegistryError`(除非有分析器模块导入失败,此时依赖者运行时 `skipped("dependency X not available")`)。

### 3.5 `ipa_analyzer.pipeline`
```python
run(ctx, registry=None) -> PipelineRun        # stage_results(执行序), invalid_input, failed -> list[str]
plan(registry, cfg) -> list[StageSpec]
build_report(ctx, stage_results=None) -> Report   # 按 §7 映射的基础报告(WP8 可在此基础上加工)
ensure_analyzers_loaded() -> Registry
```
`--stages a,b` ⇒ 运行 a、b 及其传递硬依赖 + `always_run` 阶段;其余标 `skipped("not selected by --stages")`。`--skip x` ⇒ `skipped("disabled by --skip")`。未知阶段名 ⇒ `UsageError`(退出码 1)。导入失败的分析器模块 ⇒ 伪阶段 `import:<module>`(`failed`),不崩溃。

### 3.6 `ipa_analyzer.context.AnalysisContext`
```python
AnalysisContext(cfg, input_path, *, out_dir=None, workdir=None, source=None, app_root="")
# 属性
cfg; input_path; source: ArchiveSource|None; app_root: str; results: Results; stage_results: dict[str, StageResult]
findings: list[Finding]; warnings: list[str]; artifacts: dict[str,str]; log; input_name; input_sha256
out_dir -> Path   # 最终产物目录 <output>/<name>-<sha12>/ ;未绑定时访问抛 RuntimeError
workdir -> Path   # 临时目录 <out_dir>/work(运行结束自动删除,除非 --keep-workdir)
is_bound -> bool
# 方法
bind_input(sha256, name=None)      # ingest 阶段在算出 sha256 后调用,确定 out_dir/workdir(幂等)
set_extractor(fn)                  # ingest 阶段安装安全提取器: fn(ctx, names: list[str]) -> dict[str, Path]
extract(paths: Iterable[str]) -> dict[str, Path]   # key=archive 名;失败/不安全/超限的名字不在结果里并产生 warning;已提取的复用
artifact_path(rel) -> Path         # out_dir 内的产物路径(自动建父目录,越界抛 ValueError)
register_artifact(name, rel)       # 记录产物(报告 artifacts 字段);report 阶段写 report.json 后须 register_artifact("report.json","report.json")
app_path(rel) / rel(name) / add_warning(msg) / stage_status(name) / findings_by_id(id) / close()
```
`ingest` 阶段职责:打开 `ArchiveSource` 赋给 `ctx.source`,设 `ctx.app_root`,算 sha256,`ctx.bind_input(sha256, name)`,`ctx.set_extractor(...)`。未安装提取器时 `ctx.extract` 用内置默认实现(`extract_to` + `sanitize_component` + 限额 + 复用),WP1 应替换。

### 3.7 `ipa_analyzer.ingest`
```python
@dataclass(frozen=True) EntryInfo(name, size, compressed_size=0, is_dir=False, is_symlink=False, crc=0, mode=0)
class ArchiveSource(Protocol):  kind: str ("zip"|"dir"); path: Path
    namelist() -> list[EntryInfo]          # 含目录条目(name 以 "/" 结尾,is_dir=True);稳定顺序
    stat(name) -> EntryInfo                # 不存在 KeyError
    open(name) -> BinaryIO                 # 可 seek;不存在 KeyError
    read_head(name, n) -> bytes
    extract_to(name, dest: Path) -> Path   # dest 由调用方保证安全
    close() -> None
open_source(path) -> ArchiveSource         # WP0 只支持 zip;WP1 扩展目录
ZipSource(path)                            # WP0 最小实现(minimal_zip.py),WP1 可重写,接口不变
```
`EntryInfo.name` 为存储名(UTF-8 解码后),同时是 `open/stat/read_head/extract_to` 的键。不安全的名字照常出现在 `namelist()`,由提取层拒绝。

### 3.8 `ipa_analyzer.il2cpp`(契约;实现归 WP6)
```python
class Il2CppErrorCode(str, Enum): E_BINARY_FAIRPLAY, E_METADATA_ENCRYPTED, E_METADATA_VERSION_UNSUPPORTED,
                                  E_REGISTRATION_NOT_FOUND, E_DOTNET_MISSING, E_TOOL_DOWNLOAD_FAILED, E_TIMEOUT, E_UNKNOWN
Il2CppRunRequest(binary_path, metadata_path, out_dir, unity_version=None, metadata_version=None, force_dump=False,
                 timeout_s=900, work_dir=None, extra={})
Il2CppRunResult(ok, error_code=None, message="", remediation="", backend="", backend_version="", out_dir=None,
                artifacts={}, stdout_tail=[], stderr_tail=[], duration_s=0.0, cached=False, attempts=[])
ProvisionResult(ok, command=[], version="", error_code=None, message="")
class Il2CppBackend(Protocol): name; supports(meta_version, unity_version)->bool; provision(tools, cfg)->ProvisionResult; run(req, provisioned, cfg)->Il2CppRunResult
run_il2cpp_dump(req: Il2CppRunRequest, tools, cfg: Config) -> Il2CppRunResult     # WP0: NotImplementedError;WP6 提供实现并在此导出
```
`tools` 命令接线:`ipa_analyzer.il2cpp.tools` 若提供 `cmd_tools_list(args)->int`、`cmd_tools_install(args)->int`、`cmd_tools_path(args)->int`,CLI 自动委托(`args` 含 `name`、`offline`、`yes`、`dotnet`、`verbose`);否则 CLI 打印"未实现"。

### 3.9 `ipa_analyzer.engines.api`
```python
SignalSpec(type, pattern, weight=0.0, strong=False, unverified=False, note="")
EngineSignature(id, name, family="", kind="game_engine", signals=[], confirm_threshold=1.0, exclusive_with=[], language_hints=[], notes="", sources=[])
FingerprintHit(id, confidence=0.0, name="", evidence=[], extra={}) ; FingerprintResult(render, shader_formats, script_vms, physics, audio, animation, network, asset_formats, containers, host, summary_text)
EngineMatch(id, name="", confidence=0.0, family="", kind="", confirmed=False, signals_matched=[], evidence=[], extra={})
DetectResult(primary: EngineMatch|None, candidates, wrapper, custom, languages, is_game_engine, extra)
    .primary_id ; .candidate_ids(min_confidence=0, confirmed_only=False) ; .has(engine_id, min_confidence=0) ; to_dict()/from_dict()
CheckerResult(findings=[], data={}, status=Status.OK, reason=None, warnings=[])
class EngineChecker(Protocol): engine_id: str; applies(ctx, detect: DetectResult)->bool; run(ctx, detect)->CheckerResult
register_checker(engine_id)           # 类装饰器,无参构造;重名 / 以 "_" 开头 ⇒ RegistryError
get_checkers() -> list[EngineChecker] # 按 engine_id 排序;首次调用自动 import engines.checkers 全部模块
checker_import_failures() -> dict[module, error]
```
`engines/checkers/*.py` 自动发现,单个模块导入失败只记录。`_example.py` 注册了 `example`(`applies` 恒 False),仅作模板。
`SIGNAL_TYPES = file|dir|string|dylib|symbol|objc_prefix|plist_key|binary_section`;`ENGINE_KINDS = game_engine|cross_platform_ui|web_hybrid|native|open_source_lib`。

### 3.10 `ipa_analyzer.util`(WP0 提供,他人只用不改)
```python
hashing.sha256_stream(path_or_fileobj, *, chunk=1MiB) -> hex ; hashing.sha256_bytes(b) ; hashing.hash_stream(f, algo)
entropy.shannon(data: bytes) -> float(0..8) ; entropy.sampled_entropy(fileobj, size, *, head=65536, blocks=16, block_size=4096) -> float
paths.cache_dir() / user_data_dir() / tools_dir() -> Path ; paths.resource_dir(name) -> Path
paths.is_within(base, p, *, resolve=True) -> bool          # resolve=False 为纯词法比较(PureWindowsPath 单测用)
paths.sanitize_component(name, *, max_len=255, replacement="_") -> str ; paths.is_windows_reserved(name) ; paths.to_long_path(p)
procs.run(cmd, timeout, env=None, cwd=None, input=None, stdin=None) -> ProcResult(cmd, returncode, stdout, stderr, timed_out, duration_s, error) ; .ok
procs.popen(cmd, *, cwd, env, stdin, stdout, stderr) -> Popen      # 新进程组/会话,供逐行读取 stdout 的运行器使用
procs.kill_tree(proc, *, grace_s=0.0) ; procs.minimal_env(extra=None) -> dict ; procs.taskkill_command(pid)
plist_utils.load_plist(bytes) -> obj|None ; plist_utils.to_jsonable_plist(obj)
```

## 4. 各阶段 `ctx.results[...]` 数据形状

标注:**必有** = 阶段为 `ok`/`partial` 时必须存在;可选字段缺失时消费者必须容忍。所有阶段可以增加 `extra`(dict)或其他字段,但不得改名 / 删除下列字段。

### 4.1 `ingest`
```
{kind: "ipa"|"zip"|"app_dir"|"payload_dir"|"dir", path: str, size: int, sha256: str, app_root: str,
 app_name_dir: str ("Foo.app"), entries: int, warnings: [str]}
```
### 4.2 `inventory`
```
files: [{path, size, csize, ext, magic, category, entropy?}]   # path=archive 全名;ext 小写含点(".png",无扩展名为 "");magic=类型 id(如 "macho","png","unityfs","lua_bytecode","unknown");
                                                               # 按 path 排序;可能只含前 N 条(见 files_total/files_truncated)
files_total: int ; files_truncated: bool ; inventory_file: "inventory.json"(完整表,相对 out_dir)
by_category: [{category, count, size, percent}]                # 按 size 降序
by_ext: [{ext, count, size}]
top_files: [{path, size, category}]                            # N=30
localizations: [str]                                           # 语言码,如 "zh-Hans","en","Base"
archives: [{path, size, magic, category}]                      # pak/obb/zip/pck/...
nested_units: [{path, rel, kind: "framework"|"appex"|"watch_app"|"app_clip"|"bundle"|"dylib", name, size, file_count}]
tree: {name, size, count, children: [..同结构..]}              # 根=.app,节点名相对;默认深度 3,超深汇总到祖先
structure_hints: {top_level_dirs: [str], has: {Frameworks, PlugIns, Watch, SC_Info, _CodeSignature, Data, Assets_car, embedded_mobileprovision, iTunesMetadata_plist: bool}}
```
文件类别 id(冻结):`executable framework plugin dylib assets_car ui_layout localization plist image audio video font database script shader model_3d engine_data assetbundle packed_archive signing config text other`。

### 4.3 `meta`
```
identity: {names: [{value, source, lang}], selected_name, bundle_id, version, build, executable, min_os, devices: [str], ...}
distribution: {type: "appstore"|"adhoc"|"enterprise"|"development"|"unsigned_or_repackaged"|"unknown", verdict, confidence, evidence: [Evidence dict]}
provision: {present: bool, name, team_name, team_id, app_id_prefix, creation_date, expiration_date, provisions_all_devices, device_count, device_hash_prefixes: [str], entitlements: {}}
itunes: {item_id, item_name, artist_name, genre, genre_id, genres, ..., 购买者字段已替换为 "<redacted>"}
fairplay_container: {sc_info_present: bool, files: [str]}
permissions: [{key, description, localized: {lang: text}, level: "low"|"medium"|"high", meaning_zh, meaning_en}]
url_schemes: [str] ; query_schemes: [str] ; ats: {allows_arbitrary_loads: bool, exception_domains: [str]}
extensions: [{path, bundle_id, kind: "appex"|"watch"|"app_clip", point}]
background_modes: [str] ; capabilities: [str]   # UIRequiredDeviceCapabilities
sdk: {name, platform_version, xcode, compiler} ; signature_integrity?: {checked, missing, modified, extra, examples: []}
redaction: {applied: bool, keys: [str]} ; warnings: [str]
```
### 4.4 `macho`
```
binaries: [{path, rel, role: "main"|"framework"|"dylib"|"appex"|"watch"|"other", kind: <首个 slice 的 filetype 名, 如 "execute"|"dylib"|"bundle">,
            size, is_fat,
            slices: [{arch, filetype, platform, min_os, sdk, uuid, encrypted: bool, cryptid: int|null, cryptsize: int|null,
                      is_pie, stripped, has_swift, has_objc, has_cpp, signed, team_id, entitlements_keys: [str]}],
            dylibs: [{path, kind: "system"|"bundled"|"other", load_kind: "load"|"weak"|"reexport"|"lazy"|"upward", weak: bool}],
            rpaths: [str], parse_warnings: [str]}]
summary: {main_binary: path|null, any_encrypted: bool, all_encrypted: bool, archs: [str], min_os: str|null, languages_hint: [str]}
```
`slice.encrypted = (cryptid != 0 and cryptsize > 0)`。FairPlay 汇总只由 `protect` 阶段产出 `protect.fairplay`。

### 4.5 `engine.fingerprint`(= `FingerprintResult.to_dict()`)
```
render: {metal|gles|vulkan|angle: Hit}        # 只含检出的后端
shader_formats|script_vms|physics|audio|animation|network|asset_formats|containers: [Hit]
host: {thin_uikit_shell: bool|null, cpp_ratio: float|null, objc_swift_ratio: float|null, main_loop_hints: [str]}
summary_text: str
Hit = {id, name, confidence, evidence: [Evidence dict], extra: {}}
```
`containers[i].id` = 容器 archive 全名;`extra` 建议含 `size, magic, verdict("compressed"|"encrypted_suspected"|"plain"|"custom_format"|"unknown"), compression, entropy, header{}, xor_hypothesis`。脚本 VM id 建议:`lua luajit quickjs v8 jsc mozjs duktape python squirrel angelscript wren mruby mono il2cpp hermes`。

### 4.6 `engine.detect`(= `DetectResult.to_dict()`)
```
primary: {id, name, family, kind, confidence, confirmed, signals_matched, evidence, extra}|null   # 无已知引擎达阈值时为 null
candidates: [同 primary 结构]                                      # confidence>0,按 confidence 降序、id 升序
wrapper: {host: {id,name,confidence}, embedded: [{id,name,confidence}]}|null
custom: {verdict, confidence, evidence: [Evidence dict], profile_ref: "engine.fingerprint", conditions: {}, next_steps: [{key, params, text}], deviations: [], open_source_base: []}
languages: [{lang, confidence, evidence: [Evidence dict]}]       # lang: objc swift c cpp csharp lua javascript typescript dart python java kotlin rust go
is_game_engine: bool ; extra: {}
```
### 4.7 `engine.other`
```
{"<engine_id>": <该 checker 的 CheckerResult.data>, ..., "_checkers": {"<engine_id>": {status, reason, error, duration_s}}}
```
checker engine_id 取值(WP7b):`cocos egret laya unreal godot flutter react_native lua defold gamemaker solar2d_love xamarin web_hybrid generic_scripts`(Cocos 全家共用 `cocos`,变体在 `data.variant`)。键以 `_` 开头保留。Cocos:`{variant, version_hint, scripts{plain,bytecode,suspected_encrypted,counts,samples}, resources{}, xxtea_hint{}, bundles[]}`;Lua 画像字段与 §4.9 `lua` 对齐。

### 4.8 `engine.unity`
```
version: {value: str|null, sources: [{source, value, ref}], conflicts: [..]}
backend: "il2cpp"|"mono"|"unknown"
binary: {path, slice: str|null, encrypted: bool|null}                       # il2cpp 承载二进制(优先 UnityFramework)
metadata: {path, present: bool, version: int|null, header_ok: bool|null, entropy: float|null, string_region_ok: bool|null,
           string_region: {offset, size}|null, verdict: Verdict.value, evidence: [Evidence dict]}
bundles: {total, by_class: {standard, offset_prefix, xor_simple, high_entropy_unknown, other, unknown}, compression: {}, unity_versions: {},
          samples: {class: [path≤10]}, paths_sample: [path≤200], sampled: int, addressables: {catalog_found: bool, ...}}
mono: {assemblies: [{path, valid_pe_cli: bool, ...}], verdict, evidence}
precheck: {ready: bool, error_code: str|null, reasons: [str]}
dump: {ran: bool, ok: bool, backend, backend_version, out_dir (相对 out_dir), artifacts: {name: rel}, error_code: str|null, remediation, cached, duration_s,
       namespaces: [str ≤500], summary: {assemblies, classes, interfaces, enums, methods, fields, string_literals, framework_namespaces: [str],
       obfuscation: {score, non_standard_ratio, short_ratio, non_ascii_ratio}}}
```
### 4.9 `engine.unity.hotfix`(权威定义 `04-UNITY-HOTFIX.md` §5,此处冻结字段名)
```
frameworks: [{id, name, kind: "csharp"|"lua"|"js"|"resource", confidence, version_hint: str|null, evidence: [Evidence dict]}]
lua: {runtime_versions: [{flavor: "puc"|"luajit", version, source, confidence}],
      bytecode: {by_version: {"5.1": n, "5.3": n, "luajit_2.1": n, ...}, invalid: n, stripped_count: n, arch_bits: {"32": n, "64": n}},
      files: {plain, bytecode, compressed, encrypted_suspected, total}, dialect_hints: [str],
      consistency: {ok: bool, notes: [str]}, custom_lua_suspected: bool}
js: {backends: [{id, confidence}], files: {plain, bytecode, encrypted_suspected, total}, formats: [str]}
csharp: {assemblies: [{name, source: "loose"|"bundle"|"serialized", size, format: "pe_cli"|"compressed"|"encrypted_suspected"|"unknown", clr, asm_refs: [str], kind: "hot"|"aot_meta"|"unknown", path?}]}
resource_update: {frameworks: [..], catalogs: [..], manifests: [..], hosts: [域名 ≤20]}
storage: {loose, in_bundles, in_serialized, scanned: {bundles_sampled, total}}
script_protection: {lua: Verdict.value, js: ..., csharp: ...} ; summary_text: str
```
其中 `lua` 画像是 Cocos/通用 Lua checker 的**共享形状**(`engine.other.cocos.scripts.lua` 等用同名字段)。

### 4.10 `libs`
```
items: [{id, name, kind: "system"|"bundled_dylib"|"framework"|"static_sdk"|"resource_bundle"|"unity_namespace", vendor, category, purpose_zh, purpose_en, tags: [str], version?, confidence, evidence: [Evidence dict]}]
unknown: [{name, kind, evidence: [Evidence dict], hint?}]      # 未命中库:purpose 留空;hint 仅为低置信名称猜测
by_category: {category: count} ; privacy_tags: {ads: [id], analytics: [id], tracking: [id], social: [id]}
```
### 4.11 `protect`
```
fairplay: {verdict, scope: "all"|"partial"|"none"|"unknown", encrypted_binaries: [path], total_binaries: int, main_encrypted: bool|null, sc_info_present: bool|null}
codesign: {signed: bool|null, team_id: str|null, signature_type: str|null, get_task_allow: bool|null, entitlements_keys: [str]}
hardening: {main: {pie, stack_canary, arc, stripped: bool|null}, all: {pie, stack_canary, arc, stripped: bool|null}}
antidebug: {hits: [{kind, ref}]} ; jailbreak_detect: {hits: [{kind, ref}]} ; obfuscation: {}; packer: {}   # 后两项可为空对象
```
### 4.12 `classify`
```
{category: <id>|"unknown", subcategory: str|null, confidence, scores: {category: float}, evidence: [Evidence dict], runner_up: {category, score}|null}
category id(冻结): game media lifestyle social utility finance education health_fitness shopping travel news_reading other unknown
```
### 4.13 `report`
`{files: {"report.json": "report.json", "report.md": "report.md", ...}, formats: [str]}`;写文件后必须 `ctx.register_artifact(name, rel)`。**`report.json` 总是写出**(`--format` 只决定额外格式);若 `report` 阶段没写,CLI 用 `pipeline.build_report` 兜底写基础版。

## 5. Finding ID 表(冻结;新增允许,改名 / 删除需变更)

| 阶段 | Finding ID |
|---|---|
| meta | `meta.identity` `meta.distribution` `meta.permissions` `meta.fairplay_container` `meta.signature_integrity` |
| macho | `macho.summary` |
| engine.fingerprint | `engine.fingerprint` `engine.container.unknown`(无容器时 verdict `n/a`) |
| engine.detect | `engine.primary` `engine.language` `engine.custom` `engine.wrapper` |
| engine.other | `engine.pak.encrypted` `engine.script.encrypted` `engine.resource.encrypted` `engine.hermes` `engine.flutter_aot` `engine.cocos.variant`(同 ID 可由多个 checker 产出,用 `tags=["engine:<id>"]` 区分) |
| engine.unity | `unity.detected` `unity.version` `unity.backend` `unity.metadata.present` `unity.metadata.encrypted` `unity.binary.fairplay` `unity.il2cpp.precheck` `unity.il2cpp.dump` `unity.il2cpp.names_obfuscated` `unity.assetbundle.encryption` `unity.mono.dll_encrypted` |
| engine.unity.hotfix | `unity.hotfix.framework` `unity.hotfix.lua` `unity.hotfix.lua_version` `unity.hotfix.csharp_dll` `unity.hotfix.js` `unity.hotfix.resource_update` `unity.hotfix.script_protection`(取代旧 `unity.hotupdate`) |
| libs | `libs.summary` `libs.unknown` |
| protect | `protect.fairplay` `protect.codesign` `protect.stripped` `protect.antidebug` `protect.jailbreak_detect` `protect.obfuscation` `protect.packer` |
| classify | `classify.category` |

ID 格式:小写 `[a-z0-9_]` 段以 `.` 分隔,至少两段(schema 强制)。语义约定:`unity.il2cpp.dump` 的 `no` = "没跑成功"(附错误码);`engine.*.encrypted` 的 `no` 必须在 `summary` 里写明"已编译 / 已压缩 ≠ 加密";`protect.antidebug` / `protect.jailbreak_detect` verdict 至多 `suspected`。

## 6. 输出目录布局
`<output>/<name>-<sha12>/`:`report.json`(总是)、`report.md`、`report.html`、`inventory.json`、`il2cpp/`(dump 产物)、`split/<category>/`(`--extract`)、`work/`(临时,默认运行后删除)。

## 7. `report.json` 顶层与 `pipeline.build_report` 的来源映射
顶层键(schema 见 `schemas/report.schema.json`,顶层 `additionalProperties:false`):
`schema_version, tool{name,version}, generated_at, input{path,sha256,size,kind}, app, classification, structure, resources, libraries, protection{findings[]}, engine_details, privacy, stages[], findings[], warnings[], redaction{applied,fields[]}`,可选:`summary`(执行摘要数据,WP8)、`artifacts`、`config`。

| 报告键 | 来源 |
|---|---|
| `input` | `ingest.{path,sha256,size,kind}`(缺失时回退 CLI 参数) |
| `app` | `meta.identity` 全部键 + `distribution`(= `meta.distribution`)+ `sdk/extensions/background_modes/capabilities` |
| `classification` | `classify.{category,subcategory,confidence,evidence}` |
| `structure` | `{tree: inventory.tree, nested_units: inventory.nested_units, binaries: macho.binaries, languages: engine.detect.languages, engine: {primary, candidates}}` |
| `resources` | `inventory.{by_category,by_ext,top_files,archives,localizations}` |
| `libraries` | `libs.items` |
| `protection.findings` | `findings` 中 `protect.*` 与 `meta.fairplay_container, meta.signature_integrity, unity.metadata.encrypted, unity.binary.fairplay, unity.assetbundle.encryption, unity.mono.dll_encrypted, unity.hotfix.script_protection, engine.pak.encrypted, engine.script.encrypted, engine.resource.encrypted` |
| `engine_details` | `fingerprint`←`engine.fingerprint`;`detect`←`engine.detect`;`unity`←`engine.unity` + `hotfix`←`engine.unity.hotfix`;其余键 = `engine.other` 的各 `<engine_id>` |
| `privacy` | `{permissions, url_schemes, query_schemes, ats ← meta.*, trackers ← libs.items 中 tags ∩ {ads,analytics,tracking,attribution}}` |
| `stages` | 每个阶段的 `StageResult.summary_dict()`(执行序) |
| `findings` | 全部 Finding(执行序) |
| `warnings` | `ctx.warnings` |

稳定性:除 `generated_at` 与 `duration_s` 外同输入同版本输出一致(dataclass 字段键序固定;自由 dict 在 `Report.to_dict` 中按键排序)。

## 8. CLI 契约
```
ipa-analyze analyze <input> [-o DIR] [--lang zh|en] [--format md,json,html] [--stages a,b] [--skip a,b]
            [--no-il2cpp] [--force-dump] [--il2cpp-tool PATH] [--dotnet PATH] [--il2cpp-timeout SEC] [--offline] [--yes]
            [--no-redact] [--extract cat1,cat2] [--max-extract-size N] [--libs-user PATH] [--engines-user DIR]
            [--no-signature-integrity] [--keep-workdir] [-v|-vv]
ipa-analyze doctor [--offline] [--dotnet PATH] [--json]
ipa-analyze tools list | install <name> | path <name>      # 接线点见 §3.8
```
退出码:**0** 无 `failed` 阶段(`skipped`/`partial` 不影响);**1** 用法错误(含未知 `--stages/--skip` 阶段名、非法 `--lang/--format/--extract/--max-extract-size`、无子命令);**2** 输入无效(路径不存在、空文件、`ingest` 抛 `InvalidInput`;仍会尽力写 `report.json`);**3** 有阶段 `failed`(report 已写);**4** 致命错误(注册表非法 / 循环依赖 / 无法创建输出目录 / 未捕获异常 / `tools install|path` 未实现)。`-o DIR` 是输出**基目录**(默认 `./out`)。`stdout/stderr` 启动即 `reconfigure(encoding="utf-8", errors="replace")`;`python -m ipa_analyzer` 与 `scripts/ipa_analyze.py` 等价。

## 9. 测试基础设施约定
* `pyproject.toml` 的 pytest 配置:`pythonpath=["src","tests"]`,`--import-mode=importlib`(测试文件名无需全局唯一)。夹具生成器放 `tests/fixtures/*.py`,导入写 `from fixtures.ipa_builder import build_ipa`(命名空间包,无需 `__init__.py`)。
* `tests/conftest.py` 提供:`make_zip(files, name)` fixture、`report_schema`、`check_report(report_dict) -> list[str]`(自写 draft-07 子集校验器;装了 `jsonschema` 时同时用它)、`validate_schema(...)`;常量 `SKILL_ROOT, SCHEMA_PATH, SCRIPT_PATH`。
* 标记:`slow`(需 `--runslow` 或 `IPA_TEST_SLOW=1`)、`network`(需 `IPA_TEST_NETWORK=1`)、`macos_only`(非 macOS 自动 skip)。
* WP0 自带测试:`tests/unit/test_*.py`(models/config/util/registry+pipeline/engines api/context/smoke)。

## 10. 编写阶段的最小模板
```python
from __future__ import annotations
from ..context import AnalysisContext
from ..models import Evidence, Finding, StageResult, Verdict
from ..registry import register

@register(name="meta", requires=("ingest",))          # 参数与 §2 完全一致
class MetaStage:
    def run(self, ctx: AnalysisContext) -> StageResult:
        ing = ctx.results["ingest"]                    # 硬依赖保证存在且为 ok/partial
        opt = ctx.results.get("macho")                 # 软依赖/可选上游:必须容忍缺失
        ...
        return StageResult.ok("meta", {...}, [Finding("meta.identity", Verdict.YES, 0.9, "App identity resolved")])
```

## 11. 已知局限(WP0 范围)
* 13 个阶段均为桩;`report` 阶段未实现时由 CLI 写基础 `report.json`,不写 md / html。
* 最小 `ZipSource` 不处理 zip-slip、非 UTF-8 名、zip64 校验、符号链接策略与炸弹限额(WP1 负责)。
* `ctx.extract` 的内置默认实现仅作兜底,限额与冲突处理由 WP1 的 `set_extractor` 替换。
* Windows 专有逻辑(`taskkill`、`\\?\` 前缀、保留名)只有纯函数单测,真机验证依赖 CI。

## 12. 裁决记录(提示词之间 / 与示例不一致处,以此为准)
1. `ctx.results["unity"]` vs 阶段名 `engine.unity`:规范键 `engine.unity`,`unity` 为只读别名。
2. WP0 提示词示例的 `macho.binaries[i].kind` / `slices[].cryptid_encrypted` 与 WP3/WP4 提示词的 `role` / `slices[].encrypted` 冲突:冻结为 **`role`(位置角色)+ `kind`(Mach-O 文件类型)**、**`encrypted`**(bool,= `cryptid!=0 and cryptsize>0`);不提供 `cryptid_encrypted`。
3. `engine.other` 结果在 `<engine_id>` 键下,另有保留键 `_checkers`(各 checker 状态)。
4. `--max-extract-size` 映射 `limits.max_total_extract`;新增 CLI 旗标 `--force-dump`、`--il2cpp-timeout`、`--libs-user`、`--engines-user`、`--no-signature-integrity`(提示词中被引用但未列入 WP0 旗标表)。
5. `report.json` 总是写出;`partial` 不计入退出码 3。
6. 输出目录 `<output>/<name>-<sha12>/`,`workdir = <out_dir>/work`(运行后删除),WP1 提示词里"workdir 以 sha256 前 12 位命名"由此满足。
7. `ArchiveSource` 增加 `path` 属性与 `close()`(Windows 句柄释放需要)。
8. `IPA_ANALYZER_HOME` 同时作为缓存根与用户数据目录(`libs.user.json`、`engines.user.d/`)。
9. 测试文件超出提示词列出的 `tests/conftest.py` + `tests/unit/test_pipeline_smoke.py`:util / models / registry / context / engines.api 的单测同在 `tests/unit/test_*.py`(要求"每个 util 都要有单测")。
10. 打包:`setup.py` 的 `build_py` 钩子把 `data/ schemas/ references/` 拷进 wheel 的 `ipa_analyzer/_data|_schemas|_references`(包外目录无法用 package-data 表达);源码树 / editable 直接读 Skill 根目录。

## 13. Wave 1 追加裁决(总监,2026-10-04)
1. **大表外置(WP8)**:`report.json` 中 `engine_details.unity.dump.namespaces`(>100 项)与 `bundles.paths_sample`(>50 项)会被截断内联,完整内容写入 `details/*.json`,原处加 `*_total` 与 `*_file`。消费者(含 WP5/WP5b)读取这些字段时必须容忍"仅有 total/file、无完整列表"。`ctx.results` 内部形状不变(仍是完整列表)。
2. **`libs.unknown` 等放置**:`libs.unknown / by_category / privacy_tags` 放在 `report.summary.libs`;`protect` 各键合入 `protection.*`;不新增顶层 `libraries_unknown`(顶层 `additionalProperties:false` 保持)。
3. **`inventory.files` 可能被截断**(>20000 条):需要全表的阶段用 `filetypes.load_inventory_files(inv, ctx.out_dir)`。新增 Finding `inventory.summary`;`inventory` 新增可选字段 `total_size/entropy_info/read_errors/split`。
4. **库子包导入**:阶段可 import `macho`、`formats`;`report_stage` 对 `pipeline` 做运行时延迟导入,允许。
5. **加密二进制降级**:`slice.encrypted=True` 时,依赖二进制内容的检测必须用 `skip_encrypted=True` 并降级。

# ipa-analyzer 技术方案 v1.0

配套阅读:`01-REQUIREMENTS.md`。本文是所有子 agent 的 **共同契约**;子 agent 不得擅自改契约,需要变更走 "Contract change request"(见 `prompts/_common.md`)。

---

## 1. 总体架构:阶段(Stage)流水线 + 数据驱动知识库

```
          ┌────────── CLI / SKILL.md ──────────┐
 input ─► │ ingest → inventory → meta → macho  │
          │            │                │      │
          │       engine.fingerprint(渲染/脚本VM/物理/容器画像)
          │            └──► engine.detect(已知引擎签名 + 自研判定)
          │                  ├─► engine.unity ──► (il2cpp runner ─► Il2CppDumper/Cpp2IL/…)
          │                  │       └─► engine.unity.hotfix(DLL/Lua+版本/JS/资源热更,详见 docs/04-UNITY-HOTFIX.md)
          │                  └─► engine.other(各引擎 checker 插件:Cocos/Egret/Laya/Unreal/…)
          │      libs ─► protect ─► classify   │
          │                  │                 │
          │                report (md/json/html)
          └────────────────────────────────────┘
          所有阶段读写同一个 AnalysisContext,互不直接 import(只通过 ctx.results)
```

- **阶段隔离**:每个阶段是一个 `Analyzer`,声明 `name / requires(硬依赖)/ after(软依赖,仅排序)`;失败只影响自身及其硬依赖者,状态落 `StageResult`。
- **自动发现**:`analyzers/` 下的模块被 `pkgutil` 扫描并通过装饰器 `@register` 注册 → 各 agent 只新增自己的文件,**不共改注册表**,可并行开发。
- **数据驱动**:库 / 引擎 / 保护器 / 分类规则放 `data/*.json`,不写进代码。
- **证据模型**:任何判断都产出 `Finding(verdict, confidence, evidence[])`。

## 2. 目录结构与文件归属

```
skillsAgent/
├── docs/            01-REQUIREMENTS, 02-ARCHITECTURE, CONTRACT-FREEZE(WP0), ACCEPTANCE(WP9)
├── prompts/         子 agent 提示词
└── skills/ipa-analyzer/
    ├── SKILL.md  README.md  pyproject.toml                         (WP0 骨架 → WP9 定稿)
    ├── scripts/ipa_analyze.py            # 免安装入口(把 src 加入 sys.path)   (WP0)
    ├── src/ipa_analyzer/
    │   ├── cli.py models.py context.py pipeline.py registry.py errors.py  (WP0)
    │   ├── util/            hashing, entropy, paths, procs, plist_utils, strings_file
    │   ├── ingest/          source.py(ZipSource/DirSource) safe_extract.py          (WP1)
    │   ├── macho/           parser.py codesign.py scan.py writer.py                 (WP3)
    │   ├── formats/         unityfs.py lz4.py lua_bytecode.py lua_source.py pe_cli.py magic_scan.py compress_sniff.py (WP3b,零依赖可复用)
    │   ├── unity/           metadata.py mono.py version.py bundles.py precheck.py (WP5);hotfix/{detect,lua,csharp,js,storage,...}.py (WP5b)
    │   ├── il2cpp/          tools.py dotnet.py runner.py backends.py summarize.py   (WP6)
    │   ├── report/          render_md.py render_json.py render_html.py redact.py i18n.py schema.py (WP8)
    │   ├── engines/         api.py(WP0) signatures.py fingerprint.py containers.py custom.py(WP7)
    │   │                    checkers/{cocos,egret_laya,unreal,godot,flutter,rn,lua,defold,gamemaker,...}.py(WP7b)
    │   └── analyzers/       inventory.py(WP1) meta.py(WP2) macho_stage.py(WP3)
    │                        engine_fingerprint.py engine_detect.py(WP7) engines_other.py(WP7b) unity.py(WP5)
    │                        libs.py protect.py classify.py(WP4)  report_stage.py(WP8)
    ├── data/                libs.json engines/<id>.json(+engines.index.json) fingerprint.json protectors.json classify.json
    │                        il2cpp_backends.json i18n/{zh,en}/<module>.json
    ├── schemas/report.schema.json                                                   (WP0 定义,WP8 校验)
    ├── references/          供 Agent 按需阅读的专题文档(渐进披露)                    (各 WP + WP9)
    └── tests/               fixtures/build_fixtures.py  unit/  integration/         (各 WP 自带,WP9 汇总)
```

`util/` 共享小工具由 **WP0 先建好最小集**(hashing、entropy、paths、procs、plist_utils);其他 WP 需要新工具函数时放自己目录,**不改 util**。

## 3. 数据契约(WP0 落地为 `models.py` + JSON Schema,之后冻结)

```python
class Verdict(str, Enum): YES="yes"; NO="no"; SUSPECTED="suspected"; UNKNOWN="unknown"; NA="n/a"
class Status(str, Enum):  OK="ok"; PARTIAL="partial"; SKIPPED="skipped"; FAILED="failed"

@dataclass class Evidence:   kind: str; ref: str; detail: str = ""     # kind: file|plist_key|macho|string|symbol|heuristic|tool_output
@dataclass class Finding:
    id: str                    # 稳定 ID,见 §3.1
    verdict: Verdict
    confidence: float          # 0..1
    title: str                 # 英文兜底文案;报告层用 i18n 覆盖
    summary: str = ""
    params: dict = {}          # 供 i18n 模板插值
    evidence: list[Evidence] = []
    remediation: str = ""      # 下一步建议(英文兜底)
    tags: list[str] = []
@dataclass class StageResult: name; status: Status; duration_s: float; error: str|None; reason: str|None; findings: list[Finding]; data: dict   # data = 该阶段写入 ctx.results[name] 的 JSON 可序列化内容
```

`AnalysisContext`(只读摘要):`source: ArchiveSource`、`app_root: str`(zip 内 `Payload/X.app/`)、`workdir: Path`、`cfg: Config`、`results: dict[str, dict]`、`findings`、`extract(paths) -> dict[str, Path]`(懒提取到 workdir)、`log`。

`ArchiveSource` Protocol(WP0 定义,WP1 实现):`namelist() -> list[EntryInfo]`、`stat(name)`、`open(name) -> BinaryIO`、`read_head(name, n)`、`extract_to(name, dest)`。`ZipSource` 与 `DirSource` 同一接口,上层不关心输入形态。

### 3.1 稳定 Finding ID(首版)
```
meta.identity  meta.distribution  meta.permissions  meta.fairplay_container  meta.signature_integrity
macho.summary
engine.primary  engine.language  engine.fingerprint  engine.custom  engine.container.unknown  engine.wrapper
protect.fairplay  protect.codesign  protect.stripped  protect.antidebug  protect.jailbreak_detect  protect.obfuscation  protect.packer
libs.summary  libs.unknown
classify.category
unity.detected  unity.version  unity.backend  unity.metadata.present  unity.metadata.encrypted
unity.binary.fairplay  unity.il2cpp.precheck  unity.il2cpp.dump  unity.il2cpp.names_obfuscated
unity.assetbundle.encryption  unity.mono.dll_encrypted
unity.hotfix.framework  unity.hotfix.lua  unity.hotfix.lua_version  unity.hotfix.csharp_dll  unity.hotfix.js  unity.hotfix.resource_update  unity.hotfix.script_protection
engine.pak.encrypted  engine.script.encrypted  engine.resource.encrypted  engine.hermes  engine.flutter_aot  engine.cocos.variant
```
新增 ID 允许(加 i18n 即可),**改名 / 删除需走契约变更**。

### 3.2 `report.json` 顶层
```
schema_version, tool{name,version}, generated_at, input{path,sha256,size,kind},
app{names[],selected_name,bundle_id,version,build,min_os,devices,distribution,...},
classification{category,subcategory,confidence,evidence[]},
structure{tree,nested_units[],binaries[],languages[],engine{primary,candidates[]}},
resources{by_category[],by_ext[],top_files[],archives[],localizations[]},
libraries[{id,name,kind,vendor,category,purpose_zh,purpose_en,tags,confidence,evidence[]}],
protection{findings[]},
engine_details{unity{...}, unreal{...}, ...},
privacy{permissions[],url_schemes[],ats,trackers[]},
stages[StageResult 摘要], findings[], warnings[], redaction{applied:bool}
```
时间戳之外的字段输出必须稳定(列表排序、dict 键序固定)。

## 4. 关键算法(实现方须按此,细节以官方文档 / 实测为准)

### 4.1 Mach-O(纯 Python,`struct` + `mmap`)
- magic:`FEEDFACE/FEEDFACF`(及 CIGAM 反序),fat `CAFEBABE`(大端)、fat64 `CAFEBABF`。注意 Java class 文件也以 `CAFEBABE` 开头:用 `nfat_arch` 合理性(<30)区分。
- Load commands 至少解析:`LC_SEGMENT(_64)`(含 section)、`LC_LOAD_DYLIB / WEAK / REEXPORT / LAZY`、`LC_ID_DYLIB`、`LC_RPATH`、`LC_UUID`、`LC_BUILD_VERSION`、`LC_VERSION_MIN_IPHONEOS`、`LC_SYMTAB`、`LC_DYSYMTAB`、`LC_CODE_SIGNATURE`、`LC_ENCRYPTION_INFO(0x21)/_64(0x2C)`、`LC_MAIN`、`LC_DYLD_INFO(_ONLY)`、`LC_DYLD_CHAINED_FIXUPS`、`LC_SOURCE_VERSION`。所有读取做边界检查,`cmdsize` 非法 / 为 0 时终止。
- **FairPlay**:`cryptid != 0` 且 `cryptsize > 0` ⇒ 加密。逐 slice 报告。
- 代码签名:SuperBlob(大端)`0xFADE0CC0`;CodeDirectory `0xFADE0C02`;XML entitlements `0xFADE7171`;DER entitlements `0xFADE7172`;requirements `0xFADE0C01`。
- 字符串:`__TEXT,__cstring`、`__objc_classname`、`__objc_methname`、符号表(`nlist`)按需惰性迭代;大文件用 mmap + 编译好的 `bytes` 正则。
- `write_thin(slice, dest)`:从 fat 中切出单架构(优先 arm64 / arm64e)写临时文件,供 dumper 使用。

### 4.2 项目类型打分(F-CLS)
1. `iTunesMetadata.genre/genreId` 命中 → 直接定主类(置信度 0.95)。
2. `LSApplicationCategoryType`(如 `public.app-category.games*`)→ 0.9。
3. 引擎为游戏引擎(Unity/Unreal/Cocos/Godot…)→ 游戏 +0.6(Unity 也可能做非游戏应用,故非 1.0)。
4. 框架 / SDK / 权限信号加权(`GameKit`、`AVKit+ffmpeg`、`HealthKit`、`StoreKit`、广告 SDK 数量…),规则表 `data/classify.json`。
5. 取最高分;若第一二名分差 <0.15 ⇒ 置信度降档并在证据里写明竞争项。

### 4.3 Unity 判定
最小 Unity 签名(写入 `data/engines.json`,WP7 落地):任一强信号即候选,≥2 类信号即确认。
- 文件:`Frameworks/UnityFramework.framework/`;`Data/Managed/Metadata/global-metadata.dat`;`Data/Managed/*.dll`;`Data/globalgamemanagers`;`Data/Resources/unity default resources`;`Data/data.unity3d`;`Data/level0` / `sharedassets*.assets`;`Data/Raw/`。
- 二进制字符串:`il2cpp_`、`UnityMain`、`UnityAppController`、`unity_version`、Unity 版本号正则。
- 后端:有 `global-metadata.dat` ⇒ IL2CPP;有 `Data/Managed/Assembly-CSharp.dll` ⇒ Mono;两者都无 ⇒ `unknown`。
- **il2cpp 承载二进制**:优先 `Frameworks/UnityFramework.framework/UnityFramework`(Unity 2019.3+),否则主可执行文件。

### 4.4 `global-metadata.dat` 加密 / 魔改判定
1. 读头:`magic == 0xFAB11BAF`(字节 `AF 1B B1 FA`),`version`(int32,偏移 4),合法区间由 `data/il2cpp_backends.json` 维护(实现方查证后填写)。
2. 头部自洽:各 `(offset,size)` 对应区间落在文件内、按偏移基本单调、不重叠(具体字段表依版本,实现方据官方 `il2cpp-metadata.h` 或 Il2CppDumper 源码核对)。
3. 熵:整体 + 抽样;未加密 metadata 熵显著低于加密文件。
4. 字符串区可读性:字符串表中应出现 `mscorlib` / `System` / `UnityEngine` / `Assembly-CSharp` 等。
5. 判定矩阵:
   - magic 错 + 全文件高熵 ⇒ `YES`(整体加密);magic 错 + 低熵 ⇒ `SUSPECTED`(魔改 magic / 头部 XOR,尝试单字节 / 短密钥 XOR 还原头并记录密钥假设);
   - magic 对 + 头部不自洽 ⇒ `SUSPECTED`;magic 对 + 头部自洽 + 字符串区不可读 ⇒ `SUSPECTED`(字符串级加密);
   - 全部通过 ⇒ `NO`。
6. dump 成功后追加 **标识符混淆度**(`dump.cs` 中非标准标识符占比、单字符名占比、非 ASCII 占比)⇒ `unity.il2cpp.names_obfuscated`。

### 4.5 AssetBundle 加密判定
1. **发现**:扩展名(`.bundle .ab .unity3d .assetbundle .bytes .pck? ` 等)+ `StreamingAssets`(iOS 下为 `Data/Raw/`)+ Addressables(`aa/`、`catalog_*.json|bin`、`settings.json`)+ **所有未知扩展名文件的 magic 嗅探**。
2. **分类**(读文件头):
   - `STANDARD`:以 `UnityFS\0` / `UnityWeb` / `UnityRaw` / `UnityArchive` 开头;
   - `OFFSET_PREFIX`:签名出现在偏移 >0(前 4 KB 内);
   - `XOR_SIMPLE`:头部 XOR 单字节或短重复密钥后得到签名(由前 8 字节反推密钥并验证);
   - `HIGH_ENTROPY_UNKNOWN`:无已知 magic 且抽样熵 ≥7.5;
   - `OTHER_KNOWN`(zip/png/mp4…)、`UNKNOWN`。
3. **深度校验 STANDARD**:UnityFS 头(格式版本 BE uint32、两个 NUL 结尾版本串、`int64 size`、`uint32 compressedBlocksInfoSize`、`uint32 uncompressedBlocksInfoSize`、`uint32 flags`);`flags & 0x3F` 压缩类型(0 none / 1 LZMA / 2 LZ4 / 3 LZ4HC;细节与其余标志位以官方 / 社区文档核对)。检查 size 字段与文件大小自洽;解压 BlocksInfo(**自带纯 Python LZ4 block 解码**;LZMA 用 stdlib `lzma` 的 raw 模式 + 5 字节属性头)。解压失败 ⇒ 数据级加密嫌疑(含国内 "UnityCN" 变种)。
4. **聚合**:标准且深度通过占比 ≥95% ⇒ `NO`;非标准且高熵占多数 ⇒ `YES`;其余 ⇒ `SUSPECTED`;`unknown` 仅用于"没找到任何 bundle"。输出分类计数 + 每类前 10 样本。大量 bundle 时深度校验采样(默认上限 200,可配),浅校验全量。

### 4.6 Il2CppDumper 集成(`il2cpp/`)
- **解析顺序**:`--il2cpp-tool` → `IL2CPPDUMPER_PATH` → `PATH` → 缓存 → 下载(GitHub Releases API 选与本机 .NET 运行时匹配的资产;**固定版本 + SHA256 校验**,校验值存 `data/il2cpp_backends.json`;没有可校验值时拒绝自动下载并提示手动)。
- **.NET**:`dotnet --list-runtimes` 判断;缺失 ⇒ 若已授权则用官方 `dotnet-install` 脚本装到缓存目录(用户级);设置 `DOTNET_ROLL_FORWARD=LatestMajor` 以让旧 TFM 的工具跑在新运行时上(实现方需实测验证);无授权 ⇒ `skipped + E_DOTNET_MISSING + 安装指引`。
- **缓存目录**:macOS `~/Library/Caches/ipa-analyzer`;Linux `${XDG_CACHE_HOME:-~/.cache}/ipa-analyzer`;Windows `%LOCALAPPDATA%\ipa-analyzer\cache`;环境变量 `IPA_ANALYZER_HOME` 覆盖。
- **运行**:`<tool> <binary> <metadata> <outdir>`(以所用版本 README 为准);写 `config.json`(关闭 `RequireAnyKey` 等,字段名以所用版本为准);`stdin` 管道关闭或应答;全程超时;失败时终止整棵进程树(Windows 用 `taskkill /T` 或 job object,POSIX 用进程组)。
- **Unity 版本**:部分 metadata 版本需要 Unity 版本才能准确解析,优先使用 4.3 里交叉得到的版本传给后端。
- **后端适配器**:`Il2CppBackend` Protocol:`name / supports(meta_version, unity_version) / provision() / run(req) -> Il2CppRunResult`。

### 4.7 引擎层:已知引擎签名 + 自研指纹 + 检查器插件

**三层结构**(任何一层失败不影响其他层):
1. `engine.fingerprint`(与引擎名无关的"能力画像"):
   - 维度:`render{metal,gles,vulkan,angle}`、`shader_formats`、`script_vms[]`、`physics[]`、`audio[]`、`animation[]`、`network[]`、`asset_formats[]`、`containers[]`、`host{thin_uikit_shell, cpp_ratio, objc_swift_ratio, main_loop_hints}`。
   - 规则表 `data/fingerprint.json`:`{dimension, id, signals[{type: symbol|string|dylib|file|objc_prefix, pattern, weight}]}`。例如脚本 VM 的 `luaL_newstate`、`JS_NewRuntime`(QuickJS)、`duk_create_heap`、`Py_Initialize`、`asIScriptEngine`——**符号 / 字符串须实现方核对**。
   - **容器分析 `engines/containers.py`**:对候选大文件(大小 ≥1 MB 且 magic 未知 / 扩展名在可疑集合)做:前 4 KB header 整数合理性(把 header 当作 u32/u64 序列,找 "count + 偏移表" 模式:偏移单调递增、末项 + size ≈ 文件大小)、内部压缩 magic 扫描(zlib `78 01/9C/DA`、gzip `1F 8B`、LZ4 frame `04 22 4D 18`、zstd `28 B5 2F FD`、LZMA `5D 00 00`)、分块熵与字节分布(卡方 / 唯一字节数)区分"压缩(有内部结构)"与"疑似加密(均匀分布)";已知明文探测(对前 16 字节与 PNG / zip / `1B 4C 75 61` / `{"` 等做 XOR 差分,若得到一致的短密钥则记为证据假设)。**结论上限 `suspected`;不做解密。**
2. `engine.detect`:读取 `data/engines/*.json`(一引擎一文件:`{id,name,family,kind,signals[],confirm_threshold,exclusive_with[],notes}`)+ 用户目录 `engines.user.d/*.json`;评分 = 弱信号累加 + 强信号直通;**多引擎可并存**(宿主 + 嵌入,如原生壳 + Unity UaaL、Cordova + 原生);输出 `primary / candidates / wrapper`。
   - **自研判定 `engines/custom.py`**:无已知引擎达到确认阈值,且 `fingerprint` 满足:渲染 API 命中 + (C++ 占比高 或 自带脚本 VM 或 自定义容器) + 游戏信号 ⇒ `engine.custom = yes/suspected`;若同时命中某开源引擎的**部分**特征(如 cocos2d-x 符号但目录结构异常)⇒ `engine.wrapper`/"魔改开源引擎" `suspected`,列出偏离项。自研结论必须附"画像摘要 + 下一步建议"。
3. `engine.other`:按 `primary` 与候选集合分发到 **checker 插件**。
   ```python
   # engines/api.py (WP0)
   class EngineChecker(Protocol):
       engine_id: str
       def applies(self, ctx, detect) -> bool: ...
       def run(self, ctx, detect) -> CheckerResult   # findings + data
   @register_checker("cocos")   # 自动发现 engines/checkers/*.py
   ```
   每个 checker 只读 `ctx`,输出写入 `ctx.results["engine.other"][engine_id]`;异常被隔离为该 checker 的 `failed`。

**Cocos 家族判定要点**(实现方须核实后落地):区分 ①cocos2d-x C++(符号 `cocos2d::`、`libcocos2d`、`Resources/`/`res/`)②cocos2d-x Lua(`LuaEngine`/`luaL_*` + `src/`/`.lua(c)`;xxtea 加密脚本带 sign 头,`xxtea` 符号 / `setXXTEAKeyAndSign` 一类字符串)③cocos2d-x JS(`ScriptingCore`/`jsb_` + SpiderMonkey 或 V8/JSC;`.jsc`)④Cocos Creator 2.x(`main.js`、`project.json`、`src/project.js(c)`、`res/import|raw-assets`)⑤Creator 3.x(`application.js`、`assets/<bundle>/config.*.json`、`cc.js`、`.cconb`、`src/chunks`)⑥cocos2d-iphone(ObjC `CCDirector`)。脚本保护三态:明文 JS/Lua ⇒ `no`;字节码(jsc/luac)⇒ `no`(已编译,非加密,但需注明);高熵 + 无已知 magic + `xxtea`/自定义解密线索 ⇒ `suspected`。资源(图集、csb、cconb、音频)是否被自定义加密由容器 / magic 嗅探判定。

**Egret / Laya**:Egret 的 `resource/*.res.json|.thm.json|.exml`、`egret.min.js`/`manifest.json`、native runtime 库;Laya 的 `laya*.js`、`.atlas`、`.lh/.lmat/.ls`、`conch` 运行时。具体文件名与格式须联网核实后写入 `data/engines/`,拿不准的标 UNVERIFIED 并降权。

## 5. 跨平台策略(硬性)
| 风险 | 对策 |
|---|---|
| 平台专有命令 | 禁止依赖 `otool/plutil/codesign/lipo/unzip/file/strings`;可选地"若存在则交叉验证",默认不用 |
| 路径 | 一律 `pathlib`;zip 内部路径用 `PurePosixPath`;输出路径做规范化 + 越界检查;Windows 长路径前缀 `\\?\`;保留名(CON/PRN/AUX/NUL/COM1…)与非法字符替换并记录映射 |
| 大小写 | macOS / Windows 默认不区分大小写:提取时检测冲突并加后缀,记录于 manifest |
| 符号链接 | 仅记录;POSIX 可选创建(目标必须仍在输出目录内),Windows 不创建 |
| 编码 | 所有 `open()` 显式 `encoding="utf-8"`;stdout `reconfigure(encoding="utf-8", errors="replace")`;zip 文件名按标志位选 UTF-8 / cp437,失败回退并记录 |
| 子进程 | `subprocess.run([...], shell=False, timeout=...)`;可执行文件解析用 `shutil.which`(Windows 自动含 `.exe`);进程树清理分平台实现 |
| 换行 | 写文件统一 `newline="\n"` |
| mmap | Windows 上 mmap 的文件不可同时被删除:用完显式关闭;临时文件清理放 `finally` |
| Python 版本 | 3.9 语法:不用 `match`、不在运行时注解里用 `X \| Y`(加 `from __future__ import annotations`)、不用 3.10+ 标准库新 API |
| 架构 | .NET 由 dotnet 自行适配 RID;不假设 x64 |

## 6. 安全设计
- 不可信输入:zip-slip(拒绝 `..`、绝对路径、盘符)、总解压量 / 单文件 / 文件数 / 压缩比上限(默认 8 GB / 2 GB / 200k / 200:1,可配);提取量按 "实际需要" 计。
- 外部进程:参数列表、固定工作目录、超时、环境变量白名单、不继承用户 stdin。
- 下载:仅 HTTPS、固定主机白名单(`github.com`、`api.github.com`、`dot.net`、`dotnetcli.azureedge.net`/微软官方分发域,以实测为准)、SHA256 校验、落盘到缓存目录原子重命名。
- 隐私:`redact.py` 对 `apple-id / userName / DSPersonID / purchaseDate / receipt` 等字段脱敏;日志不打印完整路径中的用户名(可选)。

## 7. 测试与质量
- **夹具生成器** `tests/fixtures/build_fixtures.py`:程序生成最小 Mach-O(thin / fat / 含 `LC_ENCRYPTION_INFO_64` 且 `cryptid` 0/1 / 含 dylib 依赖 / 含 `__objc_classname`)、假 IPA(zip,含 `Info.plist` 二进制 + XML 两种、`embedded.mobileprovision` 伪 CMS、`iTunesMetadata.plist`)、假 Unity 目录(合成 `global-metadata.dat`:正常头 / 错 magic / XOR / 随机;合成 UnityFS:none / LZ4 / LZMA 的 BlocksInfo、偏移前缀、XOR、高熵)、假 dumper(Python 脚本:成功 / 失败码 / 睡死 / 弹交互提示)。
- 单元测试各 WP 自带;集成测试(完整流水线)WP9;**黄金文件**测试 `report.json` 稳定性。
- 可选真实样本 e2e:`IPA_SAMPLES_DIR`;网络相关测试默认跳过(`IPA_TEST_NETWORK=1` 打开)。
- CI:GitHub Actions `ubuntu / macos / windows` × Python `3.9 / 3.12 / 3.13`。

## 8. 风险与对策
| 风险 | 影响 | 对策 |
|---|---|---|
| 新 Unity(2022.3+/Unity 6)metadata 新版本,Il2CppDumper 不支持 | dump 失败 | 后端链 + 兼容矩阵 + 明确 `E_METADATA_VERSION_UNSUPPORTED` |
| 厂商魔改 metadata / il2cpp | 误判 / dump 失败 | 三态 + 证据;不确定标 `suspected`,绝不报 `no` |
| 国产 Unity 加密变种(UnityCN 等) | AssetBundle 判定不准 | 深度校验(解 BlocksInfo)+ 熵;报告写明局限 |
| 自研 / 魔改引擎无固定签名 | 引擎识别落空 | 与引擎名无关的能力指纹 + 容器通用分析 + 画像摘要与下一步建议;不凭印象给引擎起名 |
| 压缩与加密在熵上不可分 | 容器误判 | 内部结构(压缩 magic / 偏移表)优先于熵;结论上限 `suspected` |
| FairPlay 包比例高 | dump 常被跳过 | 前置检查 + 清晰提示"提供已解密 IPA";其余分析不受影响 |
| 知识库(libs)过时 | 用途缺失 | unknown 显式标注 + 用户可扩展 + SKILL 指引 Agent 联网补全 |
| 记忆性事实出错(偏移 / magic / 版本区间) | 判定错 | 所有此类常量必须在代码注释中标注来源(文档 / 源码 / 实测);无法核对的在返回报告中列为 UNVERIFIED |
| 3 OS 无法本地全测 | Windows/Linux 缺陷 | CI 矩阵 + `PureWindowsPath` 单测 + 评审 agent 专查跨平台坑 |

## 9. SKILL.md 设计要点(WP9 定稿)
- `description`:触发词 "分析 ipa / ipa 结构 / ipa 报告 / unity ipa / il2cpp dump / assetbundle 加密 / 拆包 / 逆向摸底"。
- 正文流程:① `doctor` ② `analyze` ③ 读取 `report.json` 的执行摘要向用户汇报 ④ 对 `libs.unknown` 联网查证并写入 `libs.user.json` ⑤ FairPlay 命中时明确告知并停止 dump,不尝试任何解密 ⑥ 不粘贴被脱敏字段。
- 引擎识别结果为 `engine.custom` 时:读 `references/custom-engine-playbook.md`,按报告里的"引擎画像 + 下一步建议"继续人工 / Agent 深挖,并把确认过的特征回写到 `engines.user.d/<id>.json`,下次即可直接识别。
- 渐进披露:详细专题放 `references/*.md`(Mach-O / FairPlay、UnityFS、IL2CPP 排障、报告字段表),SKILL.md 只放流程与命令。

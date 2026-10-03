# ipa-analyzer 需求文档 v1.0

> 一句话:给定 IPA(或 `.app` 目录),在 **任意 OS(macOS / Linux / Windows)** 上自动产出 **结构化(JSON)+ 可读(Markdown)** 的分析报告;对 Unity 游戏额外判定 IL2CPP / AssetBundle 是否加密,并在条件满足时 **自动运行 Il2CppDumper**。
> 交付形态:Claude Code Skill(`SKILL.md` + Python 脚本),同时可作为独立 CLI(`ipa-analyze`)使用。

---

## 1. 目标用户与典型场景

| 用户 | 场景 | 最关心 |
|---|---|---|
| 逆向 / 安全研究员 | 拿到一个 IPA,先摸底再决定怎么深入 | 引擎、是否加密 / 加壳、能不能 dump、SDK 清单 |
| 竞品 / 合规分析 | 梳理第三方 SDK、权限、隐私面 | SDK 用途分类、权限说明、追踪类 SDK |
| 开发者自查 | 看自家包体构成与残留 | 体积构成、冗余资源、符号是否剥离、签名类型 |

适用边界:仅用于 **自有应用、已获授权的安全研究、合规审计、学习研究**。工具不提供任何绕过保护的能力(见 §3 Out of scope)。

## 2. 范围与优先级

P0 = 首版必须;P1 = 首版尽量;P2 = 后续。

### F-ING 输入与摄取
- P0 支持输入:`.ipa`、改名的 `.zip`、`.app` 目录、`Payload/` 目录、已解压目录。
- P0 只读 zip 中央目录 + 按需读取;**不整包解压**(IPA 动辄 1–4 GB)。支持 zip64。
- P0 安全处理不可信输入:zip-slip、zip bomb(总大小 / 压缩比 / 文件数上限)、Windows 保留名与非法字符、大小写冲突、符号链接(仅记录,Windows 不创建)、非 UTF-8 文件名。
- P0 计算 IPA 的 sha256 / 大小,用于缓存与报告溯源。
- P1 `.xcarchive` 输入。

### F-META 应用元信息
- P0 **项目名**:候选全部给出并标明来源,按优先级选定:本地化 `InfoPlist.strings`(zh-Hans / zh-Hant / en)的 `CFBundleDisplayName` → `CFBundleDisplayName` → `CFBundleName` → `iTunesMetadata.plist` 的 `itemName` → 可执行文件名 → IPA 文件名。
- P0 Bundle ID、版本 / build、最低系统、设备族、`UIRequiredDeviceCapabilities`、后台模式、URL Schemes、`LSApplicationQueriesSchemes`、ATS 配置、所有 `NS*UsageDescription`(含本地化文本)、App Extension / Watch / App Clip 列表。
- P0 分发类型判定:AppStore / AdHoc / Enterprise / Development / 未签名(依据 `embedded.mobileprovision`、`SC_Info`、`iTunesMetadata.plist`、entitlements `get-task-allow`)。
- P0 `iTunesMetadata.plist` 中购买者信息(Apple ID、姓名等) **默认脱敏**。
- P1 `_CodeSignature/CodeResources` 完整性校验(资源被改 / 重打包检测)。

### F-STRUCT 项目结构
- P0 目录树(深度可配,默认 3,带体积汇总)、嵌套单元清单(`Frameworks/*.framework`、`PlugIns/*.appex`、`Watch/*.app`、`*.bundle`、`*.dylib`)。
- P0 每个 Mach-O(主程序 / framework / dylib / appex)单独给出:架构、文件类型、SDK / 最低系统、UUID、是否 PIE、是否剥离符号、是否 FairPlay 加密、签名信息。
- P0 实现语言推断:ObjC / Swift / C++ / C# (IL2CPP) / Lua / JS / Dart 等(带证据)。
- P0 引擎 / 框架识别(已知引擎库,每个引擎一个 `data/engines/<id>.json`,可插拔):Unity(Mono / IL2CPP)、Unreal、Cocos 家族(cocos2d-x C++ / Lua / JS、Cocos Creator 2.x / 3.x、cocos2d-iphone ObjC)、Egret(白鹭)、LayaAir、Godot、Defold、GameMaker、Solar2D(Corona)、LÖVE、Flutter、React Native(含 Hermes)、Xamarin / MAUI / MonoGame、Cordova / Capacitor / 纯 WebView 游戏(Phaser / Pixi / Construct)、Haxe(Heaps / Flixel)、SDL / Qt / Kivy 类宿主、开源渲染 / 引擎库(Ogre3D / Irrlicht / bgfx / Filament / Unigine / O3DE 等,仅在特征可核实时收录)、纯原生(UIKit / SwiftUI)。
- P0 **自研 / 未知引擎识别**:未命中任何已知引擎时,不得简单报 unknown,而要输出 **引擎指纹画像**(见 F-ENG)并判定 `engine.custom`。

### F-RES 资源结构
- P0 按类别汇总(数量 / 体积 / 占比):可执行代码、Frameworks、Assets.car、图片、音频、视频、字体、本地化、nib / storyboard、脚本、着色器、数据库、引擎数据、AssetBundle、打包归档(pak / obb / zip / pck)、签名与元数据、其他。
- P0 扩展名分布、Top-N 大文件、本地化语言列表、打包归档清单。
- P0 对每个文件做 magic 嗅探(不信任扩展名),标注真实类型;对 ≥4 KB 的文件抽样计算熵,用于加密 / 压缩判定。
- P1 Assets.car 渲染项概览(pure-Python BOM 解析失败时降级为仅体积)。

### F-LIB Lib 用途识别
- P0 来源:`LC_LOAD_DYLIB`(系统 / 内嵌)、`Frameworks/`、`PlugIns/`、资源 `*.bundle`、ObjC 类名前缀(`__objc_classname`)、Swift 模块名与符号、特征字符串 / 域名、Unity dump 命名空间。
- P0 知识库 `data/libs.json`(种子 ≥150 条常见库 / SDK,每条含厂商、类别、中英文用途、隐私标签、匹配规则),可被用户文件 `libs.user.json` 覆盖 / 扩充。
- P0 类别:引擎 / 渲染、网络、广告、归因 / 统计、崩溃监控、支付、社交 / 登录、推送、音视频 / RTC、安全 / 反作弊、热更新、存储 / 数据库、UI、其他系统框架。
- P0 **未命中的库明确标记 `unknown`,不得凭名字臆测用途**;SKILL 指引 Agent 对 unknown 库联网查证后写回 `libs.user.json`。
- P0 每条结论带 **证据 + 置信度**(独立证据类型越多置信度越高)。

### F-ENC 加密 / 保护判定(统一三态:`yes` / `no` / `suspected` / `unknown` / `n/a`)
- P0 **FairPlay**:逐 Mach-O、逐架构读取 `LC_ENCRYPTION_INFO(_64)` 的 `cryptid`;汇总"整包是否可直接做二进制分析"。
- P0 代码签名:有无签名、Team ID、entitlements、CodeDirectory 哈希算法。
- P0 符号剥离、PIE、栈保护、ARC、Bitcode 残留。
- P0 反调试 / 越狱检测特征(`ptrace`、`sysctl`、`/Applications/Cydia.app` 等字符串与符号),标注为 **特征命中,非结论**。
- P1 常见加固 / 混淆器特征(商业壳、字符串加密、OLLVM 痕迹),只做特征匹配,低置信度。
- P0 资源级加密(由引擎分析器负责,见 F-UNITY / F-ENG)。

### F-CLS 项目类型分类(游戏 / 影音 / 生活 …)
- P0 内部分类:游戏、影音(含音乐 / 视频 / 摄影)、生活、社交、工具 / 效率、金融、教育、健康健身、购物、出行、新闻 / 阅读、其他。
- P0 证据优先级:`iTunesMetadata.genre/genreId`(游戏 genreId=6014)→ `LSApplicationCategoryType` → 引擎(游戏引擎强信号)→ 框架 / SDK 信号打分(`data/classify.json`)→ `unknown`。
- P0 输出主类、子类(游戏子类型若可得)、置信度、证据列表。

### F-UNITY Unity 专项(识别为 Unity 时自动执行)
- P0 Unity 版本(多来源交叉:UnityFS 头 revision、`globalgamemanagers`、二进制字符串;冲突时都列出并说明采信哪个)。
- P0 脚本后端:**IL2CPP** vs **Mono**(`Assembly-CSharp.dll` 等)。
- P0 **IL2CPP 检查**:`global-metadata.dat` 是否存在 / magic / 版本 / 头部自洽性 / 熵 / 字符串区可读性 → 判定是否 **被加密或魔改**;定位承载 il2cpp 的二进制(`UnityFramework` 或主程序)并检查其 FairPlay 状态与 il2cpp 特征。
- P0 **AssetBundle 检查**:发现全部 bundle(扩展名 + magic,含 Addressables / StreamingAssets);分类为 标准 / 偏移前缀 / 简单 XOR / 疑似加密 / 其他;对标准 bundle 解析 UnityFS 头并解 BlocksInfo(LZ4 / LZ4HC / LZMA / none)验证;给出 **整体加密判定 + 样本证据**。
- P0 **Mono**:DLL 是否为合法 PE + CLI 元数据(`BSJB`),否则判定疑似加密;识别常见混淆器特征。
- P0 **热更新专项**(详见 `docs/04-UNITY-HOTFIX.md`,独立阶段 `engine.unity.hotfix`):
  - 机制识别:C# 热更(HybridCLR / ILRuntime / InjectFix)、Lua(xLua / ToLua / SLua / MoonSharp 等)、JS(puerts 的 V8 / QuickJS / Node 后端等)、资源热更(Addressables / YooAsset / 自研 manifest + CDN 域名)。
  - 证据来自四路:metadata 字符串表(**不依赖 dumper**)、dump 命名空间、原生符号/字符串、散文件与 AssetBundle/SerializedFile 内容签名扫描(采样并报告比例)。
  - **Lua 版本区分**:字节码头解析区分 PUC-Lua 5.1 / 5.2 / 5.3 / 5.4 与 LuaJIT 2.0 / 2.1,并给出端序、位宽、是否剥离;原生串推断运行时版本;字节码与运行时不一致告警;魔改 Lua(头部篡改 / XOR)嫌疑;明文 Lua 方言推断(P1)。
  - 热更 DLL 画像:程序集名、CLR 版本、AssemblyRef;区分热更程序集与 AOT 补充元数据 DLL;压缩 / 疑似加密 / XOR 假设。
  - 脚本保护三态(lua / js / csharp):明文 `no`、字节码 `no`(注明已编译)、高熵或篡改 `suspected`。**只报告,不解密、不提取密钥。**
- P0 **自动 Il2CppDumper**(见 F-IL2CPP)。
- P1 场景数、`StreamingAssets` 盘点、FMOD / Wwise / Spine / Live2D 等中间件识别。

### F-IL2CPP 自动 il2cpp dump
- P0 **前置条件检查**(不满足则跳过并给出原因与补救建议,**不盲跑**):binary 非 FairPlay 加密;metadata 存在且 magic / 版本 / 头部自洽;能找到 il2cpp 二进制。
- P0 多架构 fat 二进制自动切出 arm64 slice(纯 Python,不依赖 `lipo`)。
- P0 **工具自动供应**:查找顺序 `--il2cpp-tool` → 环境变量 → `PATH` → 本地缓存 → 自动下载(固定版本 + SHA256 校验);.NET 运行时缺失时,在 **一次性授权** 后做用户级安装(不需要管理员权限);`--offline` 时只用本地。
- P0 非交互运行:关闭 `RequireAnyKey`、stdin 关闭或按需喂答案、超时、杀进程树、捕获 stdout / stderr。
- P0 产物采集与摘要:`dump.cs`、`script.json`、`il2cpp.h`、`stringliteral.json`、`DummyDll/`;摘要含 assembly / namespace / 类 / 方法数量、命中的 SDK / 框架命名空间、**标识符混淆度**。
- P0 **后端链**:Il2CppDumper → Cpp2IL → Il2CppInspectorRedux(适配器模式,按 metadata 版本与失败原因选择 / 回退;兼容矩阵放 `data/il2cpp_backends.json`,**必须以实测 / 官方文档为准,不凭记忆**)。
- P0 失败分类与建议:`E_BINARY_FAIRPLAY` / `E_METADATA_ENCRYPTED` / `E_METADATA_VERSION_UNSUPPORTED` / `E_REGISTRATION_NOT_FOUND` / `E_DOTNET_MISSING` / `E_TOOL_DOWNLOAD_FAILED` / `E_TIMEOUT` / `E_UNKNOWN`。

### F-ENG 引擎专项:自研引擎指纹 + 各引擎资源保护检查
**A. 自研 / 未知引擎指纹(`engine.fingerprint`,独立于具体引擎名)**
- P0 渲染后端:Metal / OpenGLES / Vulkan(MoltenVK)/ ANGLE,及着色器形态(`.metallib`、`.metal`、`.glsl`、`.hlsl`、`.spv`、自定义 shader 包)。
- P0 脚本运行时:Lua / LuaJIT、QuickJS、V8、JavaScriptCore(自带)、mozjs、Duktape、Python、Squirrel、AngelScript、Wren、mruby、Mono / IL2CPP、Hermes。依据符号 / 字符串(如 `luaL_newstate`),规则数据驱动。
- P0 物理 / 音频 / 动画 / 网络中间件:Box2D、Bullet、PhysX、Havok、Chipmunk、Jolt;FMOD、Wwise、OpenAL、miniaudio、BASS;Spine、DragonBones、Live2D;protobuf、flatbuffers、KCP、enet 等。
- P0 资源格式画像:纹理(ASTC / PVR / KTX / DDS / ETC / Basis)、模型 / 动画、地图(Tiled)、配置(json / csv / protobuf / flatbuffers / sqlite / lua 表)。
- P0 **自定义资源容器分析**:对大体积、未知扩展名 / 未知 magic 的文件(`.pak .pck .dat .bin .data .res .assets .npk .mpq .zpk .arc .vfs` 等)做通用分析——header 整数合理性(文件数 / 偏移表单调 / 大小之和自洽)、内部压缩流 magic(zlib / gzip / LZ4 / zstd / LZMA)、熵与字节分布;区分"压缩 / 加密 / 明文 / 自定义格式",**只下 `suspected` 级结论**;对小样本做"已知明文 XOR 探测"(对照 PNG / zip / Lua 字节码 / JSON 等已知头)并把假设写入证据。
- P0 宿主形态:薄 UIKit 壳 + `CAMetalLayer` / `CADisplayLink` / `GLKView` + 大体量 C++ 二进制(`_ZN` 符号占比、`libc++`)⇒ "自研原生引擎"强信号。
- P0 **`engine.custom` 判定**:无已知引擎达到确认阈值 + 渲染 API 命中 + 原生 C++ 占比高 + 游戏信号(或自带脚本 VM / 物理 / 自定义容器)⇒ `yes/suspected`,并输出 **引擎画像摘要**(渲染 / 脚本 / 物理 / 音频 / 资源容器 / 配置格式 / 网络)与 **下一步分析建议**(应优先看哪些二进制 / 文件)。
- P0 可疑的"二次包装"识别:渠道壳 / 加固壳 / 自研 + 开源引擎混合(如 cocos2d-x 改造版),标 `suspected` 并列出命中的开源引擎与偏离项。
- P1 知名自研引擎(NeoX 系、Supercell 系等,见 `docs/03-ENGINE-RESEARCH.md`)仅在特征**可核实**时收录,并以"与某某系文件格式一致"的带置信度线索呈现,不直接断言厂商;Messiah、QuickSilver、Angelica 等暂无公开 iOS 特征,走通用指纹。

**B. 各引擎资源 / 脚本保护检查(`engine.other`,每个引擎一个 checker 插件)**
- P0 **Cocos 家族(重点)**:
  - cocos2d-x C++ / Lua:`.lua` 明文 / `.luac`(Lua / LuaJIT 字节码)/ xxtea 加密脚本(sign 头特征、`xxtea` 符号)/ 自定义 `FileUtils` 解密钩子线索;`res/`、`src/`、`.plist`+`.png` 图集、`.csb`(CocosStudio)、`.ExportJson`;
  - cocos2d-x JS(JSB):`.js` 明文 / `.jsc`(`cocos jscompile` 产物)/ 加密 jsc、SpiderMonkey 版本线索;
  - Cocos Creator 2.x / 3.x:`main.js`、`project.json` / `application.js`、`src/*.jsc`、`assets/<bundle>/config.*.json`、`import/` `native/` 目录、`.cconb`、bundle 的 hash 命名;脚本 `index.js` 明文 / jsc / 加密;资源是否带自定义加密;版本推断;
  - cocos2d-iphone(ObjC `CC*` 类)。
- P0 Egret(白鹭)/ LayaAir:原生 runtime 壳 + `resource/*.res.json`、`.exml`、`.thm.json`、`laya*.js`、`.atlas`、`.lh/.lmat` 等;脚本 / 资源是否明文或打包 / 加密。
- P0 Unreal:`.pak` 存在性、footer、索引是否加密;IoStore(`.utoc/.ucas`)。
- P0 Godot:`.pck`(`GDPC`)及加密标志;Flutter:AOT 快照;React Native:Hermes 字节码 vs 明文 jsbundle;Lua / LuaJIT 字节码;Defold(`game.arcd` 等)、GameMaker、Solar2D、LÖVE 的资源包形态(特征需核实)。
- P1 Xamarin / MAUI / MonoGame DLL 校验、Cordova `www/`。
- P0 **插件化**:新增一个引擎 = 新增 `data/engines/<id>.json`(检测签名)+ 可选一个 checker(`@register_checker("<id>")`);用户可在 `IPA_ANALYZER_HOME/engines.user.d/*.json` 放自己的签名,无需改代码。

### F-RPT 报告
- P0 `report.json`(带 `schema_version`,有 JSON Schema)+ `report.md`(默认中文,`--lang en` 可切换)。
- P0 报告章节对应需求清单:① 基本信息 ② 项目类型 ③ 项目结构 ④ 资源结构 ⑤ Lib 用途 ⑥ 加密与保护 ⑦ 引擎专项(Unity 等)⑧ 隐私与权限 ⑨ 附录(各阶段状态、工具日志、限制)。
- P0 顶部 **执行摘要**(≤15 行):一眼看到"是什么、什么引擎、加密吗、能不能 dump、风险点"。
- P0 每个结论带 `verdict` / `confidence` / `evidence`;**未执行或失败的阶段必须在报告里显式写明原因**,不能静默缺失。
- P1 单文件 `report.html`。

### F-ENV 环境与适配
- P0 `ipa-analyze doctor`:检查 Python、OS / 架构、.NET、缓存目录可写、网络可达(可跳过)、已缓存工具版本。
- P0 `ipa-analyze tools install|list|path`。
- P0 全程不依赖 `otool` / `plutil` / `codesign` / `lipo` / `unzip` 等 macOS 专有或平台相关命令(核心路径纯 Python 标准库)。

---

## 3. Out of scope(明确不做)
- 不做 FairPlay 解密 / 脱壳 / 越狱设备交互。遇到加密包 → 报告"需用户提供已解密 IPA",并指出哪些分析因此受限。
- 不做动态分析、重签名、安装、反编译为源码(仅调用现有 dumper 并汇总其输出)。
- 不做 DRM / 反作弊 / 加密的绕过或破解;只做 **检测与报告**。
- 不内置、不分发任何第三方 App 的文件;测试夹具全部程序生成。

## 4. 非功能需求
| 项 | 指标 |
|---|---|
| 跨平台 | macOS(arm64/x64)、Linux(x64/arm64)、Windows 10+;Python ≥3.9;核心仅标准库;可选依赖缺失自动降级 |
| 性能 | 1 GB IPA、不含 il2cpp dump:≤60 s、峰值内存 ≤500 MB;哈希 / 熵 / 嗅探均流式或抽样 |
| 健壮性 | 单阶段异常不拖垮整体(阶段隔离,`status: ok/partial/skipped/failed`);畸形 / 截断输入不崩溃不死循环 |
| 安全 | 永不执行 IPA 内容;外部进程 `shell=False` + 超时 + 参数白名单;下载校验 SHA256;输出目录不越界 |
| 隐私 | 默认脱敏购买者信息;报告不含完整 entitlements 之外的账号信息;`--no-redact` 显式关闭 |
| 离线 | `--offline`:不联网,工具须预置;报告注明因离线跳过的项 |
| 可复现 | 报告含工具版本、输入哈希、各阶段耗时;同输入同版本 JSON 输出稳定(排序、无随机) |
| 可测试 | 夹具程序生成;CI 矩阵 3 OS × Python 3.9 / 3.12 / 3.13;真实 IPA 的 e2e 为可选(`IPA_SAMPLES_DIR`) |
| 可扩展 | 新引擎 / 新库 / 新保护只需加 `data/**/*.json` 或新增一个 analyzer / checker 文件,无需改核心 |

## 5. 总体验收标准(DoD)
1. `python skills/ipa-analyzer/scripts/ipa_analyze.py <fixture.ipa>` 在 macOS / Linux / Windows CI 全绿,产出 `report.md` + `report.json`(通过 schema 校验)。
2. 对"合成 Unity IL2CPP IPA"夹具:正确识别 Unity / IL2CPP;metadata 正常 / 被改 magic / 被 XOR 三种情形判定正确;AssetBundle 标准 / 偏移 / XOR / 随机高熵四种情形判定正确。
3. 对 `cryptid=1` 的夹具:报告 `protect.fairplay = yes`,IL2CPP dump 被跳过且给出 `E_BINARY_FAIRPLAY` 与建议。
4. 对假 dumper(桩可执行文件)的运行器测试:成功 / 失败 / 超时 / 交互提示卡住 4 种情形行为正确。
5. 对"自研引擎"夹具(无任何已知引擎签名,有 Metal + 自带 Lua + Box2D + 自定义 `.pak` 容器):`engine.custom` 判定为 yes/suspected,引擎画像各维度命中正确,**不被误判为任何已知引擎**;对 Cocos 家族夹具(C++ / Lua 明文、Lua xxtea 疑似、JS jsc、Creator 3.x)主引擎与脚本保护判定正确。
6. 无 dotnet、无网络环境下:`doctor` 与分析均可运行,il2cpp 阶段 `skipped` 并给出可操作的补救说明。
7. Unity 热更夹具(HybridCLR / ILRuntime / xLua / ToLua(LuaJIT) / puerts / Addressables):框架、脚本存放位置与格式、**Lua 版本分布**、一致性告警、篡改嫌疑判定正确。
8. 若用户提供真实样本(见 §7):至少 1 个 Unity IL2CPP(已解密)端到端产出 dump;1 个 App Store 加密包正确报 FairPlay。
9. `docs/ACCEPTANCE.md` 逐条记录以上验收结果与 **未验证项**。

## 6. 我替你做的决定(默认假设,可推翻)
| 决策 | 理由 |
|---|---|
| 语言选 Python ≥3.9、核心零第三方依赖 | zip / plist / struct / mmap / lzma 标准库齐全;三平台都易装;Skill 脚本惯例。Go 单二进制分发更好但迭代慢,后续可重写热点 |
| 不整包解压,按需提取 | 大 IPA 磁盘与时间成本;"拆分"以 **清单分类 + 选择性提取** 实现,而非复制一份 |
| "拆分" = 逻辑拆分 | `inventory.json` 给每个文件打类别标签;`--extract binary,frameworks,metadata,bundles` 按类物理提取到 `out/<name>/split/<category>/` |
| 三态 + 置信度 + 证据 | 逆向结论常是启发式,必须区分"确认没有"和"没查出来" |
| FairPlay 只检测不处理 | 合规边界;同时是 il2cpp dump 的硬前置 |
| Il2CppDumper 自动下载 + 固定版本校验,.NET 用户级安装需一次授权 | 满足"自动",又不静默改动用户系统 |
| 报告默认中文,JSON 键为英文 | 面向你的阅读习惯;机读稳定 |
| 失败即降级,不终止 | 部分结果比没结果有用 |

## 7. 开放问题(不阻塞开工,但影响验收)
1. **样本 IPA**:请提供(或指定目录)≥3 个:① 已解密的 Unity IL2CPP 游戏 ② App Store 加密包 ③ 原生 App。没有则只能做合成夹具验收(DoD 第 6 条无法验证)。
2. 是否需要 **HTML 报告**(P1)?还是 md + json 足够?
3. 是否需要对接 **IDA / Ghidra 脚本导出**(il2cpp 的 `ida_py3.py` / `ghidra.py` 符号脚本产物已由 dumper 生成,仅需归档;更深的自动导入属 P2)?
4. 报告里的 **Unity 之外**的深度(如 Unreal pak / Cocos 资源包解析)是否要超出"检测加密"的程度?当前定为不超出。
5. 你手上有哪些**自研引擎**样本 / 目标?有的话给我名字或特征,我会把可核实的特征固化进 `data/engines/`。

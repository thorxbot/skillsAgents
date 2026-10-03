# WP5b — Unity 热更新专项:C# DLL / Lua(含版本区分)/ JS / 资源热更(Wave 2)

先读 `prompts/_common.md`、`docs/CONTRACT-FREEZE.md`、**`docs/04-UNITY-HOTFIX.md`(本包的完整设计与调研,必读)**、`docs/02-ARCHITECTURE.md` §4.3–4.5。依赖:WP3b(`formats/*`)、WP5(`ctx.results["unity"]`:backend、metadata 路径与判定、bundles 摘要)、WP1(inventory / 提取)、WP3(macho / scan)、WP6(dump 摘要,可选)。

## 目标
回答:**这个 Unity 游戏的热更新是什么机制(DLL / Lua / JS / 仅资源)、脚本放在哪(散文件 / bundle / serialized)、是什么格式(明文 / 字节码 / 压缩 / 疑似加密)、Lua 是哪个版本**。取代 WP5 里原先的简单"热更新框架识别"。

## 文件归属
`src/ipa_analyzer/analyzers/unity_hotfix.py`(阶段名 `engine.unity.hotfix`,requires `engine.unity`)、
`src/ipa_analyzer/unity/hotfix/{__init__,detect.py,metadata_strings.py,native_signals.py,storage.py,lua.py,csharp.py,js.py,resource_update.py,summary.py}`、
`data/hotfix.json`(各框架的检测规则:命名空间/类名、原生符号、文件模式、版本串正则、框架默认运行时旁证——**每条带 `sources`,未核实标 `unverified`**)、
`data/i18n/{zh,en}/unity_hotfix.json`、`references/unity-hotfix.md`、`tests/unit/unity_hotfix/*`、`tests/fixtures/unity_hotfix_builder.py`(在 `formats_builder` 与 `unity_builder` 之上组装:含 xLua / ToLua(LuaJIT) / HybridCLR / ILRuntime / puerts / Addressables / YooAsset 特征的合成 Unity 目录与 bundle)。

## 要做的事
1. **证据采集(四路,见设计 §2)**
   - `metadata_strings.py`:**不依赖 dumper**,流式扫描 `global-metadata.dat` 的字符串区(用 WP5 已解析的头/字符串区偏移;metadata 判定为 `yes/suspected` 时跳过并标注"降级")匹配 `hotfix.json` 的命名空间/类名;
   - dump 命名空间(`ctx.results["unity"]["dump"]`,可选);
   - `native_signals.py`:原生符号/字符串(Lua C API、`xlua_*`、QuickJS/V8 符号、`hybridclr::` 等)+ **Lua 运行时版本串**(`Lua 5.x.y`、`LuaJIT 2.x.y…`,正则以官方版本串格式核实)——经 WP3 `scan`,限量;
   - `storage.py`:散文件(inventory)+ **采样 bundle 的解压流签名扫描**(用 `formats.unityfs.iter_decompressed` + `formats.magic_scan`)+ `resources.assets`/`sharedassets*`/`level*` 扫描;所有上限可配(`Config.unity.hotfix_scan_bundles=100`、`hotfix_scan_bytes_per_bundle=64MiB`),**报告采样比例**。
2. **框架判定 `detect.py`**:规则驱动(`hotfix.json`),多证据归并为 `frameworks[]`,给 `confidence` 与 `evidence`;版本线索 `version_hint` **仅在存在可观察标记时给出**(否则 `null`,不得猜);同包多方案并存(如 HybridCLR + xLua)正常输出。
3. **Lua `lua.py`**(用户重点):
   - 对所有候选 Lua 脚本(散文件 + bundle/serialized 命中):用 `formats.lua_bytecode.parse_header` 分类 `plain / bytecode(version) / compressed / encrypted_suspected`;明文用 `formats.lua_source.infer_dialect`;
   - 聚合 **Lua 版本画像**:`bytecode.by_version`、`bits`、`stripped`、`runtime_versions`(原生串)、`dialect_hints`;**一致性校验**(字节码版本 vs 运行时版本;不一致 ⇒ 告警)、`custom_lua_suspected`(头部篡改信号 / XOR 假设 / 版本字节异常);
   - 框架默认运行时只作旁证(例如 tolua# 在 iOS 默认 LuaJIT——见调研;**以实测为准,冲突要写出来**);
   - Finding:`unity.hotfix.lua`、`unity.hotfix.lua_version`、`unity.hotfix.script_protection`(lua 部分:明文 `no` / 字节码 `no`(注明已编译)/ 高熵或头部篡改 `suspected` / 无脚本 `n/a`)。
4. **C# 热更 `csharp.py`**:对 `*.dll`、`*.dll.bytes`、bundle 内命中的 PE:用 `formats.pe_cli.parse` 提取程序集名/CLR 版本/TypeDef 数/AssemblyRef;识别 HybridCLR 的"热更程序集 vs AOT 补充元数据 DLL"(依据命名/数量/与 AOT 程序集同名等,规则放 `hotfix.json`);非 PE 候选按 `compress_sniff` + 熵 + XOR 假设分类;Finding:`unity.hotfix.csharp_dll`。
5. **JS `js.py`**:puerts 后端判定(V8 / QuickJS / Node.js,依据原生符号与库特征);JS 文件明文/字节码(格式须核实,拿不准只报"二进制非文本")/疑似加密;Finding:`unity.hotfix.js`。
6. **资源热更 `resource_update.py`**:Addressables(`aa/`、catalog、settings)、YooAsset/XAsset/GameFramework/QFramework(命名空间 + 清单文件模式)、通用 manifest/`filelist`/`version` 文件;从清单/配置字符串提取 **CDN 域名**(只域名,去重,最多 20,不含路径与 token);Finding:`unity.hotfix.resource_update`。
7. **汇总 `summary.py`**:`script_protection{lua,js,csharp}` 三态;`summary_text`(英文兜底 + i18n),如 *HybridCLR + xLua(LuaJIT 2.1 bytecode, 64-bit, stripped), scripts in AssetBundles, remote catalog via Addressables*。
8. **输出** `ctx.results["engine.unity.hotfix"]`,形状严格按 `04-UNITY-HOTFIX.md` §5;阶段状态:无 Unity ⇒ `skipped`;部分来源失败 ⇒ `partial`。
9. `references/unity-hotfix.md`:判定矩阵、已知局限、人工复核方法(怎么确认 Lua 版本、怎么看热更 DLL 清单)。**只写分析方法,不写绕过保护的步骤。**

## 验收标准(用 `unity_hotfix_builder` 合成夹具)
- ✅ 框架:HybridCLR / ILRuntime / xLua / ToLua(LuaJIT) / puerts(V8、QuickJS 各一) / Addressables / YooAsset 各一正例,metadata 字符串扫描路径与"metadata 加密 ⇒ 降级到原生符号 + 文件线索"路径都覆盖;并存场景(HybridCLR + xLua)正确;反例:名字含 "lua" 的普通 png、无热更的纯 Unity 包 ⇒ 不误报。
- ✅ Lua 版本:bundle 内/散文件中的 5.1 / 5.3 / 5.4 / LuaJIT 2.1 字节码正确聚合;混合版本 ⇒ 分布正确;字节码 5.1 vs 原生串 5.3 ⇒ 一致性告警;头部篡改/XOR 样本 ⇒ `custom_lua_suspected`;明文方言推断样本正确。
- ✅ C# DLL:合法热更 DLL(含 AssemblyRef)、AOT 补充元数据 DLL、压缩的、XOR 的(MZ 反推)、高熵 ⇒ 分类正确且 Finding 措辞符合"只报告不解密"。
- ✅ 采样与上限:100+ bundle 夹具下只扫采样集,报告含 `sampled/total`;超大/畸形 bundle 不崩溃、不超时(上限生效)。
- ✅ CDN 域名只含域名,不含路径/token(单测断言)。
- ✅ 上游缺数据(无 `unity` 结果、metadata 加密、无 bundle)⇒ `partial`/`skipped` 而非崩溃。
- ✅ 单测通过。

## 诚信要求
- `hotfix.json` 每条规则带 `sources`;**未核实的框架特征(xLua 内嵌 Lua 版本、YooAsset 清单名、IFix 补丁扩展名、puerts 的 JS 存放形式、各框架版本标记)一律标 `unverified` 并降权**,回报里单列。
- 压缩 ≠ 加密、字节码 ≠ 加密、采样 ≠ 全量;高熵只是 `suspected`。不做解密、不提取密钥、不还原脚本。

## 重要:真实样本的二进制全部被 FairPlay 加密
先读 `docs/05-REAL-SAMPLES-AND-HTP.md` 中"已实测"一节。凡依赖 Mach-O 字符串 / ObjC 类名 / 符号的检测,在 `slice.encrypted=True` 时必须用 `skip_encrypted=True` 并**降级**到文件、目录、metadata 字符串等不依赖加密区间的证据;报告里要有"二进制已加密,基于二进制的检测受限"的说明(`remediation`:提供已解密 IPA)。验收里增加"加密二进制夹具下不产生噪声误报"。

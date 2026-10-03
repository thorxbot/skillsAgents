# Unity 热更新(Hotfix)专项设计 + 调研

> 背景:Unity 游戏的核心逻辑常不在主程序里,而是在 **热更 DLL / Lua / JS** 中,放在 AssetBundle、StreamingAssets 或 CDN 下发。只识别"用了 HybridCLR"远远不够,需要回答:**哪种机制、脚本放在哪、是什么格式(明文/字节码/压缩/疑似加密)、Lua 是哪个版本**。
> 可靠度:A = 官方源码/文档;B = 项目 README / 多方一致;C = 单一博客/摘要,须核实。

## 1. 机制分类(检测对象)

| 类别 | 方案 | 本质 | 在包里可观察到的线索(**待实现方核实**) | 可靠度 |
|---|---|---|---|---|
| C# 热更 | **HybridCLR**(前身 huatuo) | 扩展 il2cpp 为 AOT + 解释器混合运行时,可动态加载 DLL | metadata 字符串表命名空间 `HybridCLR.*`;`libil2cpp` 内解释器符号(`hybridclr::`);热更 DLL(常见 `*.dll.bytes` 或打进 bundle)、AOT 补充元数据 DLL | B |
| C# 热更 | **ILRuntime** | 纯 C# 实现的 IL 解释器,运行在 il2cpp 之上 | 命名空间 `ILRuntime.*`、`CLRBindings`;`Hotfix.dll` 字节 + 可选 `.pdb` | B |
| C# 热更 | **InjectFix / IFix**(腾讯) | 补丁方式修改 C# | 命名空间 `IFix.*`;补丁文件(扩展名待核实) | B/C |
| Lua | **xLua**(腾讯) | 内嵌 Lua + C# 绑定 + 可选 Hotfix(IL 注入) | 命名空间 `XLua.*`、`XLua.Gen`、`LuaDLL`;原生 `xlua_*`/`lua*` 符号;嵌入的 Lua 版本**待核实(README 未取到)** | B/C |
| Lua | **ToLua / tolua#** | 绑定生成 + LuaJIT | README 称 **iOS/Android/Windows 用 LuaJIT 2.1-beta3**,macOS(Unity 5.x)用 Lua 5.1.5;类 `LuaState`、`LuaClient`、`LuaConst`、命名空间 `LuaInterface`;`LuaFramework` 系项目常见 | B |
| Lua | SLua / uLua / NLua / MoonSharp(C# 实现) / KopiLua | 各类 Lua 绑定 | 命名空间 `SLua`/`LuaInterface`/`NLua`/`MoonSharp.Interpreter`;MoonSharp 无原生 Lua 库 | C |
| JS/TS | **puerts**(腾讯) | 支持 **V8 / QuickJS / Node.js** 三个后端;3.0+ 文档提到 Lua、Python 后端 | 命名空间 `Puerts.*`;原生库/符号随后端不同(`v8::`、`JS_NewRuntime`…);JS 文件的存放形式**未取到** | B |
| JS | Jint / ClearScript / ReactUnity | C# 内的 JS 引擎 | 命名空间 | C |
| 资源热更 | **Addressables** | 目录 + bundle + 远程 catalog | `aa/` 目录、`catalog_*.json\|bin`、`settings.json`;命名空间 `UnityEngine.AddressableAssets` | B |
| 资源热更 | **YooAsset / XAsset / GameFramework / QFramework / 自研 manifest** | bundle 清单 + CDN 版本文件 | 命名空间 `YooAsset.*` 等;清单文件(`*.bytes`/`*.json`/`filelist*`/`version*`);**具体文件名待核实** | C |

> 注:iOS 上 Unity 目前基本只有 IL2CPP 后端;Mono 后端分析对 iOS 的价值有限(**待核实 Unity 各版本的 iOS 脚本后端支持**),WP5 的 Mono 检查保留但降低优先级。

## 2. 核心设计:四路证据 + 三类存放位置

**证据来源(越靠前越便宜、越可靠)**
1. **`global-metadata.dat` 字符串表扫描(不依赖 dumper!)**:IL2CPP 的类型/命名空间名都在 metadata 的字符串区。metadata 未加密时,直接流式扫描字符串区即可命中 `HybridCLR`/`ILRuntime`/`XLua`/`LuaInterface`/`Puerts`/`YooAsset`/`IFix` 等命名空间与类名。metadata 被加密时降级为下面几路。
2. **il2cpp dump 命名空间**(WP5/WP6 成功时):更全,可做版本/特性推断。
3. **原生符号/字符串**:主程序/`UnityFramework` 中的 `luaL_*`、`lua_*`、`xlua_*`、`luaopen_*`、`JS_NewRuntime`(QuickJS)、`v8::`、`hybridclr::`;Lua 运行时版本串(`Lua 5.x.y Copyright … PUC-Rio`、`LuaJIT 2.x.y-…`,**格式须核实**)。
4. **文件与 bundle 内容**:见下。

**脚本/热更内容的三类存放位置**
- **散文件**:`Data/Raw/**`(StreamingAssets)、`*.lua`、`*.lua.bytes`、`*.lua.txt`、`*.dll.bytes`、`*.js.txt`、`*.mjs`、`*.bytes`。
- **AssetBundle 内**(TextAsset,Unity 要求二进制 TextAsset 用 `.bytes` 扩展):做法 = 对采样的 bundle 解压 BlocksInfo/数据块,**在解压后的字节流中做签名扫描**(不必完整解析 SerializedFile):`1B 4C 75 61`(Lua)、`1B 4C 4A`(LuaJIT)、PE/CLI(`MZ` + `BSJB`)、以及资源容器表里的路径字符串(正则 `[\w/\.-]+\.(lua|dll|js)(\.bytes|\.txt)?`)。输出每类的数量、版本分布、样本路径。
- **SerializedFile**:`resources.assets`、`sharedassets*.assets`、`level*`:同上扫描(受体积上限约束)。

## 3. Lua 版本区分(用户明确要求)

**字节码头(来自官方 `lundump.h`/`lj_bcdump.h` 的公开事实,实现方仍需对照源码核实每个字段)**
- 标准 Lua:签名 `1B 4C 75 61`,其后版本字节:5.1 = `0x51`;5.2 = `0x52`;5.3 = `0x53`;5.4 = `0x54`(5.5 另议,核实后再收);`LUAC_FORMAT` 为 0;5.1 头 12 字节(含端序、`sizeof(int/size_t/Instruction/lua_Number)`、整型标志);5.3+ 头含 `LUAC_DATA`(`19 93 0D 0A 1A 0A`)、`sizeof(Instruction/lua_Integer/lua_Number)`、`LUAC_INT`(0x5678)、`LUAC_NUM`(370.5)。
- LuaJIT:签名 `1B 4C 4A`,其后 `version`(2.0/2.1 对应的 dump 版本号)、`flags`(ULEB128;含大端/剥离调试信息/FFI 等位,**含 GC64 相关位须核实**)、可选 chunkname。LuaJIT 字节码与标准 Lua 不兼容。
- 通过头部可推出:**flavor(PUC-Lua / LuaJIT)、版本、端序、指针宽度(32/64 位构建)、是否剥离调试信息**。

**需要输出的"Lua 版本画像"**
- `bytecode`:各文件头解析结果聚合(`{5.1: n, 5.3: n, luajit_2.1: n, invalid: n}`)。
- `runtime`:原生侧版本串/符号推断出的运行时版本(PUC 5.x.y / LuaJIT 2.x.y);
- **一致性校验**:字节码版本与运行时版本不符 ⇒ 告警(可能多 VM,或运行时被魔改);
- **魔改 Lua 嫌疑**:签名不合法但头部结构"像"Lua(XOR 后合法)、`LUAC_DATA`/`LUAC_INT` 被改、`sizeof` 异常、版本字节异常 ⇒ `suspected`(**opcode 重排无法从头部判断**,只能在报告里写"无法排除");
- **明文 Lua 的方言推断(P1)**:用词法特征推断最低版本(`goto`/`::label::` ⇒ ≥5.2;`//` 整除、`& | ~ << >>` 位运算 ⇒ ≥5.3;`<const>`/`<close>` ⇒ 5.4;`setfenv/getfenv/module(` ⇒ ≤5.1 风格),必须容忍字符串/注释里的误报。
- 与框架关联:框架默认运行时(如 tolua# 在 iOS 为 LuaJIT)只作为**旁证**,以实测头部/版本串为准。

## 4. C# 热更 DLL 画像
- 对找到的 DLL(散文件或 bundle 内 `.dll.bytes`):验证 PE + CLI(`BSJB`),提取:程序集名、CLR 运行时版本串、TypeDef 数量、`AssemblyRef` 名列表(可看出依赖 `UnityEngine.*`、`netstandard`/`mscorlib`、`Assembly-CSharp`)、是否剥离/混淆(类型名熵/长度)特征(粗略);
- 非 PE 的候选:区分 压缩(gzip/zlib/lz4/lzma 魔数)/ 疑似加密(高熵,无结构)/ 简单 XOR(可由 `MZ` 已知明文反推单字节/短密钥作为**证据假设**)。
- HybridCLR 特有:区分"热更程序集"与"AOT 补充元数据 DLL"(命名/数量/与 AOT 程序集同名),输出清单。
- 注意:能拿到 DLL 字节 ≠ 能运行;**本工具只报告,不解密、不提取密钥**。

## 5. 输出契约(`ctx.results["engine.unity.hotfix"]`)
```
frameworks[{id,name,kind(csharp|lua|js|resource),confidence,version_hint?,evidence[]}]
lua{ runtime_versions[{flavor,version,source,confidence}], bytecode{by_version{},invalid,stripped_count,arch_bits{}},
     files{plain,bytecode,compressed,encrypted_suspected,total}, dialect_hints[], consistency{ok,notes}, custom_lua_suspected }
js{ backends[{id,confidence}], files{plain,bytecode?,encrypted_suspected,total}, formats[] }
csharp{ assemblies[{name,source(loose|bundle|serialized),size,format(pe_cli|compressed|encrypted_suspected|unknown),clr,asm_refs[],kind(hot|aot_meta|unknown)}] }
resource_update{ frameworks[], catalogs[], manifests[], hosts[] }          # hosts 仅域名,最多 20
storage{ loose, in_bundles, in_serialized, scanned{bundles_sampled,total} }
script_protection{ lua: yes|no|suspected|unknown, js: ..., csharp: ... }   # 三态,附证据
summary_text
```
Finding:`unity.hotfix.framework`、`unity.hotfix.lua`、`unity.hotfix.lua_version`、`unity.hotfix.csharp_dll`、`unity.hotfix.js`、`unity.hotfix.resource_update`、`unity.hotfix.script_protection`。(取代旧的 `unity.hotupdate`。)

## 6. 风险与原则
- **不凭记忆写死框架的 Lua 版本/文件名**(xLua 嵌入的 Lua 版本、YooAsset 清单文件名、IFix 补丁扩展名、puerts 的 JS 存放形式均未取到资料)。
- 压缩 ≠ 加密;字节码 ≠ 加密;高熵 ≠ 一定加密;采样 ≠ 全量(必须报告采样比例)。
- 不做解密、不提取密钥、不还原脚本。

## 7. 来源
- Lua 字节码头:https://www.lua.org/source/5.1/lundump.h.html 、https://lua.org/source/5.3/lundump.h.html 、https://www.lua.org/source/5.4/lundump.h.html 、https://www.lua.org/source/5.2/lundump.h.html
- LuaJIT 字节码头:https://fossies.org/linux/LuaJIT/src/lj_bcdump.h
- tolua#:https://github.com/topameng/tolua
- puerts:https://github.com/Tencent/puerts
- HybridCLR 概览:https://www.hybridclr.cn/en/docs/basic/performance 、https://reporank.net/en/repo/focus-creative-games-hybridclr-unity.html
- 热更方案对比:https://www.cnblogs.com/wwhhgg/p/16784367.html

# WP7b — 各引擎资源/脚本保护检查器(Cocos 家族重点,Egret / Laya / Unreal / Godot / Flutter / RN / Lua 等)(Wave 2)

先读 `prompts/_common.md`、`docs/CONTRACT-FREEZE.md`、`docs/02-ARCHITECTURE.md` §4.7、`docs/03-ENGINE-RESEARCH.md`。依赖 WP0 的 `engines/api.py`(`EngineChecker` / `@register_checker`)、WP1(inventory / 提取)、WP3(macho / scan)。与 **WP7** 并行:`ctx.results["engine.detect"]` 的形状以 `CONTRACT-FREEZE.md` 为准,开发期用桩数据。

## 目标
为每个引擎实现一个**独立插件 checker**,只做**检测与报告**:脚本 / 资源是明文、已编译(字节码)、打包、还是疑似加密;产出变体、版本线索与下一步建议。**不解密、不绕过**。

## 文件归属
`src/ipa_analyzer/analyzers/engines_other.py`(分发器:按 `engine.detect` 的 primary + candidates 调用匹配的 checker,异常隔离)、
`src/ipa_analyzer/engines/checkers/{cocos.py,egret_laya.py,unreal.py,godot.py,flutter.py,react_native.py,lua.py,defold.py,gamemaker.py,solar2d_love.py,xamarin.py,web_hybrid.py,generic_scripts.py}`、`src/ipa_analyzer/engines/formats/{jsc.py,hermes.py,pak_ue.py,pck_godot.py,xxtea_hint.py,plist_atlas.py}`(格式嗅探/解析的小工具)、
`data/engines_checks.json`(各 checker 的文件模式、阈值)、`data/i18n/{zh,en}/engine_checkers.json`、`references/{cocos-family.md,egret-laya.md,engine-resource-protection.md}`、`tests/unit/engine_checkers/*`、`tests/fixtures/engine_checker_builder.py`。

## 一、Cocos 家族(**最高优先级,逐变体做深**)
先**联网核实**各变体的真实目录结构 / 文件名 / 加密方式(Cocos 官方文档与开源仓库),把结论与来源写入 `references/cocos-family.md`,再实现。无法核实的标 UNVERIFIED。必须覆盖:
1. **cocos2d-x C++ / Lua / JS(JSB)**
   - 脚本形态判定:明文 `.lua` / `.js` ⇒ 未保护(`no`);Lua 字节码(`1B 4C 75 61` 5.x、LuaJIT `1B 4C 4A`)/ `.jsc`(SpiderMonkey 字节码,**特征以实测/文档为准**)⇒ 已编译(`no` 加密,但标注"已编译");高熵 + 无已知 magic + 二进制含 xxtea 线索(符号 / 字符串 / sign 头)⇒ `suspected`;
   - xxtea 线索检测:二进制里的相关符号 / 字符串 + 脚本文件头部是否存在一致的固定签名前缀(sign)——**只检测不解密**;
   - 资源:`.plist+.png` 图集、`.csb` / `.ExportJson`(CocosStudio)、`.tmx`、`.fnt`、音频;是否存在自定义加密(magic 嗅探失败 + 熵);
   - 引擎版本线索(`cocos2d-x-3.x/4.x` 字符串、`COCOS2D_VERSION`、`cocos2dVersion()` 字符串)。
2. **Cocos Creator 2.x**:`main.js` / `project.json` / `src/project.js(c)` / `res/import/*.json` / `res/raw-assets` / `settings.js`;脚本明文 / jsc / 加密;资源是否带 md5 hash 命名;版本线索(`cc.ENGINE_VERSION`)。
3. **Cocos Creator 3.x**:`application.js` / `cc.js` / `src/chunks` / `assets/<bundle>/config.*.json` / `import/` / `native/` / `.cconb`;bundle 清单;脚本 jsc / 加密;原生层 V8 / JSC 线索;版本线索。
4. **cocos2d-iphone(ObjC `CC*`)**:类前缀 + 目录特征。
5. 输出 `engine.cocos.variant`(Finding,含变体、版本线索、证据)、`engine.script.encrypted`(三态)、`engine.resource.encrypted`(三态),以及 `ctx.results["engine.other"]["cocos"] = {variant, version_hint, scripts{plain,bytecode,suspected_encrypted,counts,samples}, resources{...}, xxtea_hint{...}, bundles[]}`。
6. 混合项目(Cocos + 渠道壳 / 自家 Lua 框架)不报错,按实际文件给出分布。
7. **魔改偏离项检测**(调研见 `03-ENGINE-RESEARCH.md`):有 xxtea 线索但脚本头无标准 sign 前缀;原生层有类 `setXXTEAKey` 的字符串但被混淆 / 拆段;出现 Blowfish 等其他算法常量;有 `cocos2d::` 痕迹但目录异常。统一汇总到 `engine.wrapper`/`engine.script.encrypted` 的证据里。**只报告线索,不提取密钥、不解密**——这是工具边界,需要深入的留给人工并在建议中说明。

## 一点五、NeoX 系 / Supercell 系资源包(调研来源见 `03-ENGINE-RESEARCH.md`)
仅在 WP7 已把对应签名入库且你**核实了格式**后实现:`.npk` 的头部 / 索引形态与压缩标志(只读头部判定,**不写解包器**),`.sc` 系压缩头分类。核实不了的不实现并在回报说明。

## 二、Egret(白鹭)/ LayaAir
核实后实现:Egret 的 `resource/*.res.json`、`*.thm.json`、`*.exml`、`manifest.json`、`egret*.js`、native runtime;Laya 的 `laya*.js`、`.atlas`、`.lh/.lmat/.ls`、`conch` 运行时、`libs/`。判定脚本 / 资源明文 / 压缩打包 / 疑似加密;版本线索;输出 `ctx.results["engine.other"]["egret"|"laya"]`。

## 三、其他引擎
| checker | 要检查 | Finding |
|---|---|---|
| unreal | `Content/Paks/*.pak`(footer magic / 版本 / **索引加密标志**,布局随 pak 版本变化,按官方源码核对);IoStore `.utoc/.ucas`;`.ini` 线索 | `engine.pak.encrypted` |
| godot | `.pck`(`GDPC` magic、版本、加密标志,按官方格式核对);`.gdc` 脚本是否编译 / 加密 | `engine.pak.encrypted`、`engine.script.encrypted` |
| flutter | `Flutter.framework` + `App.framework/flutter_assets`;AOT 快照特征;`kernel_blob.bin`(Debug)是否出现;引擎版本线索 | `engine.flutter_aot` |
| react_native | `main.jsbundle` 明文 / Hermes 字节码(magic 核对)/ 高熵;`RCT*` | `engine.hermes`、`engine.script.encrypted` |
| lua | 通用 Lua/LuaJIT 字节码 vs 明文 vs 高熵(供 cocos2dx_lua / 自研引擎复用) | `engine.script.encrypted` |
| defold / gamemaker / solar2d_love | 各自资源包形态(`game.arcd` / `game.projectc` / `data.win` 类 / `.love` / `resource.car` 等,**逐个核实**) | `engine.pak.encrypted` / `engine.resource.encrypted` |
| xamarin | `*.dll` 是否合法 PE + CLI(`BSJB`),自行实现 | `engine.script.encrypted` |
| web_hybrid | `www/` 或 bundle 内 HTML/JS 明文比例;minify/混淆迹象 | (信息) |
| generic_scripts | 对 detect 未归类的 `.js/.lua/.py/.json/.txt` 脚本类资源做明文 / 字节码 / 高熵汇总,供自研引擎使用 | `engine.script.encrypted` |

> **依赖 WP3b**:Lua 字节码头解析(含 5.1 / 5.2 / 5.3 / 5.4 / LuaJIT 版本区分)、Lua 明文方言推断、压缩魔数嗅探统一使用 `ipa_analyzer.formats.*`,**不要自己重复实现**。Cocos Lua / `lua` checker 的输出要包含 **Lua 版本画像**(字节码版本分布、位宽、是否剥离、原生串里的运行时版本),与 Unity 热更的 Lua 画像字段一致(见 `docs/04-UNITY-HOTFIX.md` §3、§5)。

## 共用约束
- 熵阈值、样本数、文件模式放 `data/engines_checks.json`,代码里不写魔法数;每个 checker 注明判定依据。
- 大文件只读头 + 抽样块;文件数量大时抽样并报告"已抽样 N/M"。
- 结论措辞:字节码 ≠ 加密;压缩 ≠ 加密;高熵 ≠ 一定加密——证据里要写明排除了哪些可能。
- checker 之间不互相 import;共用小工具放 `engines/formats/`。

## 验收标准(用 `engine_checker_builder` 合成夹具)
- ✅ Cocos 六个变体各一正例 ⇒ 变体、版本线索、脚本形态判定正确;`cocos_lua_xxtea`(高熵脚本 + xxtea 线索)⇒ `engine.script.encrypted = suspected`;Lua 字节码 ⇒ `no` 且标注"已编译";明文 ⇒ `no`。
- ✅ 反例:仅有 `.plist` + `.png` 的原生 App 不触发 Cocos checker;`.js` 是 minify 的明文 ⇒ 不报加密。
- ✅ Egret / Laya 各一正例;Unreal pak 三情形(无加密 / 索引加密标志 / 截断)、Godot pck、Hermes、Flutter AOT 正例;畸形输入不崩溃。
- ✅ 分发器:未命中引擎 ⇒ 阶段 `skipped`;单个 checker 异常 ⇒ 其余照常、阶段 `partial`。
- ✅ 新增 checker 只需新建一个文件并 `@register_checker`(单测)。
- ✅ 单测通过。

## 回报额外要求
- 每个 checker 的"已核实来源"与 UNVERIFIED 清单;哪些变体/引擎你**没有把握可靠检测**并如实说明。

## 真实样本线索
- ISBN 的 `.ccz` 为加密 ccz(`CCZp`,见 cocos-engine `ZipUtils.cpp`):Cocos checker 需识别 `CCZ!`(未加密)与 `CCZp`(加密)并把计数/样本写入资源保护结果;密钥来源不做提取。

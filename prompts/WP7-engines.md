# WP7 — 引擎指纹 + 已知引擎检测 + 自研引擎判定 + 通用容器分析(Wave 2)

先读 `prompts/_common.md`、`docs/CONTRACT-FREEZE.md`、`docs/02-ARCHITECTURE.md` §4.3 与 **§4.7(本包的完整设计)**,以及 **`docs/03-ENGINE-RESEARCH.md`(自研 / 魔改引擎调研:种子线索 + 可靠度分级,C 级内容必须二次核实)**。依赖 WP1(inventory)、WP3(macho / scan)。与 **WP7b**(各引擎检查器)并行,二者只通过 `engines/api.py` 与 `ctx.results["engine.detect"]` 衔接。

## 目标
解决"引擎覆盖不全 / 自研引擎识别不了"的问题:
1. `engine.fingerprint`:**与引擎名无关**的能力画像(渲染 / 脚本 VM / 物理 / 音频 / 资源格式 / 容器 / 宿主形态)。
2. `engine.detect`:数据驱动的已知引擎检测(一引擎一 JSON,可插拔)+ **自研 / 魔改引擎判定**。
3. 通用容器分析:对未知大文件判断"压缩 / 加密 / 明文 / 自定义格式"。

## 文件归属
`src/ipa_analyzer/analyzers/{engine_fingerprint.py,engine_detect.py}`、
`src/ipa_analyzer/engines/{signatures.py,fingerprint.py,containers.py,custom.py,scoring.py}`(`engines/api.py` 属 WP0,只读)、
`data/engines/*.json`(**所有**引擎的检测签名都归你维护,含 `unity.json`)、`data/engines.index.json`(可选)、`data/fingerprint.json`、
`data/i18n/{zh,en}/engines.json`、`references/{engines-detection.md,custom-engine-playbook.md}`、`tests/unit/engines/*`、`tests/fixtures/engine_builder.py`。

## A. 已知引擎签名库 `data/engines/<id>.json`
格式:`{id, name, family, kind(game_engine|cross_platform_ui|web_hybrid|native|open_source_lib), signals[{type(file|dir|string|dylib|symbol|objc_prefix|plist_key|binary_section), pattern, weight, strong?}], confirm_threshold, exclusive_with[], language_hints[], notes, sources[]}`。`sources` 必填:写明特征来源(官方文档 / 开源代码 / 实测),**不得凭印象**;拿不准的信号 `weight` 降级并加 `unverified: true`。
首批覆盖(每项逐一核实后再落地,核实不了的整体不收):
- 游戏引擎:`unity`(架构 §4.3 原样落地)、`unreal`、`godot`、`defold`、`gamemaker`、`solar2d`、`love2d`、`cocos2dx_cpp`、`cocos2dx_lua`、`cocos2dx_js`、`cocos_creator_2x`、`cocos_creator_3x`、`cocos2d_iphone`、`egret`、`layaair`、`construct_webview`、`phaser_pixi_webview`、`haxe_heaps_flixel`、`monogame_fna`、`stride`、`cryengine_o3de`(可核实时)、`unigine`、`ogre3d`、`irrlicht`、`bgfx`、`filament`、`sdl_host`、`qt_host`、`kivy_python`。
- **海外 / 中间件**(依据 `03-ENGINE-RESEARCH.md` §1b,逐个核实后入库):`defold`、`marmalade`、`libgdx_robovm`、`gdevelop`、`appgamekit`、`buildbox`、`gamesalad`、`codea`、`o3de`;大厂主机引擎(Luminous / Fox / Anvil / Snowdrop / Frostbite)**不收录**(无 iOS 产品证据)。日韩大厂无可用资料 ⇒ 不收录,走 Unity / Unreal / 通用指纹。
- 非游戏框架:`flutter`、`react_native`(+ `hermes`)、`xamarin_maui`、`cordova_capacitor`、`native_swiftui`、`native_uikit`、`native_objc`、`kotlin_multiplatform`(可核实时)。
- **Cocos 家族要能区分变体**(见架构 §4.7 的 6 类),这是用户明确点名的需求;变体判定的细粒度深度检查归 WP7b,你负责"检测 + 变体归类 + 版本线索"。
- **自研 / 魔改引擎种子**(依据 `03-ENGINE-RESEARCH.md`,逐条核实后才可入库):`neox_family`(`*.npk`、`NXPK`、`redirect.nxs`、`script.npk` + 内嵌 Python 指纹;**只写"与网易 NeoX 系文件格式一致"这类带置信度的线索,不断言厂商**)、`supercell_sc`(`*.sc`/`*_tex.sc`/`*.sctx` + 压缩头形态)、`modified_cocos`(cocos 痕迹 + 偏离项)。Messiah / QuickSilver / Angelica **无已核实的 iOS 侧特征 ⇒ 不收录**,在回报中说明。
- 用户扩展:加载 `IPA_ANALYZER_HOME/engines.user.d/*.json` 与 `--engines-user DIR`;同 `id` 覆盖;格式错误只 warning。

评分:弱信号累加 + 强信号直通;`exclusive_with` 抑制(如 cocos2dx_lua 与 cocos2dx_cpp 的包含关系);**多引擎并存**(宿主 + 嵌入)输出 `primary / candidates / wrapper`;置信度 0..1,可解释(每个信号的贡献写入证据)。

## B. `engine.fingerprint`(自研引擎的基础)
按架构 §4.7 实现,规则放 `data/fingerprint.json`:
- 维度:`render`、`shader_formats`、`script_vms`(**含内嵌 Python:`Py_Initialize` / `marshal` 符号、`.pyc`/`.nxs`;并检查 pyc magic 是否合法 ⇒ opcode 魔改嫌疑,至多 `suspected`**)、`physics`、`audio`、`animation`、`network`、`asset_formats`、`containers`、`host`。
- 证据源:macho(dylib、符号、`__cstring`、`_ZN` 符号占比、C++/ObjC/Swift 比例)、inventory(扩展名 / magic / 目录名)、少量二进制字符串扫描(WP3 `scan`,限额)。
- 每个命中带 `evidence[]` 与 `confidence`;**符号 / 字符串模式必须核实**(例如 Lua C API 符号名、QuickJS/Duktape/AngelScript/Box2D/Bullet/PhysX/FMOD/Wwise 的典型符号或命名空间前缀),拿不准的写 UNVERIFIED 并降权。
- 输出 `ctx.results["engine.fingerprint"] = {render{}, shader_formats[], script_vms[], physics[], audio[], animation[], network[], asset_formats[], containers[], host{}, summary_text}`;`summary_text`(英文兜底 + i18n)是"引擎画像一句话",如 *Native C++ engine on Metal, embedded Lua 5.x, Box2D physics, custom .pak container (zlib blocks)*。
- Finding:`engine.fingerprint`。

## C. 通用容器分析 `engines/containers.py`
按架构 §4.7:header 整数合理性(偏移表单调 / 末项 + size≈文件大小 / 条目数合理)、内部压缩 magic 扫描(zlib / gzip / LZ4 frame / zstd `28 B5 2F FD` / LZMA `5D 00 00`,以及 Supercell 式 `SC`/`SCLZ`/`Sig:`/`START` 头形态——后者入库前须读开源工具源码核实)、哈希化文件名 + 偏移表 + 配套 `.list`/索引文件、成对容器(`.pck+.pkx`)、分块熵 + 字节分布(区分压缩与疑似加密)、已知明文 XOR 探测(只记录证据假设,**不还原整个文件**)、容器尺寸/数量汇总。候选选择策略:大小 ≥1 MB 且 magic 未知,或扩展名在可疑集合;全量浅检、抽样深检(上限可配,默认 50)。结论上限 `suspected`。Finding:`engine.container.unknown`(无容器时 `n/a`)。
所有算法参数(阈值)写成常量并注明依据,单测覆盖边界。

## D. 自研 / 魔改引擎判定 `engines/custom.py`
- 条件与输出见架构 §4.7:`engine.custom` + `engine.wrapper`(魔改开源引擎)。
- **反误报**:纯原生 App 即使有 Metal(地图 / 视频类 App 也会用)不得判自研引擎;需 "渲染 API + (C++ 占比高 / 自带脚本 VM / 自定义容器 / 物理库) + 游戏信号" 的组合;给出各条件命中情况与得分。
- **输出下一步建议**(i18n):例如"重点分析 `XXX` 二进制中的 Lua 绑定"、"`data/xx.pak` 为自定义容器,偏移表位于文件头 N 字节"、"建议人工确认 shader 格式"。
- 写 `references/custom-engine-playbook.md`:面向 Agent/人工的"自研引擎分析起手式"(看哪些文件、怎么确认脚本 VM、怎么初判容器)。注意只写分析方法,不写绕过保护的步骤。

## 输出契约
`ctx.results["engine.detect"] = {primary{id,name,family,confidence,evidence[]}, candidates[{id,name,confidence,signals_matched[]}], wrapper?{host,embedded[]}, custom{verdict,confidence,evidence[],profile_ref}, languages[{lang,confidence,evidence}], is_game_engine}`,字段名以 `CONTRACT-FREEZE.md` 为准。Finding:`engine.primary`、`engine.language`、`engine.custom`、`engine.wrapper`。

## 验收标准(用 `engine_builder` 夹具:最小假 IPA 目录 + 极简 Mach-O 字符串/符号)
- ✅ 每个已收录引擎一个正例夹具 ⇒ 主引擎判定正确;Cocos 六种变体各一 ⇒ 变体归类正确。
- ✅ **自研引擎夹具**(薄 UIKit 壳 + Metal + `luaL_*` 符号 + Box2D 符号 + 自定义 `.pak`(合成偏移表 + zlib 块)+ 高熵 `.dat`)⇒ `engine.custom` 为 yes/suspected,画像各维度命中,**无任何已知引擎被误判为 primary**。
- ✅ **反例**:纯原生地图 App(Metal + MapKit)⇒ 不是自研引擎;只含名为 `unity.png` 的图片 ⇒ 非 Unity;含 "Flutter" 字样但无 framework ⇒ 非 Flutter;Cocos 的 `.plist` 资源 + 原生 App ⇒ 不误判。
- ✅ 混合:Unity 嵌入原生壳、Cordova + 原生、魔改 cocos2d-x(符号在但目录异常)⇒ primary / wrapper / candidates 合理。
- ✅ 容器分析:合成 4 类文件(zlib 块容器 + 偏移表 / 均匀随机(疑似加密)/ 明文 JSON / 单字节 XOR 的 PNG)⇒ 分类正确;**压缩文件不会被报成加密**(至少 `suspected` 且证据写明"含压缩结构")。
- ✅ 新增引擎只需添加一个 JSON(单测:临时 `engines.user.d` 里注册假引擎能被检出);JSON 格式校验测试(必填字段、`sources` 非空、正则可编译、`id` 唯一)。
- ✅ 上游缺 macho / inventory 时 `partial` / `skipped`,不崩溃。
- ✅ 单测通过。

## 备注
- 回报里单列:每个引擎签名的**来源**与哪些是 UNVERIFIED;以及你判断"无法可靠识别"的引擎清单(如实说明,而非硬凑)。

## 重要:真实样本的二进制全部被 FairPlay 加密
先读 `docs/05-REAL-SAMPLES-AND-HTP.md` 中"已实测"一节。凡依赖 Mach-O 字符串 / ObjC 类名 / 符号的检测,在 `slice.encrypted=True` 时必须用 `skip_encrypted=True` 并**降级**到文件、目录、metadata 字符串等不依赖加密区间的证据;报告里要有"二进制已加密,基于二进制的检测受限"的说明(`remediation`:提供已解密 IPA)。验收里增加"加密二进制夹具下不产生噪声误报"。

## 真实样本线索(必读 `docs/05-REAL-SAMPLES-AND-HTP.md`)
- ISBN:`.ccz`(`CCZp`)⇒ 应判 Cocos 家族(cocos2d-x);验收时用真实样本跑 `engine.detect`,记录结果。
- SeaWorld:~5,400 个文件头为 `NHPK/NHPT/NHPO` 的自定义封装 ⇒ 用于容器画像:统计头 4 字节聚类、去掉头后内容是否为标准格式。不得因此断言厂商。
- 真实样本二进制被 FairPlay 加密,基于二进制的指纹缺失时必须降级并说明。

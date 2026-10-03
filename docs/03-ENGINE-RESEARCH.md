# 自研 / 魔改引擎调研(2026-10 初版)

> 用途:给 WP7 / WP7b 作为 **种子线索**,不是已核实的签名。可靠度分级:**A** = 多个独立来源或官方文档;**B** = 一个可信来源(开源项目 README / 官方页面);**C** = 单个博客 / 搜索摘要,必须由实现方再核实才能写进 `data/engines/`。
> 本轮搜索的局限:搜索引擎只返回摘要;**没有找到任何一家的 iOS 二进制符号 / 目录特征的权威资料**。因此下表"可用于检测的特征"很多是推断,明确标了待核实。

## 1. 常见自研 / 魔改引擎一览

| 引擎 | 归属 | 典型产品(来源声称) | 可靠度 | 已知特征(来源) | 对检测的含义 |
|---|---|---|---|---|---|
| **NeoX** | 网易 | 阴阳师、第五人格(NeoX 2)、荒野行动(Messiah 之前)等 | B | `.npk` 资源包;NeoX 2 为 `NXPK` 包(denpk2);`script.npk`、`wwise.mini.npk`、`ui.mini.npk`;`redirect.nxs`;内嵌 Python(旧 2.7.3 → 新 3.11.6);Python 用 `marshal`,**opcode 被打乱**,`dis` 不可用;脚本加密由 rotor 改为 RSA + XOR 自定义方案;脚本能力:C++/Python/Lua | 可做 **文件级强信号**(`*.npk`、`redirect.nxs`、`script.npk`)+ **内嵌 Python 指纹**。`.pyc/marshal` magic 不合法 ⇒ opcode 魔改嫌疑 |
| **NPK 索引结构** | 同上 | – | **C** | 某博客称:头部 `0x14` 处为索引偏移;索引项为 7 个 u32(名字哈希、偏移、原始大小、压缩大小、压缩标志、两个保留);压缩标志 1 = zlib | **单一博客来源,不得直接写死**;实现方须对照 denpk2 源码 / 实测。可用作"偏移表 + 哈希名 + zlib 块"的容器分析样例 |
| **Messiah** | 网易 | 暗黑破坏神:不朽、天下、楚留香、荒野行动、燕云十六声 | A(产品归属)/ 无(技术特征) | 2013 首款产品,面向移动端,含 PBR、GPU 粒子等;Wikipedia 称使用 Lua 脚本 | **没有找到公开的 iOS 文件 / 符号特征。** 只能走通用指纹(Metal + Lua VM + 自定义容器),**不要凭印象写签名** |
| **QuickSilver** | 腾讯 | 天涯明月刀手游 | C | 搜索摘要称是 Unity 混合模式引擎 | 实质是 **Unity 魔改** 路线,应由 Unity 分析器覆盖(metadata / 加载器被改),不单独建引擎 |
| **Titan(Supercell 自研)** | Supercell | 部落冲突、皇室战争、荒野乱斗、卡通农场、海岛奇兵 | B(资源格式)/ C(引擎名) | 资源:`*.sc`、`*_tex.sc`、`*_dl.sc`、`*.sctx`、压缩的 `*.csv`、`*.ktx`;压缩头:LZMA(以 `5D 00 00` 开头)、`SC` 头、`SCLZ`、`Sig:` 签名、`START`(sc2)、ZSTD(`28 B5 2F FD`);社区工具:scPacker / cat_tools / SC Tools / sc-compression | **通用容器分析的绝佳样本**:多种压缩魔数 + 自带头;`.sc` 扩展名可作为文件级信号。"Titan"这个名字需核实再用 |
| **Angelica** | 完美世界 | 完美世界系 PC 游戏(手游线未确认) | C | `.pck` + `.pkx` 成对;PyPI `autoangel` 可读 | iOS 手游是否使用未确认;只作 `.pck/.pkx` 成对的容器线索,不写进主引擎库 |
| **Marmalade** | 中间件(商业) | Cut the Rope、Doodle Jump 等 | B(Wikipedia) | C++/Lua/HTML5 | 现代 iOS 包少见,低优先级,特征未核实 |
| **魔改 cocos2d-x / Cocos Creator** | 大量国内厂商 | 大量 2D / 棋牌 / 休闲 | A | 脚本 `XXTEA` 加密;密钥在引擎启动时传给 `setXXTEAKey()`,是原生库里的普通字符串常量;**带签名前缀(sign)**;已见变体:密钥被拆成多段拼接、XXTEA 函数名被混淆、改用 Blowfish 等其他算法、密钥被移除 / 转移到未知位置;Android 上库名可能为 `libcocos2djs.so`/`libcocos2dlua.so` 或被改名(iOS 一般静态链接进主程序) | **魔改特征 = 与标准 cocos 的"偏离项"**:有 `cocos2d::` 痕迹但无标准目录、脚本高熵无标准 sign、有 Blowfish/自定义解密痕迹。这与我们 `engine.wrapper` 设计吻合 |
| **魔改 Unity** | 米哈游(原神)、腾讯等 | 原神、王者荣耀 等 | B | `global-metadata.dat` 被加密(从简单 XOR 到自定义方案);商业 / 自家保护:布局随机化的 metadata 加密、导出符号修改、初始化模式混淆(Mfuscator 自称借鉴原神);腾讯 ACE 等 iOS 代码加密产品 | 与 WP5 的 metadata 判定一致,**不需要新引擎条目**;报告里应把"自定义加载器 / 魔改 il2cpp"作为已知局限写明 |
| **Roblox / Minecraft(RenderDragon)等整机应用** | 厂商自有 | – | 未调研 | – | 属"单产品自有引擎"。通用指纹足以描述;不做专门签名 |

## 1b. 海外(欧美 / 日韩)自研与中间件引擎

| 引擎 | 归属 | 典型产品(来源声称) | 可靠度 | 已知信息 | 对检测的含义 |
|---|---|---|---|---|---|
| **King 内部引擎(Candy Crush 系)** | King | Candy Crush 系列 | B(归属)/ 无(特征) | 报道称 Candy Crush 用"较老的内部引擎",而非 Defold | 无公开特征 ⇒ 只能走通用指纹 |
| **Defold** | King 开发,现为开源(Defold Foundation) | Blossom Blast Saga、Pet Rescue 等 | B | 2D 引擎,Lua 脚本,带编辑器;资源包形态(如 `game.arcd`/`game.projectc`,**待核实**) | 可识别引擎,入 `data/engines/defold.json`(特征须核实) |
| **Rovio 旧版专有引擎** | Rovio | 2012 版 Angry Birds(已用 Unity 重制) | B | 新版为 Unity;旧版专有引擎细节无公开资料 | 现代 iOS 包基本是 Unity,低优先级 |
| **Titan** | Supercell | 见 §1 | B/C | 见 §1 | 海外自研里**唯一资料较全的资源格式** |
| **RenderDragon** | Mojang / Microsoft | Minecraft Bedrock(iOS) | B(归属) | 渲染层自研,面向移动 / 主机 / PC;属单产品引擎 | 通用指纹即可;不做专门签名 |
| **MT Framework Mobile** | Capcom | Android / iOS 上的早期 Capcom 移动游戏 | C(维基摘要) | 现主力引擎为 RE Engine(主机 / PC) | 老包才可能出现,低优先级 |
| **Marmalade** | 商业中间件 | Cut the Rope、Doodle Jump、Angry Birds POP! | B(Wikipedia 列表) | C++ / Lua / HTML5 | 老包常见,入签名库,特征须核实 |
| **LibGDX(经 RoboVM / MobiVM)** | 开源 | Slay the Spire(移植)、Mindustry、Ingress | B | Java 栈在 iOS 上经 AOT 编译 | 特征须核实(原生库、`gdx` 痕迹) |
| **Solar2D / Corona、LÖVE、GameMaker、Construct、GDevelop、AppGameKit、Buildbox、GameSalad、Codea、Kivy、MonoGame/XNA、Ogre、O3DE** | 各开源 / 商业 | 见维基列表 | B(Wikipedia 列表) | 均支持 iOS 或可打包 iOS | 均入已知引擎库;**无代码级特征依据的,先只收录文件 / 目录级信号** |
| **Square Enix Luminous / Crystal Tools、Konami Fox、Ubisoft Anvil/Snowdrop、EA Frostbite** | 各大厂 | 主机 / PC 为主 | B | 搜索中**没有证据**显示它们在 iOS 产品中使用(Frostbite Go 仅为 2013 年的传闻报道) | **不收录**;避免臆造 |
| **日韩手游大厂(Cygames、Netmarble、NCSOFT、Nexon、Com2uS 等)** | – | – | 无 | 本轮搜索**没有找到**任何公开的自研引擎资料;这些厂商多数产品的引擎归属本轮未能核实 | 不下结论;靠 Unity / Unreal 检测 + 通用指纹 |

**结论**:海外大厂移动端以 Unity / Unreal 为主;可靠的"自研 / 专有"线索集中在 Supercell(资源格式有社区工具)、King(Defold 开源)、Marmalade 等中间件。日韩大厂本轮无可用资料。

## 2. 从调研归纳的"魔改"四种模式(指导检测设计)
1. **完全自研 C++ 引擎 + 内嵌脚本 VM + 自定义资源包**(NeoX / Messiah / Titan 类)。资源包常见:哈希化文件名、偏移表、zlib/LZMA/ZSTD 块、自家头部;脚本 VM 为 Python / Lua。
2. **魔改开源引擎**(cocos2d-x / Creator 最典型):标准结构上叠加自定义加解密(XXTEA 变体 / Blowfish / 密钥拼接)、符号混淆、库改名。
3. **魔改商业引擎**(Unity / Unreal):metadata、pak、bundle 的自定义加载与加密;il2cpp 导出与初始化模式被改。
4. **商业加固壳包装**(腾讯 ACE、Virbox 等):外层保护,内层仍是上面某一种。

## 3. 对设计 / 提示词的具体改动(已同步到 WP7 / WP7b)
1. **新增"内嵌 Python VM"指纹**:`Py_Initialize`/`marshal` 等符号 + `.pyc` / `.nxs`;并检查 `.pyc` magic 是否合法(**opcode 魔改嫌疑**,只能到 `suspected`)。
2. **容器压缩魔数清单扩充**:LZMA(`5D 00 00`)、ZSTD(`28 B5 2F FD`)、zlib、gzip、LZ4 frame,以及 Supercell 式 `SC`/`SCLZ`/`Sig:`/`START` 头(仅作 *头部形态参考*,实现方需核实后再入库)。
3. **容器特征**:哈希化文件名(无可读路径)+ 偏移表 + 同目录配套 `.list`/索引文件;成对容器(`.pck+.pkx`)。
4. **XXTEA/自定义脚本加密的"偏离标准"检测**:有 xxtea 线索但没有标准 sign 前缀;有 `setXXTEAKey` 类字符串但被混淆;出现 Blowfish 等其他算法常量。**仅报告线索,不提取密钥**(工具边界:不做密钥提取 / 解密;这类线索留给人工分析)。
5. **文件级强信号**入 `data/engines/`(须再核实):`*.npk`、`redirect.nxs`、`script.npk`(NeoX 系);`*.sc`/`*_tex.sc`/`*.sctx`(Supercell 系)。
6. **不凭印象命名**:Messiah / QuickSilver / Angelica 暂无可核实的 iOS 侧特征 ⇒ 首版 **不收录为"可识别引擎"**,走 `engine.custom` + 画像;若用户提供样本,再固化。
7. **报告措辞**:自研引擎结论里附"可能的归属线索"(如命中 `.npk`/`NXPK` ⇒ "与网易 NeoX 系文件格式一致,低-中置信度"),而不是直接断言厂商。

## 4. 未解决 / 需要样本或进一步调研
- Messiah、QuickSilver、米哈游自研 Unity 魔改、字节(朝夕光年)、莉莉丝、鹰角等 **iOS 侧实际目录与符号特征**:无公开资料。
- NXPK 头部魔数与索引布局:需读 denpk2 源码 / 实测样本确认(上表 C 级)。
- Supercell "Titan" 命名与 `.sc` 头的完整定义:需读 SC Tools / sc-compression 源码核实。
- iOS 上 cocos 的静态链接符号保留情况(release 剥离后还剩什么)。
- 日韩大厂(Cygames、Netmarble、NCSOFT、Nexon、Com2uS、Square Enix 手游线等)的引擎归属与特征:本轮搜索无结果,需样本或专项调研。
- Defold、Marmalade、LibGDX/RoboVM、Solar2D、GameMaker 在 iOS 包里的**具体文件名 / 符号**:需逐个读官方文档或开源构建脚本核实。

## 5. 来源
- Messiah Engine — https://en.wikipedia.org/wiki/Messiah_Engine
- NeoX engine(IGDB)— https://www.igdb.com/game_engines/neox-engine-by-netease-games
- denpk2(NeoX 2 / NXPK 解包说明)— https://github.com/hax0r31337/denpk2
- NetEase 自研引擎综述(知乎)— https://zhuanlan.zhihu.com/p/516250879
- NPK 结构博客(**C 级**)— https://blog.csdn.net/gitblog_00113/article/details/162001250
- Supercell 资源工具:cat_tools — https://github.com/PeterHackz/cat_tools ;sc-compression — https://npmjs.com/package/sc-compression ;scPacker — https://github.com/Galaxy1036/scPacker
- 海外:King Defold — https://www.pocketgamer.biz/king-on-game-engine-defold-and-launching-third-party-games/ ;https://wnhub.io/news/engines/item-17033 ;Rovio 重制 — https://www.gamedeveloper.com/game-platforms/inside-the-process-of-re-releasing-the-first-angry-birds ;Minecraft RenderDragon — https://minecraft.net/article/render-dragon-and-nvidia-ray-tracing ;MT Framework — https://en.wikipedia.org/wiki/MT_Framework ;Fox Engine — https://en.wikipedia.org/wiki/Fox_Engine ;Luminous — https://en.wikipedia.org/wiki/Luminous_Engine ;引擎总表 — https://en.wikipedia.org/wiki/List_of_game_engines
- autoangel(Angelica `.pck/.pkx`)— https://pypi.org/project/autoangel/
- Cocos 逆向与 XXTEA — https://felipejfc.medium.com/reverse-engineering-a-cocos2dx-js-game-6cecc1c08f28 ;https://www.decompiler.com/cocos ;https://zboralski.net/tags/cocos/
- IL2CPP metadata 保护 — https://dev.to/guardingpearsoftware/whats-this-global-metadatadat-thing-and-why-does-it-matter-50ch ;https://assetstore.unity.com/packages/tools/utilities/mfuscator-il2cpp-encryption-256631 ;https://intl.anticheatexpert.com/products/code-encryption-ios

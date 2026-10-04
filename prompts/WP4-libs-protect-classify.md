# WP4 — Lib 用途识别、保护/加密汇总、项目类型分类(Wave 2)

先读 `prompts/_common.md`、`docs/CONTRACT-FREEZE.md`、`docs/02-ARCHITECTURE.md` §4.2。依赖 WP1/2/3 的产出(已合入);Unity dump 命名空间为**软依赖**。

## 目标
回答用户的三个核心问题:**用了哪些库、各自干什么**;**有哪些保护 / 是否被加密**;**这是什么类型的项目(游戏 / 影音 / 生活…)**。

## 文件归属
`src/ipa_analyzer/analyzers/{libs.py,protect.py,classify.py}`、`src/ipa_analyzer/libs/{__init__,matcher.py,kb.py,sysframeworks.py}`、`src/ipa_analyzer/protect/{__init__,antidebug.py,fairplay.py,obfuscation.py}`、`src/ipa_analyzer/classify/{__init__,scorer.py}`、
`data/{libs.json,protectors.json,classify.json,sysframeworks.json}`、`data/i18n/{zh,en}/{libs,protect,classify}.json`、`references/libs-kb-format.md`、`tests/unit/{libs,protect,classify}/*`。

## A. 库识别(`libs` 阶段)
1. **证据源**(每条证据记录来源类型,置信度按"独立证据类型数"递增):
   - `macho.binaries[*].dylibs`(系统 `/System/Library/Frameworks|/usr/lib` vs 内嵌 `@rpath|@executable_path`);
   - `inventory.nested_units`(`Frameworks/*.framework`、`*.bundle`、`PlugIns`);
   - ObjC 类名前缀(用 WP3 的 `objc_class_names()`;前缀表在 `libs.json`);
   - Swift 模块名(符号 / 字符串中的 `$s<len><Module>` 形式,或 `.swiftmodule`、`libswift*`);
   - 特征字符串 / 域名(流式扫描,限定每文件 / 总量上限,正则预编译);
   - `ctx.results.get("engine.unity.hotfix")`:热更框架与 **Lua 运行时版本**(PUC-Lua 5.x / LuaJIT 2.x)作为库条目输出(`kind=static_sdk`,`category=热更新/脚本`,版本写入条目 `version`);
   - `ctx.results.get("engine.fingerprint")` 中的中间件命中(物理 / 音频 / 脚本 VM / 动画库),作为 `static_sdk` 证据;`libs.json` 有同 id 条目则合并,不重复造规则;
   - Unity dump 命名空间(`ctx.results.get("unity",{}).get("dump",{}).get("namespaces")`,可能不存在);
   - 资源文件名(`*.bundle`、`GoogleService-Info.plist`、`AppsFlyer*`…)。
2. **知识库 `data/libs.json`**(格式写入 `references/libs-kb-format.md`):每条 `{id, name, vendor, category, purpose_zh, purpose_en, tags[], homepage?, match{dylib[], framework[], objc_prefix[], symbol_regex[], string[], bundle[], namespace[], file[]}}`。**种子 ≥150 条**,覆盖:广告(AdMob、AppLovin、Unity Ads、ironSource、Vungle、Mintegral、穿山甲/Pangle、优量汇/GDT、快手联盟、Meta Audience Network…)、归因统计(AppsFlyer、Adjust、Firebase Analytics、Singular、Branch、友盟、TalkingData、神策、GrowingIO…)、崩溃(Crashlytics、Sentry、Bugly、PLCrashReporter)、社交登录支付(微信/QQ/微博/支付宝/Facebook/Google Sign-In/Apple Pay/Stripe/PayPal/IAP 相关)、推送(极光、个推、OneSignal、FCM)、网络(AFNetworking、Alamofire、Moya、curl、OkHttp 无关项勿放)、图片/音视频(SDWebImage、Kingfisher、Lottie、ffmpeg、libwebp、GPUImage、Agora、腾讯 TRTC、网易云信、融云)、引擎与中间件(Unity、Unreal、cocos2d-x、Spine、FMOD、Wwise、Live2D、Box2D…)、数据(SQLite、Realm、FMDB、Protobuf、FlatBuffers、MMKV)、安全反作弊(腾讯 ACE/MTP/TSS、网易易盾、数美、梆梆、爱加密、iXGuard、Arxan 等**仅按可核实的特征**)、热更新(HybridCLR、xLua、ILRuntime、JSPatch 类)。
   - **每一条都必须是你有把握的**:不确定的厂商 / 用途宁可不收录。不得编造特征串;**能联网查证的先查证**。
   - 系统框架另放 `sysframeworks.json`(名称 → 中英文用途 → 是否敏感能力,如 `CoreLocation`/`AdSupport`/`AppTrackingTransparency`/`HealthKit`)。
3. **用户覆盖**:合并 `libs.user.json`(位置:`IPA_ANALYZER_HOME` 或 `--libs-user PATH`),同 `id` 覆盖;格式错误只 warning。
4. **输出** `ctx.results["libs"]`:`{items[{id,name,kind(system|bundled_dylib|framework|static_sdk|resource_bundle|unity_namespace),vendor,category,purpose_zh,purpose_en,tags,confidence,evidence[]}], unknown[{name,kind,evidence,hint?}], by_category{}, privacy_tags{ads,analytics,tracking,social}}`。**未命中的库一律进 `unknown`,`purpose` 留空,最多附"仅基于名称的低置信提示 `hint`"(明确标注为猜测)**。Finding:`libs.summary`、`libs.unknown`(verdict=unknown)。
5. 同一库多证据归并(如 Firebase 的 framework + 类前缀 + 域名)。

## B. 保护/加密汇总(`protect` 阶段)
1. `protect.fairplay`:汇总 `macho.binaries[*].slices[*].encrypted`:全部加密 / 部分加密(哪些文件)/ 全未加密;并结合 `meta.fairplay_container`。**明确写出后果**(主程序加密 ⇒ 不能直接做二进制分析 / il2cpp dump;Unity 的 metadata 与资源是否受影响由 Unity 阶段说明)。注意:仅 `SC_Info` 存在而 `cryptid=0` ⇒ 说明已被解密但保留了容器(`yes` 容器、`no` 加密)。
2. `protect.codesign`:有无签名、Team ID、签名类型(与 meta 分发类型交叉)、`get-task-allow`。
3. `protect.stripped`、PIE、栈保护、ARC:从 macho 汇总到"主程序 / 全部"两个层级。
4. `protect.antidebug`:符号(`_ptrace`、`_sysctl`、`_syscall`、`_task_get_exception_ports`、`_getppid`、`_dlsym` 组合…)+ 字符串;`protect.jailbreak_detect`:路径字符串(`/Applications/Cydia.app`、`/bin/bash`、`/usr/sbin/sshd`、`MobileSubstrate`…)+ `fork`/`canOpenURL cydia://`;规则放 `protectors.json`。**一律"特征命中,非结论",verdict 至多 `suspected`**。
5. `protect.obfuscation` / `protect.packer`(P1):商业壳 / 混淆器特征(来自 `protectors.json`,可核实的才收录),低置信。
6. 汇总 Unity / 其他引擎阶段的资源加密 Finding 到 `protection.findings`(只引用,不重复判定)。
7. 每个 Finding 带 `remediation`(例如:FairPlay 命中 ⇒ "请提供已解密 IPA;本工具不提供解密")。

## C. 项目类型分类(`classify` 阶段)
按架构 §4.2 实现可解释的打分器:输入 `meta`(iTunes genre / LSApplicationCategoryType / 权限)、`engine.detect`(含 `custom` 判定)、`engine.fingerprint`(渲染 API + 物理 / 动画 / 脚本 VM 是游戏强信号;自研引擎 + Metal + 物理库 ⇒ 游戏,置信度低于已知游戏引擎)、`libs`(类别与系统框架信号)、`inventory`(视频 / 音频占比等)。输出 `{category, subcategory?, confidence, scores{}, evidence[], runner_up?}`。内部类别与 01 需求 F-CLS 一致。`data/classify.json` 存 App Store 类别名 → 内部类别映射(`Games`=genreId 6014;其余 genreId 以 Apple 文档 / iTunes 元数据实测为准,不确定的只按 genre 名称映射并标 UNVERIFIED)、信号权重表。游戏子类型(如有 `public.app-category.games.*` 或 genre 列表中的子类)输出到 `subcategory`。

## 验收标准
- ✅ `libs.json` ≥150 条,脚本校验(`tests/unit/libs/test_kb_schema.py`):必填字段、`id` 唯一、正则可编译、无重复匹配规则冲突、`category` 在白名单内。
- ✅ 夹具:构造含 Firebase+AppsFlyer+AdMob 特征的假 Mach-O(经 `macho_builder`)→ 正确识别并归并证据;无任何特征的自研库 → 进入 `unknown` 且 `purpose` 为空。
- ✅ 用户 `libs.user.json` 覆盖生效;损坏文件不崩溃。
- ✅ `protect`:`cryptid=1` / `0` / 混合(主程序明文 + 某 framework 加密)三种夹具结论与措辞正确;SC_Info 在 + cryptid=0 的组合正确。
- ✅ 反调试 / 越狱检测不会在无特征时命中;命中时 verdict 不超过 `suspected`。
- ✅ `classify`:iTunes genre=Games → 游戏(≥0.9);无元数据 + Unity + 无 GameKit → 游戏但置信度较低并列竞争项;纯原生 + `AVFoundation` + ffmpeg + 大量视频 → 影音;分数接近时降置信度并给 `runner_up`。
- ✅ 全部阶段在上游缺数据(macho/meta 缺失)时 `partial`/`skipped` 而非崩溃。
- ✅ 单测通过。

## 备注
- 种子库的质量决定产品口碑:**准确 > 数量**。回报里列出你"有把握"与"来自单一来源"的条目比例。

## 加密二进制的降级(通用原则)
凡依赖 Mach-O 字符串 / ObjC 类名 / 符号的检测,在 `slice.encrypted=True` 时必须用 `skip_encrypted=True` 并**降级**到文件、目录、metadata 字符串等不依赖加密区间的证据;输出里要说明"二进制已加密,基于二进制的检测受限"(`remediation`:提供已解密 IPA)。验收里增加"加密二进制夹具下不产生噪声误报"。


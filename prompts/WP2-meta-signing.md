# WP2 — 应用元信息、描述文件、权限与分发类型(Wave 1)

先读 `prompts/_common.md`、`docs/CONTRACT-FREEZE.md`。

## 目标
从 `Info.plist`、本地化字符串、`embedded.mobileprovision`、`iTunesMetadata.plist`、`SC_Info`、`_CodeSignature` 得出应用身份、分发类型、权限与隐私面。**购买者信息默认脱敏。**

## 文件归属
`src/ipa_analyzer/analyzers/meta.py`、`src/ipa_analyzer/meta/{__init__,infoplist.py,strings_file.py,provision.py,itunes_meta.py,coderesources.py,permissions.py}`、
`data/permissions.json`(`NS*UsageDescription` 键 → 中英文含义与敏感级别)、`data/i18n/{zh,en}/meta.json`、`tests/unit/meta/*`。
(`util/plist_utils.py` 属 WP0,只可调用,不可改;缺功能写在 `meta/` 内。)

## 要做的事
1. **Info.plist**:二进制 / XML 皆可(经 `plist_utils.load_plist`);提取:`CFBundleIdentifier, CFBundleShortVersionString, CFBundleVersion, CFBundleExecutable, CFBundleDisplayName, CFBundleName, MinimumOSVersion, UIDeviceFamily, UIRequiredDeviceCapabilities, UIBackgroundModes, UISupportedInterfaceOrientations, CFBundleURLTypes(schemes), LSApplicationQueriesSchemes, NSAppTransportSecurity(是否 AllowsArbitraryLoads / 例外域名), UIApplicationSceneManifest, LSApplicationCategoryType, DTSDKName/DTPlatformVersion/DTXcode/DTCompiler, WKCompanionAppBundleIdentifier, NSExtension*`。缺失键不报错。
2. **项目名解析**:按 01 需求 F-META 的优先级给出 `names[]`(每个含 value + source + lang)与 `selected_name`。
3. **strings 文件解析 `strings_file.py`**:`*.lproj/InfoPlist.strings` 可能是二进制 plist、UTF-16(带 BOM)、UTF-8 的 OpenStep 文本格式;实现健壮解析(含转义、注释)。语言码归一(`zh-Hans`/`zh_CN`/`zh-Hant`/`en`/`Base`)。
4. **权限**:收集全部 `NS*UsageDescription` 与 `NSUserTrackingUsageDescription`(ATT)、本地化文本(多语言)、敏感级别(来自 `data/permissions.json`);输出 `privacy.permissions[]`;`meta.permissions` Finding 汇总。
5. **embedded.mobileprovision**:CMS(PKCS#7)包裹的 plist——不做 CMS 验签,直接在字节流中定位 `<?xml` … `</plist>` 切片再解析;提取 `Name, TeamName, TeamIdentifier, ApplicationIdentifierPrefix, ExpirationDate, CreationDate, ProvisionedDevices(数量,**不输出 UDID 明文**,只给数量与哈希前缀)、ProvisionsAllDevices, Entitlements(get-task-allow, aps-environment, application-identifier, com.apple.developer.associated-domains, application-groups, keychain-access-groups …)`。
6. **分发类型判定 `meta.distribution`**(三态 + 证据):
   - AppStore:有 `iTunesMetadata.plist` 或 `SC_Info/`,且无 `embedded.mobileprovision`(App Store 下发包通常无),或 provision 为 App Store 类型;
   - Development:`get-task-allow=true` 且有设备列表;
   - AdHoc:有设备列表且 `get-task-allow=false`;
   - Enterprise:`ProvisionsAllDevices=true`;
   - 无签名 / 无 provision / 无 SC_Info ⇒ `unsigned_or_repackaged`(suspected)。
   规则以 Apple 文档 / 实测为准,有歧义时标 `suspected` 并写明竞争项。
7. **iTunesMetadata.plist**:提取 `itemId, itemName, artistName, genre, genreId, genres, bundleDisplayName, softwareVersionBundleId, releaseDate, bundleVersionExternalIdentifier`。**脱敏**:`apple-id, userName, DSPersonID, appleId, purchaseDate, com.apple.iTunesStore.downloadInfo(accountInfo)` 等购买者相关字段在输出结构里替换为 `"<redacted>"`,并在 `redaction.applied=true` 记录被脱敏的键名(不含值)。`Config.redact=False` 时才保留。
8. **`meta.fairplay_container`**:`SC_Info/*.sinf|*.supp` 存在 ⇒ 该包经 App Store FairPlay 下发(证据);注意这不等于二进制一定被加密——最终以 Mach-O `cryptid` 为准(WP3 / WP4 负责),此处只给容器层证据。
9. **P1 `meta.signature_integrity`**:解析 `_CodeSignature/CodeResources`(plist,`files`/`files2`,含 `hash`/`hash2`、`optional`),对其中列出的文件计算哈希比对(流式、限制总量与耗时),输出"缺失 / 被改 / 额外文件"计数与前 10 例。哈希算法(SHA1 / SHA256)以文件中字段为准。可由 `Config` 关闭。
10. **嵌套单元的 Info.plist**:对 `PlugIns/*.appex`、`Watch/*.app`、`AppClip` 读取其 Info.plist,输出 `extensions[]`(bundle id、`NSExtensionPointIdentifier`、类型)。

## 输出
`ctx.results["meta"] = {identity{names,selected_name,bundle_id,version,build,executable,min_os,devices,...}, distribution{...}, provision{...}, itunes{...(脱敏后)}, permissions[], url_schemes[], query_schemes[], ats{...}, extensions[], background_modes[], capabilities[], sdk{...}, signature_integrity?, warnings[]}`。字段名遵循 `CONTRACT-FREEZE.md`;新增字段放 `extra`。

## 验收标准
- ✅ 夹具覆盖:二进制 / XML Info.plist、缺键、乱码 plist、UTF-16 / UTF-8 / 二进制 strings、多语言名称优先级、Provision(Dev/AdHoc/Enterprise/AppStore 伪造样例)、含购买者信息的 iTunesMetadata。
- ✅ 脱敏默认生效,断言输出 JSON 中不出现夹具里的邮箱 / 姓名 / UDID 明文;`--no-redact` 才出现(UDID 仍只给哈希前缀)。
- ✅ 任一子文件解析失败只产生 warning,阶段状态 `partial`,不抛异常。
- ✅ 项目名候选顺序有单测。
- ✅ 单测通过。

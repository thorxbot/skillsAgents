# WP5 — Unity 专项:版本/后端、metadata 与 AssetBundle 加密判定、Mono、热更新、自动 il2cpp dump 编排(Wave 2)

先读 `prompts/_common.md`、`docs/CONTRACT-FREEZE.md`、`docs/02-ARCHITECTURE.md` §4.3 / §4.4 / §4.5 / §4.6。依赖:WP1(inventory/提取)、WP3(macho / thin / fairplay)、WP6(`run_il2cpp_dump`)、WP7(`engine.detect` 输出 `candidates`;开发期用桩数据;Unity 检测签名在 `data/engines/unity.json`,由 WP7 维护)。

## 目标
这是用户最关心的部分。对 Unity 包给出**可信的**:版本、后端、metadata 是否加密、AssetBundle 是否加密、Mono DLL 是否加密、热更新方案,并在前置条件满足时**自动完成 il2cpp dump**;不满足时说清原因与下一步。

## 文件归属
`src/ipa_analyzer/analyzers/unity.py`、`src/ipa_analyzer/unity/{__init__,metadata.py,mono.py,version.py,bundles.py,precheck.py}`、
`data/i18n/{zh,en}/unity.json`、`references/{unity-assetbundle.md,unity-il2cpp-metadata.md}`、
`tests/unit/unity/*`、`tests/fixtures/unity_builder.py`(合成 `global-metadata.dat` / Unity 目录结构,签名稳定,供全员使用;**UnityFS / PE-CLI / Lua 样本直接复用 WP3b 的 `formats_builder`,不要重复实现**)。

> **分工变更**:UnityFS / LZ4 / PE-CLI 解析已抽到 WP3b 的 `ipa_analyzer.formats.*`(Wave 1 完成),你只写 Unity 语义层(分类/聚合/判定)。**热更新(DLL / Lua / JS / 资源热更)整体交给 WP5b**(阶段 `engine.unity.hotfix`),本包不再实现 `hotupdate`。读 `docs/04-UNITY-HOTFIX.md` 了解边界。

## 要做的事
1. **激活条件**:`engine.detect` 候选含 `unity`(WP7 产出),否则 `skipped(reason="not a Unity app")`。
2. **版本 `version.py`**:多来源交叉并说明采信顺序与冲突:UnityFS 头 revision/版本串、`Data/globalgamemanagers` 或其他 SerializedFile 头中的版本串(**按官方/社区格式文档核对布局**)、二进制字符串(用 WP3 `scan`)、`Data/Resources/unity_builtin_extra`;输出 `{value, sources[], conflicts[]}`。
3. **后端判定**:`global-metadata.dat` ⇒ IL2CPP;`Data/Managed/Assembly-CSharp.dll`(或 `Data/Managed/*.dll` 且无 metadata)⇒ Mono;并存或皆无 ⇒ `unknown`,写明证据。定位 il2cpp 承载二进制(架构 §4.3)。
4. **`metadata.py`**(架构 §4.4):读头、版本区间(查证后写入 `data/il2cpp_backends.json` 的 `metadata_versions`——该文件归 WP6,**只读引用,缺项请在回报提 Contract change request**)、头部自洽(`(offset,size)` 字段表**依据官方 `il2cpp-metadata.h` 或 Il2CppDumper 源码核对**,按版本分支)、熵、字符串区可读性、XOR 还原尝试;输出 `unity.metadata.present` / `unity.metadata.encrypted`(三态)含证据。
5. **`precheck.py`**:il2cpp 前置检查聚合 → `unity.il2cpp.precheck`:
   - 承载二进制 slice 是否 FairPlay 加密(来自 `macho`)⇒ 若是,`E_BINARY_FAIRPLAY`,**不运行 dump**;
   - metadata 判定 `YES/SUSPECTED` ⇒ 不运行(`E_METADATA_ENCRYPTED`),但提供 `--force-dump` 让用户强制尝试;
   - 二进制中缺少 il2cpp 特征(如 `il2cpp_` 符号 / 字符串)⇒ 警告;
   - 通过 ⇒ `ready`。
6. **AssetBundle `bundles.py`**(架构 §4.5;解析用 `formats.unityfs` / `formats.lz4`):
   - 调用 `formats.unityfs.parse_header / read_blocks_info / probe_variants`,不自己写解析;
   - 发现 + 分类 + 深度校验 + 聚合 ⇒ `unity.assetbundle.encryption`;
   - 采样策略与上限可配(`Config.unity.bundle_deep_sample=200`);
   - 输出 `bundles{total, by_class{standard,offset_prefix,xor_simple,high_entropy_unknown,other,unknown}, compression{}, unity_versions{}, samples{class:[top10]}, addressables{catalog_found, ...}}`;
   - 处理超大 bundle(只读头 + BlocksInfo,不读全文件)。
7. **Mono**(`mono.py`,用 `formats.pe_cli`;注意 iOS 现代 Unity 基本只有 IL2CPP,Mono 分析降低优先级,见 `04-UNITY-HOTFIX.md` §1 注):`Assembly-CSharp.dll` 等是否合法 PE(`MZ` + PE 头)且含 CLI 元数据(`BSJB`),否则 `unity.mono.dll_encrypted = suspected/yes`;识别常见混淆器特征(仅可核实的:如 ConfuserEx、Beebyte 的典型属性 / 字符串),低置信。
8. **热更新**:不在本包实现(见上方分工变更)。仅在 `ctx.results["unity"]` 里暴露 WP5b 需要的事实:`metadata{path, header_ok, string_region{offset,size}, verdict}`、`bundles{paths_sample[], total}`、`binary{path}`。
9. **自动 il2cpp dump 编排**:
   - `precheck` 通过且 `Config.il2cpp.enabled` ⇒ 经 `ctx.extract` 取二进制与 metadata;用 `write_thin` 取 arm64 slice;调用 `il2cpp.runner.run_il2cpp_dump(req, tools, cfg)`;把结果与 `summarize_dump` 摘要写入 `ctx.results["unity"]["dump"]`(含输出目录相对路径、后端名与版本、命名空间 Top、混淆度);
   - 失败 ⇒ `unity.il2cpp.dump`(verdict=no,附 `Il2CppErrorCode` 与 remediation),阶段 `partial` 而非 `failed`;
   - 产出 `unity.il2cpp.names_obfuscated`(来自混淆度);
   - **dotnet 缺失 / 离线 / 未授权** ⇒ `skipped` + 可操作建议(调用 WP6 的错误码与指引文案);
   - 任何情况下不得因 dump 失败而丢掉前面已得的 Unity 判定结果。
10. 输出 `ctx.results["unity"]`:`{version, backend, binary{path,slice,encrypted}, metadata{path,present,version,header_ok,entropy,string_region_ok,verdict,evidence}, bundles{...}, mono{...}, precheck{}, dump{}}` 与 Finding 全集(见架构 §3.1 `unity.*`)。
11. 参考文档 `references/unity-assetbundle.md`、`unity-il2cpp-metadata.md`:写清判定矩阵、已知局限(UnityCN 变种、自定义加载器)、如何人工复核。

## 验收标准(全部用 `unity_builder` 夹具)
- ✅ metadata 四情形:正常 ⇒ `no`;错 magic+低熵(魔改)⇒ `suspected`;整体随机高熵 ⇒ `yes`;magic 对但字符串区被 XOR ⇒ `suspected`。
- ✅ AssetBundle 五情形:标准 UnityFS(none/LZ4/LZMA 各一)⇒ `no`;偏移前缀 ⇒ 正确归类;单字节 XOR 头 ⇒ 归类 `xor_simple` 且还原出密钥假设;随机高熵 ⇒ `high_entropy_unknown`;混合(80% 标准 + 20% 高熵)⇒ `suspected`;无 bundle ⇒ `unknown`。
- ✅ UnityFS 头部畸形(截断、size 字段巨大、BlocksInfo 压缩声明与内容不符)不崩溃、不 OOM(LZ4 输出上限生效)。
- ✅ Mono 三情形:合法 DLL / 非 PE 随机数据 / PE 但无 `BSJB`。
- ✅ 前置检查:加密二进制 ⇒ 不调用 runner(用 mock 断言),`E_BINARY_FAIRPLAY`;metadata 疑似加密 ⇒ 不调用 runner;`--force-dump` ⇒ 调用。
- ✅ 用 WP6 的假 dumper 跑通一条端到端(合成 Unity IL2CPP 目录 → thin → dump → summarize → Finding)。
- ✅ 非 Unity 包:阶段 `skipped`;Unity 但无 metadata 无 Mono DLL:`unknown` 而不崩溃。
- ✅ 版本多来源冲突有单测。
- ✅ 单测通过。

## 补充(metadata 版本与产物路径,通用原则)
- metadata 版本合法性必须取 `data/il2cpp_backends.json` 中 `metadata_versions` 各后端范围的**并集**:**版本超出某一个后端(如 Il2CppDumper)的范围 ≠ metadata 被加密**。只有版本号不在任何后端范围内(过大或过小)时才算可疑。`precheck` 把"版本被哪些后端支持"写进证据,供 `select_backends` 选择后备后端。
- `Il2CppRunResult.artifacts` 的值相对 `req.out_dir`,写入 `dump.artifacts` 时要转换为相对 `ctx.out_dir`。
- 二进制 FairPlay 加密时 dump 由前置检查拦截(`E_BINARY_FAIRPLAY`),这是预期行为。

## 补充(块级加密分类,通用概念)
- AssetBundle 分类包含 **`block_encrypted_suspected`**:头部标准 + BlocksInfo 可解 + 第一个 LZ4/LZ4HC 数据块解压失败;证据里记录块前 256 字节内跨块重复出现的固定字节序列(疑似 marker,仅作证据,不猜测含义)。`by_class` 同步加此键并在 `references/unity-assetbundle.md` 写明。**不实现解密。**
- 用 `unity_builder` 补夹具:可解 BlocksInfo + 数据块为"前 256 字节内含固定 marker + 其后高熵"的 LZ4 块 ⇒ 归类 `block_encrypted_suspected`;正常 LZ4 块不得误判。
- 具体案例与特征留待实际使用中积累,不要预置到规则里。

## 诚信要求
- 本阶段所有"加密"结论都是**启发式**:报告措辞与置信度必须体现;没把握的绝不输出 `no`。
- 不尝试解密 metadata / bundle,不实现任何破解;可记录"疑似 XOR 单字节密钥"作为**证据**,不用于自动还原整个文件。

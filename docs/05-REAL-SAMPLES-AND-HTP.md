# 真实样本与 Htp 块加密线索

## 1. 真实样本(用户提供,只读使用,禁止复制进仓库、禁止提交)
目录:`/Users/thor/Desktop/worker/code/python/ipa-gsa-probe/download/ipa`

| 文件 | 大小 | .app | 已观察到的特征(用 zip 列表初筛,2026-10-04) |
|---|---|---|---|
| `com.cis.jiangnan.cn_6.0.2.ipa` | 1.0 GB | JiangNan.app | Unity:有 `UnityFramework`、`Data/Managed/Metadata/global-metadata.dat`;无散落 `.bundle/.ab`;含 `SC_Info`;781 个文件 |
| `com.tapblaze.coffeebusiness_1.24.1.ipa` | 579 MB | GoodCoffee.app | Unity:同上;**2368 个 AssetBundle 类文件**;含 `SC_Info`;2933 个文件 |
| `com.jiawentech.pizzabusiness_5.57.5.ipa` | 418 MB | ISBN.app | **无 Unity 特征**,无 Flutter/Cocos 命名线索;含 `SC_Info`;7197 个文件(引擎待 `engine.fingerprint` 判断) |
| `com.sheworld.waterworld.chn_1.1.7.ipa` | 221 MB | SeaWorld.app | **无 Unity 特征**;含 `SC_Info`;12858 个文件(引擎待判断;可能是自研/其他引擎,是 `engine.custom` 的真实检验) |

用途:
- WP9 端到端验收(见 WP9 提示词"真实样本"一节);WP1/WP3/WP6 的性能与健壮性验证。
- 四个包都带 `SC_Info`,**主程序的 cryptid 需实测**(可能已解密,也可能是加密包)。结果只写进验收记录,不入库。
- 期望:GoodCoffee 是 AssetBundle 分类与热更新扫描的最佳样本(2368 个 bundle,需采样);SeaWorld/ISBN 是"未知引擎 → 指纹画像"的真实检验;JiangNan 是 1GB 级性能样本。

## 2. 用户自有项目 `appkill`(AssetStudio 分支)中的 Htp 块加密线索
来源:`https://git.tt56.lol/banxia/appkill/raw/branch/v2/AssetStudio/BundleFile.cs`(用户本人项目;`HtpDecryptor` 源文件在 v2 分支的 `AssetStudio/`、`src/`、`AssetStudio/Classes/` 下均未找到,**实现细节、marker 字节、密钥来源未知**)。

可确认的事实(来自 `BundleFile.cs` 的读取摘要,**需实现方再读一遍原文件核对**):
1. 仅识别标准签名 `UnityFS / UnityWeb / UnityRaw / UnityArchive`,**没有自定义签名**:头部看起来是标准的。
2. 加密发生在 **数据块(data blocks)层**,不是 BlocksInfo:BlocksInfo 能正常解压解析。
3. 只对压缩类型 **LZ4 / LZ4HC** 的块生效,且在 **LZ4 解压之前** 对压缩块做解密。
4. 判定方式:在块的前 `min(256, compressedSize-4)` 字节内搜索一个固定 **marker**;找到才调用 `DecryptBlock`,返回 `(decrypted, ok)`。
5. 开关是布尔标志 `IsHtpEncrypted`(由外部设置),说明是"某类游戏的已知变体",不是通用方案。

对检测器的含义(WP5 已纳入):
- 新增 AssetBundle 分类 **`block_encrypted_suspected`**:头部标准 + BlocksInfo 可解 + 但第一个 LZ4/LZ4HC 数据块解压失败 ⇒ 块级加密嫌疑;证据里额外记录:块前 256 字节内是否存在重复出现于多个块同一相对位置的固定字节序列(**疑似 marker**,仅作证据,不猜测其含义)。
- **不实现解密**:检测器只报告"疑似块级加密(Htp 风格:LZ4 块 + 前 256 字节内 marker)"。是否内置解密由用户后续决定。
- 网络检索摘要(**UNVERIFIED,单一来源**):UnityCN 类私有引擎的加密 bundle 报告为"仅数据块加密,按 0x10020 分块,AES-256-GCM";用于交叉参考,不要写进规则。

待用户补充(醒来后):`HtpDecryptor.cs` 的位置或内容(marker 字节、块结构)。有了才能把 Htp 变体升级为"确认",否则仅为 `suspected`。

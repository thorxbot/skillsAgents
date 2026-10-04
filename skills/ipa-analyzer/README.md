# ipa-analyzer

分析 iOS IPA(或 `.app` 目录)的 **Claude Code Skill + 跨平台 Python CLI**:给出结构化 `report.json` 与可读的 `report.md`,覆盖应用信息、项目结构、资源构成、第三方库用途、加密 / 保护判定、游戏引擎识别(含自研引擎指纹)、Unity 专项(IL2CPP / AssetBundle 加密、热更新、自动 Il2CppDumper)、隐私与权限。

- 纯静态、只读:**不执行** IPA 里的任何内容;不解密、不脱壳、不绕过任何保护(FairPlay 只检测、只报告)。
- 零第三方依赖:Python >= 3.9 标准库即可,macOS / Linux / Windows 通用,不依赖 `otool` / `lipo` / `codesign` / `unzip`。
- 每个结论都带 `verdict`(`yes / no / suspected / unknown / n/a`)+ 置信度 + 证据;没把握就报 `suspected` / `unknown`,不会报 `no`。
- 某个阶段失败或被跳过不会拖垮整体,报告里会写明原因(附录 10.1)。

适用范围:自有应用、已获授权的安全研究、合规审计、学习研究。

## 能力矩阵

| 领域 | 内容 | 阶段 |
|---|---|---|
| 摄取 | `.ipa` / `.zip` / `.app` / `Payload/` / 已解压目录;只读中央目录、不整包解压;zip-slip、zip bomb、非法文件名防护 | `ingest` |
| 资源 | 按类别 / 扩展名 / Top-N 大文件 / 本地化 / 打包归档汇总;按 magic 嗅探真实类型;熵抽样 | `inventory` |
| 元信息 | 项目名候选与来源、Bundle ID、版本、权限(含本地化文案与敏感度)、URL Scheme、ATS、扩展 / Watch / App Clip、分发类型、签名封印校验;购买者信息默认脱敏 | `meta` |
| Mach-O | 每个二进制每个架构:文件类型、SDK / 最低系统、UUID、PIE、符号剥离、签名、entitlements、**FairPlay(`cryptid`)** | `macho` |
| 引擎 | 与引擎名无关的能力画像(渲染 / 脚本 VM / 物理 / 音频 / 资源容器 / 宿主形态)+ 40 余种已知引擎签名 + **自研引擎判定与下一步建议** | `engine.fingerprint` `engine.detect` |
| 引擎资源保护 | Cocos 全家(C++ / Lua / JS / Creator 2.x、3.x)、Egret、Laya、Unreal、Godot、Flutter、React Native / Hermes、Defold、GameMaker、Solar2D、LÖVE、Xamarin、Web 混合 | `engine.other` |
| Unity | 版本交叉验证、IL2CPP / Mono、metadata 加密 / 魔改判定、AssetBundle 分类(标准 / 偏移 / XOR / 高熵 / 块级加密嫌疑)、Mono DLL 校验 | `engine.unity` |
| Unity 自动 dump | 前置检查(非 FairPlay、metadata 自洽)→ 工具供应(固定版本 + SHA256)→ 非交互运行 → 产物与混淆度摘要;后端链 Il2CppDumper → Cpp2IL → Il2CppInspectorRedux | `engine.unity` |
| Unity 热更新 | HybridCLR / ILRuntime / InjectFix、xLua / ToLua / SLua / MoonSharp、puerts(V8 / QuickJS)、Addressables / YooAsset;脚本存放位置;**Lua 版本分布**(5.1-5.4、LuaJIT 2.x)、一致性告警、魔改嫌疑;热更 DLL 画像 | `engine.unity.hotfix` |
| 库 | 种子库 200 条 SDK / 系统框架,可用 `libs.user.json` 扩充;**未识别的库明确标 `unknown`,不臆测用途** | `libs` |
| 保护 | FairPlay、代码签名、PIE / 栈保护 / ARC / 符号、反调试与越狱检测特征(仅特征命中) | `protect` |
| 分类 | 游戏 / 影音 / 生活 / 社交 / 工具 / 金融 / 教育 / 健康 / 购物 / 出行 / 新闻 / 其他 | `classify` |
| 报告 | `report.json`(带 JSON Schema)+ `report.md`(中 / 英)+ 可选 `report.html`;执行摘要 ≤ 15 行 | `report` |

## 安装

### 作为 Claude Code Skill

```bash
git clone <本仓库>
cd skillsAgent/skills/ipa-analyzer
python3 scripts/install_skill.py            # macOS / Linux 建立软链接;Windows 复制
python3 scripts/install_skill.py --force    # 已存在时直接替换(默认会询问)
python3 scripts/install_skill.py --dry-run  # 只看会做什么
```

目标是 `~/.claude/skills/ipa-analyzer`(`--target DIR` 可改)。安装后重启 Claude Code,对它说"分析一下这个 ipa"即可。Windows 下是复制:更新代码后重新运行脚本。

### 作为命令行工具(pip)

```bash
cd skills/ipa-analyzer
pip install -e .            # 无第三方依赖(pip >= 21.3;旧 pip 先 python -m pip install -U pip);可选 pip install -e .[full] 装 lief
ipa-analyze doctor
```

### 免安装

```bash
python3 scripts/ipa_analyze.py doctor
python3 scripts/ipa_analyze.py analyze app.ipa -o out
```

## 用法

```bash
ipa-analyze doctor                          # 环境自检:Python、平台、.NET、缓存目录、网络、已缓存工具
ipa-analyze analyze app.ipa -o out          # 默认输出 md + json
ipa-analyze analyze app.ipa -o out --offline            # 完全不联网
ipa-analyze analyze app.ipa -o out --lang en --format md,json,html
ipa-analyze analyze app.ipa -o out --extract metadata,bundles   # 同时把这些文件提取到 out/.../split/
ipa-analyze analyze app.ipa -o out --stages meta,libs   # 只跑部分阶段(自动带上硬依赖)
ipa-analyze analyze app.ipa -o out --il2cpp-tool /path/Il2CppDumper.dll --dotnet /path/dotnet
ipa-analyze tools list | install il2cppdumper | install dotnet --yes | path il2cppdumper
```

输出在 `out/<名字>-<sha12>/`:`report.md`、`report.json`、`inventory.json`(完整文件表)、`il2cpp/`(dump 产物)、`split/`(`--extract`)。退出码:0 正常,1 用法错误,2 输入无效(仍尽力写报告),3 有阶段失败(报告已写),4 致命错误。

### 示例(合成夹具的输出,非真实应用)

FairPlay 加密的 Unity IL2CPP 包:

```
== 执行摘要 ==
  引擎         Unity(置信度 0.99 高,已确认);另有候选:native_objc, native_uikit
  FairPlay   ❌ 是(范围:全部二进制),2/2 个二进制加密
  Unity 专项   Unity 2021.3.16f1 / il2cpp;metadata 加密:否;AssetBundle 加密:否;热更:未发现
  能否 dump    暂不能 dump:E_BINARY_FAIRPLAY(binary_fairplay)
  主要风险       FairPlay 加密(范围:全部二进制),二进制分析与 dump 受限;包未签名或疑似重打包
```

自研引擎(薄 UIKit 壳 + Metal + 自带 Lua + Box2D + 自定义 `.pak` 容器):

```
  项目类型       游戏(置信度 0.81 高)
  引擎         疑似自研引擎(判定:是,置信度 0.80 高),见 8.1
  主要风险       疑似自研引擎,需人工深入分析;包未签名或疑似重打包
```

报告 8.1 会给出引擎画像("Thin UIKit shell on Metal, embedded Lua (PUC), Box2D physics, 2 custom container(s)")和下一步建议(优先检查哪些容器 / 脚本绑定)。

xLua + Lua 5.3 字节码热更(8.2.1):

| 项目 | 值 |
| --- | --- |
| 热更新框架 | xLua(Lua,置信度 0.97) |
| 脚本存放位置 | AssetBundle 内 lua=2 |
| 字节码版本 | 5.3 × 2(64-bit);原生运行时 puc 5.3.6;字节码与运行时一致 |
| 魔改 Lua 嫌疑 | 否 |

## 环境要求

| 项 | 要求 |
|---|---|
| Python | >= 3.9(CI 矩阵:ubuntu / macos / windows × 3.9 / 3.12 / 3.13) |
| 系统 | macOS(arm64 / x64)、Linux(x64 / arm64)、Windows 10+ |
| 第三方包 | 无;可选 `lief`(缺失自动降级) |
| .NET | 仅 Il2CppDumper 需要(6+);Cpp2IL 不需要。缺失时 dump 阶段给出安装指引,**不会**静默安装 |
| 网络 | 仅在下载工具 / .NET 时需要;`--offline` 全程不联网 |

## 常见问题

**FairPlay 加密的包能分析什么?** Mach-O 头 / 加载命令 / 签名、文件和目录层面的引擎与 SDK 线索、`global-metadata.dat`、AssetBundle、Lua / JS / DLL 等普通文件都照常分析;二进制内的字符串、类名、符号落在加密区间内,相关检测会降级并在报告里写明。il2cpp dump 不可能,会被前置检查拦截(`E_BINARY_FAIRPLAY`)。本工具不解密;需要 dump 请自行提供合法获得的已解密 IPA。详见 `references/macho-fairplay.md`。

**没有 dotnet 怎么办?** 其余分析不受影响;dump 失败信息会告诉你如何安装,或用 `tools install dotnet --yes` 做用户级安装(不需要管理员权限)。

**离线环境?** `--offline`;工具需预先 `tools install`(联网时一次)或用 `--il2cpp-tool` 指定本地路径。

**metadata 版本不支持?** Unity 2022.3+ / Unity 6 的 metadata(如 v31、v39)超出 Il2CppDumper 支持范围(16-31)时,会尝试 Cpp2IL / Il2CppInspectorRedux(实验性),仍失败则给出 `E_METADATA_VERSION_UNSUPPORTED`。兼容表:`data/il2cpp_backends.json`。

**"压缩 ≠ 加密"。** 引擎脚本 / 资源判定:明文与字节码为 `no`(会注明"已编译");高熵、每个文件都有自定义头、xxtea 式签名 + 长度规律为 `suspected`;不会下 `yes`,也不会解密。

更多见 `references/faq.md`、`references/report-fields.md`。

## 合规声明

本工具只做**检测与报告**:不实现 FairPlay 解密、脱壳、反作弊 / DRM 绕过、动态分析、重签名或安装;不内置或分发任何第三方 App 的文件(测试夹具全部程序生成)。请仅用于自有应用、已获授权的安全研究、合规审计与学习研究,并遵守适用的法律与服务条款。

## 局限

- 未在真实的"已解密 Unity IL2CPP IPA"上验证 Il2CppDumper / Cpp2IL / Redux 的成功路径(只用假 dumper 验证运行器行为)。
- Windows / Linux 行为依赖 CI 验证(核心逻辑为 POSIX / Windows 纯函数 + 参数化单测);Windows 长路径与 `shutil.which` 搜索当前目录等未实机验证。
- 自研引擎、容器与脚本判定都是启发式,结论上限为 `suspected`;Messiah、QuickSilver 等暂无公开 iOS 特征的引擎走通用指纹。
- Htp 风格块级加密(LZ4 块 + 块首 marker)只报告 `block_encrypted_suspected`,未确认具体方案。
- 商业壳 / 混淆器识别、Assets.car 渲染项、`.xcarchive` 输入、HTML 报告的完善等属于后续迭代。
- 性能目标(1 GB IPA ≤ 60 s、峰值内存 ≤ 500 MB)未在真实 1 GB 样本上实测。

## 开发

```bash
cd skills/ipa-analyzer
pip install -e .[dev]
python -m pytest -q                  # 慢测试:--runslow;网络测试:IPA_TEST_NETWORK=1;真实样本:IPA_SAMPLES_DIR=...
python tests/fixtures/build_fixtures.py out-fixtures   # 生成全部合成整包夹具
```

文档:`../../docs/`(需求、架构、冻结契约、验收记录 `ACCEPTANCE.md`)。新增引擎 / 库只需加 `data/**/*.json`(或用户目录的 `engines.user.d/*.json`、`libs.user.json`)。

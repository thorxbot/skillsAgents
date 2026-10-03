# 共用前言(每个子 agent 必读,优先级高于各 WP 提示词中的细节)

## 项目
你在参与 **ipa-analyzer**:一个 Claude Code Skill + 跨平台 Python CLI,用于分析 iOS IPA 的结构、资源、Lib 用途、加密 / 保护情况,并对 Unity 游戏做 IL2CPP / AssetBundle 加密判定和自动 Il2CppDumper。
- 项目根:`/Users/thor/Desktop/worker/skillsAgent`
- Skill 根:`/Users/thor/Desktop/worker/skillsAgent/skills/ipa-analyzer`(下文路径均相对于它,除非写明 `docs/`、`prompts/`)
- **开工前先完整阅读**:`docs/01-REQUIREMENTS.md`、`docs/02-ARCHITECTURE.md`(你的工作包说明引用其中章节)。若存在 `docs/CONTRACT-FREEZE.md` 也必须读,它是已冻结的公共 API。

## 硬性规则
1. **跨平台**:必须在 macOS / Linux / Windows 都能跑。核心路径只用 Python 标准库;禁止依赖 `otool/plutil/codesign/lipo/unzip/file/strings` 等命令(可选的"存在则交叉验证"可以,默认不走)。用 `pathlib`;zip 内路径用 `PurePosixPath`;`open()` 显式 `encoding`;子进程 `shell=False` + 超时。详见 `02-ARCHITECTURE.md` §5。
2. **Python ≥ 3.9 语法**:每个模块 `from __future__ import annotations`;不用 `match`;不用 3.10+ 的标准库 API。可选第三方依赖(如 `lief`)只能 `try-import` 并优雅降级,且不得是唯一实现。
3. **文件归属**:只创建 / 修改你的工作包"文件归属"清单里的文件(含你自己的 tests 与 `data/i18n/*/<你的模块>.json`)。**不得修改** `models.py`、`context.py`、`pipeline.py`、`registry.py`、`cli.py`、`schemas/`、他人文件。需要契约变化 → 在回报中写 "Contract change request",由总监裁决,不要自行改。
4. **证据 + 置信度 + 三态**:所有判定产出 `Finding`;不确定时用 `suspected` / `unknown`,**绝不在没有把握时报 `no`**。
5. **事实核对**:凡是 magic、偏移、结构体布局、版本区间、命令行参数、配置字段名、SHA256 等"记忆性事实",必须以官方文档 / 源码 / 实测为准。在代码注释中写明来源(如 `# Source: Apple mach-o/loader.h` 或 `# Verified against Il2CppDumper vX.Y.Z README`)。没法核对的:代码里加 `# UNVERIFIED:` 并在回报中单列。**宁可写 UNVERIFIED,不要编造。** 网络不可用时直接说明。
6. **安全**:永远不执行 IPA 内的任何内容;解压必须走 `ingest/safe_extract.py`(WP1 提供后);外部进程超时 + 杀进程树;不写出输出目录之外;测试不依赖网络(网络测试用 `IPA_TEST_NETWORK=1` 门控)。
7. **不要引入/复制第三方代码**(许可证风险)。可以参考协议规范自己实现。
8. **不要做的事**:不实现 FairPlay 解密 / 脱壳 / 任何保护绕过;不在仓库里放任何真实 App 的文件;夹具全部程序生成。
9. **风格**:与 `models.py` 及已有代码保持一致;类型标注完整;模块 docstring 说明职责;不写无用注释;库代码用 `logging`,不 `print`(CLI 除外);函数小而可测。
10. **语言**:代码 / 标识符 / docstring / 兜底文案用英文;给用户看的报告文案通过 `data/i18n/{zh,en}/<模块>.json` 提供(zh 必须有)。

## 质量门槛(提交前必须自检)
- 你的测试全部通过:`python -m pytest -q skills/ipa-analyzer/tests/<你的范围>`(在 Skill 根目录执行时去掉前缀)。至少覆盖:正常路径、畸形 / 截断输入、跨平台路径边界、与 `unknown` / `suspected` 的分支。
- 在本机(macOS)跑通;对 Windows 特有逻辑(路径、保留名、进程树)用纯函数 + 参数化单测覆盖,不能真机验证的在回报中注明。
- `python -W error -c "import ipa_analyzer"` 无警告(把 `src` 加到 `PYTHONPATH`)。
- 不留调试输出、临时文件、`TODO` 无主。

## 回报格式(最终消息必须按此结构,简洁)
1. **完成情况**:逐条对照你的"验收标准",✅/⚠️/❌ + 一句话。
2. **产出文件**:路径列表。
3. **公共 API**:你新增的对外函数 / 类签名(供下游 WP 使用)。
4. **测试**:运行的命令与结果(通过 / 失败数)。
5. **UNVERIFIED 清单**:代码中所有未核实的事实及位置。
6. **已知局限**。
7. **Contract change requests**(如有)。
不要复述需求,不要贴大段代码。

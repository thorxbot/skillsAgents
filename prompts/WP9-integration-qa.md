# WP9 — 集成、端到端测试、CI、文档、SKILL.md 定稿与验收(Wave 3)

先读 `prompts/_common.md`、`docs/CONTRACT-FREEZE.md`、`docs/01-REQUIREMENTS.md`(尤其 §5 DoD)、`docs/02-ARCHITECTURE.md`(尤其 §7、§9)。前 8 个 WP 已合入,评审意见已处理。

## 目标
让整个东西**作为一个产品**成立:跨阶段联调、端到端测试、CI 绿、文档与 SKILL.md 可用、逐条对照 DoD 出验收记录。

## 文件归属(可修改任何 WP 的 `tests/`;**业务代码修复**只在"发现缺陷且责任方不可得"时做最小修改,并在回报中逐条列出)
`SKILL.md`、`README.md`(中文,含安装 / 用法 / FAQ / 局限)、`references/{report-fields.md,macho-fairplay.md,faq.md}`、`tests/integration/*`、`tests/fixtures/build_fixtures.py`(聚合入口)、`tests/fixtures/full_ipa_builders.py`、`.github/workflows/ci.yml`(完善)、`docs/ACCEPTANCE.md`、`pyproject.toml`(仅发布元数据)、`scripts/*`(辅助脚本,如 `install_skill.py`:把 skill 复制/链接到 `~/.claude/skills/ipa-analyzer`,Windows 用复制)。

## 总监约束(token 节约)
- 只用合成夹具;不跑真实样本;不做 1GB 级性能夹具(可只做小规模的性能回归,标 slow 且默认跳过)。
- 能用已有测试覆盖的不要重复写;集成测试聚焦跨阶段一致性与 CLI 端到端。

## 已知待修(必做)
- `tests/unit/il2cpp/test_runner.py::test_supervisor_merges_stderr_and_keeps_tail_bounded` 在 CPU 负载下偶发失败(单独跑通过):找出时序假设(固定 sleep / 过紧超时)并改为基于事件/同步的确定性写法,不要只加大超时。
- 集成夹具要保持两种情形可区分:自研引擎 = 无已知引擎 + 画像;已知引擎内的自定义资源封装 = 已知引擎 + 容器画像。

## 要做的事
1. **合成整包夹具**(用各 WP 的 builder 组合):
   - `unity_il2cpp_plain.ipa`:Unity IL2CPP,metadata 正常,bundle 标准,Mach-O 明文,`UnityFramework` + 假 dumper 可跑;
   - `unity_il2cpp_encrypted_binary.ipa`:`cryptid=1`;
   - `unity_il2cpp_meta_xor.ipa`:metadata 被 XOR;bundle 高熵;
   - `unity_mono.ipa`:Mono + 加密 DLL;
   - `native_swift_app.ipa`:原生 + Firebase/AppsFlyer 特征;
   - **Unity 热更新夹具**:`unity_hybridclr.ipa`、`unity_ilruntime.ipa`、`unity_xlua_lua53.ipa`(bundle 内 Lua 5.3 字节码)、`unity_tolua_luajit.ipa`(LuaJIT 2.1 字节码)、`unity_lua_mixed_versions.ipa`(5.1 与 5.4 混合 + 运行时串不一致 ⇒ 一致性告警)、`unity_lua_tampered.ipa`(头部篡改 / XOR)、`unity_puerts_quickjs.ipa`、`unity_addressables_remote.ipa`、`unity_hotdll_encrypted.ipa`(热更 DLL 非 PE 高熵);断言 `engine.unity.hotfix` 各字段与 Finding;
   - `custom_engine.ipa`(**自研引擎**:薄 UIKit 壳 + Metal + 自带 Lua 符号 + Box2D 符号 + 自定义 `.pak` 容器(合成偏移表 + zlib 块)+ 高熵 `.dat`;断言 `engine.custom` 成立、画像各维度正确、不被误判为任何已知引擎);
   - `cocos_cpp_lua_plain.ipa`、`cocos_lua_xxtea.ipa`、`cocos_js_jsc.ipa`、`cocos_creator3.ipa`、`egret_app.ipa`、`laya_app.ipa`(Cocos 家族与 Egret / Laya 变体判定);
   - `flutter_app.ipa`、`media_app.ipa`(影音)、`broken_*.ipa`(截断 / 非 zip / 无 Payload / zip-slip)。
2. **集成测试**:对每个夹具跑完整 CLI(`subprocess` 调 `scripts/ipa_analyze.py`,验证免安装入口)与库调用两种方式:断言退出码、`report.json` 通过 schema、关键 Finding 的 verdict、`report.md` 章节齐全、被跳过阶段的原因可见;黄金文件对比(忽略时间 / 耗时)。
3. **跨阶段一致性检查**:所有阶段名、Finding ID、`ctx.results` 键是否与 `CONTRACT-FREEZE.md` 一致(写成测试);所有 `data/i18n/zh/*.json` 覆盖了全部 Finding ID(写成测试,缺失列清单);所有 `UNVERIFIED` 注释汇总到 `docs/ACCEPTANCE.md`。
4. **跨平台**:
   - 完善 CI:`ubuntu/macos/windows × 3.9/3.12/3.13`,另加一个 job "no-dotnet-no-network"(显式清空 PATH 中的 dotnet、设 `--offline`)验证 DoD #5,一个可选 job "with-dotnet"(安装 .NET + 跑真实 Il2CppDumper 获取 / `--help` 冒烟,`IPA_TEST_NETWORK=1`)。
   - 路径/编码专项测试:含中文 / 空格 / emoji 的输入路径与输出目录、超长路径、Windows 保留名(参数化,macOS 上也跑纯函数部分)、CRLF 不影响 JSON 稳定性。
   - 无法本机验证的 Windows/Linux 项,在 `ACCEPTANCE.md` 标"依赖 CI 验证"。
5. **性能与健壮性**:生成 ≈1 GB 稀疏 / 低成本构造的 IPA(例如大量 stored 的零填充文件,注意磁盘与 CI 时间,标 `slow`),断言耗时 / 内存目标(`01` §4);异常输入模糊测试(随机截断 / 位翻转若干夹具,断言不崩溃不卡死,超时保护)。
6. **SKILL.md 定稿**(`02-ARCHITECTURE.md` §9):frontmatter(`name: ipa-analyzer`,`description` 含触发词);正文流程精炼(≤150 行):doctor → analyze → 读摘要 → unknown 库查证回写 → FairPlay 提示 → 脱敏提醒 → 常用命令速查 → 按需读 `references/`。**写给 Agent 看的指令要可执行、无歧义**(明确哪些情况必须问用户:下载工具 / 安装 .NET)。
7. **README.md**(中文):简介、能力矩阵、安装(skill 方式 + pip 方式)、示例命令与示例报告片段(来自合成夹具)、环境要求(三平台)、常见问题(FairPlay、dotnet、离线、metadata 版本不支持)、合规声明、局限。
8. **真实样本 e2e:默认不做**。总监决定不做真实 IPA 实操验证。只保留一个**默认跳过**的可选测试(需设置 `IPA_SAMPLES_DIR` 才运行),供用户日后自行在本机验证;你不要运行它,也不要读取任何真实 IPA。`docs/ACCEPTANCE.md` 里真实样本一节写\'未验证(按需由用户本机运行)\'。案例留待实际使用中积累。
9. **验收记录 `docs/ACCEPTANCE.md`**:对照 `01-REQUIREMENTS.md` §5 的 7 条 DoD 与 §2 每个 F-* 条目的 P0 项,逐条 ✅ / ⚠️ / ❌ + 证据(测试名 / 命令输出);汇总 UNVERIFIED;列出已知局限与建议的下一步(P1/P2)。

## 验收标准
- ✅ `cd skills/ipa-analyzer && python -m pytest -q` 全绿(`slow`/`network` 另跑);本机 macOS 实测通过。
- ✅ 新开一个干净 venv 仅 `pip install -e .`(无可选依赖)后,免安装入口与 `ipa-analyze` 两种方式均可用。
- ✅ 在"无 dotnet、`--offline`"环境下对 `unity_il2cpp_plain.ipa` 运行:报告完整,il2cpp 阶段 `skipped` 且有可操作指引。
- ✅ 在假 dumper 注入下对同一夹具:完整产出 dump 摘要。
- ✅ `docs/ACCEPTANCE.md` 完整、诚实(未验证的写未验证)。
- ✅ SKILL.md 经"冷读测试":另起一个不了解项目的 agent 只读 SKILL.md,能正确完成一次分析并汇报(你可以自己模拟:只依据 SKILL.md 执行一遍,记录卡点并修正)。

## 回报额外要求
- 列出你修改过的**业务代码**(非 tests/docs)的每一处及原因。
- 列出 CI 尚未实际运行的 job(因没有远端仓库),如实说明。

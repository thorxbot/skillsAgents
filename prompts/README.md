# 子 agent 编排说明

## 先决条件
- 目录当前不是 git 仓库。建议先 `git init && git add -A && git commit -m "docs+prompts"`,每个 Wave 结束后提交一次,便于回滚与评审 diff。
- 各 WP 的文件归属互不重叠,同一工作区并行安全(不需要 worktree)。注册表采用自动发现,没有共改文件。

## 波次(Wave)与依赖

```
Wave 0 (串行)   WP0 骨架+契约 ──────────────────────────────┐ 闸门 G0:契约冻结
Wave 1 (并行)   WP1 摄取/清单   WP2 元信息/签名   WP3 Mach-O   WP3b 格式库   WP6 IL2CPP 工具链   WP8 报告渲染
                                                              闸门 G1:各自单测绿 + 评审 R1
Wave 2 (并行)   WP4 库/保护/分类    WP5 Unity 专项    WP5b Unity 热更新    WP7 引擎指纹+检测+自研    WP7b 各引擎检查器(Cocos/Egret/Laya/…)
                                                              闸门 G2:单测绿 + 评审 R2
Wave 3 (串行)   WP9 集成/CI/文档/SKILL 定稿 + 验收
                                                              闸门 G3:DoD 全部达成或列明未验证项
```
| WP | 提示词 | 依赖 | 预估规模 |
|---|---|---|---|
| WP0 | `WP0-skeleton-contracts.md` | – | M |
| WP1 | `WP1-ingest-inventory.md` | WP0 | L |
| WP2 | `WP2-meta-signing.md` | WP0 | M |
| WP3 | `WP3-macho.md` | WP0 | L |
| WP3b | `WP3b-formats.md` | WP0 | L |
| WP6 | `WP6-il2cpp-toolchain.md` | WP0 | L |
| WP8 | `WP8-report.md` | WP0 | M |
| WP4 | `WP4-libs-protect-classify.md` | WP1/2/3 | L |
| WP5 | `WP5-unity.md` | WP1/3/3b/6/7 契约 | XL |
| WP5b | `WP5b-unity-hotfix.md` | WP3b、WP5 的 `ctx.results["unity"]` 契约、WP1/3 | L |
| WP7 | `WP7-engines.md` | WP1/3 | XL |
| WP7b | `WP7b-engine-checkers.md` | WP0 接口、WP1/3;与 WP7 并行 | L |
| WP9 | `WP9-integration-qa.md` | 全部 | L |
| 评审 | `R-review.md` | 各 Wave 之后 | M |

## 派发方式
每个子 agent 的启动指令(把 `<WP文件>` 换掉):

> 先完整阅读 `/Users/thor/Desktop/worker/skillsAgent/prompts/_common.md`,再阅读 `/Users/thor/Desktop/worker/skillsAgent/prompts/<WP文件>`,严格按其执行并按其回报格式汇报。

Wave 内的 agent 在同一条消息里并行启动。每个 Wave 结束:
1. 跑全量测试:`cd skills/ipa-analyzer && python -m pytest -q`。
2. 启动评审 agent(`R-review.md`,把"评审范围"替换为本 Wave 的 WP)。
3. 总监(你)读各 agent 的回报:重点看 **UNVERIFIED 清单** 与 **Contract change requests**,裁决后再放行下一 Wave。
4. 评审问题 → 回派给原 WP 的 agent(用 SendMessage 续接,保留上下文)修复。

## 总监裁决要点(阅读回报时的检查表)
- 有没有出现"凭记忆写死"的 magic / 偏移 / 版本区间?是否都有来源注释或 UNVERIFIED 标记?
- 有没有任何地方在"没把握"时返回 `no`?
- 有没有 `subprocess(shell=True)`、未限制的解压、未脱敏的购买者信息?
- 有没有只在 macOS 可用的依赖或路径假设?
- 是否出现与 `02-ARCHITECTURE.md` §3.1 不一致的 Finding ID?

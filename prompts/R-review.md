# R — 独立评审(每个 Wave 结束后各派一次)

先读 `prompts/_common.md`、`docs/01-REQUIREMENTS.md`、`docs/02-ARCHITECTURE.md`、`docs/CONTRACT-FREEZE.md`。你是**独立评审者**:不写功能代码,**只读 + 跑测试 + 出问题清单**(可写 `docs/review/<wave>.md`,这是你唯一允许新建的文件)。

## 评审范围
`{{WAVE / WP 列表,例如:Wave 1 = WP1, WP2, WP3, WP6, WP8}}`

## 检查清单(逐项给结论,附 `file:line` 证据)
**A. 契约与架构**
1. 阶段名 / 依赖 / Finding ID / `ctx.results` 形状是否与 `CONTRACT-FREEZE.md`、`02-ARCHITECTURE.md` §3 一致?有没有越权修改他人文件(对比各 WP 文件归属)?
2. 失败是否被阶段隔离?上游缺数据时下游是否 `skipped/partial` 而非崩溃?

**B. 正确性(最重要)**
3. **记忆性事实**:magic、偏移、结构体布局、版本区间、命令行参数、配置字段名。抽查每个 WP 至少 5 处,对照官方文档 / 源码 / 实测核实;没有来源注释的,列出。
4. 判定逻辑是否存在"没把握却返回 `no`"的路径?三态使用是否正确?置信度是否合理而非常数?
5. 边界:空输入、截断、巨大字段、`cmdsize=0`、整数溢出式偏移、负数、循环引用。读取是否全部做了边界检查?有无可能死循环 / OOM(尤其 LZ4/LZMA 解压、`dump.cs` 解析、正则回溯)?

**C. 跨平台(重点)**
6. 搜索:`shell=True`、`os.system`、`open(` 无 `encoding`、`os.path` 拼接 zip 内路径、硬编码 `/` 或 `\\`、`os.getlogin`、`signal`/`os.killpg`/`fork` 等 POSIX-only API 无 Windows 分支、`/tmp` 硬编码、`lipo/otool/plutil/unzip` 依赖、`str.removeprefix` 等 3.9 之后 API(`removeprefix` 3.9 OK;`match`、`zip(strict=)`、`X | Y` 运行时注解 不 OK)。
7. Windows:保留名、非法字符、大小写冲突、长路径、mmap 句柄未关导致无法删除、`.exe` 解析、PowerShell 参数引用。
8. 编码:stdout 非 UTF-8 终端(Windows cp936/cp1252)下打印中文 / emoji 会不会抛 `UnicodeEncodeError`?

**D. 安全与隐私**
9. zip-slip / 炸弹 / 符号链接逃逸 / 输出目录越界是否都有拦截与测试?外部进程是否 `shell=False`、有超时、能杀进程树?下载是否 HTTPS + 白名单 + SHA256?
10. 购买者信息、UDID、邮箱、用户名路径是否在 JSON / MD / 日志 / 异常信息中泄漏?

**E. 测试质量**
11. 跑 `python -m pytest -q`(本 Wave 范围),报告通过 / 失败 / 跳过数。测试是否真的断言了行为(而不是只调用)?是否存在依赖网络 / 本机 dotnet / 特定 OS 的非门控测试?
12. 抽样做 3 个**变异检查**:临时改动关键逻辑(如把 `cryptid != 0` 改成 `== 1`、反转熵阈值、去掉 zip-slip 检查),看测试是否会红。改动前先把被改文件备份到 scratchpad,检查后**从备份还原**并 `diff` 确认无残留。

**F. 可用性**
13. 错误信息是否可操作?报告里跳过 / 失败原因是否清晰?中文文案是否通顺、i18n 键是否齐全?

## 输出格式
按严重度分级:**Blocker**(必须修才能进下一 Wave)/ **Major** / **Minor** / **Nit**。每条:`[级别][WP][file:line] 问题 → 影响 → 建议修法`。末尾给出:
- 放行建议(Go / No-Go)与理由;
- 本 Wave 的 UNVERIFIED 汇总(去重);
- 你没有能力验证的项(如 Windows 实机)。
不要夸奖,不要复述实现。

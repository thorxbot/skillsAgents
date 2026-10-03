# WP8 — 报告生成:Markdown / JSON / HTML、i18n、脱敏、Schema 校验(Wave 1)

先读 `prompts/_common.md`、`docs/CONTRACT-FREEZE.md`、`docs/01-REQUIREMENTS.md` F-RPT。

## 目标
把 `ctx.results` + `findings` 渲染成 **人能快速读完、机器能稳定消费** 的报告。你不实现任何分析逻辑,但必须能在**任何阶段缺失 / 失败 / 跳过**时仍产出完整、诚实的报告。

## 文件归属
`src/ipa_analyzer/report/{__init__,render_md.py,render_json.py,render_html.py,redact.py,i18n.py,schema.py,summary.py}`、`src/ipa_analyzer/analyzers/report_stage.py`、
`data/i18n/{zh,en}/report.json`(章节标题、通用词、判定词 yes/no/suspected/unknown/n/a、置信度分级)、
`tests/unit/report/*`、`tests/fixtures/sample_report.py`(手写的完整 `Report` 夹具,含各种状态,供全员测试渲染)。

## 要做的事
1. **i18n 加载器**:合并 `data/i18n/<lang>/*.json`(各 WP 各一个文件;键冲突报错并列出两方);Finding 渲染:`i18n[finding.id].title/summary` 用 `params` 插值,缺失则回退 Finding 自带英文兜底文案;语言缺失键回退 `en`。
2. **JSON**:`render_json`:按契约序列化,键序稳定、列表排序稳定;`schema.validate(report_dict)`:优先用已安装的 `jsonschema`,否则用你自写的**最小校验器**(支持 `type/required/properties/items/enum/additionalProperties/oneOf 的简单形态`)——校验失败写 warning,不阻断输出。大表(完整文件清单、dump 命名空间全量)写独立文件并在 JSON 里给相对路径。
3. **脱敏 `redact.py`**:对最终输出做兜底扫描(邮箱、疑似 Apple ID 字段名、UDID 40 位 hex / 新格式 `XXXXXXXX-XXXXXXXXXXXXXXXX`、home 目录路径中的用户名);`Config.redact=False` 时跳过;记录 `redaction.applied` 与被脱敏字段名统计。
4. **Markdown(默认 zh)**,章节固定顺序:
   0. 标题 + 元数据条(工具版本 / 时间 / 输入 sha256 / 耗时)
   1. **执行摘要**(≤15 行表格或要点:项目名 / BundleID / 版本 / 类型 / 引擎 / 语言 / FairPlay / 签名类型 / 关键保护 / Unity 专项一句话 / 能否 dump / 主要风险 / 被跳过的阶段)
   2. 基本信息 3. 项目类型(证据表) 4. 项目结构(目录树代码块 + 嵌套单元表 + 每个 Mach-O 一行表) 5. 资源结构(类别表带占比条、扩展名 Top、大文件 Top、打包归档) 6. Lib 用途(分类分组表:名称 | 类型 | 厂商 | 类别 | 用途 | 置信度 | 证据摘要;`unknown` 单独成节) 7. 加密与保护(逐项 verdict 徽标 + 证据 + 建议) 8. 引擎专项:**8.1 引擎识别与画像**(主引擎 / 候选 / 宿主与嵌入;**`engine.fingerprint` 画像表:渲染 / 脚本 VM / 物理 / 音频 / 资源格式 / 容器 / 宿主形态**;`engine.custom` 判定与"下一步分析建议",自研引擎时此节置前并加醒目标注)**8.2 Unity**(版本 / 后端 / metadata 判定 / AssetBundle 表 / dump 摘要)**及 8.2.1 热更新**(框架表;脚本存放位置与格式统计表;**Lua 版本画像表**:字节码版本分布 / 位宽 / 是否剥离 / 运行时版本 / 一致性告警;C# 热更 DLL 表:程序集名、CLR、引用、格式;JS 后端;资源热更:框架 + CDN 域名;`script_protection` 三态;**阶段缺失时显示原因**)**8.3 其他引擎**(Cocos 变体与脚本 / 资源保护表、Egret / Laya、Unreal / Godot / Flutter / RN 等,逐引擎一小节) 9. 隐私与权限 10. 附录:阶段状态表(含跳过原因与补救建议)、工具与版本、限制说明、UNVERIFIED/启发式声明。
   - verdict 用文本徽标(如 `✅ 否 / ❌ 是 / ⚠️ 疑似 / ❔ 未知 / —`),Windows 控制台也能读(写文件为 UTF-8,不依赖终端渲染)。
   - **阶段缺失 / 失败 / 跳过时,对应章节显示"未执行:<原因>(<建议>)"**,绝不静默省略。
   - 表格单元格内转义 `|` 与换行;超长证据截断并指向 JSON。
5. **HTML(P1)**:单文件、无外链资源、内嵌 CSS、深色 / 浅色自适应、可折叠章节、表格可点击排序(原生 JS,<150 行)。若时间紧张可只做 Markdown→HTML 的简单转换,但需在回报中说明。
6. **`report` 阶段**:无论其他阶段成败都运行;写 `report.json` / `report.md` / (`report.html`)/ `inventory.json` 到输出目录 `out/<name>-<sha12>/`;控制台打印执行摘要(UTF-8,Windows 安全);退出码决策依据(有 failed 阶段 ⇒ 3)交回 CLI(通过返回值,不自己 `sys.exit`)。
7. **报告稳定性**:除 `generated_at` 与耗时外,同输入同版本输出字节级一致(黄金文件测试时忽略这两项)。

## 验收标准
- ✅ 用 `sample_report.py` 的 3 个夹具(全成功 / 大量跳过失败 / 仅 ingest 成功)渲染 zh 与 en,断言:章节齐全、跳过原因可见、无 `None`/`{}` 之类泄漏文本、表格列数一致。
- ✅ 黄金文件测试:`report.json` 稳定;故意打乱输入 dict/list 顺序结果不变。
- ✅ 脱敏:夹具含邮箱 / UDID / `/Users/xxx/` 路径 → 输出不含;关闭脱敏才含。
- ✅ i18n:缺 zh 键回退英文兜底并产生 warning;键冲突检测有单测。
- ✅ Schema:合法夹具通过;破坏必填字段被检出。
- ✅ Markdown 中的竖线 / 换行 / 反引号转义单测。
- ✅ 单测通过。

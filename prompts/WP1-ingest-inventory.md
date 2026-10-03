# WP1 — 输入摄取、安全提取、文件清单与资源结构(Wave 1)

先读 `prompts/_common.md`、`docs/CONTRACT-FREEZE.md`。

## 目标
把 IPA / `.app` / 目录统一成 `ArchiveSource`;产出完整的 **文件清单(inventory)**,并据此生成"项目结构"与"资源结构"数据;提供安全的选择性提取能力(即"拆分")。

## 文件归属
`src/ipa_analyzer/ingest/{source.py,safe_extract.py,layout.py}`(可重写 WP0 的最小 `ZipSource`,接口不变)、
`src/ipa_analyzer/analyzers/{ingest_stage.py,inventory.py}`(替换桩)、
`src/ipa_analyzer/util/{magic.py,filetypes.py}`、`data/filetypes.json`、
`data/i18n/{zh,en}/inventory.json`、`tests/unit/ingest/*`、`tests/fixtures/ipa_builder.py`(只含 zip/IPA 构造工具,供全员使用,函数签名要稳定:`build_ipa(path, files: dict[str, bytes|str], *, app_name="Test", symlinks=None, zip64=False)`)。

## 要做的事
1. **输入归一**:`open_source(path) -> ArchiveSource`:`.ipa/.zip`(魔数判断而不是只看扩展名)、`.app` 目录、含 `Payload/` 的目录、已解压目录。`layout.find_app_root(source)`:定位 `Payload/<X>.app/`(唯一则取之;多个时选含 `Info.plist` 且体积最大者并给 warning;找不到 → 清晰错误)。
2. **ZipSource**:只读中央目录;zip64;非 UTF-8 文件名(检查 flag bit 11,失败回退 cp437 并在 warnings 记录);目录项、符号链接(`external_attr` 高 16 位 `S_IFLNK`)、损坏 / 截断 zip 的明确异常(`errors.InvalidInput`);`read_head(name, n)` 高效;`open()` 返回可 seek 的流(必要时落盘到 workdir 缓存,大小阈值可配)。
3. **safe_extract**:拒绝 `..` / 绝对路径 / 盘符 / UNC;限额(总量 / 单文件 / 文件数 / 压缩比,默认见架构 §6,可由 `Config` 覆盖);Windows 保留名与非法字符消毒 + 映射表落 `manifest`;大小写冲突检测并加后缀;符号链接仅记录(POSIX 可选创建且目标必须仍在根内;Windows 不创建);写入先写临时文件再原子重命名;提取结果返回 `Path`,并保证 `is_within(workdir, p)`。**同时提供 `ctx.extract(paths)` 的实现钩子**(WP0 在 context 中留了回调位)。
4. **ingest 阶段**:产出 `ctx.results["ingest"]`:`{kind, path, size, sha256, app_root, app_name_dir, entries, warnings}`;sha256 流式计算;`workdir` 以 sha256 前 12 位命名,支持缓存复用(同一 IPA 重跑不重复提取)。
5. **magic 嗅探 `util/magic.py`**:仅读文件头 ≤64 字节识别:Mach-O/fat、zip、gzip、PNG/JPEG/GIF/WebP/HEIC、MP4/MOV/M4A、MP3/OGG/FLAC/WAV/CAF、ttf/otf/woff、SQLite、plist(bplist00 / `<?xml` / `<plist`)、`UnityFS/UnityWeb/UnityRaw/UnityArchive`、`GDPC`、Lua 字节码(`\x1bLua` / LuaJIT `\x1bLJ`)、PE(`MZ`)、ELF、Car(`BOMStore`)、Hermes(magic 须核对)、UE pak(尾部 footer,需 seek;留接口)、`.metal`/文本启发。返回 `(type, confidence)`。每个 magic 注释来源。
6. **分类 `util/filetypes.py` + `data/filetypes.json`**:把每个文件归入类别(与 `01-REQUIREMENTS` F-RES 一致):`executable, framework, plugin, dylib, assets_car, ui_layout(nib/storyboardc), localization(lproj), plist, image, audio, video, font, database, script, shader, model_3d, engine_data, assetbundle, packed_archive, signing, config, text, other`。规则按 "路径模式 → 扩展名 → magic" 优先级;**以 magic 为准纠正扩展名**(如 `.dat` 实为 UnityFS)。
7. **inventory 阶段**:产出 `ctx.results["inventory"]`:
   - `files[]`:`{path, size, csize, ext, magic, category, entropy?}`(≥4KB 的文件抽样熵;超大量文件时对熵计算设上限并记录"已抽样"),按路径排序;
   - `by_category[]`(数量 / 体积 / 占比)、`by_ext[]`、`top_files[N=30]`、`localizations[]`、`archives[]`(pak/obb/zip/pck/…)、`nested_units[]`(`*.framework`、`*.appex`、`*.app`(Watch)、`*.bundle`、`*.dylib` 及其路径 / 体积)、`tree`(默认深度 3,每节点含 size/count,超深目录汇总到祖先);
   - `structure_hints`:顶层目录清单、是否有 `Frameworks/ PlugIns/ Watch/ SC_Info/ _CodeSignature/ Data/ Assets.car embedded.mobileprovision iTunesMetadata.plist`。
   - 同时写 `out/<name>/inventory.json`(完整文件表),`ctx.results["inventory"]` 里只放摘要 + 文件表的前 N(JSON 报告体积控制,完整表单独成文件)。
8. **拆分(split)**:`--extract binary,frameworks,metadata,bundles,plists,all` 物理提取到 `out/<name>/split/<category>/`,保持相对路径;默认**不提取**(除后续阶段按需)。提供 `list_categories()` 供 CLI 校验。
9. i18n:`inventory.json`(zh/en)含类别显示名与 finding 文案。

## 验收标准
- ✅ 夹具:正常 IPA / 含 zip-slip 条目 / 含 Windows 保留名(`CON.txt`、`aux`) / 大小写冲突 / 符号链接 / 非 UTF-8 文件名 / 截断 zip / 空 zip / 无 `Payload` / 多 `.app` / zip64 标志(可用构造小文件 + 强制 zip64)。每项行为符合预期且不崩溃。
- ✅ 压缩炸弹夹具(高压缩比的零填充文件)触发限额并给出明确错误。
- ✅ 1 万文件 IPA 夹具 inventory < 5 s;只读头部嗅探(用计数器断言没有读全文件)。
- ✅ `DirSource` 与 `ZipSource` 对同一内容产出**相同**的 `inventory`(单测对比)。
- ✅ 扩展名与 magic 冲突时以 magic 为准。
- ✅ 路径安全函数有 `PureWindowsPath` 参数化测试(在 macOS 上也能跑)。
- ✅ 单测通过。

## 备注
- 不要解析 plist / Mach-O 内容(WP2 / WP3 负责),这里只嗅探 magic 和分类。
- 熵阈值只记录数值,**不在此下加密结论**(由引擎分析器判断)。

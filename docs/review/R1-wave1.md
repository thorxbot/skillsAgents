# R1 评审:Wave 1(WP1 / WP2 / WP3 / WP3b / WP6 / WP8)

评审基线:`8f189f1`(main,评审开始时工作树干净,评审结束后 `git status` 仍干净)。依据:`_common.md`、`R-review.md`、`01/02`、`CONTRACT-FREEZE.md`(含 §13)、`05-REAL-SAMPLES-AND-HTP.md`。
评审方式:通读 ingest / util(magic, filetypes, paths, procs) / analyzers(ingest, inventory, meta, macho, report) / meta / macho / formats / il2cpp / report 源码;全量跑测试;4 个真实 IPA 只读端到端;14 个变异检查;针对性探测(手工构造 zip、正则、脱敏)。

## 0. 总览

| 项 | 结果 |
|---|---|
| 全量测试 | `python -m pytest -q`(Python 3.14.3,macOS arm64):**1319 passed, 9 skipped, 0 failed**(31 s)。9 个跳过全部是有门控的:network×2、slow×5、`IPA_SAMPLES_DIR`×1、缺 `jsonschema`×1。 |
| 其他解释器 | 3.12.10 / 3.10.13 上 `-W error` 导入全部子包无警告,3.10 上端到端跑通合成 IPA;全部源码与测试通过 `ast.parse(feature_version=(3,9))`。无 3.9 解释器,**3.9 运行时行为未实测**。 |
| 变异检查 | 14 个,13 个被测试杀死,1 个存活(M12,见 E-1)。所有被改文件均先备份到 scratchpad,检查后从备份还原并 `diff`/`filecmp` 确认逐字节一致。 |
| 真实样本(4 个,FairPlay 加密) | ingest 0.28–0.54 s,inventory 0.23–0.67 s,峰值 RSS ≤ 57 MB;macho 的 cryptid / cryptsize / team id / cdhash 经 `otool -l` 与 `codesign -dvvv` 对 SeaWorld 主程序**逐项吻合**;4 个样本的购买者字段(apple-id / userName 的值)在 report.json / report.md 中**均未泄漏**。 |
| Blocker | **0** |
| Major | **3**(1 条 WP8 脱敏误伤、1 条 WP8 路径误伤、1 条 WP2 ReDoS) |

**放行建议:Go(有条件)**。无 Blocker;Wave 2 的数据契约(`ctx.results`)没有受 Major 影响,Wave 2 可以并行开工。3 条 Major 必须在 Wave 3(WP9)前修完,建议与 Wave 2 并行做一轮小修复。理由见 §6。

---

## 1. Major

**[Major][WP8][src/ipa_analyzer/report/redact.py:32] 40 位十六进制被一律当作"旧式 UDID"脱敏,真实分析数据被抹掉**
→ 影响:`macho.binaries[].slices[].signature.cdhash / cdhashes.sha1 / cdhashes.sha256`(代码目录哈希,取前 20 字节 = 40 hex)全部变成 `[REDACTED-UDID]`。真实样本上命中数:JiangNan 15、ISBN 48、SeaWorld 6、GoodCoffee 57,**全部是 cdhash,没有一个是 UDID**。同时 `redaction.fields` 里出现虚假的 `udid`,误导读者以为包里有设备标识。任何以 SHA-1(git 提交号、文件哈希)形式出现的字段都会被误伤。我对 SeaWorld 主程序用 `codesign -dvvv` 核对过,被抹掉的值正是正确的 CDHash。
→ 建议:不要对任意字符串做 40-hex 扫描。只在键名/上下文显示为设备标识时脱敏(`ProvisionedDevices`、`udid`、`device` 等键,或紧跟 `UDID` 字样);cdhash/sha1/sha256/hash 类键加白名单;新式 `XXXXXXXX-XXXXXXXXXXXXXXXX` 模式较特异,可保留。补测试:cdhash、SHA-1 字符串不得被改。(`meta` 阶段本身已经只输出设备哈希前缀,不会产出明文 UDID,所以兜底扫描收窄后风险不增。)

**[Major][WP8][src/ipa_analyzer/report/redact.py:34] `(/Users|/home)/<name>` 规则会改写 App 包内的正常路径与 URL**
→ 影响:我实测 `Payload/X.app/res/home/btn.png` → `Payload/X.app/res/home/[user]`;`assets/home/index.json`、`https://example.com/home/page` 同样被改。游戏 UI 资源里 `home/` 目录极常见,`top_files`、`archives`、`engine_details.*.samples`、`paths_sample` 等字段里的路径会被改成不存在的路径,下游(人或 Agent)按路径去找文件会失败。同一正则对带空格的 Windows 用户名只替换第一个词(`C:\Users\John Smith\x` → `C:\Users\[user] Smith\x`,姓氏泄漏),对 UNC 路径 `\\server\share\Users\bob` 不处理。
→ 建议:只在"路径以 `/Users/`、`/home/` 开头且前一个字符不是路径字符"时替换(不对 `a/b/home/c` 生效),或只对 `input.path` 与 warnings/日志类字段做家目录脱敏、不碰资源路径字段;Windows 用户名按"到下一个分隔符为止"(允许空格),并补 `\\?\` 与 UNC 形式、`%USERPROFILE%` 不需要处理。补参数化测试(含 `res/home/…`)。

**[Major][WP2][src/ipa_analyzer/meta/coderesources.py:50-94] 不可信 IPA 里的正则被直接 `re.compile` 并在文件名上执行,存在灾难性回溯(ReDoS)**
→ 影响:`CodeResources` 的 `rules2` 键来自 IPA 本身。我实测规则 `^(a+)+$` 对 `"a"*N+"!"` 的耗时:N=22→0.09 s、24→0.36 s、26→1.43 s(每 +2 字符 ×4)。攻击者在 IPA 里放这条规则 + 一个 40 字符的文件名即可让 `meta` 阶段无限期挂起(pipeline 没有阶段级超时,`signature_integrity` 的 60 s 预算只检查哈希循环,管不到单次 `search`)。这违反"输入不可信、永不卡死"的硬要求。
→ 建议:(1) 对 `rule_expects` 的输入截断到 ≤256 字符;(2) 拒绝长度 >200 或含嵌套量词(`(...+)+`、`(...*)*`、`(...|...)*` 等)的规则并计入 `unsupported` 而不是执行;(3) 更稳妥的做法是在独立线程/子进程里带超时执行,超时则放弃"extra files"判定(该判定本来就只是辅助)。补一个带 `^(a+)+$` 的对抗测试,断言在 1 s 内返回。

---

## 2. Minor

**WP1**

- **[Minor][WP1][src/ipa_analyzer/ingest/source.py:435] 构造的 zip64 局部头偏移(≥2^63)会抛 `ValueError`,不是 `InvalidInput`**
  → 影响:我构造了 CD 里 zip64 extra 的 offset=2^63+5 的 zip,`ZipSource` 构造成功,`read_head()` 抛 `ValueError: cannot fit 'int' into an offset-sized integer`。`inventory`(只捕获 `InvalidInput, OSError`,`analyzers/inventory.py:118`)和 `SafeExtractor.extract_many`(同样不捕获)因此整个阶段 `failed`,而不是把该文件记为 `unreadable`。阶段隔离生效、不会崩溃/OOM/死循环,但一个畸形条目就能让 inventory 失败(`macho` 随之 skipped,报告大半为空)。
  → 建议:在 `_parse_cd` 里校验 `hoff + concat` 与 `csize/usize` 不超过 `fsize`(或 `2**62`),越界条目打标记并在访问时抛 `InvalidInput`;同时在 inventory/extract 的 except 里加 `ValueError, OverflowError`。

- **[Minor][WP1][src/ipa_analyzer/ingest/source.py:322-327] 先读完整个中央目录再检查条目数上限**
  → 影响:`cd_size` 最多 512 MiB 会整块读入内存后才在第 200001 条处抛 `LimitExceeded`;与"峰值内存 ≤500 MB"目标冲突(仅限恶意输入)。
  → 建议:在读 CD 前用 EOCD 的 `n_total` 与 `max_entries` 比较,并用 `cd_size / 46` 做上界交叉检查;或把 `_MAX_CD_BYTES` 降到 64 MiB。

- **[Minor][WP1][src/ipa_analyzer/util/magic.py:60] `true`(Apple TrueType 标签)只凭 4 个字节就以 0.9 置信度判成 ttf**
  → 影响:任何以 `true` 开头的文本/JSON(如布尔配置)在 `classify()` 里被"以 magic 为准"纠成 `font`(实测 `res/data.json` 内容 `true\n` → font)。同类的还有 `ID3`(0.85→audio)、`icns`、`DDS `、`FSB5`、`MThd` 开头的文本,风险较低。
  → 建议:`true` 需要同时校验 numTables(offset 4 的 u16 在 4..64)且后续不是可打印文本;对 3~4 字节纯 ASCII 魔数把置信度压到 <0.6(弱信号不覆盖扩展名)或要求第二个字段验证。

- **[Minor][WP1][src/ipa_analyzer/util/magic.py:236] UTF-16LE 文本(BOM `FF FE`)被 `_mpeg_audio` 判成 `mp3`(0.5)**
  → 影响:真实数据上已出现:SeaWorld 的 2 个 `.strings` 文件 `magic=mp3`。置信度 0.5 < 0.6 所以类别仍按路径规则正确归为 localization,但 `files[].magic` 是错的,依赖 magic 的下游(统计"音频文件"、WP7 容器分析)会被污染。
  → 建议:在 `sniff` 里把 BOM 检查(`FF FE`、`FE FF`、`EF BB BF`)放到 `_mpeg_audio` 之前,或 `_mpeg_audio` 要求连续两个帧头。

- **[Minor][WP1][data/filetypes.json + src/ipa_analyzer/util/filetypes.py:~95] magic 为 unknown 时按扩展名定类,会把"扩展名与内容不符"的自定义封装计入标准类别**
  → 影响:SeaWorld 约 5,400 个 `NHPK/NHPT/NHPO` 头的文件里,4,654 个 `.json` 被计为 config、768 个 `.astc` + 26 个 `.png` 被计为 image(image 占体积 70%)、392 个 `.js` 计为 script,而 `magic` 都是 `unknown`。`05-REAL-SAMPLES` 已指出这是 `engine.custom` 的关键线索,但 inventory 里没有任何字段标出"ext 暗示格式 X 而内容不是 X"。报告第 5 章的占比因此偏乐观地"像是标准资源"。ISBN 上 `.ccz`(`CCZp`)按 magic 正确归 image,不受影响。
  → 建议:在 `files[]`(或 `extra.ext_magic_mismatch`)里为"已知结构化扩展名(png/jpg/json/js/astc/ogg/mp3/…)但 magic=unknown 且头部不是文本"的文件加标记并汇总计数,供 WP7 与 WP8 使用;类别可保持按扩展名,但报告要显示"N 个文件头部与扩展名不符"。

- **[Minor][WP1][src/ipa_analyzer/ingest/safe_extract.py:303] 提取用 `tempfile.mkstemp`/`is_file()` 等调用不带 `to_long_path`**
  → 影响:Windows 默认(未启用长路径)下,工作目录 + 深层游戏资源路径超过 260 字符时 `mkstemp` 抛 `FileNotFoundError`,被记为"I/O error"跳过;`ctx.extract` 返回的 `Path` 在下游 `open()` 也会失败。**无法在本机验证**。
  → 建议:提取根目录尽量短(例如 `work/x` → `w`),并对 Windows 在 `mkstemp` 之前用 `to_long_path` 预检长度、给出可操作的 warning。

**WP2**

- **[Minor][WP2][src/ipa_analyzer/meta/provision.py:191] 仅凭"存在 iTunesMetadata.plist / SC_Info + 存在 `_CodeSignature/CodeResources`"就给 `appstore` verdict=YES、置信度 0.9**
  → 影响:这些文件在被解密重打包、侧载重签的 IPA 里同样保留(`CodeResources` 存在只表示签过名,不表示 Apple 签名)。当前 4 个样本结论正确,但对改过的包会"确认"错误结论,违背"证据不足用 suspected"。
  → 建议:没有 `embedded.mobileprovision` 时上限 `0.8` 并保持 YES 仅当 macho 阶段给出的 `team_id` 存在且签名为证书链签名(`signature_kind=cms`);`meta` 对 `macho` 是可选上游(`after`)即可读。至少在 summary 写明"无法区分被解密后重打包的商店包"。

- **[Minor][WP2][src/ipa_analyzer/meta/permissions.py:17,72] 数据库里没有的权限键默认判为 `medium`**
  → 影响:无法判断敏感度的键被呈现为"中敏感"而不是未知;摘要里 `high_count` 因此可能漏计新键(例如 iOS 17+/18 新增键)。字段 `known=false` 存在,但渲染层未必使用。
  → 建议:未知键 `level="unknown"`(契约允许新增值需同步 schema/i18n),或渲染时对 `known=false` 加"未收录"徽标。

- **[Minor][WP2][src/ipa_analyzer/meta/coderesources.py:71-79] 规则平局"倾向于覆盖"+ 大小写敏感,均为 UNVERIFIED**
  → 影响:`extra` 计数在平局时可能偏多/偏少;已在代码中标 UNVERIFIED,但报告里的 `meta.signature_integrity` 没有声明该启发式。
  → 建议:`SUSPECTED`("Files outside the seal")的 summary 附一句"规则解释为启发式"。

**WP3b**

- **[Minor][WP3b][src/ipa_analyzer/formats/lua_bytecode.py:92] LuaJIT 2.1 的 `BCDUMP_F_DETERMINISTIC (0x80000000)` 未列入已知 flag,会被报为 tamper**
  → 影响:我对 LuaJIT v2.1 分支 `lj_bcdump.h` 做了核对:`BITOP=0x10` 确实存在(代码正确),但另有 `BCDUMP_F_DETERMINISTIC 0x80000000`(`-d` 确定性输出)。使用该选项编译的合法字节码会得到 `luajit_unknown_flag_bits:0x80000000`,`valid=False`,进而被聚合成"篡改"。`_uleb128` 最多读 5 字节所以能读出该值。
  → 建议:把 `0x80000000` 加入 dump_version=2 的已知集合;并在注释中标明"2.1 分支 HEAD 核对于 <日期>"。

- **[Minor][WP3b][src/ipa_analyzer/formats/unityfs.py:479] `iter_decompressed` 先 `read(block.compressed_size)` 再解压,压缩块大小只受文件大小约束**
  → 影响:声明 `uncompressed_size ≤ max_block` 但 `compressed_size` 为文件大小(例如 1.5 GB)的块会先把 1.5 GB 读入内存才报 `block_decompress_failed`(`read_blocks_info` 已保证不越过文件末尾,所以不是越界,只是 OOM 面)。
  → 建议:`compressed_size > max_block + max_block // 255 + 64`(LZ4 最坏膨胀)或 `> max_block * 2` 时直接抛 `limit_exceeded`。

**WP6**

- **[Minor][WP6][src/ipa_analyzer/il2cpp/dotnet.py:221-224 + backends.py:101-123] 工具本体(Il2CppDumper / Cpp2IL / Redux)的下载在 `provision()` 里自动发生,没有任何用户确认;只有 `--offline` 能阻止**
  → 影响:与 `01-REQUIREMENTS §6`("自动下载 + 固定版本校验,.NET 安装需一次授权")一致,所以不是违规;但一次普通的 `analyze` 在遇到未加密 Unity 包时会静默联网下载并执行第三方可执行文件。下载有 HTTPS + 主机白名单 + 逐跳重定向复核 + 固定 SHA256 + 大小上限,安全性本身可以接受。
  → 建议:首次下载时在 stdout/报告 `warnings` 里写明"已下载 <tool> <version> 到 <dir>(sha256 …)",并在 SKILL.md 中说明。

- **[Minor][WP6][src/ipa_analyzer/il2cpp/dotnet.py:221-224] `.NET` 安装脚本以 `sha256=None, allow_unpinned=True` 下载后用 `bash`/`powershell -ExecutionPolicy Bypass` 执行**
  → 影响:授权门槛有效(见 §5 专查 a),但脚本本身只有 TLS 保护;脚本随后自己下载运行时,这部分不受本项目的主机白名单/SHA 校验约束(无法在代码层面强制)。`ExecutionPolicy Bypass` 仅作用于该次调用,不改系统策略,可接受。
  → 建议:同意提示里明确写出"将下载并运行 https://dot.net/v1/dotnet-install.* ,脚本不做固定哈希";可选地在 catalog 中记录脚本最近一次观测到的 SHA256 并在不符时给出 warning(不阻断)。

- **[Minor][WP6][src/ipa_analyzer/il2cpp/tools.py:520 + dotnet.py:108] `shutil.which()` 在 Windows 上会先搜索当前目录**
  → 影响:用户在含有恶意 `dotnet.exe` / `Il2CppDumper.exe` 的目录(如刚下载并解压的文件夹)里运行本工具,会执行该文件。POSIX 无此问题。**Windows 行为无法在本机验证**(CPython 3.12 之前对 `which` 的行为即如此)。
  → 建议:Windows 上解析出的路径若位于 CWD 下则丢弃(或显式把 `path` 里的 CWD 剔除并检查返回值)。

- **[Minor][WP6][src/ipa_analyzer/il2cpp/backends.py:236-248 + data/il2cpp_backends.json `applied_note`] `Il2CppRunRequest.force_dump` 从未写入 `config.json` 的 `ForceDump`**
  → 影响:目录里说"ForceDump 仅在请求要求时设置",代码里只在 `runner.py:493` 用它跳过 metadata magic 检查;用户传 `--force-dump` 时 dumper 实际仍按 `ForceDump=false` 运行,且 magic 错误的 metadata 会被送进 dumper。
  → 建议:`_write_config` 里 `cfg["ForceDump"] = bool(req.force_dump)`,并更正 `applied_note`;或者保留现状但把说明改成"仅跳过 magic 预检"。

- **[Minor][WP6][src/ipa_analyzer/util/procs.py:23-35] `minimal_env` 会透传用户环境里所有 `DOTNET_*` 变量**
  → 影响:例如用户 shell 里设了 `DOTNET_STARTUP_HOOKS`,会被带进 dumper。IPA 无法设置环境变量,所以不是外部攻击面;仅是"环境白名单"名不副实。
  → 建议:`DOTNET_*` 只透传已知安全子集(`DOTNET_ROOT`、`DOTNET_ROLL_FORWARD`、`DOTNET_CLI_*`、`DOTNET_NOLOGO`、`DOTNET_SKIP_FIRST_TIME_EXPERIENCE`)。

**WP8**

- **[Minor][WP8][src/ipa_analyzer/report/redact.py:31] 邮箱正则会把 `btn@ipad.png` 这类资源名当成邮箱**
  → 影响:`<name>@<word>.<ext>` 形式(`@2x/@3x` 已排除)的资源文件名被改成 `[REDACTED-EMAIL]`。
  → 建议:域名最后一段限制为已知 TLD 长度/排除常见资源扩展名(png/jpg/jpeg/gif/webp/pdf/…)。

- **[Minor][WP8][src/ipa_analyzer/report/redact.py 全局] 兜底脱敏不覆盖 `inventory.json` 与 il2cpp 的 `run.log`(后者有自己的 `redact_text`)**
  → 影响:`inventory.json` 只含 App 内路径,风险低;但若用户用 `--extract` 并把产物目录分享,`split/*.manifest.json`(含 archive 名)同理未处理。
  → 建议:文档说明或对这些旁路文件复用 `redact_report(extras=...)`。

**测试 / 可用性**

- **[Minor][测试][tests/unit/test_pipeline_smoke.py:135-148] `test_doctor_offline`、`test_tools_stub_subcommands` 会读写真实用户缓存目录并依赖主机 dotnet**
  → 影响:整套 `tests/unit` 运行会改写 `~/Library/Caches/ipa-analyzer` 的 mtime(`doctor` 的可写性探测);`tools install il2cppdumper --offline` 断言 `in (0, 1, 4)`,在已缓存工具的机器上返回 0、未缓存返回 4,等于没有断言。
  → 建议:这些测试 `monkeypatch.setenv("IPA_ANALYZER_HOME", tmp_path)`,并分别断言缓存存在 / 不存在两种场景。

- **[Minor][测试][tests/unit/ingest/test_zip_source.py] 中央目录越界(`cd_off + concat + cd_size > fsize`)检查没有被任何测试覆盖**
  → 变异 M12(删除 `source.py:320` 的判断)后 226 个测试全绿。
  → 建议:加一个"CD 偏移指向文件外/EOCD 的 `cd_size` 虚大"的截断夹具。

- **[Minor][B-4][全局] 多个 Finding 的置信度是常数**(`meta.identity` 0.95、`meta.permissions` 0.95、`macho.summary` 0.95/0.7、`meta.fairplay_container` 0.85 / 0.6 / 0.4 等)
  → 影响:置信度不随证据数量变化,与"独立证据越多置信度越高"的设计不符;不影响正确性。
  → 建议:放入 Wave 3 打磨(把证据条数/一致性纳入),不阻塞。

---

## 3. Nit

- **[Nit][WP1][ingest/source.py:317-319]** zip64 记录之间若存在 "zip64 extensible data sector",`concat` 推算为负会误报"central directory lies outside the file"。用 `off64 - cd_size - cd_off` 更稳。
- **[Nit][WP1][ingest/source.py:367-381]** CD 里 `usize == 0xFFFFFFFF` 而没有 zip64 extra 时不报错,按 4 GiB-1 记录。
- **[Nit][WP3][macho/parser.py:445]** `is_pie` 对 dylib/bundle 恒 True(注释已说明);报告里单列 `is_pie` 的读者可能误解。
- **[Nit][WP3b][formats/magic_scan.py:84-90]** `script_path` 正则在长段 `[A-Za-z0-9_/.\-]` 上最坏 O(n×200);`max_seconds` 只在 chunk 之间检查。
- **[Nit][WP8][report/render_html.py:25-29]** 用 PUA 字符(U+E000 / U+E100 起)做占位,若 IPA 内文本本身含这些码位会被错误还原。
- **[Nit][WP8][report 2.x 章节]** "构建 SDK" 行直接输出 `extra=platform_build=…` 的字典串,可读性差。
- **[Nit][WP6][il2cpp/summarize.py:~330]** `ns_counts` 字典不设上限,极端混淆的 dump 里命名空间数可达百万级;`examples` 里的混淆名可能含控制字符,进入 JSON/MD 前建议转义。

---

## 4. 检查清单逐项结论

**A 契约与架构**
1. 阶段名/依赖/Finding ID/`ctx.results` 形状:与 CONTRACT-FREEZE §2/§4/§5 一致(`test_stub_stage_table_matches_contract` 绿);`inventory.summary` 与 §13.3 新增字段(`total_size/entropy_info/read_errors/split`)已落实,i18n zh/en 键完全对齐(逐文件比对:无缺失、无跨文件冲突,所有 `Finding(...)` ID 与 8 个 `il2cpp.error/remediation.*` 键都有 zh 文案)。文件归属:Wave 1 的两次提交只改了 `report/render_md.py`、`report/summary.py`(WP8)、`il2cpp/{backends,runner}.py`(WP6)与 `tests/unit/test_pipeline_smoke.py`(总监授权的 WP0 修复),`models/context/pipeline/registry/cli/config/schemas` 均未被改动。
2. 失败隔离:真实样本与畸形输入下各阶段均隔离;唯一例外见 Minor"zip64 偏移 ValueError"(阶段 `failed`,但被隔离)。macho 依赖 inventory 为硬依赖,inventory 失败时 macho 正确 `skipped`。

**B 正确性**
3. 记忆性事实抽查(每个 WP ≥5 处):
   - WP3:`LC_ENCRYPTION_INFO(0x21)/_64(0x2C)` 字段顺序、`cryptid!=0 and cryptsize>0`、CodeDirectory 偏移(`teamOffset@48`、`execSegFlags@80`)、`CSMAGIC_*` 与 slot 值、`CS_HASHTYPE_*`、`MH_*`/`LC_*`/`PLATFORM_*`/`CPU_*` 常量均与 Apple/xnu 头文件一致(对照记忆与 SeaWorld 实测:`otool -l` cryptoff=147456、cryptsize=20447232、cryptid=1、minos 13.0、sdk 26.2、UUID 一致;`codesign` 的 TeamIdentifier、Identifier、CDHash=`199082ca…` 与 `sha1` CandidateCDHash 都与 `cdhashes` 完全相同)。
   - WP3b:LZ4 block 语法与边界、UnityFS 头/BlocksInfo 布局与 flag 位(与 AssetStudio/UnityPy 描述一致)、Lua 5.1–5.4 头布局与 `LUAC_DATA/INT/NUM`、LuaJIT `BCDUMP_VERSION`/flag(**经 WebFetch 读取 LuaJIT v2.1 `lj_bcdump.h` 核对**:`HEAD=1B 4C 4A`、`VERSION=2`、`BE/STRIP/FFI/FR2/BITOP=0x01/02/04/08/10` 正确,另有 `DETERMINISTIC=0x80000000` 漏列,见 Minor)、PE/CLI 表 schema(逐表核对 ECMA-335 II.22:Module…GenericParamConstraint 的列宽、coded index 标签位与目标表顺序全部正确)。
   - WP1 magic:PNG/JPEG/GIF/KTX/KTX2/PVR3/DDS/ASTC(0x5CA1AB13 LE)/CCZ(`CCZ!`/`CCZp`,与 cocos-engine 一致)/xz/7z/zstd/LZ4 frame/Lua/Hermes(0x1F1903C103BC1FC6 LE)/UE `uasset`(0xC1832A9E)/ASF GUID/il2cpp metadata(AF 1B B1 FA)均正确;上述中 PVR/ASTC/ASF/UE/Live2D/FMOD/Wwise 已在代码里标 UNVERIFIED。`true` 作为 ttf 的判定过弱(Minor)。
   - WP6:Il2CppDumper 命令行 `<exe> <metadata> <outdir>`、config 字段名、`Done!` 标记、metadata 版本区间 16–31、退出码恒 0 的描述与记忆一致;三个 Il2CppDumper 资产的**大小**与 GitHub release API 返回一致(406027 / 408192 / 11215992);该 release 的 API `digest` 为 null,所以 **SHA256 钉值无法独立复核**(WP6 称其为本地下载计算)。Cpp2IL/Redux 的 sha256 来自 API digest,我没有复核。
   - WP2:`iTunesMetadata.plist` 敏感键(`apple-id`、`userName`)在 4 个真实样本中都确实存在,与代码的键表吻合(原先标 UNVERIFIED 的 `userName` 现已被真实数据证实);`CodeResources` 的 `files2/hash2` 校验在 4 个样本上 0 缺失/0 篡改/0 额外,与未改动的商店包预期一致;`UIDeviceFamily` 6/7 仍 UNVERIFIED。
4. 三态:未发现"没把握却返回 `no`"的路径。`E_BINARY_FAIRPLAY` 只在确认 `cryptid!=0 and cryptsize>0` 时返回;`encrypted=None`(无法判定)时进入 dumper 而不是被判成"未加密"。`meta.signature_integrity=no` 的语义是"未发现与封印不符",summary 已写明"一致的封印不证明真实性"。需要注意的是 §2 的两条:`appstore=YES` 偏强、未知权限键默认 medium。
5. 边界:
   - Mach-O:`cmdsize<8/0`、越界、`ncmds` 巨大(`MAX_LOAD_COMMANDS=20000`)、`sizeofcmds` 超限、fat 偏移越界/Java class 伪装均有检查和测试;nlist 迭代按批读取、`MAX_SYMBOL_SCAN` 封顶。
   - LZ4/LZMA:输出上限、偏移合法性、字典上限均到位(M3 变异被杀死);见 Minor"unityfs 先读压缩块"。
   - zip:见 §5(b)。
   - 正则:`strings_file`、`lua_source`、`magic_scan` 无灾难性回溯;**唯一的 ReDoS 面是 `coderesources` 的 IPA 提供的正则(Major)**。

**C 跨平台**
6. `shell=True` / `os.system` / `os.popen`:源码中 0 处。`open(...)` 文本模式均显式 `encoding`;`Path.read_text/write_text` 均带 `encoding`。`os.killpg/signal.SIGKILL` 仅出现在 `util/procs.py` 的非 Windows 分支(Windows 走 `taskkill /T /F`)。硬编码 `/tmp` 0 处。zip 内路径用 `PurePosixPath`/字符串切分,`os.path.join` 只用于真实文件系统路径(`summarize.py`、`backends.py`)。依赖 `otool/plutil/codesign/lipo/unzip/file/strings` 的核心路径 0 处;**唯一的外部命令是 `tools.py:391` 的 `codesign -s -`(仅 Darwin、仅对刚下载校验过的原生可执行文件)**。语法层面全部通过 3.9 `feature_version` 解析;没有 `match`、`zip(strict=)`、`removeprefix`、运行时 `X | Y`;所有模块均 `from __future__ import annotations`。
7. Windows:保留名/非法字符/尾随点空格/大小写与 NFC 冲突/`\\?\` 前缀都在 `util/paths.py` 与 `safe_extract.py` 有纯函数 + `PureWindowsPath` 参数化测试(M10、M13 被杀死)。mmap 一律 `with` 或 `finally` 关闭(`macho.parse`、`scan._open_view`)。PowerShell 参数是列表形式,`-NoProfile -NonInteractive -ExecutionPolicy Bypass -File`。风险项:长路径(Minor)、`shutil.which` 搜索 CWD(Minor)——**均无法本机验证**。
8. 编码:`report_stage._print_console` 对 `UnicodeEncodeError` 回退为 `errors="replace"`;CLI 启动时已 `reconfigure(utf-8, replace)`;写文件一律 `encoding="utf-8", newline="\n"`。HTML/MD 内徽标为文本(✅❌⚠️ 等 emoji 只出现在文件里),终端输出走回退路径,不会抛异常。

**D 安全与隐私**
9. zip-slip(含反斜杠与盘符)、总量/单文件/文件数/压缩比、符号链接(默认只记录、POSIX 才可选创建且目标须在根内)、输出越界(`is_within` 双重检查 + 原子 rename)都有拦截与测试(M2、M13、M4 被杀死)。外部进程全部 `shell=False`、列表参数、环境白名单、超时 + 进程树清理(测试断言无残留)。下载:HTTPS + 6 个主机白名单 + 每一跳重定向复核 + 固定 SHA256 + 200 MB 上限 + 原子落盘(M5、M9、M14 被杀死);`safe_extract_zip` 对工具压缩包也做了路径/符号链接/炸弹检查。唯一未钉哈希的下载是 dotnet 安装脚本(Minor)。
10. 购买者信息/UDID/邮箱/用户名路径:4 个真实样本上,`apple-id`、`userName` 的**值**在 report.json / report.md 中均不存在(程序化比对,未打印值);`input.path` 被改写为 `/Users/[user]/…`;`provision` 只输出设备数量 + SHA-256 前 8 位。问题是脱敏**过度**(两条 Major),不是遗漏;遗漏面:带空格的 Windows 用户名、UNC 路径(Major #2 内)。

**E 测试质量**
11. 见 §0。测试都断言行为(字段值、异常种类、文件内容、无残留进程),`il2cpp` 全部用本地假 dumper / 本地 HTTP 服务器,无外网、无主机 dotnet 依赖(除上面 Minor 的 doctor 测试)。
12. 变异检查(全部先备份后还原,`filecmp` 确认一致;`git status` 空):

| # | 变异 | 结果 |
|---|---|---|
| M1 | `EncryptionInfo.encrypted` 去掉 `cryptsize>0` | 杀死(macho) |
| M2 | `safe_extract` 去掉 `..` 检查 | 杀死(ingest) |
| M3 | LZ4 去掉 `offset>len(out)` 检查 | 杀死(formats) |
| M4 | ZipSource 去掉"解压量超过声明大小"守卫 | 杀死(ingest) |
| M5 | 下载去掉 SHA256 比对 | 杀死(il2cpp) |
| M6 | runner FairPlay 判断取反 | 杀死(il2cpp) |
| M7 | provision 的 `get-task-allow` 分支互换 | 杀死(meta) |
| M8 | 脱敏去掉邮箱替换 | 杀死(report) |
| M9 | 下载主机白名单检查关闭 | 杀死(il2cpp) |
| M10 | Windows 保留名消毒关闭 | 杀死(全量) |
| M11 | `MAX_FAT_ARCHS` 放大到 100000(Java class 误判) | 杀死(macho) |
| M12 | ZipSource 中央目录越界/前置数据检查关闭 | **存活**(Minor,见上) |
| M13 | `unsafe_reason` 盘符检查关闭 | 杀死(ingest) |
| M14 | 重定向目标复核关闭 | 杀死(il2cpp) |

**F 可用性**
13. 错误信息可操作(每个 `E_*` 都有英文兜底 + zh/en 文案 + 补救步骤;`InvalidInput` 文案指出文件名与原因);跳过/失败原因在报告执行摘要与附录阶段表中可见("未成功阶段 8 个:engine.fingerprint (已跳过)…")。未发现 `None` / `{}` / `[]` 泄漏进 Markdown(对 SeaWorld 报告 grep 验证)。小问题:SDK 行的字典串(Nit)。

---

## 5. 专项问题回答

### a) WP6 下载 / 安装路径是否会在未授权时产生系统级副作用

结论:**没有发现系统级副作用;.NET 安装受授权门控;codesign 的影响范围仅限缓存目录里的那一个文件。**

- **.NET 安装脚本**(`dotnet.py: ensure_runtime / install_runtime`):只有 `allow_install=True`(`tools install dotnet` 这个显式子命令)或 `consent_cb` 返回 True 才会执行。`default_consent(assume_yes)`:`--yes`→是;否则仅当 stdin 与 stdout 都是 TTY 时才提示,**非 TTY 一律否**;`--offline` 与显式 `--dotnet PATH` 失败时都不安装。`backends.provision()` 对 `ensure_runtime` 传的是 `allow_install=False`,只经 `consent_cb=mgr.consent` 触发,所以不存在"无授权安装"路径(M-系列测试 `test_provision_dotnet_missing_without_consent_does_not_download` 覆盖)。安装目标是缓存目录下的 `dotnet/`,命令行 `--install-dir <cache> --no-path`(PowerShell 为 `-InstallDir … -NoPath`),不需要管理员权限,不改 PATH,不写注册表。残留风险仅是:脚本无哈希固定 + 其自身的下载不受本项目白名单约束(Minor)。`--yes` 是全局开关,意味着一次性授权覆盖 .NET 安装(符合 REQUIREMENTS 的"一次性授权")。
- **工具本体下载**:`provision()` 会自动 `mgr.install()`,**不需要确认**(设计如此,见 Minor)。FairPlay 预检发生在 provision 之前(`runner.py:507`),所以对加密包不会白下载。
- **Cpp2IL / Redux 的 ad-hoc codesign**(`tools.py:380-394, 674-678`):仅在 macOS、仅对 `kind in (native, dotnet_apphost)` 的资产、且在 SHA256 校验和安全解压之后,对**缓存目录 staging 里的那个文件**执行 `codesign -s - --force <file>`。`-s -` 是 ad-hoc 签名:不需要证书/钥匙串、不加 `--deep`、不碰其它文件;没有 `xattr`、`spctl`、`sudo`、隔离标志(quarantine)处理。因此它是对"我们自己刚下载的文件"的本地修改,不是系统级副作用。下载物本身用 `urllib` 获得,不带 quarantine 属性。Il2CppDumper(`dotnet_dll`)与 Windows 的 self-contained 资产不会被签名。失败只产生 warning。
- 其它:`tools list / path / doctor --offline` 不联网(我在隔离的 `IPA_ANALYZER_HOME` 下实测);`tools install il2cppdumper --offline` 返回退出码 4 与可操作提示;`cmd_tools_install dotnet` 的 `allow_install=True` 只在用户显式敲该子命令时发生。

### b) WP1 `ZipSource` 手写 zip 读取器的越界 / DoS 风险

结论:**没有 OOM / 死循环 / 越界读写;有一个 `ValueError` 未归一化(Minor)和一个"先读 CD 再计数"的内存峰值(Minor)。**

- **方法**:只支持 stored(0)/deflate(8);其它方法(实测 12/bzip2)、加密条目在访问时抛 `InvalidInput`,在 `namelist/stat` 上仍可见;size=0 条目短路为空流(不看方法)。
- **数据描述符(flag bit 3)**:读取器只信中央目录里的 `crc/csize/usize`,不读描述符;我用不可 seek 流写出的 zip(bit 3 置位)实测 `read_head` 与 `stat` 正确。
- **ZIP64**:`EOCD64`/定位记录/条目 extra 的字段顺序(usize→csize→hoff)正确;`zipfile` 的 `force_zip64` 样本读取正确;缺少 zip64 记录但字段为 0xFFFF…时报 `InvalidInput`。局限见 Nit(extensible data sector)。
- **越界**:`data_off + need > fsize` 检查覆盖 stored 与 deflate;`seek` 到超大偏移时 `read` 返回空 → `InvalidInput`;唯一漏网是偏移 ≥2^63 时 `fh.seek` 抛 `ValueError`(Minor)。
- **炸弹**:`_DeflateReader` 把实际输出量限制为声明大小(M4 变异被杀死),`extract_to` 校验 size+CRC;限额由 `check_archive_limits`(声明总量/比例)和 `SafeExtractor`(逐文件 + 预算)执行。我测试了 64 KiB 整数倍大小的可压缩数据(0、重复串、随机字母)的回退 seek / 物化,0/15 失败(担心的"EOB 尚未消费"情形没有出现);50 MB 零填充条目向后 seek 在无 spill 目录时用时 0.01 s。
- **重叠条目炸弹**(多个 CD 条目指向同一压缩流):inventory 只读每个条目前 64 KB;提取预算按声明大小累加,最大 8 GiB,有界。
- **文件句柄**:`read_head`/`open` 每次开新 fd,`with`/`close()` 会释放,`close()` 关闭 WeakSet 里的所有流。

### c) WP8 脱敏正则的误伤与漏网

- **误伤**(见 Major ×2 与 Minor):40-hex(cdhash、sha1)、`/home/<x>` 与 `/Users/<x>` 出现在 App 内路径或 URL 里、`name@word.png` 当邮箱。
- **漏网**:Windows 路径——标准 `C:\Users\Bob\…`、`c:/users/bob/…`、`D:\Users\…`、`\\?\C:\Users\…` 均能处理;**漏掉**带空格的用户名(只替换第一个词)与 UNC `\\server\share\Users\bob`;`/Users/Shared`、`C:\Users\Public` 按设计保留。
- **键名脱敏**(`apple-id/username/dspersonid/purchasedate/receipt/accountinfo…`):实现正确,值为空或已是 `<redacted>` 时保持原样;meta 阶段的 allow-list 复制 + 敏感键替换是主防线,兜底扫描是第二道。
- **HTML**:所有文本经 `html.escape`,不生成链接/图片,实测 `<script>`、`javascript:` 链接、`<img onerror>` 均被转义为文本,无 XSS 面。

---

## 6. 放行建议

**Go(有条件)**,理由:
1. 无 Blocker;契约、阶段隔离、跨平台硬规则、zip 与下载安全、三态使用、变异检查与真实样本验证都达到 Wave 2 的开工门槛,macho/codesign/cdhash 在真实数据上已被系统工具独立证实。
2. 3 条 Major 都局部且修法明确,且不改变 `ctx.results` 契约:WP8 两条只影响最终报告文本;WP2 一条是 `meta` 内部。建议立即回派给原 WP agent(WP8 ×2、WP2 ×1),与 Wave 2 并行修复,**Wave 3 前必须关闭**。
3. 建议同时顺手处理的 Minor:zip64 偏移归一化为 `InvalidInput`(WP1)、`true`/UTF-16 magic 误判(WP1,真实样本已出现)、`ext/magic` 不符的汇总标记(WP1,供 WP7 的 `engine.custom` 使用)、LuaJIT `DETERMINISTIC` flag(WP3b)、`force_dump` 与 `ForceDump` 的实现/文档对齐(WP6)、smoke 测试隔离 `IPA_ANALYZER_HOME`。

## 7. 本 Wave 的 UNVERIFIED 汇总(去重,来自代码/数据中的标注)

- WP1 `util/magic.py`:PVR v3、ASTC、ASF GUID、UE `uasset`/`MOC3`/`FSB5`/`BKHD`/`AKPK`、RIFF `FEV `、UE pak footer 布局(仅搜魔数)。
- WP2:`UIDeviceFamily` 6(Mac Catalyst)/7(visionOS);`Extensions/*.appex` 位置(ExtensionKit);`CodeResources` 规则平局与大小写;`data/permissions.json` 中 iOS 14+/17+ 新键的含义(整体注释已标);`itunes_meta` 的 `dsid/email` 变体(`userName` 现已被真实样本证实)。
- WP3:`MAX_FAT_ARCHS=30` 的阈值依据、ARC 符号集完整性、`stripped` 的经验阈值(`STRIPPED_ALL/LOCAL_MAX_SYMBOLS`);`UNITY_VERSION_RE` 未对真实播放器二进制验证。
- WP3b:UnityFS flag 位 ≥0x100 与 Unity 版本分界(仅 UnityPy)、format version 5–8、LuaJIT 2.1 早期 beta 的 dump 版本、Lua 5.5 头与语法、`sizeof` 常见集合(启发式)、LZMA 无魔数的嗅探、PE portable-PDB 表、DOS stub 文本。
- WP6:Windows self-contained Il2CppDumper(`win_selfcontained`)的实际可运行性;Cpp2IL / Redux 的 fat Mach-O 支持;Redux 的 `cs/` `dll/` 输出文件名与 .NET 10 roll-forward;`summarize.py` 内置命名空间表中的 Puerts / LuaInterface / Photon / Mirror / DOTween / Firebase / AppLovin / Addressables / UnityAds;混淆度权重与阈值仅在合成夹具上校准。

## 8. 我没有能力验证的项

- **Windows 实机**:`taskkill` 进程树清理、`shutil.which` 搜索 CWD、长路径、PowerShell 安装脚本、`os.link` 回退、mmap 句柄释放后删除文件。
- **Python 3.9 解释器**:只做了语法级(`feature_version=(3,9)`)与 API 检索,未真机运行。
- **真实成功的 il2cpp dump**:四个真实样本全部 FairPlay 加密(预检拦截,符合预期),没有已解密的 Unity IL2CPP 包;Il2CppDumper 成功路径(`Done!` 判定、产物搬运)、Cpp2IL/Redux 的真实输出均未被端到端证实。
- **.NET 安装脚本**:未真正执行(会下载并安装运行时);只审了命令行构造与授权门控。
- **工具下载的 SHA256 钉值**:Il2CppDumper 的 API `digest` 为 null,只核对了 asset 大小;未下载任何文件复算。
- **Linux 实机**:路径/进程组逻辑只经静态检查与 macOS 同源 POSIX 分支测试。

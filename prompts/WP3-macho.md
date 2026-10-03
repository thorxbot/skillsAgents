# WP3 — 纯 Python Mach-O 解析、签名、加密位、切片(Wave 1)

先读 `prompts/_common.md`、`docs/CONTRACT-FREEZE.md`、`docs/02-ARCHITECTURE.md` §4.1。

## 目标
零依赖、跨平台、健壮的 Mach-O 读取库 + `macho` 阶段(遍历 IPA 内全部 Mach-O 并汇总)。这是 FairPlay 判定、il2cpp 前置检查、库识别、保护检测的基础。

## 文件归属
`src/ipa_analyzer/macho/{__init__,parser.py,constants.py,codesign.py,scan.py,writer.py,errors.py}`、`src/ipa_analyzer/analyzers/macho_stage.py`、
`data/i18n/{zh,en}/macho.json`、`tests/unit/macho/*`、`tests/fixtures/macho_builder.py`(程序生成 Mach-O 夹具,签名要稳定,供全员使用:`build_macho(*, arch="arm64", filetype="execute", dylibs=(), encrypted=False, cryptid=0, strings=(), objc_classes=(), symbols=(), code_signature=None, stripped=False, flags=PIE)`;`build_fat(slices: list[bytes])`)。

## 公共 API(必须提供,签名可微调但需在回报中列出)
```python
parse(path_or_bytes_or_fileobj) -> MachOFile      # fat 或 thin;失败抛 MachOError(畸形)/NotMachO
MachOFile.slices -> list[MachOSlice]; .is_fat
MachOSlice: arch_name, cputype, cpusubtype, filetype, flags, is_64, offset, size,
  load_commands, segments[Segment(name, vmaddr, vmsize, fileoff, filesize, sections[Section])],
  dylibs[DylibRef(path, kind, current_version, compat_version, weak)], rpaths, uuid,
  platform, min_os, sdk, build_tools, encryption[EncryptionInfo(cryptoff, cryptsize, cryptid)],
  code_signature: Optional[CodeSignature], symtab(nsyms, stroff, strsize), flags_decoded(pie, ...)
  # 惰性、基于 mmap 的迭代器(不一次性读入内存):
  iter_cstrings(min_len=4), objc_class_names(), objc_method_names(), iter_symbols(), iter_imported_symbols()
CodeSignature: identifier, team_id, hash_types, cdhash(hex), flags, entitlements(dict|None), entitlements_raw_xml, has_der_entitlements, requirements_present, cms_present
writer.write_thin(slice_or_macho, dest_path, prefer=("arm64","arm64e")) -> Path
scan.scan_file(path, patterns: list[re.Pattern[bytes]], *, chunk=8MiB, overlap=256, limit=...) -> dict   # 流式/mmap 正则扫描(找 Unity 版本串、il2cpp_ 等)
```

## 要做的事
1. **解析**:thin 32/64、大小端 CIGAM、fat(`CAFEBABE`)与 fat64(`CAFEBABF`)。**区分 Java class 文件**(同为 `CAFEBABE`):用 `nfat_arch` 合理性(例如 ≤ 数十)+ 各 arch 偏移 / 大小落在文件内校验。load commands 范围见架构 §4.1;未知 LC 保留原始 `cmd/cmdsize` 不报错。所有读取边界检查,`cmdsize==0` 或越界 → 停止遍历并记 warning(畸形),**绝不死循环 / 越界读**。
2. **FairPlay**:`LC_ENCRYPTION_INFO(0x21)/_64(0x2C)` 解析 `cryptoff/cryptsize/cryptid`;`MachOSlice.is_encrypted = any(cryptid!=0 and cryptsize>0)`。
3. **代码签名 `codesign.py`**:SuperBlob/Blob(大端)解析 CodeDirectory(identifier、team id、hashType、flags、`cdhash` 计算)、XML entitlements → `plistlib`、DER entitlements 仅标记存在、CMS 存在性。解析失败降级为 `CodeSignature(parse_error=...)`。
4. **符号与保护属性**:`nlist/nlist_64` 惰性迭代;`is_pie`(`MH_PIE`)、`has_stack_canary`(导入 `___stack_chk_fail/___stack_chk_guard`)、`uses_arc`(`_objc_release/_objc_retain` 等)、`stripped` 启发式(局部符号数量 / `LC_SYMTAB` 状态,阈值写明依据)、`has_swift`(`__swift5_*` section 或 `libswift*` 依赖)、`has_objc`(`__objc_*` section)、`has_cpp`(`libc++` 依赖)。
5. **writer**:从 fat 切出单架构(优先 arm64 / arm64e)到临时文件;thin 则直接返回原路径或复制。对加密 slice **允许写出但调用方需自行检查**(不要在这里拒绝)。
6. **scan**:对 ≥数百 MB 的二进制用 `mmap`;Windows 下确保关闭句柄;提供取 Unity 版本串(`\b(?:20\d\d|[5-6])\.\d+\.\d+[fpab]\d+\b` 之类,实现方评估误报)的便捷函数 `find_unity_version_strings(path)`。
7. **macho 阶段**:遍历 `inventory` 中被 magic 识别为 Mach-O 的全部文件(主程序、`Frameworks/**`、`*.dylib`、`PlugIns/*.appex`、`Watch/**`);按需从 source 提取到 workdir(经 `ctx.extract`,大文件只提取一次并缓存);产出 `ctx.results["macho"]`:
   ```
   binaries[]: {path, role(main|framework|dylib|appex|watch|other), size, is_fat,
                slices[{arch, filetype, platform, min_os, sdk, uuid, encrypted, cryptid, cryptsize,
                        is_pie, stripped, has_swift, has_objc, has_cpp, signed, team_id, entitlements_keys[]}],
                dylibs[{path, kind(system|bundled|weak|…), weak}], rpaths[], parse_warnings[]}
   summary{main_binary, any_encrypted, all_encrypted, archs[], min_os, languages_hint[]}
   ```
   并产出 Finding:`macho.summary`;**不在此产出 `protect.fairplay`**(WP4 汇总),但要把逐 slice 的 `encrypted` 数据放准。
   单个二进制解析失败只记 warning,阶段 `partial`。内存:不一次性读入整个二进制。
8. i18n。

## 验收标准
- ✅ 夹具(`macho_builder`)覆盖:thin arm64、fat(arm64+arm64e / 含 x86_64 模拟器)、32 位、CIGAM 大端、`cryptid=0/1`、含多 dylib(weak/reexport/rpath)、有 / 无 objc 类名、有 / 无符号、带手工构造的 SuperBlob(含 XML entitlements)、**畸形**(截断头、`ncmds` 巨大、`cmdsize=0`、load command 越界、fat 偏移越界、Java class 伪装)。畸形一律不崩溃、不卡死(单测用超时断言)。
- ✅ 如本机是 macOS,可用 `/bin/ls`、`/usr/bin/true` 等系统二进制做**可选**交叉验证(`otool` 存在则对比 dylib 列表;测试默认跳过,`@pytest.mark.macos_only`),**不得成为必需**。
- ✅ `write_thin` 切出的文件再 `parse` 与原 slice 的关键字段一致。
- ✅ 对 300 MB 级合成文件(稀疏生成)`iter_cstrings` 流式不爆内存(测试用 `tracemalloc` 或 resource 简单断言,可标 slow)。
- ✅ 阶段在 DirSource / ZipSource 两种输入下结果一致。
- ✅ 单测通过。

## 备注
- 所有常量(`LC_*`、`CPU_TYPE_*`、`MH_*`)写在 `constants.py`,每个常量块注明来源(Apple `mach-o/loader.h` / `mach/machine.h` / xnu `cs_blobs.h`);记不准的标 `UNVERIFIED` 并联网核对。
- chained fixups、符号绑定细节不需要完整实现,只需不因其存在而崩溃。

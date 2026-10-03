# WP3b — 通用格式库:UnityFS / LZ4 / Lua 字节码 / PE-CLI / 签名扫描(Wave 1)

先读 `prompts/_common.md`、`docs/CONTRACT-FREEZE.md`、`docs/02-ARCHITECTURE.md` §4.5、**`docs/04-UNITY-HOTFIX.md`**。

## 目标
提供一组**纯函数、零依赖、可复用**的二进制格式解析器,被 WP5(Unity)、WP5b(热更新)、WP7b(Cocos Lua 等)共同使用。只解析与校验,**不做解密**。这是把原先分散在 WP5 / WP7b 的格式代码抽成统一地基,避免重复与冲突。

## 文件归属
`src/ipa_analyzer/formats/{__init__,unityfs.py,lz4.py,lua_bytecode.py,lua_source.py,pe_cli.py,magic_scan.py,compress_sniff.py}`、
`tests/unit/formats/*`、`tests/fixtures/formats_builder.py`(**程序生成各格式样本,签名要稳定,供全员使用**:`build_unityfs(blocks, *, compression="lz4"|"lzma"|"none", blocks_info_at_end=False, ...)`、`build_unityfs_variants(...)`(偏移前缀 / 单字节 XOR / 高熵)、`build_lua_bytecode(version="5.1"|"5.2"|"5.3"|"5.4"|"luajit2.0"|"luajit2.1", *, bits=64, endian="little", strip=False, tamper=None)`、`build_pe_cli(assembly_name, refs=(), types=0, clr="v4.0.30319")`)、`data/i18n/{zh,en}/formats.json`(仅少量通用词)。

## 要做的事
1. **`lz4.py`**:纯 Python LZ4 **block** 解压(Unity 的 LZ4/LZ4HC BlocksInfo/数据块用 block 格式),带 **输出大小上限**、输入/输出边界检查、匹配偏移合法性检查(防恶意输入、防 OOM、防死循环)。附 `decompress_lzma_unity(data, props_header)`(Unity LZMA:5 字节属性头 + 原始流,用 stdlib `lzma` raw 模式,需正确构造 filter;大小来自上层)。
2. **`unityfs.py`**:
   - `parse_header(fileobj) -> UnityFSHeader`:签名(`UnityFS\\0` / `UnityWeb` / `UnityRaw` / `UnityArchive` 仅识别)、格式版本(BE u32)、两个 NUL 结尾版本串、`size`(i64)、`compressedBlocksInfoSize`、`uncompressedBlocksInfoSize`、`flags`(压缩类型 `flags & 0x3F`、BlocksInfo 位置标志等——**位定义以官方/社区文档核对,标注来源**);
   - `read_blocks_info(fileobj, header) -> BlocksInfo`:定位(文件尾/紧随头部、对齐规则按版本核对)→ 解压(LZ4/LZ4HC/LZMA/none)→ 解析 block 表与 node 表(`offset,size,flags,path`);
   - `iter_decompressed(fileobj, header, blocks_info, *, max_total, chunk)`:**流式**产出解压后的数据块(供上层做签名扫描),总量/单块上限;
   - 所有失败抛 `UnityFSError(kind=...)`,kind 区分 `bad_magic / truncated / bad_sizes / unsupported_version / blocks_info_decompress_failed / ...`;
   - `probe_variants(head: bytes)`:对"偏移前缀(签名出现在前 4KB 内非 0 偏移)"与"短密钥 XOR(用 `UnityFS\\0` 已知明文反推单字节或短重复密钥并验证)"做**探测**,返回假设,**不还原文件**。
3. **`lua_bytecode.py`**(用户重点,详见 `04-UNITY-HOTFIX.md` §3):
   - `parse_header(data: bytes) -> LuaBytecodeInfo`:`valid`、`flavor`(`puc|luajit|unknown`)、`version`(`5.1/5.2/5.3/5.4`;`5.5` 仅在核实后收录;LuaJIT 给 dump 版本号与对应 2.0/2.1 说明)、`format`、`endian`、各 `sizeof`(int/size_t/Instruction/lua_Integer/lua_Number)、`integral_flag`、`bits`(由 size_t 推)、LuaJIT `flags`(BE/STRIP/FFI/FR2 等位含义以 `lj_bcdump.h` 为准)、`stripped`、`chunkname?`、`tamper_signals[]`(`LUAC_DATA` 不符、`LUAC_INT/NUM` 不符、sizeof 异常、版本字节异常);
   - `looks_like_lua_after_xor(data)`:短密钥 XOR 后头部合法 ⇒ 返回密钥假设(仅证据);
   - 常量:`LUA_SIGNATURE`、各版本头常量,**逐项注明出自 `lundump.h`(哪个版本)/ `lj_bcdump.h`**;
   - 提供 `summarize(infos) -> {by_version, invalid, bits, stripped}` 聚合。
4. **`lua_source.py`**:`infer_dialect(text) -> DialectHints`:词法级最低版本推断(`goto`/标签、`//` 与位运算、`<const>/<close>`、`setfenv/getfenv/module`),**必须先剥离注释与字符串**避免误报;输出 `min_version`、`signals[]`、`confidence`;大文件只读前 N KB 并说明。
5. **`pe_cli.py`**:`parse(data) -> PeCliInfo`:`MZ` → PE 头 → CLI header(Data Directory 14)→ 元数据根(`BSJB`)→ 版本串(CLR 运行时版本)→ 流(`#~`/`#Strings`)→ 读取 Assembly 名、TypeDef 数、**AssemblyRef 名列表**、是否 .NET;全程边界检查,畸形不崩溃。`is_dotnet_assembly(data)` 快速判定。**不需要完整元数据表解析**,仅取所需项;字段偏移必须核对 ECMA-335 / PE 规范并注明。
6. **`magic_scan.py`**:`scan_stream(chunks, patterns, *, max_hits, max_bytes) -> Hits`:跨块边界的多模式扫描(保留 overlap)、命中回调、总量与耗时上限;预置模式集 `SCRIPT_SIGNATURES`(Lua / LuaJIT / PE `MZ` / `BSJB` / 路径字符串正则 `[\w/\.-]+\.(lua|dll|js)(\.bytes|\.txt)?`)。命中给出偏移与上下文片段(限长)。
7. **`compress_sniff.py`**:`sniff(data) -> CompressionGuess`:zlib(`78 01/5E/9C/DA`)、gzip(`1F 8B`)、LZ4 frame(`04 22 4D 18`)、zstd(`28 B5 2F FD`)、LZMA(`5D 00 00` 一类,说明局限)、bzip2;返回 `(kind, confidence)`;**可靠度有限的(LZMA raw)明确标低**。

## 验收标准(全部用 `formats_builder` 生成的样本)
- ✅ UnityFS:none/LZ4/LZMA × BlocksInfo 在头后/在尾 × 小/多块;偏移前缀、单字节 XOR、高熵;截断、size 字段巨大、BlocksInfo 声明与内容不符、LZ4 恶意匹配偏移/超大输出声明 ⇒ 均正确抛 `UnityFSError(kind)` 或探测,**不崩溃、不 OOM、不卡死**(用超时与内存断言)。
- ✅ Lua:5.1/5.2/5.3/5.4 + LuaJIT 2.0/2.1 样本 ⇒ flavor/version/endian/bits 正确;篡改 `LUAC_DATA`/`LUAC_INT`/sizeof ⇒ `tamper_signals` 命中;XOR 样本 ⇒ 给出密钥假设;非 Lua 数据 ⇒ `valid=False` 且不抛异常。
- ✅ `lua_source`:各方言样本推断正确;字符串/注释里出现 `goto`、`//` 不误报。
- ✅ `pe_cli`:合法程序集样本取到名字/CLR 版本/引用;非 PE、PE 但无 CLI、截断 PE、恶意偏移 ⇒ 安全失败。
- ✅ `magic_scan`:跨块边界的签名能命中;`max_hits/max_bytes` 生效。
- ✅ `compress_sniff` 各魔数正例 + 随机数据反例。
- ✅ 所有常量有来源注释;未核实的标 UNVERIFIED 并在回报单列。
- ✅ 单测通过;`formats/` 不 import 本项目其他业务模块(保持为独立可复用库)。

## 边界
只做解析、校验、探测;不做任何解密/还原/密钥提取。

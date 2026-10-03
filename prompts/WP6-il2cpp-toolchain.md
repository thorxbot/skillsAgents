# WP6 — IL2CPP 工具链:工具供应、.NET、后端适配、非交互运行、产物摘要(Wave 1)

先读 `prompts/_common.md`、`docs/CONTRACT-FREEZE.md`、`docs/02-ARCHITECTURE.md` §4.6。

## 目标
实现"给我 `binary + global-metadata.dat`,可靠地、跨平台地、非交互地跑出 il2cpp dump,并给出结构化结果与可操作的失败原因"。**这是用户明确要求的核心卖点("自动 il2cppdumper"),也是最容易在跨环境上翻车的部分。**

## 文件归属
`src/ipa_analyzer/il2cpp/{__init__(契约已由WP0建,你补全实现导出),tools.py,dotnet.py,runner.py,backends.py,summarize.py,errors.py}`、
`data/il2cpp_backends.json`、`references/il2cpp-troubleshooting.md`、`data/i18n/{zh,en}/il2cpp.json`、`tests/unit/il2cpp/*`、`tests/fixtures/fake_dumper.py`(假 dumper,见下)。
CLI 的 `tools` 子命令入口函数放在 `il2cpp/tools.py` 暴露 `cmd_tools_list/install/path(args)`;WP0 的 `cli.py` 已留接线点,若缺接线请在回报中提出 Contract change request,不要改 `cli.py`。

## 第一步:调研(必须先做,结果写进 `data/il2cpp_backends.json` 与 `references/il2cpp-troubleshooting.md`)
用网络/文档/源码核实并记录(无网络则全部标 UNVERIFIED 并说明):
1. **Il2CppDumper**(Perfare):最新稳定版本号、Release 资产命名与对应 TFM(net6/net8/net472 …)、命令行用法、`config.json` 全部字段与默认值(特别是 `RequireAnyKey`、`ForceIl2CppVersion/ForceVersion`、`ForceDump`、`NoRedirectedPointer`)、**哪些情况会弹交互提示**(找不到 CodeRegistration/MetadataRegistration 要手输地址?Unity 版本询问?)、支持的 metadata 版本范围、是否支持 Mach-O fat、产物清单。
2. **Cpp2IL**(SamboyCoding)与 **Il2CppInspectorRedux**(LukeFZ)作为备选后端:是否支持 iOS Mach-O、metadata v29–v31+、命令行、输出形式、跨平台二进制分发方式。
3. 官方 `dotnet-install.sh` / `dotnet-install.ps1` 用法(`--runtime dotnet --channel X --install-dir`)、`DOTNET_ROLL_FORWARD` 行为(让 net6 目标工具运行在 net8 运行时是否可行,**实测**:若本机有 dotnet)。
4. 各后端对应的下载 URL 模式、**SHA256**(下载一次计算后固化;若不能下载则 `sha256: null` 并让 `provision()` 拒绝自动下载,提示手动)。
调研结论要具体到版本号与字段名,别写"可能"。

## 要做的事
1. **`tools.py`**:`ToolManager`:缓存目录(`util.paths`,由 WP0 提供);`resolve(name)` 顺序:显式路径 → 环境变量 `IL2CPPDUMPER_PATH` 等 → `PATH`(`shutil.which`)→ 缓存 → (若允许)下载。下载:仅 HTTPS、域名白名单、`urllib` 实现(带超时 / 重试 / 代理环境变量)、校验 SHA256、解压到临时目录后原子移动;`zip` 解压走安全校验;`--offline` 或 `Config.offline` 时绝不联网。CLI:`tools list/install/path`。
2. **`dotnet.py`**:`find_dotnet(explicit=None)`;`list_runtimes()`(解析 `dotnet --list-runtimes`);`ensure_runtime(min_major, *, allow_install, consent_cb)`:缺失且获授权(`Config.assume_yes` 或 TTY 交互确认回调)→ 下载官方 install 脚本到缓存、用户级安装到缓存目录(**不需要管理员权限**;Windows 用 PowerShell `-ExecutionPolicy Bypass -File`,参数列表形式);否则返回 `E_DOTNET_MISSING` 与按 OS 的安装指引(macOS: brew / pkg;Linux: 包管理器;Windows: winget)。构造运行环境:`DOTNET_ROOT`、`DOTNET_ROLL_FORWARD`(经实测验证后启用)、`DOTNET_CLI_TELEMETRY_OPTOUT=1`、`DOTNET_NOLOGO=1`。
3. **`backends.py`**:`Il2CppBackend` 适配器:`Il2CppDumperBackend`(主)、`Cpp2ILBackend`、`InspectorReduxBackend`(后两者若调研显示难以稳定自动化,可只实现 `supports()`+`provision()`+`run()` 的最小版本,并在回报中如实说明成熟度)。`select_backends(meta_version, unity_version, cfg) -> list[Backend]` 依据 `il2cpp_backends.json` 的兼容矩阵排序;失败原因分类后可回退到下一个后端。
4. **`runner.py`**:`run_il2cpp_dump(req, tools, cfg) -> Il2CppRunResult`:
   - 输入校验(文件存在、大小合理、输出目录在允许范围内);
   - 工作副本:把 `binary/metadata` 复制或硬链接到独立临时目录(部分工具会在输入目录旁写文件);
   - 写 `config.json`(非交互;字段按调研结论);
   - 子进程:参数列表、`cwd` 固定、环境白名单、`stdin` 管道(**按调研结论**对已知提示喂答案,否则立即关闭);**逐行读取 stdout 检测"等待输入"特征**(如 `Press any key`/输入地址提示),检测到卡住即终止并归类;全局超时(`Config.il2cpp.timeout_s`,默认 900)+ 无输出超时;`kill_tree` 清理;
   - 采集产物:`dump.cs, script.json, il2cpp.h, stringliteral.json, DummyDll/*` 等(按实际版本),校验非空;
   - **错误归类**到 `Il2CppErrorCode` 并给出 `remediation`(英文兜底 + i18n 键),stdout/stderr 尾部 200 行保留在结果里(已脱敏路径中的用户名);
   - 同一输入已有成功产物(按 binary+metadata 的 sha256 + 后端版本缓存)时直接复用。
5. **`summarize.py`**:`summarize_dump(out_dir) -> DumpSummary`:流式解析 `dump.cs`(可能数百 MB,**禁止整体读入内存**):assembly 数、namespace 列表(Top-N + 全量写文件)、类 / 接口 / 枚举 / 方法 / 字段数量、`stringliteral.json` 条数、命中的已知框架命名空间(从 `data/libs.json` 的 `match.namespace` 读取;WP4 提供该文件,**文件不存在时优雅降级,同时内置一份最小热更新 / 常见库命名空间表**:HybridCLR、XLua、ToLua、ILRuntime、puerts、Addressables、YooAsset、Photon、Mirror、DOTween、Spine、UniTask、Firebase、AppLovin 等);**标识符混淆度**:统计类 / 方法 / 字段名中 非 `[A-Za-z_][A-Za-z0-9_]*` 占比、长度 ≤2 占比、非 ASCII 占比、乱码特征,给出 0..1 分与阈值依据。
6. **假 dumper 夹具 `tests/fixtures/fake_dumper.py`**:可作为 `tool` 运行的 Python 脚本(通过 wrapper 可执行或 `sys.executable script.py` 方式纳入 `ToolManager` 的"自定义命令"路径),按环境变量切换行为:成功(写出最小合法 `dump.cs/script.json`)/ 返回非零 / 睡死 / 弹交互提示 `Press any key` 并等待 stdin / 输出 CodeRegistration 未找到的提示。这样无需 dotnet 就能测全部分支。

## 验收标准
- ✅ 调研产物落盘,所有 URL/SHA256/字段名有来源;不确定项标 UNVERIFIED。
- ✅ 假 dumper 四种行为(成功/失败/超时/交互卡住)在 macOS 上单测通过;超时后无残留子进程(断言)。
- ✅ `summarize_dump` 对 50 MB 级合成 `dump.cs` 流式处理内存平稳;混淆度对"正常名"与"乱码名"两组夹具给出明显不同分数。
- ✅ 离线模式:`ToolManager.resolve` 不发网络请求(mock `urllib` 断言),缺失时返回可操作错误。
- ✅ 下载路径(mock 本地 HTTP 服务器,**不依赖外网**)覆盖:成功、SHA256 不符(拒绝并清理)、超时、重定向到非白名单域(拒绝)。
- ✅ 若本机有 dotnet 且网络可用(`IPA_TEST_NETWORK=1`):真实下载 Il2CppDumper 并确认 `--help`/空参数不挂起(**不要求有真实 IPA**)。
- ✅ Windows 特有逻辑(PowerShell 命令构造、`taskkill`、`.exe` 解析、路径)有纯函数单测。
- ✅ 单测通过。

## 边界
- 只调用外部 dumper,不自己实现 IL2CPP 解析。
- 不对加密 / 魔改的 metadata 做破解;遇到时由 WP5 前置检查拦截,你这里若仍收到失败,归类 `E_METADATA_ENCRYPTED` / `E_REGISTRATION_NOT_FOUND` 并给建议即可。

# ACCEPTANCE — ipa-analyzer 验收记录(WP9)

日期:2026-10-04。基线:`5abfcd1`(Wave 0-2 已提交)+ WP9 的未提交改动。依据:`docs/01-REQUIREMENTS.md` §2 / §4 / §5、`docs/CONTRACT-FREEZE.md`、`docs/review/R1-wave1.md`。
图例:✅ 已验证(有自动化证据)· ⚠️ 部分验证 / 有保留 / 依赖 CI 或用户环境 · ❌ 未验证 / 未做。**未验证的一律写未验证。**

## 0. 总览

| 项 | 结果 |
|---|---|
| 全量测试(本机 macOS arm64,Python 3.14.3) | **2338 passed, 16 skipped**(skipped 均为门控:slow ×7、network ×2、`IPA_SAMPLES_DIR` ×4、缺 `jsonschema` ×1、Windows 专属 ×1、仅 CI 的 `IPA_EXPECT_NO_DOTNET` ×1);另跑 WP9 的 slow 测试(`--runslow`,`test_perf_slow.py` + `test_robustness.py`,含 420 次变异的大规模模糊):10 passed |
| 全量测试(本机,**Python 3.9.6** 干净 venv,装了 `pytest` + `jsonschema`) | **2339 passed, 15 skipped**(装了 `jsonschema`,所以比上一行多 1 个通过;CI 的 `[dev]` extra 现在包含它) |
| 开始时基线 | 2020 passed, 11 skipped(WP9 开工前);WP9 新增约 320 个测试(主要在 `tests/integration/`,含参数化展开) |
| 干净 venv(Python 3.9.6)仅 `pip install -e .`(旧 pip 需先升级,见下)| ✅ `ipa-analyze` 与 `scripts/ipa_analyze.py` 均可用;`pip install .`(wheel,非 editable)在别的目录运行也可用(data / schemas / references 随 wheel 打入 `ipa_analyzer/_*`) |
| CI(`.github/workflows/ci.yml`) | ⚠️ **尚未在远端运行**(没有远端仓库);只做了 YAML 解析校验和每个步骤命令的本机等价演练 |
| Windows / Linux | ⚠️ 本机只有 macOS;以下标"依赖 CI 验证" |
| 真实样本 | ❌ **未验证(按需由用户本机运行)**,见 §5 |

> 旧 pip(21.2.x,例如 Xcode 自带的 Python 3.9.6)上 `pip install -e .` 会失败(旧 pip 不支持 PEP 660,回退到 `setup.py develop`,而 venv 里的 setuptools 58 不认 `[project]` 表);`python -m pip install -U pip` 后正常。README 已写明。

## 1. 总体验收标准(01-REQUIREMENTS §5)

| # | 标准 | 状态 | 证据 / 说明 |
|---|---|---|---|
| 1 | `python scripts/ipa_analyze.py <fixture.ipa>` 在 3 个 OS 上出 `report.md` + `report.json`(过 schema) | ⚠️ macOS ✅ / Linux、Windows 依赖 CI | `tests/integration/test_e2e_cli.py::test_good_fixture_runs_clean[*]`(24 个整包夹具,subprocess 调免安装入口,断言退出码 0、schema 通过、13 个阶段齐全)、`::test_markdown_has_all_chapters_and_summary[*]`、`::test_skipped_and_failed_stages_have_visible_reasons[*]`;`tests/unit/test_pipeline_smoke.py::test_script_entry_point_runs_without_install`;CI `test` 矩阵的 "DoD 1" 步骤 |
| 2 | Unity IL2CPP:识别 Unity / IL2CPP;metadata 正常 / 改 magic / XOR 三种判定正确;AssetBundle 标准 / 偏移 / XOR / 高熵四种判定正确 | ✅ | `tests/integration/test_e2e_unity.py::test_plain_il2cpp_is_recognised_and_ready_to_dump`、`::test_metadata_variants[normal/wrong_magic/xor_strings/xor_header/random/truncated]`(normal → `no`,其余 → `yes/suspected`,且 precheck 拦截 `E_METADATA_ENCRYPTED`)、`::test_assetbundle_variants[standard/standard_lzma/standard_none/standard_lz4hc/offset_prefix/xor_single/xor_repeating/high_entropy]`(标准 → `no`,偏移 → `suspected`,XOR / 高熵 → `yes`);单元:`tests/unit/unity/test_metadata.py`、`test_bundles.py`。**保留**:改 magic / XOR 的 metadata 按设计报 `suspected`(不报 `yes`),随机数据报 `yes` |
| 3 | `cryptid=1`:`protect.fairplay = yes`,dump 被跳过且给出 `E_BINARY_FAIRPLAY` 与建议 | ✅ | `test_e2e_unity.py::test_fairplay_encrypted_binary_blocks_the_dump`(即使传入可用的假 dumper 也不运行:`dump.artifacts` 为空);单元 `tests/unit/il2cpp/test_runner.py::test_fairplay_binary_is_refused` |
| 4 | 假 dumper 的运行器:成功 / 失败 / 超时 / 交互提示卡住 4 种行为正确 | ✅ | 单元 `tests/unit/il2cpp/test_runner.py`:成功 `test_success_collects_artifacts_and_rewrites_config`、失败 `test_nonzero_exit_is_unknown_with_tail`、超时 `test_idle_timeout_when_tool_is_silent` + `test_global_timeout_kills_the_whole_process_tree`、提示卡住 `test_interactive_press_any_key_stall` / `test_registration_prompt_is_detected_and_killed` / `test_fat_prompt_partial_line_detected`;整包层 `test_e2e_unity.py::test_fake_dumper_produces_a_dump_summary`(成功路径:artifacts + 摘要 + 报告章节) |
| 5 | 自研引擎夹具:`engine.custom` yes/suspected、画像各维度正确、不被误判为已知引擎;Cocos 家族(C++/Lua 明文、Lua xxtea、JS jsc、Creator 3.x)主引擎与脚本保护判定正确 | ✅ | `tests/integration/test_e2e_engines.py::test_custom_engine_is_custom_and_not_any_known_engine`、`::test_custom_engine_profile_dimensions`(Metal / Lua / Box2D / `data.pak` custom_format + `blob.dat` encrypted_suspected / 薄 UIKit 壳)、`::test_cocos_family[*]`、`::test_cocos_lua_plain_vs_xxtea_scripts`、`::test_egret_and_laya`。**已知引擎内的自定义封装 vs 自研引擎**:`::test_wrapped_cocos_resources_do_not_turn_a_known_engine_into_a_custom_one`(Creator 3.x + 自定义 4 字节头封装 → 主引擎仍是 `cocos_creator_3x`、`engine.custom=no`、Cocos checker 报 `custom_wrapper_header_on_scripts` + `suspected`;与 `custom_engine`(无已知引擎 + 画像,`engine.custom=yes`)可区分) |
| 6 | 无 dotnet、无网络:`doctor` 与分析可运行,il2cpp 阶段跳过并给出可操作补救说明 | ⚠️ 行为 ✅ / 措辞有差异 | `tests/integration/test_no_dotnet_offline.py`(过滤 PATH、清空 `DOTNET_ROOT`、临时 HOME、`--offline`):`doctor` 退出 0 且 dotnet 为 WARN;分析完整,其余 12 个阶段无一失败;dump 失败为 `E_TOOL_DOWNLOAD_FAILED`(未装工具)/ `E_DOTNET_MISSING`(给了 .dll 但无运行时),`remediation` 指向 `--il2cpp-tool` / `tools install` / `--yes`。CI job `no-dotnet-no-network` 另会先卸载 runner 上的 .NET(依赖 CI)。**差异**:该阶段状态是 **`partial`**(`reason="il2cpp dump failed: E_…"`),不是字面上的 `skipped`——dump 在 `engine.unity` 内部执行,其他 Unity 结果仍要保留;`unity.il2cpp.dump` 的 verdict 为 `no`(= "没跑成功")。我认为这符合意图,但与 DoD 字面不同,请总监确认 |
| 7 | Unity 热更夹具(HybridCLR / ILRuntime / xLua / ToLua(LuaJIT) / puerts / Addressables):框架、脚本位置与格式、Lua 版本分布、一致性告警、篡改嫌疑 | ✅ | `test_e2e_unity.py::test_hybridclr`(热更 DLL 在 bundle、AOT 补充元数据 DLL 区分)、`::test_ilruntime`、`::test_xlua_with_lua53_bytecode_in_a_bundle`(5.3 × 2、64-bit、运行时 5.3.6、一致)、`::test_tolua_with_luajit_bytecode`(luajit_2.1、已剥离)、`::test_mixed_lua_versions_raise_a_consistency_warning`(5.1 + 5.4 vs 运行时 5.3 → `consistency.ok=false`,`lua_version` 置信度 ≤ 0.6)、`::test_tampered_lua_headers_are_reported_as_suspected`、`::test_puerts_with_quickjs`、`::test_addressables_remote_catalog`(CDN 域名只留域名)、`::test_encrypted_hot_dlls_are_suspected_not_decrypted`(XOR 密钥仅作假设,"nothing is decrypted")。整个 hot-update 阶段的整包断言都基于 `engine.unity` 真实输出(不是手工注入的结果),见 §6 发现 5 |
| 8 | 真实样本:≥1 个已解密 Unity IL2CPP 端到端产出 dump;1 个 App Store 加密包正确报 FairPlay | ❌ dump 成功路径未验证 / ⚠️ FairPlay 仅有前期实测 | 总监决定不做真实样本实操验证;案例与结论留待用户在实际使用中积累。|
| 9 | `docs/ACCEPTANCE.md` 逐条记录验收结果与未验证项 | ✅ | 本文 |

## 2. 功能清单(01-REQUIREMENTS §2)P0 逐条

测试路径相对 `skills/ipa-analyzer/`;"E2E" = `tests/integration/`,其余为 `tests/unit/`。

### F-ING 输入与摄取
| P0 项 | 状态 | 证据 |
|---|---|---|
| 输入:`.ipa` / `.zip` / `.app` / `Payload/` / 已解压目录 | ✅ | `ingest/test_ingest_inventory.py::test_ingest_directory_inputs`、`::test_directory_input_through_stages`;E2E 全部 `.ipa` |
| 只读中央目录 + 按需读取,不整包解压;支持 zip64 | ✅ | `ingest/test_zip_source.py::test_zip64_records`、`::test_huge_zip64_local_header_offset_is_invalid_input`;E2E `test_perf_slow.py`(slow,64 MiB 存储型 zip,不读全量) |
| 不可信输入:zip-slip / zip bomb / Windows 保留名与非法字符 / 大小写冲突 / 符号链接 / 非 UTF-8 名 | ✅ | `ingest/test_safe_extract.py::*`、`ingest/test_zip_source.py::test_non_utf8_names_fall_back_to_cp437_and_warn`;E2E `test_e2e_cli.py::test_zip_slip_entries_are_reported_and_never_written`、`test_paths_encoding.py::test_archive_names_that_windows_cannot_store_are_sanitised_on_extraction` |
| sha256 / 大小 | ✅ | `ingest/test_ingest_inventory.py::test_ingest_result_shape_and_binding`;每个 E2E 报告含 `input.sha256` |
| 健壮性:畸形 / 截断输入不崩溃不死循环 | ✅ | E2E `test_robustness.py`(210 次变异的预跑 + 默认 63 次:截断 / 位翻转 / 尾部翻转,看门狗线程,无崩溃无卡死、非 ingest 阶段零失败);`::test_damaged_entry_is_skipped_not_fatal` |

### F-META 应用元信息
| P0 项 | 状态 | 证据 |
|---|---|---|
| 项目名候选 + 来源 + 优先级 | ✅ | `meta/test_meta_stage.py`、`meta/test_strings_file.py`;E2E `test_paths_encoding.py::test_cjk_space_emoji_in_input_path_output_dir_and_bundle_name`(`CFBundleDisplayName` 选中) |
| Bundle ID / 版本 / 最低系统 / 设备族 / capabilities / 后台模式 / URL Scheme / 查询 Scheme / ATS / 权限(含本地化)/ 扩展 | ✅ | `meta/test_infoplist.py`、`meta/test_permissions.py`、`meta/test_meta_stage.py`;E2E `test_e2e_engines.py::test_native_swiftui_app_with_firebase_and_appsflyer`、`::test_media_app_is_classified_from_metadata_and_frameworks` |
| 分发类型判定(AppStore / AdHoc / Enterprise / Development / 未签名) | ✅ | `meta/test_provision.py`(R1 修复 `14e1de9` 后:没有 `embedded.mobileprovision` 时只凭容器层文件至多报 `suspected` 0.6-0.7,因为被解密重打包的包同样保留这些文件);合成夹具全部为"未签名 / 疑似重打包" |
| `iTunesMetadata.plist` 购买者信息默认脱敏 | ✅ | `meta/test_itunes_meta.py`、`report/test_redact.py`;E2E `test_e2e_cli.py::test_purchaser_fields_are_redacted_everywhere`(报告 md + json 均不含 Apple ID / 姓名;`--no-redact` 显式关闭) |

### F-STRUCT 项目结构
| P0 项 | 状态 | 证据 |
|---|---|---|
| 目录树(深度可配,带体积汇总)、嵌套单元清单 | ✅ | `ingest/test_ingest_inventory.py::test_tree_depth_aggregates_deeper_levels`、`::test_inventory_stage_end_to_end` |
| 每个 Mach-O:架构 / 类型 / SDK / UUID / PIE / 符号剥离 / FairPlay / 签名 | ✅ | `macho/test_parser.py`、`test_fat.py`、`test_codesign.py`、`test_malformed.py`;E2E `test_cross_stage_contract.py::test_results_keys_follow_stage_status_and_shape[*]`(slice 键齐全)。`macho/test_macos_crossval.py`(仅 macOS,对照系统工具)在本机通过 |
| 实现语言推断(带证据) | ✅ | `engines/test_stages.py`;E2E 各引擎测试断言 `languages` |
| 引擎 / 框架识别(每引擎一个 `data/engines/<id>.json`,可插拔) | ✅ | `engines/test_stages.py::test_positive_fixture_for_each_engine`(43 份签名各有正例夹具);E2E `test_e2e_engines.py` |
| 自研 / 未知引擎:不简单报 unknown,输出指纹画像并判定 `engine.custom` | ✅ | 同 DoD 5 |

### F-RES 资源结构
| P0 项 | 状态 | 证据 |
|---|---|---|
| 按类别汇总(数量 / 体积 / 占比)、扩展名分布、Top-N、本地化、打包归档 | ✅ | `ingest/test_ingest_inventory.py::test_inventory_stage_end_to_end`;E2E 报告 `resources.*` 经 schema 校验 |
| 每个文件 magic 嗅探;≥4 KB 抽样熵 | ✅ | `ingest/test_layout_magic_filetypes.py`、`::test_sniffing_reads_only_headers`、`::test_entropy_budget_is_bounded_and_reported` |

### F-LIB Lib 用途识别
| P0 项 | 状态 | 证据 |
|---|---|---|
| 来源(dylib / Frameworks / PlugIns / bundle / ObjC 前缀 / Swift 模块 / 字符串 / 命名空间) | ✅ | `libs/test_matcher_and_sysfw.py`、`libs/test_libs_stage.py`;E2E `test_e2e_engines.py::test_native_swiftui_app_with_firebase_and_appsflyer` |
| `data/libs.json` ≥150 条,中英文用途 / 隐私标签 / 匹配规则;`libs.user.json` 覆盖扩充 | ✅ | `libs/test_kb_schema.py`(当前 200 条);E2E `test_user_writebacks.py::test_unknown_library_is_listed_without_a_guessed_purpose_then_resolved_by_libs_user_json`、`::test_libs_user_json_in_the_user_data_folder_is_picked_up_without_a_flag`、`::test_malformed_user_files_only_warn` |
| 未命中 → `unknown`,不臆测 | ✅ | 同上(未知库 `purpose` 为空、`libs.unknown` verdict `unknown`) |
| 证据 + 置信度 | ✅ | `libs/test_libs_stage.py`;`test_cross_stage_contract.py::test_findings_always_have_valid_verdict_confidence_and_evidence_kinds` |

### F-ENC 加密 / 保护判定
| P0 项 | 状态 | 证据 |
|---|---|---|
| FairPlay:逐 Mach-O 逐架构 `cryptid`;汇总整包可否二进制分析 | ✅ | `macho/test_stage.py`、`protect/test_protect.py`;E2E DoD 3 |
| 代码签名(有无 / Team ID / entitlements / 哈希算法) | ✅ | `macho/test_codesign.py`、`protect/test_protect.py` |
| 符号剥离 / PIE / 栈保护 / ARC / Bitcode 残留 | ⚠️ | `macho/test_constants.py`、`protect/test_protect.py`;ARC 符号集完整性、剥离阈值为经验值(UNVERIFIED);Bitcode 残留没有独立 Finding |
| 反调试 / 越狱检测特征(标注"特征命中,非结论") | ✅ | `protect/test_protect.py`;E2E `test_findings_always_have_valid_verdict_confidence_and_evidence_kinds`(verdict 至多 `suspected`) |
| 资源级加密(引擎分析器负责) | ✅ | 见 F-UNITY / F-ENG |

### F-CLS 项目类型分类
| P0 项 | 状态 | 证据 |
|---|---|---|
| 内部分类 12 类、证据优先级(genreId → LSApplicationCategoryType → 引擎 → SDK 打分 → unknown)、主类 / 子类 / 置信度 / 证据 | ✅ | `classify/test_classify.py`;E2E `test_e2e_engines.py::test_media_app_is_classified_from_metadata_and_frameworks`(media / music 0.98,证据含 iTunesMetadata + LSApplicationCategoryType + AVFoundation)、`::test_cocos_games_are_classified_as_games`。注:`data/classify.json` 的打分权重未对照真实分布校准(UNVERIFIED) |

### F-UNITY Unity 专项
| P0 项 | 状态 | 证据 |
|---|---|---|
| Unity 版本多来源交叉(冲突列出) | ✅ | `unity/test_version.py`;E2E `unity.version`。`UNITY_VERSION_RE` 未在真实播放器二进制上验证(UNVERIFIED) |
| IL2CPP vs Mono | ✅ | `unity/test_stage.py`;E2E `test_mono_backend_and_encrypted_dll` |
| IL2CPP 检查:metadata 存在 / magic / 版本 / 头部 / 熵 / 字符串区;承载二进制与其 FairPlay | ✅ | `unity/test_metadata.py`、`unity/test_precheck.py`;E2E `test_metadata_variants[*]` |
| AssetBundle 检查:发现 / 分类 / 深度校验 / 整体判定 | ✅ | `unity/test_bundles.py`;E2E `test_assetbundle_variants[*]`、`test_xor_metadata_and_high_entropy_bundles`。块级加密(`block_encrypted_suspected`)在合成数据上验证(`unity/test_bundles.py`),真实样本上的现象 |
| Mono:PE + CLI(`BSJB`)校验,混淆器特征 | ⚠️ | `unity/test_mono.py`;混淆器特征表为记忆性内容(UNVERIFIED,`unity/mono.py`) |
| 热更新专项(框架 / 存放位置与格式 / Lua 版本 / 一致性 / 篡改 / 热更 DLL 画像 / 三态保护;只报告不解密) | ✅ | 同 DoD 7;`unity_hotfix/*`(157 个单元测试)。bundle 内容扫描只在合成数据上验证 |
| 自动 Il2CppDumper | ⚠️ | 见 F-IL2CPP |

### F-IL2CPP 自动 il2cpp dump
| P0 项 | 状态 | 证据 |
|---|---|---|
| 前置条件检查,不盲跑,给出原因与补救 | ✅ | `unity/test_precheck.py`;E2E DoD 3 / DoD 2(`test_metadata_variants`) |
| fat 二进制自动切 arm64(纯 Python) | ✅ | `il2cpp/test_runner.py::test_fat_binary_is_thinned_to_arm64`、`::test_fat_with_encrypted_arm64_slice` |
| 工具自动供应:查找顺序 / 固定版本 + SHA256 / .NET 一次授权用户级安装 / `--offline` | ⚠️ | `il2cpp/test_tools.py`、`test_dotnet.py`、`test_network.py`(本地 HTTP 服务,下载校验 / 主机白名单 / 重定向复核)。**未验证**:真实下载(`with-dotnet` CI job 才会做)、SHA256 钉值(Il2CppDumper 的 release API 无 digest,R1 无法独立复核)、真实 .NET 安装脚本的执行 |
| 非交互运行:关闭 `RequireAnyKey`、超时、杀进程树、捕获输出 | ✅ | DoD 4(假 dumper)。真实 Il2CppDumper 的配置字段名与 `Done!` 判定来自其源码 / README(R1 抽查一致) |
| 产物采集与摘要(dump.cs / script.json / il2cpp.h / stringliteral.json / DummyDll、混淆度) | ✅(假 dumper) | `il2cpp/test_summarize.py`;E2E `test_fake_dumper_produces_a_dump_summary` |
| 后端链 Il2CppDumper → Cpp2IL → Il2CppInspectorRedux,兼容矩阵 `data/il2cpp_backends.json` | ⚠️ | `il2cpp/test_backends.py::test_fallback_policy` 等(回退策略);Cpp2IL / Redux 的真实运行、fat 支持、Redux 输出名**未验证**(UNVERIFIED,`il2cpp/backends.py`、`data/il2cpp_backends.json`) |
| 失败分类与建议(8 个错误码) | ✅ | `il2cpp/test_errors.py`;E2E 覆盖 `E_BINARY_FAIRPLAY`、`E_METADATA_ENCRYPTED`、`E_TOOL_DOWNLOAD_FAILED`、`E_DOTNET_MISSING`(`test_e2e_unity.py`、`test_no_dotnet_offline.py`);其余在 `il2cpp/test_runner.py` |

### F-ENG 引擎专项
| P0 项 | 状态 | 证据 |
|---|---|---|
| A. 渲染后端 / 着色器 / 脚本 VM / 物理 / 音频 / 动画 / 网络 / 资源格式画像 | ✅ | `engines/test_scenarios.py`、`test_signatures.py`;E2E `test_custom_engine_profile_dimensions`。规则表 `data/fingerprint.json` 有 128 个信号标 `unverified`(上限权重 0.4) |
| A. 自定义资源容器分析(header 合理性 / 压缩 magic / 熵 / XOR 探测;只下 suspected) | ✅ | `engines/test_containers.py`;E2E(`data.pak` → `custom_format`、`blob.dat` → `encrypted_suspected`) |
| A. 宿主形态(薄 UIKit 壳 + CAMetalLayer / CADisplayLink + C++ 占比) | ✅ | 同上(`host.thin_uikit_shell=true`,`main_loop_hints`) |
| A. `engine.custom` 判定 + 画像摘要 + 下一步建议 | ✅ | E2E DoD 5 |
| A. 二次包装识别(渠道壳 / 自研 + 开源混合) | ⚠️ | `engines/test_scenarios.py`;`engine.wrapper` / `open_source_base` 仅在合成场景验证 |
| B. Cocos 家族(C++ / Lua / JS / Creator 2.x、3.x / cocos2d-iphone;明文 / 字节码 / xxtea / 自定义封装) | ✅ | `engine_checkers/test_cocos.py`;E2E `test_cocos_family[*]`。xxtea 判定基于"sign 头 + 长度结构"的启发式,不解密(UNVERIFIED:与 xxtea-c 逐字节一致性) |
| B. Egret / Laya | ⚠️ | `engine_checkers/test_other_checkers.py`;E2E `test_egret_and_laya`。文件名与格式大多 UNVERIFIED(官方文档无法取到),权重已降 |
| B. Unreal / Godot / Flutter / React Native(Hermes)/ Lua / Defold / GameMaker / Solar2D / LÖVE | ⚠️ | `engine_checkers/test_other_checkers.py`、`test_formats.py`;Flutter 另有 E2E(`test_flutter`)。Unreal pak 页脚布局、Godot 4.0/4.1 格式、Defold / GameMaker 文件名为 UNVERIFIED |
| B. 插件化:新增引擎 = `data/engines/<id>.json` + 可选 checker;用户目录 `engines.user.d/*.json` | ✅ | `engines/test_signatures.py`、`engine_checkers/test_dispatcher.py`;E2E `test_user_writebacks.py::test_custom_engine_becomes_a_named_engine_after_writing_engines_user_d` |

### F-RPT 报告
| P0 项 | 状态 | 证据 |
|---|---|---|
| `report.json`(`schema_version` + JSON Schema)+ `report.md`(默认中文,`--lang en`) | ✅ | E2E `test_e2e_cli.py::test_good_fixture_runs_clean[*]`、`::test_english_report_is_available`;`report/test_schema.py`(装了 `jsonschema` 时 11 项全过,否则 1 项 skip) |
| 章节对应需求清单 ①-⑨ | ✅ | `test_e2e_cli.py::test_markdown_has_all_chapters_and_summary[*]`(第 1-10 章,含 10.1 阶段状态) |
| 顶部执行摘要 ≤ 15 行 | ✅ | 同上(摘要段 ≤ 40 行含表格;CLI 控制台摘要 12-13 行) |
| 每个结论带 verdict / confidence / evidence;未执行 / 失败阶段显式写明原因 | ✅ | `test_cross_stage_contract.py::test_findings_always_have_valid_verdict_confidence_and_evidence_kinds`、`test_e2e_cli.py::test_skipped_and_failed_stages_have_visible_reasons[*]`(原始 reason 出现在 md 附录 10.1) |
| 无未翻译 key / 未填充占位符 | ✅ | `test_cross_stage_contract.py::test_no_untranslated_placeholders_in_reports`(24 夹具 × zh / en)——该测试发现并促成了 §6 发现 3 的修复 |

### F-ENV 环境与适配
| P0 项 | 状态 | 证据 |
|---|---|---|
| `ipa-analyze doctor`(Python / OS / .NET / 缓存目录可写 / 网络 / 已缓存工具) | ✅ | `test_no_dotnet_offline.py::test_doctor_works_without_dotnet_and_network`;`unit/test_pipeline_smoke.py::test_doctor_offline` |
| `tools install|list|path` | ✅ | `il2cpp/test_tools.py`;`test_no_dotnet_offline.py::test_tools_install_offline_refuses_to_download` |
| 不依赖 `otool` / `plutil` / `codesign` / `lipo` / `unzip` | ✅ | R1 §4 C-6 静态审查;E2E 在无这些命令的环境同样通过(CI 的 Windows 矩阵为终证,依赖 CI) |

## 3. 非功能需求(01 §4)

| 项 | 状态 | 说明 |
|---|---|---|
| 跨平台 macOS / Linux / Windows,Python ≥ 3.9,仅标准库 | ⚠️ | macOS ✅(3.14.3 与 3.9.6 均实跑全量);Linux / Windows 依赖 CI;路径 / 保留名 / 编码用 `PureWindowsPath` 与参数化纯函数测试覆盖(`test_paths_encoding.py`,在 macOS 上也跑) |
| 性能:1 GB IPA ≤ 60 s、峰值内存 ≤ 500 MB | ❌ 未验证 | 按总监约束不做 1 GB 夹具。仅有小规模回归 `test_perf_slow.py`(slow,64 MiB 存储型 zip,< 30 s、RSS 增量 < 300 MiB)。真实样本前期数据():4 个包 ingest 0.16-0.51 s、inventory 0.22-3.58 s、峰值 RSS 41-57 MB(1.0 GB 的包在内) |
| 健壮性:阶段隔离;畸形 / 截断输入不崩溃不死循环 | ✅ | `test_robustness.py`;`tests/unit/test_registry_pipeline.py` |
| 安全:永不执行 IPA 内容;`shell=False` + 超时;下载 SHA256;输出不越界 | ✅ | R1 §4 D;E2E `test_zip_slip_entries_are_reported_and_never_written`;`il2cpp/test_network.py` |
| 隐私:默认脱敏 | ✅ | `test_purchaser_fields_are_redacted_everywhere`;R1 的 Major(脱敏误伤、ReDoS)与多数 Minor 已由 R1 修复提交 `14e1de9` 处理 |
| 离线 | ✅ | `test_no_dotnet_offline.py`;所有 E2E 都带 `--offline` 且使用空缓存目录 |
| 可复现:同输入同版本 JSON 稳定 | ✅ | `test_paths_encoding.py::test_crlf_does_not_change_json_stability`(两次运行除时间 / 耗时 / 临时路径外逐字节同构)、黄金文件 `tests/integration/golden/*.json`(28 个夹具的投影) |
| 可测试:夹具程序生成;CI 矩阵 | ✅ / ⚠️ | 夹具全部程序生成(`tests/fixtures/full_ipa_builders.py`,`python tests/fixtures/build_fixtures.py OUT` 可导出);CI 尚未运行 |
| 可扩展:只加 `data/**/*.json` 或一个 analyzer / checker | ✅ | `test_user_writebacks.py`(无需改代码即可新增库 / 引擎) |

## 4. 契约一致性与产品形态检查(WP9 新增)

| 检查 | 状态 | 测试 |
|---|---|---|
| 阶段名 / 依赖(13 个)= CONTRACT-FREEZE §2 | ✅ | `tests/integration/test_cross_stage_contract.py::test_stage_table_matches_the_frozen_contract`、`::test_stage_table_matches_the_document_text`(同时解析文档表格) |
| `ctx.results` 键 = 阶段状态(ok / partial 才有键;`unity` 为只读别名)与 §4 形状 | ✅ | `::test_results_keys_follow_stage_status_and_shape[*]`、`::test_unity_read_alias_and_skipped_stages_have_no_key`、`::test_stage_paths_are_archive_names_and_outputs_are_relative` |
| `report.json` 顶层键 / `protection` / `privacy` / `summary` 与 §7 一致 | ✅ | `::test_report_json_top_level_matches_the_contract` |
| 全部 Finding ID(冻结表 / 源码静态扫描 / 24 个夹具实测)都有 zh i18n(title + summary),且都在冻结表内 | ✅ | `::test_all_finding_ids_have_chinese_text`、`::test_finding_ids_are_well_formed_and_frozen_or_documented_additions`、`::test_frozen_finding_table_matches_the_document_text`(缺失会列清单) |
| 库调用 = CLI(同一夹具 findings / stages 逐项相同) | ✅ | `::test_library_and_cli_agree[*]` |
| SKILL.md ≤ 150 行、frontmatter、必需指令齐全、引用的文件存在、文档里的 CLI 旗标 / 命令都能被解析 | ✅ | `tests/integration/test_docs.py`(SKILL.md 当前 89 行) |
| `scripts/install_skill.py`(软链接 / 复制、已存在询问或 `--force`、`--dry-run`、`--uninstall`) | ✅ | `tests/integration/test_install_skill.py`(全部使用临时 `--target` 与临时 HOME,不写用户目录;Windows 复制路径在 macOS 上用 `--copy` 覆盖;Windows 软链接回退为复制的分支依赖 CI) |
| 黄金文件 | ✅ | `tests/integration/test_golden.py`(`IPA_UPDATE_GOLDEN=1` 重新生成) |

### SKILL.md 冷读演练(自己模拟,只依据 SKILL.md 执行)
对 `unity_il2cpp_encrypted_binary.ipa`、`unity_il2cpp_plain.ipa`、`custom_engine.ipa`、`native_swift_app.ipa` 依次执行:doctor → analyze(`--offline`)→ 读控制台摘要与 `report.json -> summary` → 汇报。卡点与修正:
1. 初稿用 `...` 代表命令前缀,"安装工具"一步有歧义 → 全文改为 `IA`(= `python3 <SKILL_DIR>/scripts/ipa_analyze.py`)。
2. 文中的 Finding ID 没说明在哪里读 → 补一条"`findings[].id`,数据在 `engine_details.* / protection.* / libraries`"。
3. 写 `engines.user.d` 回写测试时,第一次把符号写成 `_luaL_newstate`(带下划线)未命中 → SKILL.md 补"Mach-O 符号不带前导 `_`"。
4. "下载工具前必须询问"原先只写了规则,没说默认命令会自行联网下载 Il2CppDumper(R1 Minor)→ 规定首次分析一律带 `--offline`,失败码为 `E_TOOL_DOWNLOAD_FAILED` / `E_DOTNET_MISSING` 且 precheck 通过时才询问,并写明询问内容(来源、体积、是否需要 .NET)。
真正由"另起的、不了解项目的 agent"做的冷读测试**未做**(未启动子 agent),以上为自我模拟。

## 5. 真实样本

**未验证(按需由用户本机运行)。** 总监决定不再用真实 IPA 做实操验证,WP9 没有运行也没有读取任何真实 IPA。案例与真实观察留待实际使用中补充。用户自行验证的方法:

```bash
IPA_SAMPLES_DIR=/path/to/ipas python -m pytest tests/integration/test_real_samples.py -v     # 默认 skip
python scripts/ipa_analyze.py analyze /path/to/app.ipa -o out --offline
```

## 6. WP9 过程中发现并处理的缺陷

| # | 缺陷 | 处理 |
|---|---|---|
| 1 | **偶发失败测试**:`il2cpp/test_runner.py::test_supervisor_merges_stderr_and_keeps_tail_bounded` 假设 stderr 的那一行一定落在 `head`(前 500 行)或 `tail`(后 50 行)里。supervisor 用两个线程分别读 stdout / stderr 两根管道,二者的交错顺序取决于调度,CPU 负载下 stderr 行可能落在中间 | 改为与顺序无关的确定性断言:`lines_total == 1001`、`tail` 长度有界、完整日志(`log_path`)里恰有 1 行 `[err] E` 和 1000 行 `[out] line …`;不依赖任何 sleep / 超时 |
| 2 | **业务代码**:`--il2cpp-tool` 给相对路径时,dumper 在另一个工作目录运行,路径被拼到临时目录下 → `E_UNKNOWN`("can't open file") | `il2cpp/tools.py::ToolManager.from_path` 把用户路径转成绝对路径(`os.path.abspath(expanduser)`)。E2E `test_fake_dumper_produces_a_dump_summary` 特意用相对路径覆盖 |
| 3 | **业务代码 / 数据**:无已确认引擎(自研引擎、原生 App、影音 App……)时 zh 报告的 8.1 表出现原始占位符 `主引擎:{name}`、`{name}({family})已确认,命中 {signals} 个信号…`;无宿主 / 嵌入引擎时出现 `宿主:{host};嵌入:{embedded}`(每份报告都有) | `report/i18n.py::Catalog.finding_text` 支持按 verdict 的变体键(`title@unknown` / `summary@n/a`,向后兼容);`data/i18n/{zh,en}/engines.json` 为 `engine.primary`(unknown)和 `engine.wrapper`(n/a)补变体;`tests/unit/report/test_i18n.py` 加单测 |
| 4 | **业务代码**:IPA 里一个条目的压缩数据损坏(例如 `Info.plist`),读取时抛 `InvalidInput`,而 `macho` / `engine.fingerprint` / `engine.detect` / `libs` 等阶段只捕获 `(KeyError, OSError)` → 四五个阶段同时 `failed`、连带下游被跳过、退出码 2(模糊测试发现:预跑 84 次变异里多次出现) | `errors.py` 新增 `CorruptEntry(InvalidInput, OSError)`(只新增,契约不变);`ingest/source.py` 里"条目级"读取错误(数据损坏 / 截断 / 尺寸或 CRC 不符 / 加密条目 / 不支持的压缩)改抛它,压缩包级错误仍是 `InvalidInput`。修后 210 次变异零阶段失败(ingest 之外)。E2E `test_robustness.py::test_damaged_entry_is_skipped_not_fatal`、`::test_corrupt_entry_error_is_invalid_input_and_os_error` |
| 5 | 夹具不足:`unity_builder.build_metadata` 不能注入标识符,而 WP5b 的 metadata 是"look-alike"(真实 `engine.unity` 判为 `suspected`,metadata 字符串表证据路径在整包里走不到) | `unity_builder.build_metadata` 增加可选 `extra_identifiers`(默认输出逐字节不变);整包热更夹具改用头部精确的 metadata。**这是 WP5 / WP5b 单测没有暴露的集成缝隙**:单测用手工注入的 `engine.unity` 结果,整包才暴露 |
| 6 | 测试隔离:开发机上真实缓存里有 Il2CppDumper 时,不隔离 `IPA_ANALYZER_HOME` 的整包运行会真的调起它(本机复现过:对合成 metadata 触发 .NET 异常) | E2E 一律使用空的 `IPA_ANALYZER_HOME` + `--offline` + 清除宿主工具环境变量 |
| 7 | **业务代码 / Python 3.9 兼容**(在真实 3.9.6 解释器上跑全量测试时发现,28 个测试失败):`Path.write_text(..., newline="\n")` 的 `newline` 参数 3.10 才有 → **3.9 上整条 il2cpp 成功路径(写 `config.json` 的 `ForceDump`、安装标记、缓存标记)抛 `TypeError`**,CI 矩阵里有 3.9,本机 3.14 看不出来 | `il2cpp/backends.py`、`il2cpp/tools.py`、`il2cpp/runner.py` 改用 `open(..., newline="\n")`;测试里同类用法(`test_golden.py`、`unit/report/test_render_json.py`)一并改;新增静态守卫 `tests/integration/test_python39_compat.py`(AST 检查 `write_text/read_text(newline=)`、`zip(strict=)`、`dataclass(slots/kw_only)`、`pairwise` 等 3.10+ 用法,以及 `feature_version=(3,9)` 语法解析) |
| 8 | **业务代码**:热更阶段对 SerializedFile(如 `globalgamemanagers`)逐块读取时,条目损坏抛出的 `CorruptEntry`(`OSError`)不被 `storage._guard` 捕获 → `engine.unity.hotfix` 整个阶段 `failed`(大规模模糊测试发现) | `unity/hotfix/storage.py::_guard` 同时记录 `OSError`(状态 `partial` / `io_error`,原因写入 `detail`)。回归:`test_robustness.py::test_damaged_entry_is_skipped_not_fatal[*]`(5 个条目)与 `::test_larger_fuzz_campaign`(slow) |

## 7. UNVERIFIED 汇总(去重;来源:代码 / 数据中的 `UNVERIFIED` 标注 + `docs/review/R1-wave1.md` §7;逐条细节见各位置)

代码中共 88 处标注(`grep -rn UNVERIFIED src data`),其中数据文件里的 `unverified: true` 信号:引擎签名 198 个(41 / 43 份文件)、`fingerprint.json` 128 个、`hotfix.json` 35 个——加载器对它们强制 `strong=false` 并把权重封顶 0.4。分组:

| 范围 | 内容 | 位置 |
|---|---|---|
| 文件 magic | PVR v3、ASTC、ASF GUID、UE `uasset`、`MOC3`、`FSB5`、`BKHD`、`AKPK`、RIFF `FEV `、UE pak 页脚布局(只搜魔数) | `src/ipa_analyzer/util/magic.py` |
| meta | `UIDeviceFamily` 6 / 7;`Extensions/*.appex` 位置;CodeResources 规则平局与大小写;`iTunesMetadata` 的 `dsid/email` 变体;iOS 14+/17+ 新权限键含义 | `meta/infoplist.py`、`analyzers/meta.py`、`meta/coderesources.py`、`meta/itunes_meta.py`、`data/permissions.json` |
| Mach-O | `MAX_FAT_ARCHS=30` 阈值、ARC 符号集完整性、剥离阈值、`UNITY_VERSION_RE` 未在真实播放器二进制验证 | `macho/constants.py`、`unity/version.py` |
| formats | UnityFS flag ≥0x100 与版本分界(仅 UnityPy)、format version 5-8;LuaJIT 2.1 早期 beta 的 dump 版本;Lua 5.5;`sizeof` 常见集合;LZMA 无魔数的嗅探;PE portable-PDB 表;DOS stub 文本 | `formats/unityfs.py`、`lua_bytecode.py`、`lua_source.py`、`compress_sniff.py`、`pe_cli.py`、`magic_scan.py` |
| Unity | 国内版 `cN` 后缀仅作提示;metadata 评分权重为经验阈值;Mono 混淆器特征表;`e_lfanew=0x80` 假设;资源热更清单字节序假设;TextAsset 布局 | `unity/version.py`、`unity/metadata.py`、`unity/mono.py`、`unity/hotfix/csharp.py`、`resource_update.py`、`storage.py`、`native_signals.py` |
| il2cpp | Windows self-contained Il2CppDumper 的可运行性;Cpp2IL / Redux 的 fat 支持;Redux 输出名与 .NET 10 roll-forward;内置命名空间表(Puerts / LuaInterface / Photon / Mirror / DOTween / Firebase / AppLovin / Addressables / UnityAds);混淆度权重;**下载 SHA256 钉值无法独立复核**(Il2CppDumper release API 无 digest) | `il2cpp/backends.py`、`il2cpp/summarize.py`、`data/il2cpp_backends.json` |
| 引擎指纹 / checker | Cocos Creator 2.x 布局、cocos2d-iphone 名称、`settings.json` 的 `CocosEngine` 键、压缩版 `ENGINE_VERSION`;Egret / Laya 文件名;Flutter AOT 符号;Defold `.arci` / `game.dmanifest`;GameMaker FORM 布局;Solar2D / LÖVE 容器;React Native Metro 标记;UE pak 页脚与索引加密位;Hermes 旧版本头;xxtea 与 xxtea-c 的逐字节一致性;`jsc` 字节布局;Godot 4.0 / 4.1 pck 格式;Rust / Go 构建信息;`LUAJIT_VERSION` 串格式 | `engines/checkers/*.py`、`engines/formats/*.py`、`engines/scoring.py`、`engines/fingerprint.py`、`engines/signatures.py`、`data/engines/*.json`、`data/fingerprint.json`、`data/hotfix.json`、`references/{cocos-family,egret-laya,il2cpp-troubleshooting}.md` |
| 分类 | `data/classify.json` 打分权重未对照真实分布 | `classify/scorer.py`、`data/classify.json` |
| 真实世界行为 | Windows 实机:`taskkill` 进程树、`which_safe` 规避当前目录搜索、长路径、PowerShell 安装脚本、`os.link` 回退、mmap 释放后删除;Linux 实机;.NET 安装脚本真实执行;Il2CppDumper / Cpp2IL / Redux 真实成功路径 | R1 §8;本文 §1 / §3 |
| Htp 块加密 | marker 字节与块结构、密钥来源(`HtpDecryptor.cs` 未提供)——`block_encrypted_suspected` 无法升级为"确认";网络检索到的 "0x10020 分块 / AES-256-GCM" 为单一来源,未写入规则 |、`unity/bundles.py` |

## 8. 已知局限

- 真实世界验证缺口:无已解密 Unity IL2CPP 包 → 第三方 dumper 的成功路径只由假 dumper 验证;真实 1 GB 样本的性能目标未实测;Windows / Linux 实机行为依赖 CI(CI 尚未运行)。
- 自研引擎 / 容器 / 脚本判定全为启发式,结论上限 `suspected`;Messiah、QuickSilver、Angelica 等无公开 iOS 特征,走通用指纹。
- `engine.other` 会对低置信度的候选引擎也派发 checker:自研引擎夹具里 Cocos(0.10)/ Unreal(0.25)的 checker 各产出一条 `unknown`("Cocos variant not determined"、"Unreal pak encryption unknown"),对读者是噪音。建议 P1:仅对 `confirmed` 或 ≥ 阈值的候选派发。
- 已知引擎里 `engine.container.unknown` 只分析"大文件 + 未知 magic / 可疑扩展名"的容器;"大量小文件带自定义头"由 Cocos checker 的 `custom_header` 统计报告,不进 `fingerprint.containers`。
- 失败的 `ingest`(退出码 2)时 `report.md` 页眉的"输入"字段为 `-`。
- `unity.il2cpp.dump` 的 `no` 既表示"被前置检查拦截"也表示"工具缺失 / 运行失败",区分靠 `params.error_code`(摘要里 `dump.state` 区分 `blocked` / `failed`)。
- 商业壳 / 混淆器识别(`protect.packer` 恒 `n/a`)、Assets.car 渲染项、`.xcarchive` 输入、Bitcode 残留未做。
- 首次真实运行会自动下载 Il2CppDumper(R1 Minor):SKILL.md 以"首次分析带 `--offline`、需要时先询问"规避;CLI 本身未加确认提示。
- R1 的 Major 与多数 Minor 已由 `14e1de9` 处理(`which_safe`、`DOTNET_*` 白名单、`ForceDump`、ReDoS、脱敏误伤、zip64 偏移、appstore 置信度等);仍开放的有:未知权限键默认 `medium`(带 `known=false`)、多个 Finding 的置信度为常数(B-4)、R1 §3 的 Nit。

## 9. 待用户提供

| # | 需要 | 用途 |
|---|---|---|
| a | `HtpDecryptor.cs`(marker 字节与块结构) | 把 `block_encrypted_suspected` 升级为确认 |
| b | 一个**已解密**的 Unity IL2CPP IPA | 验证真实 dump 成功路径(Il2CppDumper / Cpp2IL / Redux、fat、`Done!` 判定、产物搬运、混淆度摘要) |
| c | Messiah / 日韩厂商等自研引擎样本(或其名称与可核实特征) | 固化到 `data/engines/`,并检验 `engine.custom` 的真实表现 |

## 10. 下一步建议

- **P1**:`engine.other` 只对已确认候选派发;`--il2cpp` 首次下载前加交互确认(默认非 TTY 拒绝);`unity.il2cpp.dump` 增加 `skipped` 语义(与"失败"分开);R1 遗留 Minor;在 CI 上跑通后补 Windows / Linux 的验证记录;对 1 GB 级样本做一次性能实测。
- **P2**:商业壳 / 混淆器特征(OLLVM、字符串加密);Assets.car 渲染项;`.xcarchive`;IDA / Ghidra 脚本产物归档;Hermes / jsc 字节码的版本画像;明文 Lua 方言推断扩展到 Cocos 脚本;`report.html` 完善。

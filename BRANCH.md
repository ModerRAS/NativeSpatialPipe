# BRANCH —— 分支5：运行期行为 shadow 校验（NSP1 数据契约）

分支：\`feat/hook-validate-behavioral-shadow\`（基于 alpha-dev @ \`1679ed7\`）
方法名：**behavioral-shadow**

## 1. 方法

不定位、不哈希、不比较 PE 二进制。做法是「先 shadow 观察 N 个真实 NSP1 块，
逐块校验**运行期数据契约**；全部通过才允许这些捕获数据进入 renderer」。
契约的权威来源是仓库自身的既有校验代码：

- \`tools/native-receiver/src/lib.rs:142-154\`（\`validate()\`：block/count/payload 长度/frames 一致性/序列/时间戳）
- \`tools/roar-bridge/src/capture_input.rs:23-52\`（32 B 属性布局、f32 有限性）
- \`tools/roar-bridge/src/packet.rs:145-225\`（type 集合、flags、bed 重复、非有限 PCM）
- \`tools/endpoint-probe/Native-Capture.c:31-57\`（count/frames/stride 的生产侧上限）
- \`tools/native-receiver/src/lib.rs:6-11\`（\`CAP/HEADER/PAYLOAD/SLOT\` 与 8192 B 描述符）

shadow 模式只回答一个问题：**这台机器上 Hook 实际产出的块，是否符合接收端与渲染端共同假设的数据契约。**
它天然不能回答「目标函数有没有被改」，只能回答「产出是否还能被安全消费」——这正是运行期防线。

## 2. 契约与判定规则（\`shadow_gate.c\`）

| # | 检查 | 失败码 |
|---|---|---|
| 1 | count ∈ [1,160] | 2 E_COUNT |
| 2 | frames ∈ [1,4096] | 3 E_FRAMES |
| 3 | stride ∈ [4,16384] 且 %4==0 | 4 E_STRIDE |
| 4 | frames*4 ≤ stride | 5 E_STRIDE_FRAMES |
| 5 | properties 长度 == count*32 | 6 E_PAYLOAD |
| 6 | pcm 长度 == count*frames*4 | 6 E_PAYLOAD |
| 7 | 每条 property.frames == block.frames | 7 E_PROP_FRAMES |
| 8 | type == 1（动态）或 2 的幂 2..4096（bed） | 8 E_TYPE |
| 9 | 同 type 的 bed 不重复 | 12 E_DUP_BED |
| 10 | xyz 三个 f32 有限 | 9 E_XYZ |
| 11 | gain f32 有限 | 10 E_GAIN |
| 12 | gain ∈ [0,8]（默认 warn，\`--strict-gain\` 升级为错） | 17 E_GAIN_RANGE |
| 13 | 所有 PCM f32 有限 | 11 E_PCM |
| 14 | flags 仅允许 bit0/bit2/bit3（其它 warn） | —（warn） |
| 15 | sequence == prevSequence+1（严格 +1） | 13 E_SEQ |
| 16 | captureQpcNs 单调不减 | 14 E_QPC |
| 17 | frames == 480（生产约束；默认 warn，\`--strict-frames\` 升级） | 18 E_FRAMES_PROD |
| 18 | raw slot：ready==1、nh≤8192、nd 边界、描述符字段一致 | 15/16 E_SLOT/E_DESCRIPTOR |

输出 JSON：\`{ok, code, detail, stats:{count,frames,stride,checks}, warnings:[...]}\`；
warn 不影响 \`ok\`（可用 \`--warnings-as-errors\` 全员升级）。

## 3. 交付物

| 文件 | 作用 |
|---|---|
| \`shadow_gate.c\` | 校验核心 + \`nsp-shadow-gate.exe\` CLI + \`nsp-shadow-gate.dll\` 导出 \`nsp_shadow_check_ex\`/\`nsp_shadow_parts_check\` |
| \`gen_fixtures.py\` | 生成 19 个 JSONL 用例（7 正常、12 异常；必列类别全覆盖 + 扩展） |
| \`shadow_validate.py\` | 读 JSONL，逐条 ctypes 调 DLL + 纯 Python 同规则交叉验证 |
| \`Test-Validation.py\` | 端到端：fixtures → gate → 交叉验证 → raw slot DLL → 吞吐，打印表格并断言 |
| \`INTEGRATION.md\` | Zig host / Rust receiver 接线方案（带 file:line 与失败策略） |
| \`Build.ps1\` | gcc 构建 exe+dll 到 \`build/hook-validation/\` |
| \`out/results.json\` 等 | 本次实测证据（build 目录内另有 fixtures.jsonl，可重生成） |

## 4. 实测结果

\`python Test-Validation.py\` → **11/11 断言通过**：

| 用例 | 期望 | 实际 | 判定 |
|---|---|---|---|
| normal_160_objects | ok | OK | PASS |
| normal_pure_bed_12ch | ok | OK | PASS |
| normal_single_object | ok | OK | PASS |
| normal_mixed_beds_objects | ok | OK | PASS |
| normal_gain_out_of_range_warn | ok（2 warn） | OK | PASS |
| normal_unknown_flag_warn | ok（1 warn） | OK | PASS |
| normal_short_16f_warn | ok（1 warn） | OK | PASS |
| bad_count_zero | reject:2 | E_COUNT(2) | PASS |
| bad_count_161 | reject:2 | E_COUNT(2) | PASS |
| bad_property_frames_mismatch | reject:7 | E_PROP_FRAMES(7) | PASS |
| bad_stride_misaligned | reject:4 | E_STRIDE(4) | PASS |
| bad_xyz_nan | reject:9 | E_XYZ(9) | PASS |
| bad_pcm_nan | reject:11 | E_PCM(11) | PASS |
| bad_sequence_jump | reject:13 | E_SEQ(13) | PASS |
| bad_qpc_backwards | reject:14 | E_QPC(14) | PASS |
| bad_duplicate_bed | reject:12 | E_DUP_BED(12) | PASS |
| bad_payload_truncated | reject:6 | E_PAYLOAD(6) | PASS |
| bad_illegal_type | reject:8 | E_TYPE(8) | PASS |
| bad_stride_out_of_range | reject:4 | E_STRIDE(4) | PASS |

- gate \`totals\`: cases=19 passed=19 failed=0 okCases=7 rejectCases=12 warnings=4
- DLL↔Python 交叉验证：19/19 一致，\`dllMismatches=0\`（含警告条数、count/frames/stride）
- raw NSP1 slot（12+8192+payload）：合法块 OK；payload 截断 → E_PAYLOAD(6)；ready=0 → E_SLOT(15)；seq 连续接受
- 吞吐：C 核心 **约 38,000 blocks/s（26.2 µs/块）**（160 对象、480 帧、2.66 MB 块；5000 次迭代）
  端到端进程级 19 块约 24 ms（~780 blocks/s，含进程启动与 JSONL 解析）
- 环境：Windows x64 / gcc 16.1.0 MinGW / Python 3.14（仅标准库）

## 5. 与现有 NSP 的集成点

详见 \`INTEGRATION.md\`，要点：
- Receiver 先建环并启动（\`tools/zig-scheduler/host.zig:362\`、\`native.zig:169-209\`），Hook 后启动（\`host.zig:391-407\`）；
- 在 Rust 接收循环（\`tools/native-receiver/src/lib.rs:173-242\`）提交前加影子门：对槽起始指针零拷贝调用 \`nsp_shadow_check_ex\`，失败即 fail-closed；
- 前 N 个块只校验不提交（pre-roll 丢弃），通过后才写 \`ready.txt\`；失败则走既有 \`shutdown()\`（\`host.zig:430+\`）先停 Hook 再 join receiver。

## 6. 局限与误报

- **不检测二进制变化**：函数被 patch 但产出仍然合法时无法发现（这是分支本义，非缺陷）。
- **只覆盖「运行后行为」**：Hook 未被调用/端点未激活时窗口内收不到块，只能报 timeout。
- **窗口长度**：N=64 ≈ 0.64 s（480 帧@48 kHz）。太短可能没覆盖动态对象创建/退役；太长增加启动静音。
- **可能误报（warn）**：gain 越界、保留 flags、非 480 帧都只 warn，不阻断——因为它们是「可疑但历史可接受」的形态。
- **误拒风险**：若未来生产把 480 帧改成可变帧（或 stride 语义变化），需同步契约版本；当前规则硬编码 \`PRODUCTION_FRAMES=480\`。
- **性能开销**：窗口内 26 µs/块（≈0.26% CPU），窗口外为零；shadow 期间块被丢弃，不是运行期常驻成本。
- 未在真实 audiodg 上跑：本分支按任务要求只用合成数据；lab 的 8 个 exe 未使用（behavioral 方法不读取二进制）。

## 7. 耗时 / 复杂度

- 实现：1 个 C 文件（~900 行含 CLI）+ 3 个 Python 脚本（stdlib）+ 2 份文档；无第三方依赖。
- 构建 <2 s（gcc 两个目标）。
- 测试 <1 s（19 块 + 5000 次 bench）。
- 集成改动估计：Rust ~30 行、Zig ~15 行（见 INTEGRATION.md）。

## 8. 如果只能选一种：为什么选 / 不选它

- **选它的理由**：不依赖任何二进制定位/哈希能力，天然跨 audiodg build；规则的权威来源就是接收端代码本身，
  因此能直接回答「这批数据能不能安全渲染」；测试完全合成、可离线复现；零运行期成本（只在启动窗口）。
- **不选它的理由**：它不能替代「钩子是否挂到了正确函数」的静态校验——如果函数被改但恰好仍产出合法数据，
  shadow 会放行；它也不能在 Hook 未被调用时给出结论（只能 timeout）。
- **结论**：它适合做**第二道运行期防线**（第一道是 Native-Hook-Control 的 SHA-256+序言定位），不适合做唯一防线。

## 9. 复现

\`\`\`powershell
cd tools/hook-validation
powershell -NoProfile -ExecutionPolicy Bypass -File .\Build.ps1
python Test-Validation.py
# 单独跑：
python gen_fixtures.py --out ..\..\build\hook-validation\out\fixtures.jsonl
..\..\build\hook-validation\nsp-shadow-gate.exe --fixtures ..\..\build\hook-validation\out\fixtures.jsonl --report ..\..\build\hook-validation\out\results.json
python shadow_validate.py --fixtures ..\..\build\hook-validation\out\fixtures.jsonl --table
\`\`\`

## 10. 状态

- 已在本 worktree 提交（commit 见 \`git log -1\`），**未 push**。
- 未修改仓库既有文件；lab/ 未读取、未修改；构建产物在 \`build/\`（.gitignore 忽略），
  \`tools/hook-validation/out/\` 只提交小体积 JSON 证据。
- 遗留：真实 audiodg 采集的 JSONL dump 工具未提供（现有 \`Native-Capture.c\` 直接发共享内存，
  如需离线 dump 可在 Shadow 门里顺手落盘）；统一 CLI 契约里本方法对应的 \`decision\` 只能是
  \`unknown\`（\`located=null, targetChanged=null\`），因为它不比较二进制。

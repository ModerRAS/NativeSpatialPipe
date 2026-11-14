# INTEGRATION —— 把 shadow 校验接进 Zig host

本目录的 \`nsp-shadow-gate\` 是「先观察 N 个真实块、再放行」的独立可执行校验器。
本文给出把它接进 NSP 现有 Zig 会话的具体位置与失败策略；**不改** 现有 Python 原型链路。

## 1. 接入点（当前源码）

| 位置 | 现状 | shadow 模式要做什么 |
|---|---|---|
| \`tools/zig-scheduler/host.zig:362\` | \`var receiver = try n.Receiver.init(...)\`，先建环并启动 Rust 接收线程 | 多传一个参数 \`shadowBlocks\` |
| \`tools/zig-scheduler/native.zig:169-209\` | \`Receiver.init\`：\`nsp_link_open(create=1)\` 建 NSP1 环 → \`nsp_receiver_start_priority(...)\`，4 条 pipeline、480 帧、500 ms 动态窗口 | 建环/启动不变，追加 \`nsp_receiver_set_shadow(handle, checker, N)\` |
| \`tools/native-receiver/src/lib.rs:173-242\` | \`run()\`：185-194 等 \`ready\`；196-201 解析槽头；210-213 调 \`nsp_pipeline_submit[_timed]\`；233 \`ready.store(0)\` 释放槽；234 计数 | 在 210 前插入 shadow 分支：只校验、不提交、不释放（校验后照常 233 释放） |
| \`tools/zig-scheduler/host.zig:391-407\` | \`capture_may_have_started = true\` → \`hook.call("start")\` → 写 \`ready.txt\` | Hook start 之后**先不写 ready.txt**；轮询 \`nsp_receiver_shadow_ready\`，通过后再写；失败走 \`shutdown()\` |
| \`tools/zig-scheduler/host.zig:410-423\` | 主循环每 1 s 查 hook 状态、receiver.failed | 不变（shadow 失败会置 receiver.failed，循环自然退出） |
| \`tools/zig-scheduler/host.zig:430+\` | \`shutdown()\`：先停 Hook 并等 in-flight，再 join receiver | 不变，shadow 失败复用同一安全收尾 |

## 2. Rust 接收端改动（约 30 行，不动热路径语义）

在 \`native-receiver/src/lib.rs\` 增加一个可选影子门：

\`\`\`rust
type ShadowCheck = unsafe extern "C" fn(*const u8, usize, u64, u64, u32, *mut c_void) -> i32;

struct Control {
    // ... existing fields
    shadow: AtomicU32,        // 剩余待观察块数，0 = 关闭
    shadow_fail: Option<String>,
    checker: Option<ShadowCheck>,
    checker_ctx: usize,
}
\`\`\`

\`run()\` 内、现有 \`submit\` 调用之前（lib.rs:208-213 之间）插入：

\`\`\`rust
if shadow_remaining > 0 {
    // ptr 指向槽头 ready/nh/nd，intact SLOT = 12 + 8192 + PAYLOAD
    let rc = (checker)(ptr, SLOT, *prev_seq, *prev_qpc, 0, ctx); // 0 = ok
    if rc != 0 { stats.error = Some(format!("shadow check rejected slot: {rc}")); break; }
    shadow_remaining -= 1;
    // pre-roll 块只观察不渲染；仍执行 ready.store(0) 释放槽
} else if should_submit { /* 原 submit 逻辑 */ }
\`\`\`

要点：
- \`ptr\` 就是槽起始地址（\`map.view + 16 + next*SLOT\`，lib.rs:185），因此校验是**零拷贝**；
- 保持「提交返回后才 \`ready.store(0)\`」的顺序（lib.rs:208-233 的注释是硬约束）；
- pre-roll 块不进入 pipeline：\`nsp_pipeline_submit\` 校验首个包的序号基准，跳过 N 个不会破坏连续性；
- shadow 计数到 0 后，后续块走原路径；新增导出 \`nsp_receiver_shadow_ready(handle)->i32\`（1=预演完成或未启用，0=进行中，-1=失败）供 host 轮询。

## 3. Zig host 改动（约 15 行）

\`\`\`zig
// host.zig:362 附近
var receiver = try n.Receiver.init(root, pid, &pipelines, fullTiming, shadow_blocks);
// host.zig:391-407：Hook 已启动，但 ready.txt 延后
var activation = hook.call("start") catch |err| { ... };
// 新增：等 shadow 窗口结束（最多 ~5 s）
const deadline = c.GetTickCount64() + 5000;
while (c.GetTickCount64() < deadline) {
    const s = receiver.shadowReady(receiver.handle);
    if (s == 1) break;
    if (s < 0 or receiver.failed(receiver.handle) != 0) {
        try shutdown(&hook, &receiver, &pipelines, &bridge, &thread, &recorder, &recordThread, out);
        return error.ShadowRejected;
    }
    c.Sleep(10);
}
if (receiver.shadowReady(receiver.handle) != 1) { /* 超时：同样停 Hook */ }
try u.write(readyPath, "ready");
\`\`\`

## 4. 失败策略（fail-closed）

1. 任一块 \`nsp_shadow_check\` 非 0 → receiver 记录 \`shadow check rejected slot: <code>\` 并置 \`failed\`；
2. host 立即 \`shutdown()\`：先 \`hook.stop\`（禁用钩子、等在途回调 ≤5 s、核对 32 字节恢复），
   再 \`receiver.finish/destroy\`，然后把 \`receiver\` 报告的 JSON 与 \`shadow\` 错误写入 \`out/shadow-error.json\`；
3. 不把已观察块回放到 renderer，不做任何补偿；ASIO 会话按现有失败路径收起。

## 5. shadow 窗口长度

- 生产块率：480 帧 @48 kHz ≈ 10.0 ms/块 → N=32 ≈ 0.32 s，N=100 ≈ 1.0 s；
- 建议默认 **N=64（≈0.64 s）**，配置范围 8..512；
- 覆盖目标：至少覆盖一次回调线程切换 + 一次动态对象创建/退役（OLR 的 flags bit0/bit3 至少各见一次）；
- 若 N 个块全是纯 bed、没有动态对象（\`type==1\`），只能证明静态契约成立，不能证明对象路径可用 → 报告里记 \`shadowObservedDynamic=false\`，由 host 决定是否等更久（上限 2 s）。

## 6. 离线用法（不改运行期）

采集侧把 NSP1 槽 dump 成 JSONL 后，用本目录工具离线跑：

\`\`\`powershell
python gen_fixtures.py --out out/fixtures.jsonl        # 合成回归
nsp-shadow-gate.exe --fixtures out/fixtures.jsonl --report out/results.json
python shadow_validate.py --fixtures out/fixtures.jsonl --dll build/hook-validation/nsp-shadow-gate.dll --table
\`\`\`

## 7. 边界

- shadow 只证明「Hook 产出的数据契约成立」，**不证明二进制未被篡改**；audiodg 版本钉死仍由
  \`Native-Hook-Control.c:70-74\`（System32 路径 + SHA-256）与 \`Native-Hook.c:69-72\`（序言）负责。
- 观察窗口内的块被丢弃（不渲染），会带来 N×10 ms 的启动静音；这是可接受的启动延迟，非运行期开销。
- 校验本身 26 µs/块（160 对象/480 帧，见 BRANCH.md），相对 10 ms 周期 ≈ 0.26%，且只在窗口内运行。

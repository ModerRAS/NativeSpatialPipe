# pe-build-identity 集成方案：用「构建身份 + 微软签名」门替换整文件 SHA-256 严格门

分支：feat/hook-validate-pe-identity
工具：tools/hook-validation/pe_identity.c → build/hook-validation/nsp-hook-validate.exe
方法名：pe-build-identity；located 恒为 null（本方法不做函数定位）

## 1. 现有整文件 SHA-256 严格门（需要替换的位置）

| # | 位置 | 现状 | 语义 |
|---|---|---|---|
| 1 | tools/endpoint-probe/Native-Hook-Control.c:16-28（verified_audio()），常量在 :20（audiodg）与 :18（AudioSrv.dll） | 对目标文件整文件 SHA-256，memcmp(digest, expected, 32) 不相等即失败 | audiodg 被注入前，控制器要求它与 NSP 钉死的 26100.9444 完全同字节，否则拒绝 |
| 2 | tools/endpoint-probe/Sync-Hook.py:131-133 | hashlib.sha256(...) != '3dd24fe6…' → RuntimeError('audiodg version mismatch') | 旧捕获宿主开跑前做同一整文件哈希核验 |
| 3 | tools/backend/hook_state.py:55-57 | 同一个 SHA-256 常量，失败抛 Audio target build mismatch | 后端 prepare() 预检 |
| 4 | tools/zig-scheduler/common.zig:304-310 checkTarget() | Zig 调度器读入整文件算 SHA-256 与常量比较，失败 error.TargetBuildMismatch | 调度器启动前核验目标构建 |

另有不是 SHA 门、但同样把构建写死的假设，换门后仍需处理：

- tools/endpoint-probe/Native-Hook.c:70-72：Hook 地址 = image + 0x31930，并要求该处 16 字节序言 48 89 5c 24 08 48 89 6c 24 10 48 89 74 24 18 57；
- tools/endpoint-probe/Native-Hook.c:80：create((char*)image+0x9f4f8, (char*)image+0xa2d58, …)，另有 2 个写死的 RVA；
- tools/endpoint-probe/Native-Hook-Control.c:71-75：baseline 模式在 image_base + 0x31930 读 16 字节与序言比较。

结论：整文件哈希门把「构建合法性」和「函数体未被改」混成一个字节相等判断；任何 Windows 更新都要重新钉版本，而且它不能告诉调用方「新构建里目标函数在哪」。

## 2. 为什么换成 buildId + 微软签名门

- 新构建（26100.9711 / 26100.9974，以及系统里 servicing 后的 9949 复制品）都是微软有效签名的正版构建：旧门一律拒绝，等于把「系统正常更新」误判为「不可用」。
- 纯 buildId 比较能把「是不是同一个构建」和「函数体是否被改」区分开，但 buildId 对同构建内字节变化完全不可见（A-mut-fn 与参考 buildId 完全相同，实测见 out/build-identity-stats.json）。
- Authenticode 对整文件做哈希：签名失效 ⇒ 文件在签名后被改过（A-mut-fn / A-mut-else 均为 TRUST_E_BAD_DIGEST）。它能兜住「没重新签名的改动」，但同样只是整文件粒度，不是函数粒度。

因此正确用法是：pe-build-identity 当第一道构建/防篡改门，把「新构建」降级给函数级方法（unwind-fn-hash / crossbuild-fingerprint / structural-invariants）做函数定位与判定；本方法本身不单独作为 Hook 的最终许可。

## 3. 新门判定语义

工具输出 decision + signature + buildIdMatch，调用方按下面矩阵行动（--method pe-build-identity 默认策略）：

| buildId 对比 | 候选 Authenticode | 签名者 | decision | 调用方行动 |
|---|---|---|---|---|
| 相同 | valid | Microsoft | allow | 走 pinned 路径：固定 RVA 0x31930 + 16 字节序言复核后 Hook（本方法不证明函数体） |
| 相同 | invalid（TRUST_E_BAD_DIGEST 等） | — | deny | 拒绝 Hook：文件在签名后被改过（同构建篡改） |
| 相同 | unsigned / unknown | — | deny / unknown | unsigned 拒绝；离线下无法验证链 → unknown，人工确认 |
| 不同 | valid | Microsoft | warn | 降级：调用函数级方法定位/校验目标函数；成功 → 用新 RVA Hook；失败/低置信 → 拒绝 |
| 不同 | invalid / unsigned | — | deny | 拒绝 Hook（新构建名头 + 坏签名 = 可疑） |
| 不同 | unknown | — | unknown | 降级函数级方法 + 人工确认，不自动 Hook |
| 任意 | valid | 非 Microsoft | deny | 不是 in-box audiodg，拒绝 |

located 恒为 null、targetChanged 恒为 null：本方法不产出 RVA，也不对「目标函数是否被改」表态。warn/unknown 分支必须由别的分支补上 located。

## 4. 降级调用链（伪代码）

### 4.1 通用编排器（推荐在控制层实现一次，各入口共用）

~~~
validate(reference, candidate):
    r = pe_build_identity(reference, candidate)          # 本分支，~30 ms
    if r.decision == deny:      return REJECT(tamper, r) # 签名坏/无签名/非微软签名
    if r.decision == allow:     return ACCEPT_PINNED(r)  # buildId 相同 + 有效签名
    # r.decision in {warn, unknown}：构建变了，或离线无法验证
    for m in [unwind_fn_hash, crossbuild_fingerprint, structural_invariants]:
        v = run(m, reference, candidate)                 # 其它分支的 CLI，同一契约
        if v.decision == allow and v.located != null:
            return ACCEPT_RELOCATED(v.located, evidence=[r, v])
        if v.decision == deny:  return REJECT(function_mismatch, v)
    return MANUAL_CONFIRM(evidence=[r])                  # 不自动 Hook
~~~

要点：

1. pe-build-identity 的 allow 只覆盖「同一构建」；一旦 warn/unknown，绝不能继续用写死的 0x31930（新构建里函数可能移动），必须拿到函数级方法给出的新 RVA；
2. 新构建上 Hook 需要 3 个 RVA（目标函数 0x31930、0x9f4f8、0xa2d58，见 Native-Hook.c:70,80），因此降级链必须对三者都给证据，或明确只允许 pinned 构建；
3. 签名 unknown（例如离线下根证书不可用）不能当 allow；生产策略建议 unknown → 函数级方法 + 人工确认，宁可拒绝。

### 4.2 C：替换 Native-Hook-Control.c 的 verified_audio()

方式 A（最小改动，进程内）：把 tools/hook-validation/pe_identity.c 的解析/验签函数编进控制 exe，替换 verified_audio() 的实现，调用点 :58/:70 不变：

~~~
/* 替换 Native-Hook-Control.c:16-28 的 verified_audio() */
typedef enum { NSP_BUILD_ALLOW, NSP_BUILD_WARN, NSP_BUILD_DENY, NSP_BUILD_UNKNOWN } BuildDecision;
typedef struct { BuildDecision decision; wchar_t buildId[192]; wchar_t fileVersion[64];
                 LONG trustStatus; wchar_t signer[256]; } BuildVerdict;

static int verified_build_identity(const wchar_t *path, BuildVerdict *v) {
    PeBuild ref, cand;
    if (!parse_pe(&ref, pinned_audiodg_path(), NULL)) return 0;   /* 参考 = 钉死文件 */
    if (!parse_pe(&cand, path, NULL)) return 0;
    cand.trust = winverifytrust_file(path);
    if (cand.trust != ERROR_SUCCESS) { v->decision = NSP_BUILD_DENY; return 0; }  /* 篡改/非微软 */
    v->decision = same_build(&ref, &cand) ? NSP_BUILD_ALLOW : NSP_BUILD_WARN;
    return v->decision == NSP_BUILD_ALLOW;
}
...
if (!c.fixture) {
    wchar_t expected[1024]; GetSystemDirectoryW(expected, 1000); wcscat(expected, L"\\audiodg.exe");
    BuildVerdict v;
    if (_wcsicmp(image, expected) || !verified_build_identity(image, &v)) {
        /* warn/unknown → 交给函数级定位链（见 4.1）；本函数不负责 relocate */
        if (v.decision == NSP_BUILD_WARN || v.decision == NSP_BUILD_UNKNOWN)
            fprintf(stderr, "build changed: defer to function-level validation, buildId=%ls\n", v.buildId);
        goto done;
    }
}
~~~

方式 B（零链接，子进程）：CreateProcessW 调 nsp-hook-validate.exe --method pe-build-identity --reference … --candidate … --json，解析 decision。适合已有 JSON 编排层（Run-Native.py 等），代价是每次 ~35 ms 与一个外部文件依赖。

### 4.3 Python：替换 Sync-Hook.py:131-133 与 hook_state.py:55-57

~~~
# 旧：整文件哈希 == 常量，否则 RuntimeError
# 新：构建身份 + 签名门；warn/unknown 交给函数级校验，不直接放行
from hook_validate import pe_build_identity   # 对 nsp-hook-validate.exe 的薄封装（subprocess + json）

def verify_audio_target(image: pathlib.Path) -> None:
    verdict = pe_build_identity(REFERENCE_AUDIODG, image)
    if verdict["decision"] == "deny":
        raise RuntimeError("audiodg rejected: signature invalid / not Microsoft-signed")
    if verdict["decision"] == "allow":
        return                       # 同一构建 + 有效微软签名，继续 pinned RVA 路径
    # warn / unknown：构建已变化（或离线无法验证），必须拿函数级证据
    if not function_level_validate(image):          # 调 branch1/3/4 的 --method
        raise RuntimeError("audiodg build changed; target function not established")
~~~

替换后 hook_state.py 的 prepare() 与 Sync-Hook.py 的注释也应同步说明：allow = 同一构建，warn = 新构建需函数级复核，deny = 拒。

### 4.4 Zig：common.zig:304-310

~~~
// 旧：整文件 SHA-256 与常量 mem.eql
// 新：读 PE 头 TimeDateStamp/SizeOfImage/CheckSum + WinVerifyTrust 结果
const id = try peBuildIdentity(allocator, expected);   // 复用 pe_identity.c 或独立实现
if (!std.mem.eql(u8, &id.buildId, &approvedBuildId)) return error.TargetBuildChanged; // 调用方降级
if (!id.trustValid) return error.TargetSignatureInvalid;                              // 拒绝
~~~

Zig 侧无法直接复用 C 的 WinVerifyTrust 逻辑，建议：pinned 构建（buildId 相同）仍允许快速路径；构建变化时向控制层返回 error.TargetBuildChanged，由控制层调函数级方法（不要在 Zig 内自己放行）。

## 5. 与统一 CLI 契约的关系

~~~
build/hook-validation/nsp-hook-validate.exe \
  --method pe-build-identity \
  --reference "C:\Windows\System32\audiodg.exe" \
  --candidate <候选 audiodg.exe> --json
~~~

- stdout 单个 JSON 对象；build = 候选构建字段，另有 referenceBuild / buildIdMatch / signature 扩展字段；
- 分析完成退出码 0（decision 不影响退出码）；参数/IO 错误输出 {"error": …} 并非 0；
- located 恒 null、targetChanged 恒 null（契约允许），warn/unknown 分支由其它方法补位。

## 6. 验收与回归

- python tools/hook-validation/Test-Validation.py：8/8 严格策略通过（ref-self allow、四个 mutant deny、三个新构建 warn），另有 identity-only 对照 8/8；
- 集成后至少加一条端到端用例：参考构建 → allow + 固定 RVA Hook；26100.9974 → warn + 函数级方法给出新 RVA 后才 Hook；A-mut-fn → deny；
- 不要把 pe-build-identity 的 allow 当成「函数体未被改」的证明（checks 里已固定写 function_body: ok=false）。

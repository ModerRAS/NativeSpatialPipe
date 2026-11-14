# BRANCH — feat/hook-validate-pe-identity（方法：pe-build-identity）

| 项 | 值 |
|---|---|
| 分支 | feat/hook-validate-pe-identity |
| 基于 | alpha-dev @ 1679ed7（worktree: scratch/lead/nsp-branches/wt2-peid） |
| 提交 | 3ecc8d2 feat(hook-validation): add pe-build-identity PE build + Microsoft Authenticode gate |
| 日期 | 2026-11-15 |
| 方法 | pe-build-identity（PE 构建身份 + 微软 Authenticode 签名门） |
| 测试 | strict 策略 8/8；identity-only 对照 8/8 |
| 语言/依赖 | C（Win32：version / wintrust / crypt32）+ Python 3 标准库 |

## 0. 结论先行

该方法只能回答两个问题：**候选是不是同一个构建**（buildId）、**候选整文件签名是否仍是有效微软签名**。它**不能**回答「目标函数（audiodg+0x31930）是否被改」，因为它不做函数定位（located 恒为 null）。

因此：**不建议单独作为 Hook 的唯一许可**；推荐作为「第一道构建/防篡改门」——同一构建 + 有效微软签名 → 允许走 pinned RVA；新构建（有效签名）→ warn 并降级到函数级方法（unwind-fn-hash / crossbuild-fingerprint / structural-invariants）做定位与函数级判定；签名坏 → deny。

## 1. 方法与设计

### 1.1 buildId（构建身份）

- 解析 PE：DOS 头 → PE 签名 → COFF TimeDateStamp、可选头 magic（PE32/PE32+）、ImageBase、SizeOfImage、CheckSum；
- 读版本资源：GetFileVersionInfoSizeW / GetFileVersionInfoW / VerQueryValueW（VS_FIXEDFILEINFO，签名 0xFEEF04BD）；失败时 fileVersion = null；
- buildId = TimeDateStamp + SizeOfImage + CheckSum（+ fileVersion 若可得），输出形如 966F569F-000D7000-000E370E-v10.0.26100.9444；
- 比较规则：三元组相等且（双方版本都可得时）版本相等 → buildIdMatch = true。

### 1.2 微软签名门

- WinVerifyTrust(WINTRUST_ACTION_GENERIC_VERIFY_V2)，离线安全参数 WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_NONE，不联网、不取 CRL；
- 状态映射：S_OK → valid；TRUST_E_BAD_DIGEST / TRUST_E_EXPLICIT_DISTRUST / TRUST_E_SUBJECT_NOT_TRUSTED / CERT_E_REVOKED / CERT_E_CHAINING → invalid；TRUST_E_NOSIGNATURE 等 → unsigned；其余（如证书链离线下无法建立）→ unknown（如实返回，不猜）；
- 签名者：CryptQueryObject 取内嵌 PKCS#7 → CryptMsgGetParam(CMSG_SIGNER_INFO_PARAM) → CertFindCertificateInStore(CERT_FIND_SUBJECT_CERT) → CertGetNameStringW（显示名）；主题含 Microsoft（不区分大小写）→ microsoftSigned = true；只在签名 valid 且主体可提取时给 true/false，否则 null（unknown）。

### 1.3 决策矩阵（默认策略）

| buildId | 候选签名 | 签名者 | decision |
|---|---|---|---|
| 相同 | valid | Microsoft | allow（checks 明确写「仅构建身份，未证明函数体」） |
| 相同 | invalid | — | deny（签名后被改动） |
| 相同 | unsigned | — | deny |
| 相同 | unknown | — | unknown |
| 不同 | valid | Microsoft | warn（构建已变化，需函数级校验/人工确认） |
| 不同 | invalid / unsigned | — | deny |
| 不同 | unknown | — | unknown |
| 任意 | valid | 非 Microsoft | deny |

另有诊断开关 --ignore-signature（仅用于实验对照，不作为安全策略）：只看 buildId，相同 → allow，不同 → warn。这就是「只有构建身份」时的真实能力边界。

### 1.4 统一 CLI 契约

~~~
build/hook-validation/nsp-hook-validate.exe --method pe-build-identity \
  --reference <ref.exe> --candidate <cand.exe> --json
~~~

- stdout 单个 JSON 对象，必含 method / reference / candidate / build / located / decision / targetChanged / checks / timingMs；
- build = 候选构建（fileVersion, timeDateStamp, sizeOfImage, checksum, magic, machine, imageBase, buildId）；扩展到 referenceBuild / buildIdMatch / signature / rationale；
- located 恒 null，targetChanged 恒 null（本方法不定位、不判断函数体）；
- 分析完成退出码 0；参数/IO 错误输出 {"error": …} 且非 0；unverifiable → decision=unknown。

## 2. 与现有 NSP 的集成点

| 位置 | 现状 | 替换后 |
|---|---|---|
| tools/endpoint-probe/Native-Hook-Control.c:16-28（常量 :18 AudioSrv.dll、:20 audiodg；调用点 :58/:70） | verified_audio() 整文件 SHA-256 与常量 memcmp | verified_build_identity()：allow 走 pinned RVA；warn/unknown 返回给控制层降级函数级链；deny 拒绝 |
| tools/endpoint-probe/Sync-Hook.py:131-133 | sha256(image.read_bytes()) != '3dd24fe6…' → RuntimeError | 调 pe-build-identity；deny 抛错，allow 继续，warn/unknown 必须函数级复核 |
| tools/backend/hook_state.py:55-57 | 同一 SHA-256 常量 → Audio target build mismatch | 同上（prepare() 预检） |
| tools/zig-scheduler/common.zig:304-310 checkTarget() | 整文件 SHA-256 比较 → error.TargetBuildMismatch | 读 PE buildId + 验签；构建变化返回 error.TargetBuildChanged 由控制层降级 |
| tools/endpoint-probe/Native-Hook.c:70-72,80 与 Native-Hook-Control.c:71-75 | 写死 RVA 0x31930（+序言）与 0x9f4f8 / 0xa2d58 | pe-build-identity 不提供 RVA：warn/unknown 时必须由函数级方法给出新 RVA 后再 Hook |

详细的替换伪代码、降级调用链与验收用例见仓库根 INTEGRATION.md。

## 3. 逐用例结果（lab 8 例，参考构建 = audiodg-build-26100.9444.exe）

strict 策略（默认：构建身份 + 微软签名）：

| # | 用例 | 候选 | decision | buildId | 签名 | located | timingMs | 期望 | 结果 |
|---|---|---|---|---|---|---|---|---|---|
| 1 | ref-self | audiodg-build-26100.9444.exe | allow | 相同 | valid / Microsoft | null | 33.7 | allow | PASS |
| 2 | A-mut-else | audiodg-A-mut-else.exe | deny | 相同 | invalid | null | 30.7 | deny | PASS |
| 3 | A-mut-fn | audiodg-A-mut-fn.exe | deny | 相同 | invalid | null | 33.1 | deny | PASS |
| 4 | build-9711 | audiodg-build-26100.9711.exe | warn | 不同 | valid / Microsoft | null | 35.1 | warn | PASS |
| 5 | build-9974 | audiodg-build-26100.9974.exe | warn | 不同 | valid / Microsoft | null | 35.8 | warn | PASS |
| 6 | system-9949 | audiodg-system-26100.9949.exe | warn | 不同 | valid / Microsoft | null | 36.9 | warn | PASS |
| 7 | D-mut-fn | audiodg-D-mut-fn.exe | deny | 不同 | invalid | null | 35.5 | deny | PASS |
| 8 | D-mut-else | audiodg-D-mut-else.exe | deny | 不同 | invalid | null | 34.3 | deny | PASS |

identity-only 对照（--ignore-signature，仅看 buildId，演示方法的能力边界）：

| # | 用例 | buildId | identity decision | 与 strict 的差 | 含义 |
|---|---|---|---|---|---|
| 1 | ref-self | 相同 | allow | 一致 | pinned 构建 |
| 2 | A-mut-else | 相同 | allow | strict deny → identity allow | 无关 section 改 1 字节，函数未动：buildId 看不见 |
| 3 | A-mut-fn | 相同 | allow | strict deny → identity allow | **目标函数内改 1 字节，buildId 完全相同 → 漏报** |
| 4 | build-9711 | 不同 | warn | 一致 | 合法新构建 |
| 5 | build-9974 | 不同 | warn | 一致 | 合法新构建 |
| 6 | system-9949 | 不同 | warn | 一致 | 9949 servicing 复制品（与 9974 字节相同） |
| 7 | D-mut-fn | 不同 | warn | strict deny → identity warn | 新构建 + 函数改动：buildId 只能看到「构建不同」 |
| 8 | D-mut-else | 不同 | warn | strict deny → identity warn | 新构建 + 无关改动：同样只是 warn |

原始数据：tools/hook-validation/out/results.json（含每例完整 JSON 输出与契约校验结果）；表格 stdout 见 out/test-run.log。

## 4. 额外实验：4 个构建的 buildId / fileVersion / SHA-256

脚本 tools/hook-validation/experiments/build-id-stats.py，输出 out/build-identity-stats.json。

| 构建文件 | fileVersion | buildId | SHA-256（前 16） |
|---|---|---|---|
| audiodg-build-26100.9444.exe | 10.0.26100.9444 | 966F569F-000D7000-000E370E-v10.0.26100.9444 | 3dd24fe6faf0b56f… |
| audiodg-build-26100.9711.exe | 10.0.26100.9711 | 691840FD-000D7000-000EC7D7-v10.0.26100.9711 | 4b5981cf6bdfac2f… |
| audiodg-build-26100.9974.exe | 10.0.26100.9974 | 73D7C364-000D6000-000E661A-v10.0.26100.9974 | 017628fc0ace8061… |
| audiodg-system-26100.9949.exe | 10.0.26100.9974 | 73D7C364-000D6000-000E661A-v10.0.26100.9974 | 017628fc0ace8061…（与 9974 完全同字节） |

结论：

1. 4 个构建文件 → 3 个不同 buildId（system-9949 与 build-9974 是同一二进制的两条 servicing 路径，SHA-256 也相同），buildId 与 fileVersion 一致：**buildId 能区分构建**；
2. 4 个 mutant（A-mut-fn / A-mut-else / D-mut-fn / D-mut-else）SHA-256 全变，buildId 与各自 base **完全相同**：**同一构建内的字节变化对 buildId 完全不可见**；
3. 因此 buildId 不能单独承担「目标函数未被改」的证明；它只适合做构建门/防篡改门的第一级。

## 5. 核心结论、局限与误报

1. **核心局限（任务书预期的漏报，已在 identity-only 对照中复现）**：A-mut-fn 与参考构建 buildId 完全相同（966F569F-000D7000-000E370E），任何「buildId 相同 → allow」的门都会放行被改过目标函数的文件——漏报。若把本方法实现成纯 buildId 门（--ignore-signature 的诊断行为），实测就是 allow。
2. **实测差异（任务书预期 vs 实际）**：任务书预期 A-mut-fn「该方法会 allow（漏报）」。实际默认策略下它是 deny：因为翻转字节破坏了 Authenticode（WinVerifyTrust = 0x80096010 TRUST_E_BAD_DIGEST）。所以严格实现里签名门**顺带**抓住了这个 mutant，但这是整文件哈希的证据，不是函数级证据——不能据此认为本方法能证明函数体。
3. **函数粒度误报**：A-mut-else（目标函数未动、无关 section 改 1 字节）也被 deny——签名门只有整文件粒度，对「函数没变」无法给出可接受结论。反之，如果为了接受 A-mut-else 而关掉签名门，A-mut-fn 就会漏报。两种取舍都不满足「函数级校验」的需求。
4. **残余风险（离线无法复现）**：同构建、patch 后重新签名的二进制会通过签名门并被 allow。实验室没有微软签名私钥，无法构造；风险等级低（需要微软密钥），但方法本身没有函数级证据兜底，属未经证明的残余风险。
5. **离线下签名 unknown**：证书链/吊销在完全离线环境可能无法建立 → decision=unknown；如实返回、不当 allow。
6. **located / targetChanged 恒 null**：不定位、不判断函数体，warn/unknown 分支必须由别的分支补位。
7. A-mut-fn 与 A-mut-else 无法区分（都 deny）；D-mut-fn 与 D-mut-else 也无法区分（都 deny）。本方法对「函数内/函数外改动」零区分度。

## 6. 耗时与复杂度

- 单次分析 30.7–36.9 ms（8 例中位数约 34.7 ms）；其中绝大部分是 WinVerifyTrust 对整文件做哈希 + 证书链验证，PE 头解析 + 版本读取 < 2 ms；
- 固定开销约 30 ms，与文件大小线性（~0.9 MB 的 audiodg）；作为 Hook 前置门可接受（Hook 流程本身是秒级）；
- 代码量：pe_identity.c 733 行（单文件，无第三方库）；测试 300 行 + 实验 163 行（stdlib）；Build.ps1 39 行；
- 依赖：只链接 Windows in-box 的 version / wintrust / crypt32，无网络（CACHE_ONLY + REVOCATION_CHECK_NONE）；
- 退出码/输出稳定，可被 C/Python/Zig 任一侧以子进程或内嵌方式复用。

## 7. 如果只能选一种方法，选它吗？

**不选它作为唯一方法。** 理由：NSP 要回答的核心问题是「目标函数体是否还是可安全 Hook 的那个函数」。pe-build-identity 的证据全部停留在构建/整文件层面：

- 对同一构建内的函数改动，buildId 完全看不见（A-mut-fn 漏报，见 §5.1）；
- 对新构建，它只能给 warn，既不能定位函数（located=null），也不能证明函数等价；
- 对函数未动的良性改动（A-mut-else）又只能 deny（误报）；
- 无离线函数级证据时，唯一能依靠的 Authenticode 也只是整文件完整性。

**但它适合作为唯一方法之前的第 0 道门**：成本低（~30 ms）、无第三方依赖、能挡住未重新签名的整文件篡改、能把「合法新构建」从旧 SHA 门的死路引到函数级方法链上。推荐组合：pe-build-identity（门）→ 新构建时降级 unwind-fn-hash / crossbuild-fingerprint / structural-invariants（函数级证据）→ 仍不确定则人工确认。

## 8. 复现

~~~
# 构建（Windows PowerShell 5.1；若用 pwsh 7 直接 pwsh -File）
powershell -NoProfile -ExecutionPolicy Bypass -File tools/hook-validation/Build.ps1
# → build/hook-validation/nsp-hook-validate.exe

# 8 用例（stdout 表格 + out/results.json）
python tools/hook-validation/Test-Validation.py

# 额外实验（4 构建 buildId/version/sha256 → out/build-identity-stats.json）
python tools/hook-validation/experiments/build-id-stats.py

# 单例
build/hook-validation/nsp-hook-validate.exe --method pe-build-identity \
  --reference C:\WorkSpace\Claw\scratch\lead\nsp-branches\lab\audiodg-build-26100.9444.exe \
  --candidate C:\WorkSpace\Claw\scratch\lead\nsp-branches\lab\audiodg-A-mut-fn.exe --json
~~~

实验室语料只读，未修改。构建产物（build/）被 .gitignore 忽略，未提交。

## 9. 交付物

| 文件 | 说明 |
|---|---|
| tools/hook-validation/pe_identity.c | 方法实现（PE 解析 + 文件版本 + WinVerifyTrust + 签名者提取 + 决策 + JSON CLI） |
| tools/hook-validation/Build.ps1 | gcc 构建（-lversion -lwintrust -lcrypt32 → build/hook-validation/） |
| tools/hook-validation/Test-Validation.py | 8 用例 + 契约校验 + 表格 + out/results.json |
| tools/hook-validation/experiments/build-id-stats.py | §4 额外实验 |
| tools/hook-validation/out/results.json | 8 例实测结果（含 identity-only 对照） |
| tools/hook-validation/out/build-identity-stats.json | 4 构建 + 4 mutant 统计 |
| tools/hook-validation/out/test-run.log | 测试脚本 stdout 存档 |
| INTEGRATION.md | 替换现有 4 处整文件 SHA-256 门 + 降级调用链伪代码 |
| BRANCH.md | 本文件 |
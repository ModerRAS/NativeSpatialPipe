# BRANCH.md — 分支3：跨构建特征码 + 归一化指纹 + per-build DB

分支：`feat/hook-validate-crossbuild-fingerprint`（基于 alpha-dev @ 1679ed7）
方法代号：`crossbuild-fingerprint`
交付目录：`tools/hook-validation/`，构建产物 `build/hook-validation/nsp-hook-validate.exe`（gcc 构建，产物被 .gitignore 忽略）

## 1. 方法/设计

NSP 当前把 audiodg 的 hook 目标写死成 `image + 0x31930`（`tools/endpoint-probe/Native-Hook.c:70`）并校验 16 字节序言
（`tools/endpoint-probe/Native-Hook-Control.c:72-74`）。任何 Windows 服务更新都会让整文件 SHA 变化，但目标函数在多数
构建里只是**移动了位置**、体内只有 rel32/disp32 漂移。本方法用「定位 + 归一化指纹」取代「整文件哈希」：

1. **磁盘 PE 解析**（`pe.c`）：DOS/NT 头、节表、`.pdata` 展开信息（按 RVA 排序，提供函数边界）、`.reloc` 表（逐字节
   标出被重定位覆盖的字节）、`ImageBase/TimeDateStamp/SizeOfImage/CheckSum`、VERSIONINFO 里的 fileVersion。
2. **参考函数**：`builds.json` 的 reference 条目给出 buildId + RVA + size（本仓库钉住 `10.0.26100.9444` /
   RVA 0x31930 / 474 字节）。474 字节正是 `.pdata` 覆盖 0x31930 的范围（`[0x31930,0x31b0a)`），不是猜的。
3. **AOB 特征**（`fp_generate_aobs`）：函数体切 5 个 band，每 band 选一个 32 字节窗口，窗口内字节打分
   = 先最小化「不稳定字节数」、再最大化字节多样性。不稳定字节 = `.reloc` 覆盖字节 ∪ 启发式识别出的
   rel32（`E8/E9`、`0F 8x`）与 RIP-relative `disp32`（`48 8D/8B modrm=05`、`F6/F7 05`）操作数。这些字节在特征码里写成 `??`
   —— 它们恰好是「同一函数被重编译后唯一会变的字节」，其余字节做字面比对。
4. **归一化指纹**：整函数字节、把 `.reloc` 字节清零后 SHA-256（`fp_normalized_sha256`）。同时给出**对齐后逐字节相似度**
   （同一函数布局按偏移比较、跳过 reloc 字节，`fp_similarity`），并统计差异 run 数、**孤立 1 字节 run** 数。
5. **定位**：遍历候选的每个 `.pdata` 函数（长度 64..8192、边界严格按 `.pdata`，不会读越界），用参考 AOB 做容错扫描
   （字面字节完全一致=exact；≤2 处不一致=tolerant），再对命中函数算对齐相似度。评分 = exact×3 + tolerant；
   置信度 = **max(AOB 命中比例, 相似度)**；再加「领先第二名 ≥0.10」的裁决闸，模糊命中直接 `located:null`。
6. **判定**：
   - buildId 在 DB 且归一化哈希 == DB → `allow`（已知构建、函数未被改；A-mut-else 这类「文件别处变了」也放行）；
   - buildId 在 DB 但哈希不同 → `deny` + `targetChanged=true`（同构建函数被改）；
   - 未知 build 且定位成功：有「改动证据」（AOB 有缺 + 至少 1 个孤立 1 字节差异 run）→ `deny`+targetChanged；
     无证据且 sim ≥ 0.98 → `warn`；0.85..0.98 → `warn`（需人工确认/加入 DB）；<0.5 或定位失败 → `deny`（fail-closed）。
   - 孤立 1 字节 run 的依据：实测同一函数的跨构建漂移全部是 **2 字节成对**的 rel32/disp32 前缀（见 §4 数据），
     单字节孤立差异更像人为补丁 —— 这是启发式，不是证明（见 §5 局限）。

CLI 契约（统一契约实现）：`nsp-hook-validate --method crossbuild-fingerprint --reference <ref.exe> --candidate <cand.exe> --db tools/hook-validation/builds.json --json`
stdout 是单个 JSON 对象（method / reference / candidate / build / located / decision / targetChanged / checks[] / timingMs，
另附 buildKnown、similarity、dbBuildCount），分析完成即 exit 0。`--emit-entry` 用于「新构建入库」：重跑定位后输出可直接
粘贴进 builds.json 的条目（本仓库 9711 条目就是这样生成的）。

## 2. 与现有 NSP 的集成点（带 file:line）

| 位置 | 现状 | 建议 |
|---|---|---|
| `tools/endpoint-probe/Native-Hook.c:70` | `(char*)image+0x31930` 写死 | 换成 fingerprint locate 返回的 `rva`（见 INTEGRATION.md §1） |
| `tools/endpoint-probe/Native-Hook.c:71-72` | 16 字节序言 memcmp | 保留为第二道廉价闸；不作身份判据 |
| `tools/endpoint-probe/Native-Hook.c:83` | `MH_CreateHook(address,...)` | address 来自定位结果；定位失败则不 hook |
| `tools/endpoint-probe/Native-Hook-Control.c:72-74` | baseline 模式同样写死 +0x31930 | 同步改为 fingerprint 查表 |
| `tools/endpoint-probe/Native-Hook-Control.c:45-49,91-97` | 远端模块 TimeDateStamp/SizeOfImage/CheckSum 对比 | 保持不变：回答「驻留的是不是我验证过的文件」，与函数级指纹互补 |
| `tools/hook-validation/builds.json` | 新增 | per-build DB，可与配置一起经 FSA/Web 控制面分发 |

## 3. 实测（lab 8 个用例，8/8 通过）

命令：`python tools/hook-validation/Test-Validation.py --lab C:\WorkSpace\Claw\scratch\lead\nsp-branches\lab`
（原始 JSON：`out/results.json`）

| 用例 | 候选 | decision | targetChanged | 定位 RVA | similarity | 耗时 ms | 结果 |
|---|---|---|---|---|---|---|---|
| A-self | build-26100.9444 | allow | false | 0x31930 | 1.0000 | 5.8 | PASS |
| A-mut-else | A-mut-else（无关 section 改 1B） | allow | false | 0x31930 | 1.0000 | 5.8 | PASS |
| A-mut-fn | A-mut-fn（函数体内改 1B） | deny | true | 0x31930 | 0.9979 | 6.1 | PASS |
| B-9711 | build-26100.9711（已入库） | allow | false | 0x31930 | 0.9916 | 5.9 | PASS |
| C-9974 | build-26100.9974 | warn | null | 0x32c40 | 0.9620 | 6.1 | PASS |
| D-9949 | system-26100.9949 | warn | null | 0x32c40 | 0.9620 | 6.1 | PASS |
| D-mut-fn | D-mut-fn（新构建函数体改 1B） | deny | true | 0x32c40 | 0.9599 | 6.1 | PASS |
| D-mut-else | D-mut-else（新构建无关 section 改 1B） | warn | null | 0x32c40 | 0.9620 | 6.9 | PASS |

关键点验证：
- **B/C/D 都能定位**：9974/9949 的目标函数从 0x31930 **移动**到 0x32c40，工具靠 AOB + 相似度自行找到（不依赖固定 RVA），
  9974/9949 内容相同，输出一致。
- **A-mut-fn 判 deny**：buildId 命中 DB，归一化哈希不匹配 → targetChanged；同时 AOB 4/5、孤立 1 字节 run=1（offset 96）双证据。
- **A-mut-else 判 allow**：整文件变了（无关 section），但目标函数归一化哈希与 DB 一致 → 粒度正确。
- **D-mut-fn 判 deny+targetChanged**：D 不在 DB（未知构建），靠「AOB 4/5 + 孤立 1 字节 run」判定疑似补丁，而不是靠整文件哈希。
- **9711 入库演示**：先 `--emit-entry` 生成条目（sha256 7969e0eb…、AOB 5 段），手工写入 builds.json；入库后 B 从 `warn` 变 `allow`。

## 4. 跨构建漂移实测数据（本 lab）

| 构建 | 目标函数 RVA | 与参考差异 | 差异形态 |
|---|---|---|---|
| 10.0.26100.9444（参考） | 0x31930 | 0 | — |
| 10.0.26100.9711 | 0x31930 | 4 字节（sim 0.9916） | 2 处 2 字节 rel32/disp32 |
| 10.0.26100.9974（=system-9949） | 0x32c40 | 18 字节（sim 0.9620） | 9 处 2 字节 rel32/disp32 |
| A-mut-fn | 0x31930 | 1 字节（sim 0.9979） | 1 个孤立单字节（offset 96） |
| D-mut-fn | 0x32c40 | 19 字节（sim 0.9599） | 9 处 2 字节 + 1 个孤立单字节（offset 96） |

即：**真正的跨构建变化是成对的操作数前缀漂移，人为补丁产生孤立单字节**。这就是判定规则里「孤立 run」启发式的经验基础。

## 5. 局限与误报

1. **单字节启发式会误报**：如果微软某次更新只改了函数里 1 个字节且不属于 rel32/disp32（例如改了常量），未知构建
   会被判 `deny+targetChanged`。这与「未知构建 + 确有改动」在语义上无法区分——工具的选择是 fail-closed（拒绝 + 提示人工确认），
   宁可误拒不可误挂。己知构建不受影响（走哈希）。
2. **AOB 选择依赖启发式**：rel32/disp32 识别是前缀模式匹配，不是完整反汇编；遇到新指令形式（如 `c7 05 disp32` 写 RIP 相对）
   可能漏标、导致某个窗口在跨构建时不命中。工具用容错命中 + 相似度兜底，且 5 段窗口里丢 1 段仍能定位（实测 A-mut-fn 4/5 照样定位）。
3. **函数大改（>25% 变化）会定位失败**：`.pdata` 边界保证不越界，但相似度会掉到低于裁决闸，输出 `located:null` + deny。
   这是有意的 fail-closed；需要人工为该构建生成新参考（`--emit-entry` + 人工确认 RVA 正确）。
4. **DB 是信任根**：`builds.json` 被篡改即可放行任意函数。真实部署应签名 DB（或用 FSA 的 ACL 保护），并与
   `Native-Hook-Control.c:45-49` 的远端模块身份校验叠加。
5. **不覆盖运行时 hook 检测**：本方法只回答「磁盘上这个函数是不是我期望的那个」，不检测进程内已被别人 inline hook
   （那属于另外的分支/方法）。
6. **buildId 依赖 VERSIONINFO**：若资源被剥掉则退化为 `0.0.<tds hi>.<tds lo>`，仍可工作但可读性差。

## 6. 耗时/复杂度

- 实测单次分析 **5.5–7.1 ms**（含两次 PE 解析、2900–2907 个 `.pdata` 函数遍历、5 段 AOB 容错扫描、SHA-256、JSON 输出）。
  复杂度 O(pdata 函数数 × 函数长度 × AOB 数)，本机约 5 MB 字节比较量级；无需反汇编、无需加载镜像到内存（纯磁盘解析）。
- 代码量：`pe.c` 约 250 行、`json.c` 约 210 行（自写最小 JSON 解析，无第三方）、`fp.c` 约 210 行、`main.c` 约 330 行；
  SHA-256 用系统 `bcrypt`，版本号用 `version.dll`，无任何第三方依赖。
- 新增构建步骤：`tools/hook-validation/Build.ps1`（gcc + `-municode -lbcrypt -lversion`，输出 `build/hook-validation/`）。
  直接运行需绕过执行策略：`powershell -NoProfile -ExecutionPolicy Bypass -File tools/hook-validation/Build.ps1`。

## 7. 如果只能选一种方法，为什么选/不选它

**选它的理由**：它是唯一能同时回答「函数在哪」和「函数有没有被改」的方法，且对 Windows 服务更新（函数移动 + 操作数漂移）
天然免疫；代价极小（毫秒级、无依赖、DB 只有几百字节/构建）。对 NSP 这种「必须有确定 hook 目标才能工作」的场景，
定位能力本身就是刚需——其它只比对整文件/整函数的哈希方法在新构建上只能 deny，等于每次系统更新后 NSP 都不可用。

**不选它的理由**：信任根从「单一硬编码哈希」变成「一个可被篡改的 DB + 启发式」，且未知构建的判定依赖经验规则
（孤立单字节），存在误报；如果团队只接受「零启发式、可形式化证明」的校验，应选纯哈希/纯序言类方法，代价是更新即失效。

**结论**：建议作为**默认方法**，并与「远端模块身份校验（TimeDateStamp/SizeOfImage/CheckSum）」叠加使用；
未知构建默认 fail-closed，交互式场景用 `warn` 提示用户确认后 `--emit-entry` 入库。
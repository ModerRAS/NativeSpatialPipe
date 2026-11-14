# 分支4：结构不变量（vtable 引用 + 字段访问模式）

分支：feat/hook-validate-structural-invariants（基于 alpha-dev @ 1679ed7）；方法名：structural-invariants。

## 方法/设计

不比对函数字节，而是验证「对象-管线结构」在构建间是否保持：

1. **PE 解析**（tools/hook-validation/pe.c）：.text/.pdata/.rdata/.data、ImageBase、SizeOfImage、CheckSum、TimeDateStamp、VS_FIXEDFILEINFO 版本号。
2. **函数候选集**：.pdata 全部 Begin（参考构建 2907 条）。
3. **代码指针引用**：扫描 .rdata/.data 中 8 字节 qword，值等于 ImageBase+某候选入口即记一条引用（参考构建 1704 条）。
4. **结构签名函数**：引用数 >=2 且函数体内出现 >=3 种字段位移常量 0x510/0x5d0/0x5d4/0x5d8（块字段，Native-Capture.c:33-35）与 0xC/0x14/0x28/0x38（描述符，Native-Capture.c:35-39）。位移必须是真的 disp32 内存操作数（disp32 前一字节 ModRM 的 mod 位 = 10），以压掉指令流误命中。三个构建里都**恰好 4 个**函数满足：大小 202/203/218/143，即「对象字段访问方法」。
5. **vtable 基址推断**：签名函数所在槽向前/向后走连续「指向 .text」的 8 字节条目得到 run 起点；参考构建槽位固定在 vt+0x18..0x30，故 vt_est = min(cluster slots) - 0x18（等价 run 起点 +0x350）。输出最有把握的 vtableRva 与槽号（checks.detail）。
6. **目标函数识别（参考构建校准）**：源码 Native-Hook.c:70 写死 image+0x31930。实测该函数被 **vtable 槽 +0x100（slot 32）** 引用（0x9f5f8 = 0x9f4f8+0x100），另有第二处引用坐标在 vt2 家族 run 内；函数体本身**没有**字段位移常量（与任务书字面表述不同，按实测改为「签名簇定位 vtable → vtable+0x100 定位目标」）。参考构建校验：两个已知 vtable 0x9f4f8/0xa2d58 窗口内各有 4 个签名槽，目标 0x31930 的槽 = 0x9f4f8+0x100。
7. **判定**：
   - 参考构建自身（同 TimeDateStamp/SizeOfImage/CheckSum）且结构/已知 vtable 匹配 → allow；
   - 其他候选但能定位出结构签名函数 + 目标槽（refs>=2）→ warn（checks 明写「结构匹配，但该方法不校验函数体字节」）；
   - 有部分结构但定位不出目标 → unknown；完全找不到签名 → deny。
   - targetChanged 恒为 null（本方法不判断函数体是否被改）。
8. CLI 遵守统一契约：--method structural-invariants --reference R --candidate C --json，stdout 单个 JSON，located.rva 给推断的 rva（参考构建 203056 = 0x31930），vtable/槽号在 checks.detail。

## 与现有 NSP 的集成点（详见 tools/hook-validation/INTEGRATION.md）

- tools/endpoint-probe/Native-Hook.c:70：目标地址 (char*)image+0x31930 → 结构定位器的 target（槽 vt1+0x100）。
- tools/endpoint-probe/Native-Hook.c:80：硬编码 0x9f4f8/0xa2d58 → 结构推断的 vt1/vt2（失败时对 9444 构建回退常量，否则 fail-closed）。
- tools/endpoint-probe/Native-Capture.c:31-32：vt!=c->vt1&&vt!=c->vt2 之外增加槽位签名（*(uintptr_t*)(vt+0x100) 必须落在 audiodg 镜像内）与六处字段探针计数（0x5d4/0x5d0/0x5d8/0x510/desc+0xC/desc+0x38），报告输出 structuralSignature。
- tools/hook-validation/Build.ps1（gcc）产物 build/hook-validation/nsp-hook-validate.exe；Test-Validation.py 可进 CI。

## 逐用例实测（stdout，8/8 合同用例符合预期）

```
structural-invariants regression: 8 cases, reference=audiodg-build-26100.9444.exe
case                   decision rva       size      sig   refs  ms      verdict
-------------------------------------------------------------------------------
reference-self         allow   0x31930    474       4     2     6.71    PASS
A-mut-else             allow   0x31930    474       4     2     6.80    PASS
A-mut-fn               allow   0x31930    474       4     2     6.77    PASS*   <- 本方法漏报（见局限）
B-build-26100.9711     warn    0x31930    474       4     2     7.70    PASS
C-build-26100.9974     warn    0x32c40    474       4     2     6.82    PASS
system-26100.9949      warn    0x32c40    474       4     2     7.37    PASS
D-mut-fn               warn    0x32c40    474       4     2     6.96    PASS*   <- 本方法漏报（见局限）
D-mut-else             warn    0x32c40    474       4     2     7.18    PASS
-------------------------------------------------------------------------------
passed=8/8  (* = 本方法预期局限：1 字节函数体改动不在覆盖范围内)
```

关键定位：B(9711) 目标 RVA 仍是 0x31930；C(9974)/system(9949)/D 系列目标移到 0x32c40，本方法靠 vtable 槽相对结构定位到它；结构签名函数在三个构建里始终 4 个。原始 JSON：tools/hook-validation/out/results.json。

## 局限与误报

1. **不校验函数体字节 → 1 字节函数体改动漏报**：A-mut-fn / D-mut-fn 改的是目标函数 +0x60 处（文件偏移 0x31990/0x32ca0），既不在 16 字节序言上，也不在字段位移常量上，结构签名完全不变 → 本方法给出 allow/warn，**不保证检出**。这是结构定位器的本质结果，已如实记录。
2. **校准依赖参考构建布局**：vt_est = min(cluster slots)-0x18 与目标槽 vt+0x100 来自 9444 实测；若未来 vtable 槽序改变，会报 warn/unknown 而不是错挂。签名函数不足 2 个或没有 vtable run 时同样 fail 到 deny/unknown。
3. **disp32 误命中**：用 ModRM mod=10 前导字节过滤后，参考构建 8 个常量在 2907 个函数里只筛出 4 个签名函数，未见额外误报；小常量 0xC/0x14/0x28/0x38 仍可能偶然命中真实 disp32 访问，故要求「>=3 种且被 vtable 引用 >=2 次」双条件。
4. **仅 x64/PE32+、仅 .rdata/.data 中的绝对指针**：不支持基址重定位后的加载镜像（运行时需按模块基址重算；静态分析正好匹配）。
5. 参考构建自身 allow 依赖 build 元数据而非 SHA-256；本方法本来就不做完整性承诺，完整性交给序言/函数体哈希分支。

## 耗时/复杂度

- 单次分析 6.7–7.7 ms（880 KB PE、2907 函数、1704 引用、8 个 disp32 常量全扫）。
- 复杂度 O(F·L + S)（函数数×平均函数长度 + 数据段 qword 数）；内存约 0.8 MB；静态单 exe，gcc 构建 <2 s。
- 实现量：pe.c ~230 行 + structural-invariants.c ~250 行 + main.c ~30 行。

## 如果只能选一种：选/不选它？

**不选它作为唯一校验器**。价值是「定位 + 结构连续性证明」：能在重编译构建里不靠固定 RVA 找到目标函数，并在 vtable 层证明对象管线仍是同一套结构，这是字节级方法做不到的；但它天生无法发现函数体内的 1 字节改动（A-mut-fn/D-mut-fn 漏报）。合理组合是 **structure 定位（本方法）+ 序言/关键字段编码校验（unwind-fn-hash 等）**：前者负责跨构建找对函数，后者负责函数体完整性。单独使用只适合「构建漂移兼容性检查」，不适合「反篡改门禁」。

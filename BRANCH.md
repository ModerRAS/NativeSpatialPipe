# BRANCH.md — 分支1：unwind 表定位 + 整函数规范化哈希

- 分支：feat/hook-validate-unwind-hash（基于 alpha-dev @ 1679ed7，已 push）
- 方法名（CLI --method）：unwind-fn-hash
- 产物：build/hook-validation/nsp-hook-validate.exe（gcc 构建，构建产物不入库）
- 语料：只读 lab 目录 8 个 audiodg.exe 变体 + 2 个补测用例（见 §3）

## 1. 方法 / 设计

### 1.1 要解决什么

NSP 用 MinHook 在 audiodg.exe 写死的 RVA 0x31930 上挂对象提交函数。现有防线是
整文件 SHA-256（tools/endpoint-probe/Native-Hook-Control.c:20）和 16 字节序言
（tools/endpoint-probe/Native-Hook.c:71-72），粒度都不对：

- 整文件 SHA 对「无关字节改变」误报：A-mut-else 只翻转 .reloc 里 1 个字节，整文件
  SHA 变但目标函数没动；
- 16B 序言太弱：A-mut-fn 只改函数体内 +0x60 处 1 字节，序言完全不变。

unwind-fn-hash 用 Windows 自己的权威元数据（.pdata 展开信息）把「函数」作为校验单元：
先由 .pdata 的 RUNTIME_FUNCTION 得到精确的 [Begin,End) 代码范围，再算整函数的
重定位规范化 SHA-256。

### 1.2 算法（实现：tools/hook-validation/src/pe.c、fn_hash.c、main.c）

1. **磁盘 PE32+ 解析**：DOS/COFF/Optional/Section 表；取 ImageBase、TimeDateStamp、
   SizeOfImage、CheckSum；读 Exception 目录（.pdata）与 BaseReloc 目录（.reloc）。
   全程边界检查，不经过 Windows 加载器，不需要目标进程运行。
2. **参考函数定位**：在参考 PE 的 .pdata 中找 Begin == 0x31930 的条目（要求精确相等），
   得 {Begin=0x31930, End=0x31b0a}；再校验 16 字节 NSP 序言
   （48 89 5c 24 08 48 89 6c 24 10 48 89 74 24 18 57）。参考函数 = {rva,size,hash}。
3. **规范化哈希**（fn_engine_hash）：
   - 取 [Begin,End) 的磁盘字节副本（474B）；
   - 遍历 .reloc 全部条目，把落在函数范围内的重定位目标按类型清零
     （IMAGE_REL_BASED_DIR64=8B、HIGHLOW=4B，其它类型保守按 4B，ABSOLUTE=0 跳过）——
     重定位写入的是随 ImageBase/布局变化的绝对地址，不抹掉则同一函数换个加载基址/重编译
     哈希就变；
   - BCrypt SHA-256（bcrypt.lib）输出 32B；返回 hash + size + 被抹掉的槽数。
4. **判定**（main.c，严格按任务书规则）：
   - buildId（TimeDateStamp+SizeOfImage+CheckSum）与参考相同 → 同构建：锁定同 RVA，
     要求序言一致 + 规范化哈希一致；哈希不一致 → decision=deny、targetChanged=true。
   - buildId 不同 → 遍历候选 .pdata 的全部函数（跳过空与 >8KB 的项），逐个算规范化哈希，
     找与参考哈希精确相等者 → located=rva、decision=allow，checks 写
     「cross-build exact function match」。
   - 找不到精确匹配：若候选在参考 RVA 处存在 .pdata 条目且 16B 序言匹配但哈希不同 →
     targetChanged=true、decision=deny；否则 decision=unknown、targetChanged=null。
5. **CLI 契约**：stdout 恒为单个 JSON 对象（method/reference/candidate/build/located/
   decision/targetChanged/checks/timingMs）；分析完成退出码 0（decision 不影响），
   参数/IO 错误退出码 2 且 stdout 为 {"error":...} JSON。额外支持 --ref-rva、
   --max-function-size（默认 8KB），用于补测/适配。

### 1.3 参考构建关键数字（实测）

| 项 | 值 |
|---|---|
| 参考文件 | audiodg-build-26100.9444.exe，SHA-256 3dd24fe6…a5（与 Native-Hook-Control.c:20 常量一致） |
| buildId | TimeDateStamp 0x966f569f / SizeOfImage 0xd7000 / CheckSum 0xe370e |
| .pdata 条目 | 2907 |
| .reloc 条目 | 4202（目标函数范围内 0 个） |
| 目标函数 | RVA 0x31930（203056），End 0x31b0a，size 474 |
| 规范化 SHA-256 | dcca7f47d116f64036da540d72a0226c8eeab859859b0dcb6df8e5b1ebf18013 |
| 16B 序言 | 48 89 5c 24 08 48 89 6c 24 10 48 89 74 24 18 57（Native-Hook.c:71） |

注意：该函数范围内没有 .reloc 目标，所以本次规范化哈希 == 原始 SHA-256；.reloc 掩码
机制在当前目标上是「为未来/为跨基址重定位保留」的正确性措施（见 §5.3）。

## 2. 逐用例结果（实测，stdout 表格 + out/results.json）

参考 = audiodg-build-26100.9444.exe（目标 RVA 0x31930）。hashHit = 参考函数规范化哈希是否
在候选中出现（normalizedHashMatch check）。

| # | candidate | decision | targetChanged | located.rva/size | hashHit | timingMs | 期望 | 结论 |
|---|---|---|---|---|---|---|---|---|
| 1 | audiodg-build-26100.9444.exe | allow | false | 0x31930/474 | yes | 1.282 | allow | PASS |
| 2 | audiodg-A-mut-else.exe | allow | false | 0x31930/474 | yes | 1.493 | allow | PASS |
| 3 | audiodg-A-mut-fn.exe | deny | true | 0x31930/474 | no | 1.467 | deny+changed | PASS |
| 4 | audiodg-build-26100.9711.exe | deny | true | 0x31930/474 | no | 6.466 | deny+changed（规则3） | PASS |
| 5 | audiodg-build-26100.9974.exe | unknown | null | null | no | 7.075 | unknown | PASS |
| 6 | audiodg-system-26100.9949.exe | unknown | null | null | no | 6.789 | unknown | PASS |
| 7 | audiodg-D-mut-else.exe | unknown | null | null | no | 6.198 | unknown | PASS |
| 8 | audiodg-D-mut-fn.exe | unknown | null | null | no | 6.534 | unknown | PASS |

补测（同一构建路径的有效性验证；参考=26100.9974，目标 RVA 0x32c40，474B）：

| # | candidate | decision | targetChanged | located.rva | timingMs | 期望 | 结论 |
|---|---|---|---|---|---|---|---|
| S1 | audiodg-D-mut-else.exe | allow | false | 0x32c40 | 1.373 | allow | PASS |
| S2 | audiodg-D-mut-fn.exe | deny | true | 0x32c40 | 1.308 | deny+changed | PASS |

汇总：8/8 主用例通过（按任务书判定规则），2/2 补测通过；CLI 错误契约通过
（不存在的候选 → exit 2 + {"error":"candidate PE load failed: cannot open file"}）。

语料内部证据（用于解释 §5）：
- A-mut-else：唯一改动在 .reloc 偏移（RVA 0xd4200）1 字节 0xe0→0x1f，目标函数未动；
  且 PE 头 buildId 未更新 —— 整文件 SHA 会拒、本方法 allow（粒度正确）。
- A-mut-fn：唯一改动 RVA 0x31990（目标函数内 +0x60）1 字节 0xb7→0x48。
- D-mut-else / D-mut-fn：base=26100.9974；D 的目标函数在 RVA 0x32c40（size 474），
  D-mut-fn 改的正是该函数内 +0x60 的 1 字节，D-mut-else 改 .reloc（RVA 0xd3200）。
- 9711：目标函数仍在 RVA 0x31930、size 474、序言相同，但函数体有 4 字节不同
  （偏移 330/331、340/341，两处 RIP 相对位移低 16 位变化，ratio 0.992）。
- 9974/system-9949（同一文件）：目标函数移动到 RVA 0x32c40（size 474），与参考函数
  474B 中 456B 相同、18B 不同（布局位移）。

## 3. 与现有 NSP 的集成点（详见 tools/hook-validation/INTEGRATION.md）

| 集成点 | 文件:行 | 改动 |
|---|---|---|
| 序言校验之后、MH_CreateHook 之前 | tools/endpoint-probe/Native-Hook.c:70-83 | 用磁盘 image_path 走 .pdata 定位+规范化哈希，钉死 26100.9444 的 rva/size/hash；同构建不一致 fail(41)，新构建无 exact-match fail(42)，分析失败 fail(40) |
| final_report 组装 | Native-Hook.c:45 | hookBytesRestored 从 memcmp(before,target,32) 改为整函数哈希复核；新增 targetFnRva/targetFnSize/targetFnSha256 |
| hook 状态上报 | Native-Hook.c:116 | 同上替换 32 字节 memcmp |
| 全局状态 | Native-Hook.c:20 | before[32] 由 target_size/target_hash/target_hash_hex 取代 |
| 注入前快照 | Native-Hook.c:83 | 删除 memcpy(before,address,32)（校验阶段已捕获） |
| baseline 子命令 | Native-Hook-Control.c:71-75 | 由只读 16B 序言升级为「磁盘 .pdata 期望 hash + ReadProcessMemory 读 size 字节 + 内存 SHA-256 比对」，输出 {baselineVerified,rva,size,sha256} |
| 构建 | tools/endpoint-probe/Build-NativeHook.ps1 的 DLL clang 行 | 追加 src/pe.c、src/fn_hash.c、-I tools/hook-validation/src、-lbcrypt |

设计取舍：hook DLL 不启动子进程，直接复用库（pe.c/fn_hash.c）；nsp-hook-validate.exe
只用于离线诊断/CI/语料对照。

## 4. 局限与误报（核心结论）

1. **对「已知构建」最强，对全新构建只能 exact-match。** 同构建内函数任何一个字节变化
   （包括热补丁/inline patch）都会被 474B 规范化哈希抓到（A-mut-fn：deny+changed）；
   无关 section/.reloc 的变化不影响判定（A-mut-else：allow）。这是本方法的价值所在。
2. **跨构建 exact-match 极脆弱：RIP 相对位移不在 .reloc 表里。** x64 函数体内对
   .rdata/其它函数的 rip-relative 引用没有重定位项，重编译后布局一变位移就变。
   9711 与参考目标函数 size/RVA/序言都相同，仅 4 字节位移变化 → 哈希完全不同。
   按任务书规则 3（同 RVA+序言匹配但哈希不同）本方法给 **deny+targetChanged=true**，
   但这其实是一个**合法的新构建被重编译** → 属于保守误报。若要让它对新构建友好，
   应把这条信号降级为 warn+人工确认（或交给分支3的 AOB/相似度方法定位）。
   本分支保留任务书规则的字面实现，并把误报如实记录在此。
3. **目标移动的新构建（9974/system-9949/D 系）→ unknown，located=null。** 精确哈希扫描
   无法找到「相似但不等」的函数（9974 与参考差 18B）；本方法不做相似度定位，这是
   分支3（crossbuild-fingerprint）的职责。
4. **D-mut-fn 用 9444 参考无法检出（unknown）。** 没有 per-build DB 时，D 构建的期望
   函数不在数据库中，改 1 字节也不会与参考哈希相等。补测证明：参考换成 9974
   （目标 RVA 0x32c40）后 D-mut-else=allow、D-mut-fn=deny+changed —— 只要把新构建的
   指纹入库，同构建防篡改能力立即生效。这也是生产建议（per-build pin）。
5. **A-mut-else 的 buildId 与参考完全相同**（TimeDateStamp/SizeOfImage/CheckSum 未更新），
   说明 buildId 门单独用会漏报，而函数哈希能正确 allow（函数没变）；反过来 A-mut-fn
   的 buildId 也相同，buildId 门会 allow（漏报），函数哈希 deny。两者互补。
6. **热补丁 / inline patch**：同一构建内任何对目标函数的字节写入都会导致 deny（哈希不
   匹配）；但如果服务更新换了构建，方法只会给 unknown/deny，不会误 allow。
7. **跨编译器版本 / 函数被拆链**：跨编译器重编译几乎必然改变字节（哈希不同）→ 新构建
   需要 exact-match 或人工确认；.pdata 缺失/被篡改、chained unwind（同名 Begin 多段）
   本实现只取 Begin==RVA 的条目、不支持拼接，会 unknown/deny（fail closed，安全方向）。
8. **规范化只为重定位服务，不解决位移漂移。** 它抹掉 .reloc 覆盖的绝对地址字节
   （跨 ImageBase 重定位），但抹不掉 rip-relative 位移；当前目标函数 0 个 .reloc 目标，
   故等价原始 SHA-256。误报面：若函数内有 HIGHLOW/DIR64 绝对地址且被清零，理论上
   碰撞空间略增（SHA-256 下可忽略）。
9. **函数 >8KB 被跳过**（本目标 474B 不受影响）；扫描是「参考哈希在候选中出现」的
   单向精确匹配，不校验候选函数个数/位置唯一性（哈希碰撞概率可忽略，但语义上若未来
   出现完全相同字节的第二份函数会被判 allow，located 取第一个命中）。
10. **跨构建 allow 的语义边界**：exact-match 只证明「函数内容相同」，不证明写死 RVA
    0x31930 还能用。新构建下必须用 located.rva 重新计算 hook 地址，否则会 hook 错位置。
11. 解析限制：仅 PE32+ x64、文件 ≤512MB、节 ≤96 —— audiodg 满足；非 PE/损坏文件 →
    exit 2 + JSON error（不会静默 allow）。

## 5. 耗时 / 复杂度

| 场景 | 实测 | 说明 |
|---|---|---|
| 同构建（含自身/A-mut-*） | 1.28–1.49 ms | 2 次整文件读 + 2 次 PE 解析 + .reloc 索引 + 1 次 474B 哈希 |
| 跨构建（9711/9974/D 系） | 6.20–7.08 ms | 遍历 2880–2900 个 .pdata 函数、逐个 SHA-256（974–996KB 字节总量） |
| 补测同构建（9974 参考） | 约 1.3 ms | 同上构建 |

复杂度 O(F × (S + R))：F=.pdata 条目数（~2900），S=函数平均大小，R=.reloc 条目数
（~4200，逐函数线性扫，可优化为按 RVA 排序二分）；内存 ≈ 整文件 + 2×最大函数（<1MB）。
生产建议：启动时一次性校验（~1ms 同构建），不在热路径；跨构建扫描只在新构建首次
出现时执行，结果可缓存成 per-build 指纹。

## 6. 如果只能选一种，选不选它？

**作为唯一方法：不选。** 理由：

- 它是「同构建防篡改」的最强证据：unwind 表是 Windows 自己的权威函数边界，474B 整函数
  哈希 + 序言 + buildId，1ms 级、误报低、fail closed；A-mut-fn 这种序言不变的函数体
  单字节改动也能抓到，这是整文件 SHA（会因无关字节误报）和 16B 序言（漏报）都做不到的。
- 但它跨构建基本不可用：Windows 频繁 servicing，任何新构建都会因重编译位移导致
  exact-match 失败 → unknown（而 9711 这类同 RVA 重编译甚至会给 deny，属保守误报）。
  「只能选一种」时选它意味着每次 Windows 更新 audiodg 都要人工放行/发新版钉常量，
  UX 不可接受；且它无法把「合法重编译」和「函数被改」区分开。
- 若只能选一种且必须跨构建可用，应选分支3（crossbuild-fingerprint：AOB + 相似度 +
  per-build DB），代价是安全性弱于整函数哈希（相似度阈值可被刻意规避）。
- **推荐组合**：分支2 的 buildId+签名门做第一层（快速识别已知/未知构建），
  已知构建用本方法的函数哈希 fail-closed（分支1），新构建用分支3 定位+相似度
  warn 后人工确认/入 DB，入库后本方法立即获得对新构建的同构建防篡改能力。

## 7. 复现

~~~powershell
# 构建（gcc；产物在 build/hook-validation/）
powershell -NoProfile -ExecutionPolicy Bypass -File tools/hook-validation/Build.ps1

# 8 个主用例 + 2 个补测，打印表格并写 out/results.json
python tools/hook-validation/Test-Validation.py

# 单次调用
build/hook-validation/nsp-hook-validate.exe --method unwind-fn-hash --reference <ref.exe> --candidate <cand.exe> --json

# 补测：参考换成 9974（目标函数在 0x32c40）
build/hook-validation/nsp-hook-validate.exe --method unwind-fn-hash --reference <9974.exe> --candidate <D-mut-fn.exe> --json --ref-rva 32c40
~~~

lab 语料假定位于本 worktree 的同级目录 ../lab（Test-Validation.py 自动推算）；如语料位置
不同，直接对单次调用传路径即可。构建/运行只需 gcc 16.1 + Python 3.14（stdlib），无网络、
无第三方包。

## 8. 交付文件清单

| 文件 | 内容 |
|---|---|
| tools/hook-validation/src/pe.h / pe.c | 磁盘 PE32+ 解析（DOS/COFF/Optional/Sections/.pdata/.reloc/ImageBase/buildId） |
| tools/hook-validation/src/fn_hash.h / fn_hash.c | .pdata 精确查找、.reloc 规范化 SHA-256（BCrypt）、.pdata 全表 exact 扫描、fn_sha256_bytes 内存哈希 |
| tools/hook-validation/src/main.c | nsp-hook-validate.exe CLI（unwind-fn-hash，单 JSON 输出，退出码契约） |
| tools/hook-validation/Build.ps1 | gcc -O2 -std=c11 ... -lbcrypt -lversion -lshell32 → build/hook-validation/ |
| tools/hook-validation/Test-Validation.py | 8 主用例 + 2 补测 + CLI 错误契约；stdout 表格 + out/results.json |
| tools/hook-validation/out/results.json | 本次实测结果（含逐检查项、timing、补测），随库提交作证据 |
| tools/hook-validation/README.md | 构建/运行/测试速览 |
| tools/hook-validation/INTEGRATION.md | Native-Hook.c:20/45/54/70-83/116、Native-Hook-Control.c:71-75 的最小改动方案与代码 |
| BRANCH.md | 本文件 |

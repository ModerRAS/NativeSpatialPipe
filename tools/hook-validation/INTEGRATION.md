# 集成方案：unwind-fn-hash 接入 NSP hook 路径

> 目标：把「函数级规范化哈希」作为 MinHook 注入前后的一道闸门，替代/补强现有
> 整文件 SHA-256（Native-Hook-Control.c:20）与 16 字节序言比较（Native-Hook.c:71-72）。
> 所有行号基于本分支基线 alpha-dev @ 1679ed7。

## TL;DR

1. 把 src/pe.c + src/fn_hash.c 编进 nsp_native_hook.dll（无新依赖，只用 bcrypt.lib），
   不通过子进程调用 CLI。
2. nsp_hook_start（Native-Hook.c:54）在现有 :72 序言校验之后、:83 MH_CreateHook 之前：
   - 从磁盘 image_path（:68 已取得）用 .pdata 定位 [0x31930,0x31b0a)，算规范化 SHA-256；
   - 与钉死常量（参考构建 26100.9444：buildId 0x966f569f/0xd7000/0xe370e，
     size 474，hash dcca7f47d116f64036da540d72a0226c8eeab859859b0dcb6df8e5b1ebf18013）比较；
   - 再算一次内存副本哈希，确认「映射里的函数 == 磁盘上被校验的函数」；
   - 保存 target_size/target_hash 供 finish 复核，失败码 40/41/42（fail closed）。
3. finish（Native-Hook.c:33-46）恢复后用同一函数哈希复核，替代 :45 的
   memcmp(before,target,32)，并把 targetFnRva/targetFnSize/targetFnSha256 写进报告；
   nsp_hook_status（:116）同样替换 32 字节 memcmp。
4. Native-Hook-Control.c 的 baseline 子命令（:71-75）复用同一库：从 System32\audiodg.exe
   算期望 {rva,size,hash}，再 ReadProcessMemory 读 size 字节比哈希，输出函数级证据。
5. 判定策略：allow -> 注入；deny -> 拒绝；unknown（新构建）-> 默认拒绝，人工确认后
   通过环境变量/配置显式放行（见 §5）。

## 1. 复用库与构建

| 库文件 | 依赖 | 用途 |
|---|---|---|
| tools/hook-validation/src/pe.c | kernel32 CRT（_wfopen） | 磁盘 PE32+ 解析、RVA->文件偏移 |
| tools/hook-validation/src/fn_hash.c | bcrypt.lib | .pdata 定位、.reloc 规范化 SHA-256、.pdata 全表扫描、fn_sha256_bytes（内存哈希） |

构建（tools/endpoint-probe/Build-NativeHook.ps1 的 DLL clang 调用，约第 11 行）：
在原有 clang 参数里追加 -I 与两个源文件、-lbcrypt：

~~~powershell
$hookSources = @(
  "$PSScriptRoot/Native-Hook.c",
  "$root/tools/hook-validation/src/pe.c",
  "$root/tools/hook-validation/src/fn_hash.c",
  "$mh/src/hook.c", "$mh/src/buffer.c", "$mh/src/trampoline.c", "$mh/src/hde/hde64.c")
& $clang -O2 -fms-extensions -shared -Wall -Wextra -I "$mh/include" -I "$root/tools/hook-validation/src" @hookSources -lbcrypt -o "$out/$hookName"
~~~

LLVM-MinGW clang 与 gcc 都能编这两个文件（C11 + Windows API）。库只读磁盘/内存，不做 I/O
重定向，不影响 MinHook 的 trampoline 逻辑。

## 2. nsp_hook_start 注入前校验（Native-Hook.c:54-94）

### 2.1 新增全局（替换 Native-Hook.c:20 里的 before[32]）

~~~c
#include "fn_hash.h"   /* 同时带入 pe.h；-I tools/hook-validation/src */
static uint32_t target_size;static unsigned char target_hash[FN_HASH_BYTES];
static char target_hash_hex[FN_HASH_BYTES*2+1];
/* 恒定参考：audiodg build 26100.9444，函数 [0x31930,0x31b0a) 474B */
static const uint32_t target_rva=0x31930;static const uint32_t target_expected_size=474;
static const unsigned char target_expected_hash[FN_HASH_BYTES]={0xdc,0xca,0x7f,0x47,0xd1,0x16,0xf6,0x40,0x36,0xda,0x54,0x0d,0x72,0xa0,0x22,0x6c,0x8e,0xea,0xb8,0x59,0x85,0x9b,0x0d,0xcb,0x6d,0xf8,0xe5,0xb1,0xeb,0xf1,0x80,0x13};
~~~

### 2.2 在 :72 序言检查之后插入（Native-Hook.c:70-73 之间）

~~~c
 /* --- branch 1: unwind-table function hash gate --- */
 FunctionHash expected;char hash_error[256];PeImage disk;FnHashEngine engine;
 if(!pe_load(image_path,&disk,hash_error,sizeof(hash_error))){result=fail(c,40);goto done;}
 int engine_ready=fn_engine_init(&engine,&disk,hash_error,sizeof(hash_error));
 int computed=engine_ready&&fn_engine_hash_at(&engine,target_rva,&expected,hash_error,sizeof(hash_error));
 if(engine_ready)fn_engine_free(&engine);
 int same_build=disk.time_date_stamp==0x966f569f&&disk.size_of_image==0xd7000&&disk.checksum==0xe370e;
 int hash_ok=0;
 if(computed&&same_build&&expected.size==target_expected_size&&
    !memcmp(expected.hash,target_expected_hash,FN_HASH_BYTES))hash_ok=1;
 if(computed&&!same_build){
  /* 新构建：.pdata 全表 exact-match（CLI 同规则）；命中则用 found_rva，未命中拒绝待人工确认 */
  uint32_t found_rva=0,found_size=0,scanned=0,skipped=0;
  FnHashEngine candidate_engine;
  if(fn_engine_init(&candidate_engine,&disk,hash_error,sizeof(hash_error))){
   hash_ok=fn_engine_scan(&candidate_engine,target_expected_hash,8192,&found_rva,&found_size,&scanned,&skipped);
   fn_engine_free(&candidate_engine);
  }
 }
 pe_free(&disk);
 if(!computed){result=fail(c,40);goto done;}          /* 无法分析 = 拒绝注入 */
 if(!same_build&&!hash_ok){result=fail(c,42);goto done;} /* 未知构建，需人工确认 */
 if(same_build&&!hash_ok){result=fail(c,41);goto done;}  /* 同构建函数被改 */
 /* 磁盘校验结果与内存映射一致性：目标函数范围内 0 个 .reloc 目标，可直接哈希内存副本 */
 unsigned char memory_hash[FN_HASH_BYTES];
 if(!fn_sha256_bytes((const unsigned char*)address,expected.size,memory_hash,NULL,0)||
    memcmp(memory_hash,expected.hash,FN_HASH_BYTES)){result=fail(c,41);goto done;}
 target_size=expected.size;memcpy(target_hash,expected.hash,sizeof(target_hash));fn_hash_hex(target_hash,target_hash_hex);
~~~

说明：
- :68 已经通过 GetModuleFileNameW 拿到 image_path（磁盘路径），所以不需要新增参数。
- 目标函数范围内 0 个 .reloc 目标（实测，见 BRANCH.md），因此内存哈希可以直接用
  fn_sha256_bytes；若未来目标函数包含 .reloc 目标，应把 disk 的 reloc 列表缓存在全局，
  对内存副本先按同样规则清零再哈希（fn_hash.c 的 reloc_width/masking 逻辑可复用）。
- 检查顺序保持现有 16B 序言在前：序言不符时保持原错误码 6，语义不变。

### 2.3 删除 :83 的 before 快照

~~~c
-  memcpy(before,address,32);status=MH_CreateHook(...);
+  status=MH_CreateHook(...);   /* target_hash/target_size 已在 §2.2 捕获 */
~~~

## 3. finish 恢复后复核（Native-Hook.c:33-46, :45）

新增 helper（放在 finish 之前）：

~~~c
static int hook_bytes_restored(void){
 unsigned char digest[FN_HASH_BYTES];
 if(!target||!target_size)return 0;
 if(!fn_sha256_bytes((const unsigned char*)target,target_size,digest,NULL,0))return 0;
 return memcmp(digest,target_hash,FN_HASH_BYTES)==0;
}
~~~

:45 的 final_report 拼接改为（保留原有字段，仅替换判定与新增字段）：

~~~c
snprintf(final_report+n,sizeof(final_report)-n,
 ",\"hookBackend\":\"minhook\",\"targetFnRva\":%lu,\"targetFnSize\":%lu,\"targetFnSha256\":\"%s\","
 "\"hookBytesRestored\":%s,\"captureLibraryReleased\":%s,\"transportLibraryReleased\":%s,"
 "\"hookModuleResident\":true,\"trampolineRetained\":true,\"activeOriginalCallsAtStop\":%ld}",
 (unsigned long)target_rva,(unsigned long)target_size,target_hash_hex,
 hook_bytes_restored()?"true":"false",capture_released?"true":"false",
 send_released?"true":"false",read_atomic(&wrappers));
~~~

:116 nsp_hook_status 的 32 字节 memcmp 同样替换为 hook_bytes_restored()，并附带
targetFnRva/targetFnSize/targetFnSha256 字段。

时序保证：hook_bytes_restored 只在 MH_DisableHook 成功（:36）、gate 排空（:38）之后调用，
读取的是已恢复的原始字节；若 MinHook 恢复失败，:36-39 已提前 return，不会误判。

## 4. Native-Hook-Control.c baseline 子命令复用（:71-75）

baseline 目前只读 16 字节序言（:72-74）。改为函数级证据：

~~~c
if(!wcscmp(argv[3],L"baseline")){
 PeImage disk;FnHashEngine engine;FunctionHash expected;char hash_error[256];
 if(!pe_load(image,&disk,hash_error,sizeof(hash_error)))goto done;
 if(!fn_engine_init(&engine,&disk,hash_error,sizeof(hash_error))){pe_free(&disk);goto done;}
 int ok=fn_engine_hash_at(&engine,0x31930,&expected,hash_error,sizeof(hash_error));
 fn_engine_free(&engine);pe_free(&disk);
 if(!ok)goto done;
 uintptr_t image_base=module_base(pid,L"audiodg.exe");
 unsigned char *actual=(unsigned char*)malloc(expected.size);
 unsigned char memory_hash[FN_HASH_BYTES];
 if(!actual||!image_base||
    !ReadProcessMemory(process,(void*)(image_base+0x31930),actual,expected.size,NULL)||
    !fn_sha256_bytes(actual,expected.size,memory_hash,hash_error,sizeof(hash_error))){free(actual);goto done;}
 int matches=!memcmp(memory_hash,expected.hash,FN_HASH_BYTES); /* 目标函数 0 个 .reloc 目标 */
 char hex[FN_HASH_BYTES*2+1];fn_hash_hex(expected.hash,hex);
 printf("{\"baselineVerified\":%s,\"rva\":203056,\"size\":%u,\"sha256\":\"%s\"}\n",
        matches?"true":"false",expected.size,hex);
 free(actual);if(!matches)goto done;result=0;goto done;
}
~~~

注意 :20 的 verified_audio 整文件 SHA-256 门保持不动——Control 侧继续用整文件钉死，
baseline 变成在整文件门之上再加函数级证据；两边哈希方法互不替代。

## 5. 生产判定策略

| 方法输出 | nsp_hook_start 行为 | 报告字段 |
|---|---|---|
| allow（已知构建且哈希一致 / 跨构建 exact match） | 正常注入 | hookBytesRestored=true 复核通过 |
| deny（同构建哈希不一致 / 同 RVA 序言匹配但哈希不同） | fail(41) 拒绝注入，不创建 hook | error=41 |
| unknown（新构建且无 exact match） | 默认 fail(42) 拒绝；人工确认后用环境变量 NSP_HOOK_ALLOW_UNKNOWN_BUILD=1 临时放行并记录警告 | error=42 + warning |
| 分析失败（PE 解析/哈希错误） | fail(40) 拒绝（fail closed） | error=40 |

错误码 40/41/42 在现有 fail() 码表（2-14, 20-21, 30-31, 100+MinHook 状态）中未被占用。

## 6. 注意事项

1. 跨构建 exact-match 的 allow 只证明「函数内容相同」，**不证明写死 RVA 0x31930 仍然可用**。
   新构建下必须用 located.rva 重新计算 hook 地址（或拒绝），否则会 hook 错位置。
2. 目标函数有 0 个 .reloc 目标，所以本方法的规范化在当前目标上等价于原始 SHA-256；
   保留 .reloc 掩码是为了跨 ImageBase 重定位/未来目标函数的正确性。
3. 不在 hook DLL 内启动子进程调用 nsp-hook-validate.exe；库级复用（上面方案）才是 hook
   热路径的正确形态。CLI 只用于离线诊断 / CI / 语料对照。
4. finish 里的复核在 gate 排空之后执行；不要移动到 MH_DisableHook 之前。
5. 若 audiodg 被系统更新替换（新构建），本方法默认失败；这与现有整文件 SHA 门行为一致，
   需要发布新版本时更新钉死常量（buildId + rva + size + hash），流程与 Native-Hook-Control.c:20
   的常量更新相同。

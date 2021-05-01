
typedef PVOID (NTAPI * dll_inject_LoadLibraryA)(char *lpLibFileName);
typedef PVOID (NTAPI * dll_inject_GetProcAddress)(PVOID hModule, char *lpProcName);

#ifdef _X86_

#define DLL_INJECT_PEB_IMAGE_BASE_OFFEST   0x08
#define DLL_INJECT_PEB_LDR_TABLE_OFFSET    0x0C 

#else _AMD64_

#define DLL_INJECT_PEB_IMAGE_BASE_OFFEST   0x10
#define DLL_INJECT_PEB_LDR_TABLE_OFFSET    0x18

#endif


extern "C"
{
    ULONG NTAPI dll_inject_shellcode(PVOID Param);    
    ULONG NTAPI dll_inject_CalcHash(char *lpszString);
    PVOID NTAPI dll_inject_GetModuleAddressByHash(ULONG ModuleHash);
    PVOID NTAPI dll_inject_GetProcAddressByHash(PVOID Image, ULONG ProcHash);
    BOOLEAN NTAPI dll_inject_ProcessRelocs(PVOID Image, PVOID NewBase);
    BOOLEAN NTAPI dll_inject_ProcessImports(PVOID Image);
    void NTAPI dll_inject_shellcode_end(void);
};

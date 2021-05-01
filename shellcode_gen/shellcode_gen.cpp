#include "stdafx.h"
//--------------------------------------------------------------------------------------
int _tmain(int argc, _TCHAR* argv[])
{
    int ret = -1;

    if (argc >= 3 && !strcmp(argv[1], "--test"))
    {
        char *lpszPath = argv[2];

        printf("[+] DLL file: %s\n", lpszPath);

        HANDLE hFile = CreateFile(lpszPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
        if (hFile != INVALID_HANDLE_VALUE)
        {
            DWORD Size = GetFileSize(hFile, NULL);

            printf("[+] DLL size: %d bytes\n", Size);

            PVOID Data = LocalAlloc(LMEM_FIXED, Size);
            if (Data)
            {
                DWORD Readed = 0;

                if (ReadFile(hFile, Data, Size, &Readed, NULL))
                {
                    printf("[+] Running shellcode...\n");

                    // test the shellcode to load specified DLL image
                    DWORD Code = dll_inject_shellcode(Data);

                    printf("[+] Exit code 0x%.8x\n", Code);

                    ret = 0;
                }

                LocalFree(Data);
            }

            CloseHandle(hFile);
        }
        else
        {
            printf("ERROR: CreateFile() fails\n");
        }        
    }
    else if (argc >= 3 && !strcmp(argv[1], "--generate"))
    {
        char *lpszPath = argv[2];

        printf("[+] Output file: %s\n", lpszPath);

        HANDLE hFile = CreateFile(lpszPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
        if (hFile != INVALID_HANDLE_VALUE)
        {
            PVOID Shellcode = (PVOID)&dll_inject_shellcode;
            DWORD ShellcodeSize = (DWORD)((DWORD_PTR)&dll_inject_shellcode_end - (DWORD_PTR)&dll_inject_shellcode);
            DWORD Written = 0;

            printf("[+] Shellcode size: %d bytes\n", ShellcodeSize);

            // write shellcode into the output file
            if (WriteFile(hFile, Shellcode, ShellcodeSize, &Written, NULL))
            {
                printf("[+] DONE\n");

                ret = 0;
            }

            CloseHandle(hFile);
        }
        else
        {
            printf("ERROR: CreateFile() fails\n");
        }
    }
    else if (argc >= 4 && !strcmp(argv[1], "--hash"))
    {
        char *lpszName = argv[2];
        char *lpszData = argv[3];

        // calculate the hash used shellcode imports
        printf("#define %s 0x%.8x // \"%s\"\r\n", lpszName, dll_inject_CalcHash(lpszData), lpszData);

        ret = 0;
    }

	return ret;
}
//--------------------------------------------------------------------------------------
// EoF

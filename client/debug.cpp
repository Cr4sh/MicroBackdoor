#include "stdafx.h"
//--------------------------------------------------------------------------------------
#ifdef DBG
//--------------------------------------------------------------------------------------
typedef int(__cdecl * func_sprintf)(LPSTR, LPCSTR, ...);
typedef int(__cdecl * func_vsprintf)(LPSTR, LPCSTR, va_list arglist);
typedef int(__cdecl * func__vscprintf)(const char *format, va_list argptr);

static func_sprintf f_sprintf = NULL;
static func_vsprintf f_vsprintf = NULL;
static func__vscprintf f__vscprintf = NULL;

BOOL DbgMsg(char *lpszMsg, ...)
{
    if (f_sprintf == NULL || f_vsprintf == NULL || f__vscprintf == NULL)
    {
        HMODULE hCrt = LoadLibraryA("msvcrt.dll");
        if (hCrt == NULL)
        {
            return FALSE;
        }

        if ((f_sprintf = (func_sprintf)GetProcAddress(hCrt, "sprintf")) == NULL)
        {
            return FALSE;
        }

        if ((f_vsprintf = (func_vsprintf)GetProcAddress(hCrt, "vsprintf")) == NULL)
        {
            return FALSE;
        }

        if ((f__vscprintf = (func__vscprintf)GetProcAddress(hCrt, "_vscprintf")) == NULL)
        {
            return FALSE;
        }
    }

    va_list mylist;
    va_start(mylist, lpszMsg);

    int len = f__vscprintf(lpszMsg, mylist) + 1;

    char *lpszBuff = (char *)M_ALLOC(len);
    if (lpszBuff == NULL)
    {
        va_end(mylist);
        return FALSE;
    }

    f_vsprintf(lpszBuff, lpszMsg, mylist);
    va_end(mylist);

    OutputDebugStringA(lpszBuff);

    HANDLE hStd = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hStd != INVALID_HANDLE_VALUE)
    {
        DWORD dwWritten = 0;
        WriteFile(hStd, lpszBuff, (int)strlen(lpszBuff), &dwWritten, NULL);
    }

    M_FREE(lpszBuff);
    
    return TRUE;
}
//--------------------------------------------------------------------------------------
#endif
//--------------------------------------------------------------------------------------
// EoF

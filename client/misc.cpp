#include "stdafx.h"
//--------------------------------------------------------------------------------------
PTOKEN_USER GetProcessUser(HANDLE hProcess)
{
    PTOKEN_USER UserInformation = NULL;
    HANDLE hToken;

    // open token
    if (OpenProcessToken(hProcess, TOKEN_QUERY, &hToken))
    {
        DWORD ReturnLength = 0;
        // query size
        if (!GetTokenInformation(hToken, TokenUser, NULL, 0, &ReturnLength) &&
            GetLastError() == ERROR_INSUFFICIENT_BUFFER)
        {
            if (ReturnLength > 0)
            {
                // allocate memory for data
                UserInformation = (PTOKEN_USER)M_ALLOC(ReturnLength);
                if (UserInformation)
                {
                    // query data
                    if (!GetTokenInformation(hToken, TokenUser, UserInformation, ReturnLength, &ReturnLength))
                    {
                        DbgMsg("GetTokenInformation() ERROR %d\n", GetLastError());
                        M_FREE(UserInformation);
                    }
                }
                else
                {
                    DbgMsg(__FILE__, __LINE__, "M_ALLOC() ERROR %d\n", GetLastError());
                }
            }
        }
        else
        {
            DbgMsg("GetTokenInformation() ERROR %d\n", GetLastError());
        }

        CloseHandle(hToken);
    }
    else
    {
        DbgMsg("OpenProcessToken() ERROR %d\n", GetLastError());
    }

    return UserInformation;
}
//--------------------------------------------------------------------------------------
DWORD GetProcessIntegrity(void)
{
    DWORD dwRet = 0;

    OSVERSIONINFOEX VersionInfo;
    ZeroMemory(&VersionInfo, sizeof(VersionInfo));
    VersionInfo.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);

    if (!GetVersionExA((LPOSVERSIONINFO)&VersionInfo))
    {
        DbgMsg("GetVersionEx() ERROR %d\n", GetLastError());
        return 0;
    }

    // check for Vista and later
    if (VersionInfo.dwPlatformId == VER_PLATFORM_WIN32_NT &&
        VersionInfo.dwMajorVersion > 5)
    {
        HANDLE hToken = NULL;

        if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
        {
            DWORD dwSize = 0;

            // determine information length
            if (!GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &dwSize) &&
                GetLastError() == ERROR_INSUFFICIENT_BUFFER)
            {
                PTOKEN_MANDATORY_LABEL TokenInfo = (PTOKEN_MANDATORY_LABEL)M_ALLOC(dwSize);
                if (TokenInfo)
                {
                    // get an actual information
                    if (GetTokenInformation(hToken, TokenIntegrityLevel, TokenInfo, dwSize, &dwSize))
                    {
                        // get the integrity level
                        dwRet = *GetSidSubAuthority(
                            TokenInfo->Label.Sid,
                            (DWORD)(*GetSidSubAuthorityCount(TokenInfo->Label.Sid) - 1)
                        );
                    }
                    else
                    {
                        DbgMsg("GetTokenInformation() ERROR %d\n", GetLastError());
                    }

                    M_FREE(TokenInfo);
                }
                else
                {
                    DbgMsg(__FILE__, __LINE__, "M_ALLOC() ERROR %d\n", GetLastError());
                }
            }
            else
            {
                DbgMsg("GetTokenInformation() ERROR %d\n", GetLastError());
            }

            CloseHandle(hToken);
        }
        else
        {
            DbgMsg("OpenProcessToken() ERROR %d\n", GetLastError());
        }
    }

    return dwRet;
}
//--------------------------------------------------------------------------------------
BOOL CheckForAdminUser(void)
{
    BOOL bRet = FALSE;

    OSVERSIONINFOEX VersionInfo;
    ZeroMemory(&VersionInfo, sizeof(VersionInfo));
    VersionInfo.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);

    if (!GetVersionExA((LPOSVERSIONINFO)&VersionInfo))
    {
        DbgMsg("GetVersionEx() ERROR %d\n", GetLastError());
        return FALSE;
    }

    // check for Vista and later
    if (VersionInfo.dwPlatformId == VER_PLATFORM_WIN32_NT &&
        VersionInfo.dwMajorVersion > 5)
    {
        HANDLE hToken = NULL;

        // perform checking by process toke membership
        if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
        {
            TOKEN_ELEVATION_TYPE TokenElevation;
            DWORD dwSize = 0;

            if (!GetTokenInformation(hToken, TokenElevationType, &TokenElevation, sizeof(TokenElevation), &dwSize))
            {
                DbgMsg("GetTokenInformation() ERROR %d\n", GetLastError());
                CloseHandle(hToken);
                return FALSE;
            }

            if (TokenElevation == TokenElevationTypeLimited)
            {
                HANDLE hLinkedToken = NULL;

                if (!GetTokenInformation(hToken, TokenLinkedToken, (PVOID)&hLinkedToken, sizeof(HANDLE), &dwSize))
                {
                    DbgMsg("GetTokenInformation() ERROR %d\n", GetLastError());
                    CloseHandle(hToken);
                    return FALSE;
                }

                BYTE AdminSID[SECURITY_MAX_SID_SIZE];
                DWORD dwSidSize = sizeof(AdminSID);

                if (CreateWellKnownSid(WinBuiltinAdministratorsSid, 0, &AdminSID, &dwSidSize))
                {
                    BOOL bIsMember = FALSE;

                    if (CheckTokenMembership(hLinkedToken, &AdminSID, &bIsMember))
                    {
                        bRet = bIsMember;
                    }
                    else
                    {
                        DbgMsg("CheckTokenMembership() ERROR %d\n", GetLastError());
                    }
                }
                else
                {
                    DbgMsg("CreateWellKnownSid() ERROR %d\n", GetLastError());
                }

                CloseHandle(hLinkedToken);
            }
            else
            {
                bRet = IsUserAnAdmin();
            }

            CloseHandle(hToken);
        }
        else
        {
            DbgMsg("OpenProcessToken() ERROR %d\n", GetLastError());
        }
    }
    else
    {
        return IsUserAnAdmin();
    }

    return bRet;
}
//--------------------------------------------------------------------------------------
BOOL CheckForHighIntegrity(PBOOL pbIsHigh)
{
    BOOL bRet = FALSE;

    *pbIsHigh = FALSE;

    OSVERSIONINFOEX VersionInfo;
    ZeroMemory(&VersionInfo, sizeof(VersionInfo));
    VersionInfo.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);

    if (!GetVersionExA((LPOSVERSIONINFO)&VersionInfo))
    {
        DbgMsg("GetVersionEx() ERROR %d\n", GetLastError());
        return FALSE;
    }

    // check for Vista and later
    if (VersionInfo.dwPlatformId == VER_PLATFORM_WIN32_NT &&
        VersionInfo.dwMajorVersion > 5)
    {
        HANDLE hToken = NULL;
        if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
        {
            // make an high integrity level SID
            PSID pHighLevel = NULL;

            if (ConvertStringSidToSid("HI", &pHighLevel))
            {
                UCHAR Buff[0x200];
                PTOKEN_MANDATORY_LABEL Level = (PTOKEN_MANDATORY_LABEL)Buff;
                DWORD dwSize = 0;

                if (GetTokenInformation(hToken, TokenIntegrityLevel, Level, sizeof(Buff), &dwSize))
                {
                    if (EqualSid(pHighLevel, Level->Label.Sid))
                    {
                        *pbIsHigh = TRUE;
                    }
                }
                else
                {
                    DbgMsg("GetTokenInformation() ERROR %d\n", GetLastError());
                }

                FreeSid(pHighLevel);
            }
            else
            {
                DbgMsg("ConvertStringSidToSid() ERROR %d\n", GetLastError());
            }

            CloseHandle(hToken);
        }
        else
        {
            DbgMsg("OpenProcessToken() ERROR %d\n", GetLastError());
        }

        return TRUE;
    }

    return FALSE;
}
//--------------------------------------------------------------------------------------
// EoF

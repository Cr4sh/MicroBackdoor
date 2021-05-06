#include "stdafx.h"

#define PROXY_SETTINGS_KEY "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings"
#define PROXY_SETTINGS_VAL "ProxyServer"

CLIENT_PROXY m_ProxyCurrent;
CRITICAL_SECTION m_ProxyCriticalSection;
//--------------------------------------------------------------------------------------
BOOL ProxySettingsGet(char **lpszServers)
{ 
    INTERNET_PER_CONN_OPTION Option[5];
    INTERNET_PER_CONN_OPTION_LIST OptionList;
    DWORD dwSize = sizeof(INTERNET_PER_CONN_OPTION_LIST);

    Option[0].dwOption = INTERNET_PER_CONN_AUTOCONFIG_URL;
    Option[1].dwOption = INTERNET_PER_CONN_AUTODISCOVERY_FLAGS;
    Option[2].dwOption = INTERNET_PER_CONN_FLAGS;
    Option[3].dwOption = INTERNET_PER_CONN_PROXY_BYPASS;
    Option[4].dwOption = INTERNET_PER_CONN_PROXY_SERVER;

    OptionList.dwSize = sizeof(INTERNET_PER_CONN_OPTION_LIST);
    OptionList.pszConnection = NULL;
    OptionList.dwOptionCount = 5;
    OptionList.dwOptionError = 0;
    OptionList.pOptions = Option;

    if (!InternetQueryOption(NULL, INTERNET_OPTION_PER_CONNECTION_OPTION, &OptionList, &dwSize))
    {
        DbgMsg("InternetQueryOption() ERROR 0x%.8x\n", GetLastError());
        return FALSE;
    }
    
    if (Option[4].Value.pszValue &&
        ((Option[2].Value.dwValue & PROXY_TYPE_PROXY) ||
         (Option[2].Value.dwValue & PROXY_TYPE_AUTO_PROXY_URL)))
    {
        char *lpszValue = Option[4].Value.pszValue;

        if (*lpszServers = (char *)M_ALLOC(lstrlen(lpszValue) + 1))
        {
            lstrcpy(*lpszServers, lpszValue);
        }
        else
        {
            DbgMsg("M_ALLOC() ERROR %d\n", GetLastError());
        }
    }

    if (Option[0].Value.pszValue)
    {
        GlobalFree(Option[0].Value.pszValue);
    }

    if (Option[3].Value.pszValue)
    {
        GlobalFree(Option[3].Value.pszValue);
    }

    if (Option[4].Value.pszValue)
    {
        GlobalFree(Option[4].Value.pszValue);
    }

    return TRUE;
}
//--------------------------------------------------------------------------------------
BOOL ProxyInfoUpdate(PCLIENT_PROXY_INFO pProxyInfo, DWORD dwType, char *lpszHost, USHORT Port)
{
    if (pProxyInfo->ServersCount >= CLIENT_PROXY_MAX_SERVERS)
    {
        DbgMsg(__FUNCTION__"() ERROR: Too many servers\n");
        return FALSE;
    }

    for (DWORD i = 0; i < pProxyInfo->ServersCount; i += 1)
    {
        PCLIENT_PROXY pServer = &pProxyInfo->Servers[i];

        if (pServer->Type == dwType && 
            pServer->Port == Port &&
            !lstrcmp(pServer->szAddress, lpszHost))
        {
            // server is already present
            return FALSE;
        }
    }

    PCLIENT_PROXY pServer = &pProxyInfo->Servers[pProxyInfo->ServersCount];

    // add server to the list
    StrCpyN(pServer->szAddress, lpszHost, CLIENT_PROXY_MAX_ADDR_LEN - 1);
    pServer->Port = Port;
    pServer->Type = dwType;

    pProxyInfo->ServersCount += 1;

    if (dwType == CLIENT_PROXY_TYPE_SOCKS5 && pProxyInfo->ServersCount < CLIENT_PROXY_MAX_SERVERS)
    {
        pServer = &pProxyInfo->Servers[pProxyInfo->ServersCount];

        // add a separate entry for SOCKS v4
        StrCpyN(pServer->szAddress, lpszHost, CLIENT_PROXY_MAX_ADDR_LEN - 1);
        pServer->Port = Port;
        pServer->Type = CLIENT_PROXY_TYPE_SOCKS4;

        pProxyInfo->ServersCount += 1;
    }

    return TRUE;
}
//--------------------------------------------------------------------------------------
DWORD ProxyInfoUpdate(PCLIENT_PROXY_INFO pProxyInfo, char *lpszData)
{
    DWORD dwRet = 0;

    // parse servers list: "<TYPE_1>=<ADDRESS_1>:<PORT_1>;<TYPE_2>=<ADDRESS_2>:<PORT_2>;..."
    for (int i = 0; i < str_item_count(lpszData, ';'); i += 1)
    {
        char *lpszServer = NULL;

        if (!str_item_get(lpszData, ';', i, &lpszServer))
        {
            break;
        }

        // parse server info
        if (str_item_count(lpszServer, '=') == 2)
        {
            char *lpszType = NULL, *lpszAddr = NULL;

            if (str_item_get(lpszServer, '=', 0, &lpszType) &&
                str_item_get(lpszServer, '=', 1, &lpszAddr))
            {
                DWORD dwType = CLIENT_PROXY_TYPE_NONE;

                if (!lstrcmp(lpszType, "http"))
                {
                    dwType = CLIENT_PROXY_TYPE_HTTP;
                }
                else if (!lstrcmp(lpszType, "socks"))
                {
                    dwType = CLIENT_PROXY_TYPE_SOCKS5;
                }
                else
                {
                    DbgMsg(__FUNCTION__"() ERROR: Invalid server type \"%s\"\n", lpszType);
                }

                if (dwType != CLIENT_PROXY_TYPE_NONE)
                {
                    // parse server address
                    if (str_item_count(lpszAddr, ':') == 2)
                    {
                        char *lpszHost = NULL, *lpszPort = NULL;

                        if (str_item_get(lpszAddr, ':', 0, &lpszHost) &&
                            str_item_get(lpszAddr, ':', 1, &lpszPort))
                        {
                            DWORD dwPort = 0;

                            if (StrToIntEx(lpszPort, 0, (int *)&dwPort))
                            {
                                if (ProxyInfoUpdate(pProxyInfo, dwType, lpszHost, (USHORT)dwPort))
                                {
                                    dwRet += 1;
                                }                                
                            }
                            else
                            {
                                DbgMsg("StrToInt() ERROR %d\n", GetLastError());
                            }
                        }

                        if (lpszHost)
                        {
                            M_FREE(lpszHost);
                        }

                        if (lpszPort)
                        {
                            M_FREE(lpszPort);
                        }
                    }
                    else
                    {
                        DbgMsg(__FUNCTION__"() ERROR: Invalid server address \"%s\"\n", lpszAddr);
                    }
                }
            }

            if (lpszType)
            {
                M_FREE(lpszType);
            }

            if (lpszAddr)
            {
                M_FREE(lpszAddr);
            }
        }
        else
        {
            DbgMsg(__FUNCTION__"() ERROR: Invalid server \"%s\"\n", lpszServer);
        }

        M_FREE(lpszServer);
    }

    return dwRet;
}
//--------------------------------------------------------------------------------------
BOOL ProxyInfoGet(PCLIENT_PROXY_INFO pProxyInfo)
{
    BOOL bRet = FALSE;

    pProxyInfo->ServersCount = 0;

    HKEY hKey;
    LONG Code = RegOpenKey(HKEY_USERS, NULL, &hKey);
    if (Code == ERROR_SUCCESS)
    {
        DWORD dwIndex = 0;
        char szSubkeyName[MAX_PATH];

        // enumerate users
        while (RegEnumKey(hKey, dwIndex, szSubkeyName, MAX_PATH) == ERROR_SUCCESS)
        {
            HKEY hSubkey;
            char szSubkeyPath[MAX_PATH];

            wsprintf(szSubkeyPath, "%s\\" PROXY_SETTINGS_KEY, szSubkeyName);

            // open internet settings key
            if ((Code = RegOpenKey(hKey, szSubkeyPath, &hSubkey)) == ERROR_SUCCESS)
            {
                DWORD dwSize = 0;
                char *lpszData = NULL;

                // query value data length
                Code = RegQueryValueEx(hSubkey, PROXY_SETTINGS_VAL, NULL, NULL, NULL, &dwSize);
                if (Code == ERROR_SUCCESS)
                {
                    if (dwSize > 1)
                    {
                        if (lpszData = (char *)M_ALLOC(dwSize))
                        {
                            // query value data
                            Code = RegQueryValueEx(hSubkey, PROXY_SETTINGS_VAL, NULL, NULL, (PBYTE)lpszData, &dwSize);
                            if (Code == ERROR_SUCCESS)
                            {
                                DbgMsg(
                                    __FUNCTION__"(): \"%s\" settings obtained for user %s\n", 
                                    lpszData, szSubkeyName
                                );

                                ProxyInfoUpdate(pProxyInfo, lpszData);
                            }
                            else
                            {
                                DbgMsg("RegQueryValueEx() ERROR %d\n", Code);
                            }

                            M_FREE(lpszData);
                        }
                        else
                        {
                            DbgMsg("M_ALLOC() ERROR %d\n", GetLastError());
                        }
                    }
                }

                RegCloseKey(hSubkey);
            }

            dwIndex += 1;
        }

        RegCloseKey(hKey);
    }
    else
    {
        DbgMsg("RegOpenKey() ERROR %d\n", Code);
    }

    return TRUE;
}
//--------------------------------------------------------------------------------------
void ProxyInitialize(void)
{
    InitializeCriticalSection(&m_ProxyCriticalSection);

    m_ProxyCurrent.Type = CLIENT_PROXY_TYPE_NONE;    
}
//--------------------------------------------------------------------------------------
void ProxyUninitialize(void)
{
    m_ProxyCurrent.Type = CLIENT_PROXY_TYPE_NONE;

    DeleteCriticalSection(&m_ProxyCriticalSection);
}
//--------------------------------------------------------------------------------------
SOCKET ProxyConnect(PCLIENT_PROXY Server, DWORD Host, USHORT Port)
{
    CLIENT_PROXY ProxyCurrent;
    SOCKET Socket = INVALID_SOCKET;    

    if (Server == NULL)
    {
        EnterCriticalSection(&m_ProxyCriticalSection);

        // server was not specified, use current settings
        Server = &ProxyCurrent;
        memcpy(Server, &m_ProxyCurrent, sizeof(CLIENT_PROXY));

        LeaveCriticalSection(&m_ProxyCriticalSection);        
    }

    switch (Server->Type)
    {
    case CLIENT_PROXY_TYPE_NONE:

        if ((Socket = socket(AF_INET, SOCK_STREAM, 0)) != INVALID_SOCKET)
        {
            struct sockaddr_in SocketAddr;

            SocketAddr.sin_addr.s_addr = Host;
            SocketAddr.sin_port = htons(Port);
            SocketAddr.sin_family = AF_INET;

            // connect to server directly
            if (connect(Socket, (sockaddr *)&SocketAddr, sizeof(SocketAddr)) == 0)
            {
                return Socket;
            }
            else
            {
                DbgMsg("connect() ERROR %d\n", WSAGetLastError());
            }

            closesocket(Socket);
        }
        else
        {
            DbgMsg("socket() ERROR %d\n", WSAGetLastError());
        }

        return INVALID_SOCKET;

    case CLIENT_PROXY_TYPE_HTTP:

        return ProxyConnectHttp(Server, Host, Port);
    
    case CLIENT_PROXY_TYPE_SOCKS4:

        return ProxyConnectSocks4(Server, Host, Port);
    
    case CLIENT_PROXY_TYPE_SOCKS5:

        return ProxyConnectSocks5(Server, Host, Port);
    
    default:

        DbgMsg(__FUNCTION__"() ERROR: Unknown server type\n");
    }

    return INVALID_SOCKET;
}
//--------------------------------------------------------------------------------------
BOOL ProxySet(PCLIENT_PROXY Server)
{
    char *lpszType = NULL;

    if (Server == NULL || Server->Type == CLIENT_PROXY_TYPE_NONE)
    {
        EnterCriticalSection(&m_ProxyCriticalSection);

        // no proxy
        m_ProxyCurrent.Type = CLIENT_PROXY_TYPE_NONE;

        LeaveCriticalSection(&m_ProxyCriticalSection);
        
        return TRUE;
    }

    switch (Server->Type)
    {
    case CLIENT_PROXY_TYPE_HTTP:

        lpszType = "http";
        break;

    case CLIENT_PROXY_TYPE_SOCKS4:
    case CLIENT_PROXY_TYPE_SOCKS5:

        lpszType = "socks";
        break;

    default:

        DbgMsg(__FUNCTION__"() ERROR: Unknown server type\n");
        return FALSE;
    }

    EnterCriticalSection(&m_ProxyCriticalSection);

    memcpy(&m_ProxyCurrent, Server, sizeof(CLIENT_PROXY));

    LeaveCriticalSection(&m_ProxyCriticalSection);

    DbgMsg(
        __FUNCTION__"(): Setting current proxy server to %s=%s:%d\n", 
        lpszType, Server->szAddress, Server->Port
    );

    return TRUE;
}
//--------------------------------------------------------------------------------------
void ProxyGet(PCLIENT_PROXY Server)
{
    EnterCriticalSection(&m_ProxyCriticalSection);

    memcpy(Server, &m_ProxyCurrent, sizeof(CLIENT_PROXY));

    LeaveCriticalSection(&m_ProxyCriticalSection);
}
//--------------------------------------------------------------------------------------
// EoF

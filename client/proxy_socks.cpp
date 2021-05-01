#include "stdafx.h"
//--------------------------------------------------------------------------------------
int SocksRecv(SOCKET Socket, char *lpszBuff, int BuffSize)
{
    fd_set fds_read, fds_err;
    TIMEVAL tv;

    tv.tv_sec = 0;
    tv.tv_usec = CLIENT_PROXY_SOCKS_RECV_TIMEOUT * 1000;

    FD_ZERO(&fds_read);
    FD_SET(Socket, &fds_read);

    FD_ZERO(&fds_err);
    FD_SET(Socket, &fds_err);

    // check for data available
    int ret = select(0, &fds_read, NULL, &fds_err, &tv);
    if (ret == SOCKET_ERROR)
    {
        DbgMsg("select() ERROR %d\n", WSAGetLastError());
        return -1;
    }
    else if (ret > 0 && FD_ISSET(Socket, &fds_err))
    {
        DbgMsg(__FUNCTION__"(): Socket error\n");
        return -1;
    }
    else if (ret > 0 && FD_ISSET(Socket, &fds_read))
    {
        ZeroMemory(lpszBuff, BuffSize);

        int len = recv(Socket, lpszBuff, BuffSize, 0);
        if (len == SOCKET_ERROR)
        {
            DbgMsg("recv() ERROR %d\n", WSAGetLastError());
            return -1;
        }
        else if (len == 0)
        {
            DbgMsg(__FUNCTION__"() ERROR: Connection closed\n");
            return -1;
        }

        return len;
    }

    return -1;
}
//--------------------------------------------------------------------------------------
SOCKET ProxyConnectSocks4(PCLIENT_PROXY Server, DWORD Host, USHORT Port)
{
    DWORD dwAddr = ResolveHostname(Server->szAddress);
    if (dwAddr == INADDR_NONE)
    {
        return INVALID_SOCKET;
    }

    SOCKET Socket = socket(AF_INET, SOCK_STREAM, 0);
    if (Socket == INVALID_SOCKET)
    {
        DbgMsg("socket() ERROR %d\n", WSAGetLastError());
        return INVALID_SOCKET;
    }

    struct sockaddr_in SocketAddr;

    SocketAddr.sin_addr.s_addr = dwAddr;
    SocketAddr.sin_port = htons(Server->Port);
    SocketAddr.sin_family = AF_INET;

    // connect to server
    if (connect(Socket, (sockaddr *)&SocketAddr, sizeof(SocketAddr)) == 0)
    {                  
        char szBuff[CLIENT_PROXY_SOCKS_MAX_BUFF_LEN];
        
        PSOCKS4_REQUEST Request = (PSOCKS4_REQUEST)szBuff;
        ZeroMemory(szBuff, sizeof(szBuff));

        Request->Version = 4;
        Request->Command = 1; // connect command
        Request->Addr = Host;
        Request->Port = htons(Port);        

        // send TCP connect request
        int len = send(Socket, szBuff, sizeof(SOCKS4_REQUEST) + 1, 0);
        if (len == SOCKET_ERROR)
        {
            DbgMsg("send() ERROR %d\n", WSAGetLastError());
            goto _end;
        }

        // receive response
        if ((len = SocksRecv(Socket, szBuff, sizeof(szBuff))) == -1)
        {
            goto _end;
        }

        if (len != sizeof(SOCKS4_REQUEST))
        {
            DbgMsg(__FUNCTION__"() ERROR: Invalid response length: %d\n", len);
            goto _end;
        }

        PSOCKS4_REQUEST Response = (PSOCKS4_REQUEST)szBuff;        

        // check for successful status
        if (Response->Command != 90 || Response->Addr == 0 || Response->Port == 0)
        {
            DbgMsg(__FUNCTION__"() ERROR: Invalid response, code: %d\n", Response->Command);
            goto _end;
        }

        DbgMsg(__FUNCTION__"(): OK\n");

        return Socket;
    }
    else
    {
        DbgMsg("connect() ERROR %d\n", WSAGetLastError());
    }

_end:

    closesocket(Socket);

    return INVALID_SOCKET;
}
//--------------------------------------------------------------------------------------
SOCKET ProxyConnectSocks5(PCLIENT_PROXY Server, DWORD Host, USHORT Port)
{
    DWORD dwAddr = ResolveHostname(Server->szAddress);
    if (dwAddr == INADDR_NONE)
    {
        return INVALID_SOCKET;
    }

    SOCKET Socket = socket(AF_INET, SOCK_STREAM, 0);
    if (Socket == INVALID_SOCKET)
    {
        DbgMsg("socket() ERROR %d\n", WSAGetLastError());
        return INVALID_SOCKET;
    }

    struct sockaddr_in SocketAddr;

    SocketAddr.sin_addr.s_addr = dwAddr;
    SocketAddr.sin_port = htons(Server->Port);
    SocketAddr.sin_family = AF_INET;

    // connect to server
    if (connect(Socket, (sockaddr *)&SocketAddr, sizeof(SocketAddr)) == 0)
    {
        char szBuff[CLIENT_PROXY_SOCKS_MAX_BUFF_LEN];

        PSOCKS5_METHOD_REQUEST MethodRequest = (PSOCKS5_METHOD_REQUEST)szBuff;
        ZeroMemory(szBuff, sizeof(szBuff));
        
        MethodRequest->Version = 5;
        MethodRequest->MethodsNum = 1;

        // send methods request
        int len = send(Socket, szBuff, sizeof(SOCKS5_METHOD_REQUEST) + 1, 0);
        if (len == SOCKET_ERROR)
        {
            DbgMsg("send() ERROR %d\n", WSAGetLastError());
            goto _end;
        }

        // receive methods response
        if ((len = SocksRecv(Socket, szBuff, sizeof(szBuff))) == -1)
        {
            goto _end;
        }

        if (len != sizeof(SOCKS5_METHOD_RESPONSE))
        {
            DbgMsg(__FUNCTION__"() ERROR: Invalid response length: %d\n", len);
            goto _end;
        }

        PSOCKS5_METHOD_RESPONSE MethodResponse = (PSOCKS5_METHOD_RESPONSE)szBuff;

        if (MethodResponse->Version != 5 || MethodResponse->Method != 0)
        {
            DbgMsg(__FUNCTION__"() ERROR: Invalid method response\n");
            goto _end;
        }

        PSOCKS5_REQUEST Request = (PSOCKS5_REQUEST)szBuff;

        Request->Version = 5;
        Request->Command = 1; // connect command
        Request->Reserved = 0;
        Request->Type = 1; // IPv4 address

        *(PDWORD)&Request->Addr = Host;
        *(PUSHORT)((PUCHAR)&Request->Addr + sizeof(DWORD)) = htons(Port);

        // send TCP connect request
        if ((len = send(Socket, szBuff, sizeof(SOCKS5_REQUEST) + sizeof(DWORD) + sizeof(USHORT), 0)) == SOCKET_ERROR)
        {
            DbgMsg("send() ERROR %d\n", WSAGetLastError());
            goto _end;
        }

        // receive response
        if ((len = SocksRecv(Socket, szBuff, sizeof(szBuff))) == -1)
        {
            goto _end;
        }

        if (len != sizeof(SOCKS5_RESPONSE))
        {
            DbgMsg(__FUNCTION__"() ERROR: Invalid response length: %d\n", len);
            goto _end;
        }

        PSOCKS5_RESPONSE Response = (PSOCKS5_RESPONSE)szBuff;

        if (Response->Version != 5 || Response->Command != 0 || Response->Addr == 0 || Response->Port == 0)
        {
            DbgMsg(__FUNCTION__"() ERROR: Invalid response, code: %d\n", Response->Command);
            goto _end;
        }

        DbgMsg(__FUNCTION__"(): OK\n");

        return Socket;
    }
    else
    {
        DbgMsg("connect() ERROR %d\n", WSAGetLastError());
    }

_end:

    closesocket(Socket);

    return INVALID_SOCKET;
}
//--------------------------------------------------------------------------------------
// EoF

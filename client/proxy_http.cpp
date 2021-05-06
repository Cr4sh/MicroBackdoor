#include "stdafx.h"
//--------------------------------------------------------------------------------------
SOCKET ProxyConnectHttp(PCLIENT_PROXY Server, DWORD Host, USHORT Port)
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
        #define HTTP_PROXY_MAX_BUFF_LEN 0x200            
        char szBuff[HTTP_PROXY_MAX_BUFF_LEN];
            
        wsprintf(
            szBuff, "CONNECT %s:%d HTTP/1.0\r\n\r\n",
            inet_ntoa(*(in_addr *)&Host), Port
        );

        // send CONNECT request to the HTTP proxy
        int len = send(Socket, szBuff, lstrlen(szBuff), 0);
        if (len == SOCKET_ERROR)
        {
            DbgMsg("send() ERROR %d\n", WSAGetLastError());
            goto _end;
        }

        char *lpszReply = NULL;
        int ReplyLen = 0, StatusCode = 0;

        // receive server reply
        while (true)
        {               
            fd_set fds_read, fds_err;
            TIMEVAL tv;

            tv.tv_sec = 0;
            tv.tv_usec = CLIENT_PROXY_HTTP_RECV_TIMEOUT * 1000;

            FD_ZERO(&fds_read);
            FD_SET(Socket, &fds_read);

            FD_ZERO(&fds_err);
            FD_SET(Socket, &fds_err);

            // check for data available
            int ret = select(0, &fds_read, NULL, &fds_err, &tv);
            if (ret == SOCKET_ERROR)
            {
                DbgMsg("select() ERROR %d\n", WSAGetLastError());
                break;
            }
            else if (ret > 0 && FD_ISSET(Socket, &fds_err))
            {
                DbgMsg(__FUNCTION__"(): Socket error\n");
                break;
            }
            else if (ret > 0 && FD_ISSET(Socket, &fds_read))
            {
                ZeroMemory(szBuff, sizeof(szBuff));

                if ((len = recv(Socket, szBuff, HTTP_PROXY_MAX_BUFF_LEN - 1, 0)) == SOCKET_ERROR)
                {
                    DbgMsg("recv() ERROR %d\n", WSAGetLastError());
                    break;
                }
                else if (len == 0)
                {
                    DbgMsg(__FUNCTION__"() ERROR: Connection closed\n");
                    break;
                }                
                
                int TempLen = ReplyLen + len;
                if (TempLen >= CLIENT_PROXY_HTTP_MAX_HEADERS_LEN)
                {
                    DbgMsg(__FUNCTION__"() ERROR: Headers too long: %d\n", TempLen);
                    break;
                }

                // concat data buffers
                char *lpszTemp = (char *)M_ALLOC(TempLen + 1);
                if (lpszTemp == NULL)
                {
                    DbgMsg("M_ALLOC() ERROR %d\n", GetLastError());
                    break;
                }

                ZeroMemory(lpszTemp, TempLen + 1);

                if (ReplyLen > 0 && lpszReply)
                {
                    memcpy(lpszTemp, lpszReply, ReplyLen);
                    M_FREE(lpszReply);
                }

                memcpy(lpszTemp + ReplyLen, szBuff, len);

                lpszReply = lpszTemp;
                ReplyLen = TempLen;                
            }

            // check for the end of HTTP header
            if (ReplyLen > 4 &&
                (!StrCmpN(lpszReply + ReplyLen - 4, "\r\n\r\n", 4) ||
                 !StrCmpN(lpszReply + ReplyLen - 2, "\n\n", 2)))
            {
                char *lpszStatus = NULL;

                // parse header
                if (str_item_get(lpszReply, '\n', 0, &lpszStatus))
                {
                    if (str_item_count(lpszStatus, ' ') > 2)
                    {
                        char *lpszCode = NULL;

                        // get status code
                        if (str_item_get(lpszStatus, ' ', 1, &lpszCode))
                        {
                            if (!StrToIntEx(lpszCode, 0, &StatusCode))
                            {
                                DbgMsg("StrToIntEx() ERROR %d\n", GetLastError());
                            }

                            M_FREE(lpszCode);
                        }
                    }

                    M_FREE(lpszStatus);
                }

                if (StatusCode == 0)
                {
                    DbgMsg(__FUNCTION__"() ERROR: Invalid server reply\n");
                }
                else if (StatusCode != HTTP_STATUS_OK)
                {
                    DbgMsg(__FUNCTION__"() ERROR: Server returns an error:\n" "%s", lpszReply);
                }
                   
                break;
            }
        }

        if (lpszReply)
        {
            M_FREE(lpszReply);
        }

        // check for successful CONNECT request
        if (StatusCode == HTTP_STATUS_OK)
        {
            DbgMsg(__FUNCTION__"(): OK\n");

            return Socket;
        }
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

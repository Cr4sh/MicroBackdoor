
#define CLIENT_PROXY_TYPE_NONE      0
#define CLIENT_PROXY_TYPE_HTTP      1
#define CLIENT_PROXY_TYPE_SOCKS4    2
#define CLIENT_PROXY_TYPE_SOCKS5    3

#define CLIENT_PROXY_MAX_SERVERS    10
#define CLIENT_PROXY_MAX_ADDR_LEN   0x30

typedef struct _CLIENT_PROXY
{
    char szAddress[CLIENT_PROXY_MAX_ADDR_LEN];
    USHORT Port;
    DWORD Type;

} CLIENT_PROXY,
*PCLIENT_PROXY;

typedef struct _CLIENT_PROXY_INFO
{
    DWORD ServersCount;
    CLIENT_PROXY Servers[CLIENT_PROXY_MAX_SERVERS];

} CLIENT_PROXY_INFO,
*PCLIENT_PROXY_INFO;


BOOL ProxyInfoGet(PCLIENT_PROXY_INFO pProxyInfo);

SOCKET ProxyConnect(PCLIENT_PROXY Server, DWORD Host, USHORT Port);

void ProxyInitialize(void);
void ProxyUninitialize(void);

BOOL ProxySet(PCLIENT_PROXY Server);
void ProxyGet(PCLIENT_PROXY Server);

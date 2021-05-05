
// unique mutex name
#define MUTEX_NAME "30D78F9B-C56E-472C-8A29-E9F27FD8C985"

// protocol version
#define REMOTE_VERSION 2

// how long to wait before reconnect to the server
#define REMOTE_RECONNECT_SLEEP 10 // in seconds

// how long to wait between pings
#define REMOTE_PING_TIME 30 // in seconds

// max buffer size for the command from server
#define REMOTE_MAX_CMD_SIZE (1 * 1024 * 1024) // 1Mb

// process timeout for CommandExec()
#define EXEC_TIMEOUT 30 // in seconds

// process timeout for CommandUpd()
#define UPDATE_TIMEOUT 30 // in seconds

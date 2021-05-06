#pragma warning(disable: 4200)
#pragma warning(disable: 4996)

#pragma comment(linker, "/MERGE:.rdata=.text") 

#pragma once

#include "targetver.h"

#define WIN32_LEAN_AND_MEAN

#include <winsock2.h>
#include <windows.h>
#include <WinCrypt.h>
#include <stdint.h>
#include <wininet.h>
#include <Shlwapi.h>
#include <Shlobj.h>
#include <Sddl.h>

#include "../config.h"
#include "../common.h"

#include "debug.h"
#include "str.h"
#include "rc4.h"
#include "crypt.h"
#include "client.h"
#include "proxy.h"
#include "proxy_http.h"
#include "proxy_socks.h"
#include "misc.h"

// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#pragma once

#include "targetver.h"

#include <stdio.h>

#if WIN32
	#define uint32_t unsigned int
	#include <tchar.h>
	#include <string.h>
	#include <WinSock2.h>
#else
	#define INVALID_SOCKET -1
	#define SOCKET_ERROR -1
	#define max(a,b) ((a) > (b) ? a : b)
	#define min(a,b) ((a) < (b) ? a : b)
	#define SOCKET int
	#define DWORD unsigned int
	#define PBYTE unsigned char*
	#define closesocket close
	#include <pthread.h> 
	#include <stdlib.h>
	#include <string.h>
	#include <unistd.h>
	#include <sys/types.h> 
	#include <sys/socket.h>
	#include <netinet/in.h>
	#define vsprintf_s(b,l,f,v) vsprintf(b,f,v);
#endif

enum PacketResultFlags {
	PACKET_SUCCESS,
	PACKET_FAILED,
	PACKET_UPDATE
};

extern "C" {
	#include <curl/curl.h>
	#include <openssl/rc4.h>
	#include <openssl/sha.h>
	#include <openssl/rand.h>
}
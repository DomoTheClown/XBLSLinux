#ifndef __TCPSERVER_H_
#define __TCPSERVER_H_

#pragma once

#include "stdafx.h"

enum AuthPacketType {
	AUTH_NULL,
	AUTH_NULL2,
	AUTH_LOGIN,
	AUTH_CHALLENGE,
	AUTH_UPDATEPRESENCE,
	AUTH_ECC
};

enum AuthFlags {
	AUTH_BRONZE,
	AUTH_SILVER,
	AUTH_GOLD,
	AUTH_ADMIN
};

typedef struct _ClientData {
	SOCKET Client;
	struct sockaddr_in ClientAddr;
} ClientData;

bool AuthServerStartup(short Port);
void AuthServerListen();

#endif

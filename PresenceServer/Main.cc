// TitanServer.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "PresenceServer.h"

#define XBLHammer_PORT 4230
#define xblatlas_PORT 6977


int main(int argc, char* argv[])
{
	if (PresenceServerStartup(6979)) {
		PresenceServerListen();
	}
	return 0;
}


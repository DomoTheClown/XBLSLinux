// TitanServer.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "AuthServer.h"

#define XBLHammer_PORT 4230
#define xblatlas_PORT 6977


int main(int argc, char* argv[])
{
	if (AuthServerStartup(XBLHammer_PORT)) {
		AuthServerListen();
	}
	
	if (AuthServerStartup(6979)) {
		AuthServerListen();
	}
	
	return 0;
}


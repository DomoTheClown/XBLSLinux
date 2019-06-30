#include "stdafx.h"
#include "AuthServer.h"
#include "DataManager.h"
#include "Cryptography.h"
#include "CurlWebRequest.h"

#include <string.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

SOCKET PresenceSocket;
#if WIN32
WSADATA PresenceWsaData;
#endif
bool PresenceServerReady = false;
struct sockaddr_in PresenceServerSockAddrIn;

// This is for making sure we dont accidently add two clients at once
//CRITICAL_SECTION AddClientCriticalSection;

extern char* ServerPath;
extern char* Path;

#ifndef _MSC_VER
inline
char* strtok_s1(char* s, const char* delm, char** context)
{
        return strtok_r(s, delm, context);
}
#endif


#if WIN32
DWORD WINAPI OnPresenceClientConnect(LPVOID lpParam);
void UpdatePresence(SOCKET ClientSocket, unsigned char *Token, char *Gamertag, DWORD TitleId);
#else
void OnPresenceClientConnect ( void *ptr );
void UpdatePresence(SOCKET ClientSocket, unsigned char *Token, char *Gamertag, DWORD TitleId);
#endif

void PresenceSendSuccessResponse(SOCKET ClientSocket);
void PresenceSendFailedResponse(SOCKET ClientSocket);

bool PresenceServerStartup(short Port) {
	int Result;

#if WIN32
	Result = WSAStartup(MAKEWORD(2, 2), &PresenceWsaData);

	if (Result != 0) {
		printf(" %08X\n", WSAGetLastError());
		return false;
	}
#endif

	PresenceSocket = socket(AF_INET, SOCK_STREAM, 0);

	if (PresenceSocket == INVALID_SOCKET) {
#if WIN32
		printf("[MSG] PresenceServer: Invalid Socket %08X<br>\r\n", WSAGetLastError());
#endif
		return false;
	}
	
#if WIN32
	PresenceServerSockAddrIn.sin_addr.S_un.S_addr = INADDR_ANY;
	PresenceServerSockAddrIn.sin_family = AF_INET;
	PresenceServerSockAddrIn.sin_port = htons(Port);
#else
	PresenceServerSockAddrIn.sin_family = AF_INET;
	PresenceServerSockAddrIn.sin_addr.s_addr = INADDR_ANY;
	PresenceServerSockAddrIn.sin_port = htons(Port);
	
#endif

	 Result = bind(PresenceSocket, (struct sockaddr*)&PresenceServerSockAddrIn, sizeof(PresenceServerSockAddrIn));

	if (Result == INVALID_SOCKET) {
#if WIN32
		printf("[MSG] PresenceServer: Failed to bind %08X<br>\r\n", WSAGetLastError());
#endif
		return false;
	}

	PresenceServerReady = true;

	printf("[MSG] PresenceServer: Server is ready.<br>\r\n");

	return true;
}

struct sockaddr_in PresenceClientAddr;
void PresenceServerListen() {
	if (!PresenceServerReady) {
		printf("[MSG] PresenceServer: Server is not ready to listen<br>\r\n");
		return;
	}

	listen(PresenceSocket, SOMAXCONN);

	while (true) {
		int ClientLength = sizeof(PresenceClientAddr);
		SOCKET ClientSocket = accept(PresenceSocket, (struct sockaddr*)&PresenceClientAddr, &ClientLength);

		if (ClientSocket == INVALID_SOCKET)
		{
			printf("[MSG] PresenceServer: Accept client failed!<br>\r\n");
			continue;
		}

#if WIN32
		printf("[MSG] PresenceServer: Client connected %d.%d.%d.%d<br>\r\n", PresenceClientAddr.sin_addr.S_un.S_un_b.s_b1, PresenceClientAddr.sin_addr.S_un.S_un_b.s_b2, PresenceClientAddr.sin_addr.S_un.S_un_b.s_b3, PresenceClientAddr.sin_addr.S_un.S_un_b.s_b4);
		HANDLE handle = CreateThread(NULL, NULL, OnPresenceClientConnect, (LPVOID)ClientSocket, NULL, NULL);
		CloseHandle(handle);
#else
		pthread_t thread1;
		pthread_create (&thread1, NULL, (void *) &OnPresenceClientConnect, (void *)ClientSocket);
		pthread_join(thread1, NULL);
#endif

	}
}

#if WIN32
DWORD WINAPI OnPresenceClientConnect(LPVOID lpParam) {
#else
void OnPresenceClientConnect ( void *lpParam ) {
#endif

	unsigned char Packet[1024];
	unsigned char CpuKey[16];
	unsigned char ModuleHash[20];
	unsigned char Token[16];
	unsigned char Salt[16];
	unsigned char MSG[512];
	unsigned char logger[2048];
	SOCKET ClientSocket = (SOCKET)lpParam;
	unsigned char *RecievedData;
	int RecievedDataSize;
	int Id = 0;
	char *Gamertag;
	DWORD TitleId;

	printf("[MSG] PresenceServer: OnPresenceClientConnect Started.<br>\r\n");
	bool Continue = true;
	while (Continue) {
		printf("[MSG] PresenceServer: Pinging Client.\n");

		memset(Packet, 0, 1024);

		if (!SendData(ClientSocket, Packet, 1024, AUTH_UPDATEPRESENCE)) {
			break;
		}
		
		RecievedData = (unsigned char*)RecieveData(ClientSocket, &RecievedDataSize, &Id);

		if (!RecievedData || RecievedData == 0 || RecievedDataSize == 0) {
			printf("[MSG] PresenceServer: Failed to recieve data.<br>\r\n");
			break;
		}
		
		memcpy(Token, 		RecievedData, 16);
		Gamertag = (char*)(RecievedData + 16);
		memcpy(CpuKey,		RecievedData + 32, 16);
		memcpy(TitleId,		RecievedData + 48, 4);

		UpdatePresence(ClientSocket, Token, Gamertag, TitleId);

		//AddClient(ClientSocket, CpuKey, Token);

		free(RecievedData);

		printf("[MSG] PresenceServer: Pinged Client.\n");
		sleep(60 * 1000);
	}
	printf("[MSG] PresenceServer: OnClientConnect Ended.<br>\r\n");
	closesocket(ClientSocket);

#if WIN32
	return 0;
#endif
}


void UpdatePresence(SOCKET ClientSocket, unsigned char *Token, char *Gamertag, DWORD TitleId) {
	char Format[256];
	int *TitleIdCast = (int*)TitleId;
	int *TokenCast = (int*)Token;
	char *DelimiterContext;
	char *GamertagTemp = Gamertag;
	char FinalGamertag[64];

	memset(FinalGamertag, 0, 64);

	int i = 0;
	//while (*GamertagTemp) {
	//	if (!isalnum(*GamertagTemp) && *GamertagTemp != ' ') {
	//		FinalGamertag[i++] = 'X';
	//	} else if (*GamertagTemp == ' ') {
	//		FinalGamertag[i++] = '%';
	//		FinalGamertag[i++] = '2';
	//		FinalGamertag[i++] = '0';
	//	} else {
	//		FinalGamertag[i++] = *GamertagTemp;
	//	}

	//	GamertagTemp++;
	//}

	sprintf(Format, "http://%s/%s?x=UpdatePresence&token=%08X%08X%08X%08X&gamertag=%s&titleid=%08X", 
		ServerPath,
		Path,
		htonl(TokenCast[0]), 
		htonl(TokenCast[1]), 
		htonl(TokenCast[2]), 
		htonl(TokenCast[3]),
		FinalGamertag,
		TitleId);

	char *WebRequest = DoWebRequest(Format);

	// We failed our web request (Server not up?)
	if (!WebRequest) {
		printf("UpdatePresence: Failed web request.\n");
		PresenceSendFailedResponse(ClientSocket);
		return;
	}

	char *Message = strtok_s1(WebRequest, ":", &DelimiterContext);
	char *Level = strtok_s1(NULL, ":", &DelimiterContext);

	// We failed to tokenize our data
	if (!Message || !Level) {
		printf("UpdatePresence: Failed to tokenize web response.\n");
		PresenceSendFailedResponse(ClientSocket);
		free(WebRequest);
		return;
	}

	// Check our login string
	if (strcmp(WebRequest, "SUCCESS") != 0) {
		// We did not succeed our login
		printf("UpdatePresence: User failed authorization.\n");
		PresenceSendFailedResponse(ClientSocket);
		free(WebRequest);
		return;
	}

	PresenceSendSuccessResponse(ClientSocket);

	free(WebRequest);
}

void PresenceSendSuccessResponse(SOCKET ClientSocket) {
	char Packet[1024];

	// Clear our packet
	memset(Packet, 0, 1024);

	// Send it
	SendData(ClientSocket, Packet, 1024, PACKET_SUCCESS);
}

void PresenceSendFailedResponse(SOCKET ClientSocket) {
	char Packet[1024];

	// Clear our packet
	memset(Packet, 0xFF, 1024);

	// Send it
	SendData(ClientSocket, Packet, 1024, PACKET_FAILED);
}

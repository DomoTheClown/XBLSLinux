#include "stdafx.h"
#include "DataManager.h"
#include "Cryptography.h"
#include "math.h"

/*
	What we will do is send an 8 byte header to tell the client what its getting

	4 bytes | UGAY (lol)
	4 bytes | length

	Then we will send a SHA1 hash of the unencrypted data
	Then we will send the encrypted data with a 4 byte packet id then split up in 1024 byte packets
*/

#define min(a,b) ((a)<(b)?(a):(b))

bool Send(SOCKET ClientSocket, void *Data, int Size) {
	int Left = Size;
	int Sent = 0;

	while (Left > 0) {
		int SizeToSend = min(PACKET_SIZE, Left);
		int Result = send(ClientSocket, (const char*)(Sent + (char*)Data), SizeToSend, 0);

		if (Result == SOCKET_ERROR) {
			return false;
		}

		Sent += Result;
		Left -= Result;
	}

	return true;
}

bool Recieve(SOCKET ClientSocket, void *Data, int Size) {
	int Left = Size;
	int Recieved = 0;

	while (Left > 0) {
		int SizeToRecieve = min(PACKET_SIZE, Left);
		int Result = recv(ClientSocket, (char*)(Recieved + (char*)Data), SizeToRecieve, 0);

		if (Result == SOCKET_ERROR) {
			return false;
		}

		Recieved += Result;
		Left -= Result;
	}

	return true;
}

bool SendData(SOCKET ClientSocket, void *Data, int Size, int Id) {
	unsigned char Header[8];
	unsigned char Digest[20];
	int TotalSize = Size + 4;
	unsigned char *SendData = (unsigned char*)malloc(TotalSize);

	// Format the header
	Header[0] = 'U';
	Header[1] = 'G';
	Header[2] = 'A';
	Header[3] = 'Y';

	// Setup the size with big endian
	Header[4] = (TotalSize & 0xFF000000) >> 24;
	Header[5] = (TotalSize & 0xFF0000  ) >> 16;
	Header[6] = (TotalSize & 0xFF00    ) >> 8;
	Header[7] = (TotalSize & 0xFF      );

	// Endian swap our id
	Id = htonl(Id);

	// Set up our data with its id
	memcpy(SendData    , &Id, 4);
	memcpy(SendData + 4, Data, Size);

	DoSha1(SendData, TotalSize, Digest);

	// Send the header
	if (!Send(ClientSocket, Header, 8)) {
		printf("Failed to send header.\n");
		return false;
	}
	
	// Send the hash
	if (!Send(ClientSocket, Digest, 20)) {
		printf("Failed to send hash.\n");
		return false;
	}

	// Encrypt
	DoRc4(SendData, TotalSize);

	// Send the data
	if (!Send(ClientSocket, SendData, TotalSize)) {
		free(SendData);
		printf("Failed to send data.\n");
		return false;
	}

	free(SendData);
	
	return true;
}

void *RecieveData(SOCKET ClientSocket, int *Size, int *OutId) {
	unsigned char Header[8];
	unsigned char Digest[20];
	unsigned char CalcDigest[20];
	int DataSize;
	unsigned char *RecievedData;
	unsigned char *Data;

	// Get our header
	if (!Recieve(ClientSocket, Header, 8)) {
		printf("Failed to recieve header.\n");
		return 0;
	}

	// Check our packet header
	if (Header[0] != 'U' || Header[1] != 'G' || Header[2] != 'A' || Header[3] != 'Y') {
		printf("Header had bad UGAY magic.\n");
		return 0;
	}

	// Our data size
	DataSize = (Header[4] << 24) | (Header[5] << 16) | (Header[6] << 8) | (Header[7]);

	// Allocate
	RecievedData = (unsigned char*)malloc(DataSize);
	Data =  (unsigned char*)malloc(DataSize - 4);

	// Our data hash
	if (!Recieve(ClientSocket, Digest, 20)) {
		printf("Failed to recieve data hash.\n");
		return 0;
	}

	// Get our data
	if (!Recieve(ClientSocket, RecievedData, DataSize)) {
		printf("Failed to recieve data.\n");
		return 0;
	}

	// Decrypt
	DoRc4(RecievedData, DataSize);

	// Get our digest
	DoSha1(RecievedData, DataSize, CalcDigest);

	// Compare them
	if (memcmp(Digest, CalcDigest, 20) != 0) {
		printf("Data hash failed.\n");
		free(RecievedData);
		return 0;
	}

	*Size = (int)(RecievedData - 4);

	// Get our id
	*OutId = (RecievedData[0] << 24) | (RecievedData[1] << 16) | (RecievedData[2] << 8) | (RecievedData[3]);

	// If we succeed our hash check we copy the data over
	memcpy(Data, RecievedData + 4, DataSize - 4);

	free(RecievedData);

	return Data;
}

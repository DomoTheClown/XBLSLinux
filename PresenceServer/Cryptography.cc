#include "stdafx.h"
#include "Cryptography.h"

unsigned char DataKey[16] = {
	0x6B, 0x83, 0x3B, 0xD3,
	0x61, 0xA0, 0x93, 0x19,
	0x5C, 0xFF, 0xFC, 0x9D,
	0xE4, 0x5D, 0x18, 0x2A
};

void GetRandomBytes(void *Data, int Length) {
	RAND_bytes((unsigned char*)Data, Length);
}

void DoSha1(void *Data, int Length, void *Out) {
	SHA1((unsigned char*)Data, Length, (unsigned char*)Out);
}

void DoRc4(void *Data, int Length) {
	RC4_KEY Rc4Key;
	unsigned char *OutData = (unsigned char*)malloc(Length);
	RC4_set_key(&Rc4Key, 16, DataKey);
	RC4(&Rc4Key, Length, (unsigned char*)Data, (unsigned char*)OutData);
	memcpy(Data, OutData, Length);
	free(OutData);
}

void DoCreateChallengeResponse(void *OutHash, void *Salt) {
	extern unsigned char Hypervisor[];
	SHA_CTX ShaContext;
	SHA1_Init(&ShaContext);

	SHA1_Update(&ShaContext,  Salt				    , 0x10 );
	SHA1_Update(&ShaContext,  Hypervisor + 0x34		, 0x40 );
	SHA1_Update(&ShaContext,  Hypervisor + 0x78		, 0xF88);
	SHA1_Update(&ShaContext,  Hypervisor + 0x100C0	, 0x40 );
	SHA1_Update(&ShaContext,  Hypervisor + 0x10350	, 0xDF0);
	SHA1_Update(&ShaContext,  Hypervisor + 0x16D20	, 0x2E0);
	SHA1_Update(&ShaContext,  Hypervisor + 0x20000	, 0xFFC);
	SHA1_Update(&ShaContext,  Hypervisor + 0x30000	, 0xFFC);
	SHA1_Final((unsigned char*)OutHash, &ShaContext);
}

bool CheckXexChallenge(void *Salt, void *Challenge) {
	extern unsigned char *TitanXex;
	extern int TitanXexSize;
	unsigned char Digest[20];
	SHA_CTX ShaContext;
	SHA1_Init(&ShaContext);
	SHA1_Update(&ShaContext, Salt     , 16);
	SHA1_Update(&ShaContext, TitanXex , TitanXexSize);
	SHA1_Final(Digest, &ShaContext);
	return (memcmp(Challenge, Digest, 20) == 0);
}

#ifndef __CRYPTOGRAPHY_H_
#define __CRYPTOGRAPHY_H_

#pragma once

#include "stdafx.h"
void GetRandomBytes(void *Data, int Length);
void DoSha1(void *Data, int Length, void *Out);
void DoRc4(void *Data, int Length);
void DoCreateChallengeResponse(void *OutHash, void *Salt);
bool CheckXexChallenge(void *Salt, void *Challenge);
#endif
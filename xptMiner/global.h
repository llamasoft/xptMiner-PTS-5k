#ifndef __GLOBAL_H__
#define __GLOBAL_H__

// #define GLOBAL_DEBUG
#ifdef GLOBAL_DEBUG
    #define DEBUG(x) { x; }
#else
    #define DEBUG(x)
#endif

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstring>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <set>
#include <string>

#include "OpenCLObjects.h"
#include "algorithm.h"
#include "jhlib.h"
#include "sha2.h"
#include "sha2.h"
#include "transaction.h"

#ifdef _WIN32
#define _CRT_SECURE_NO_WARNINGS
#define NOMINMAX
#pragma comment(lib,"Ws2_32.lib")
#include <Winsock2.h>
#include <ws2tcpip.h>
typedef __int64           sint64;
typedef unsigned __int64  uint64;
typedef __int32           sint32;
typedef unsigned __int32  uint32;
typedef __int16           sint16;
typedef unsigned __int16  uint16;
//typedef __int8            sint8;
//typedef unsigned __int8   uint8;

//typedef __int8 int8_t;
typedef unsigned __int8  uint8_t;
typedef __int16          int16_t;
typedef unsigned __int16 uint16_t;
typedef __int32          int32_t;
typedef unsigned __int32 uint32_t;
typedef __int64          int64_t;
typedef unsigned __int64 uint64_t;

#define PLUS_MINUS "\xF1"
#else
// Cygwin specific tweak
// #ifdef __CYGWIN__
// #include <cstdlib>
// #endif

// Include the Windows/Linux compatability header
#include "win.h"
#define PLUS_MINUS "\u00B1"
#endif

// connection info for xpt
typedef struct  
{
    char* ip;
    uint16 port;
    char* authUser;
    char* authPass;
    float donationPercent;
}generalRequestTarget_t;

#include "xptServer.h"
#include "xptClient.h"

#include "sha2.h"

#include "transaction.h"

// global settings for miner
typedef struct  
{
    generalRequestTarget_t requestTarget;
    uint32 protoshareMemoryMode;
    float donationPercent;
}minerSettings_t;

extern minerSettings_t minerSettings;

#define PROTOSHARE_MEM_512		(0)
#define PROTOSHARE_MEM_256		(1)
#define PROTOSHARE_MEM_128		(2)
#define PROTOSHARE_MEM_32		(3)
#define PROTOSHARE_MEM_8		(4)

// block data struct

typedef struct  
{
    // block header data (relevant for midhash)
    uint32	version;
    uint8	prevBlockHash[32];
    uint8	merkleRoot[32];
    uint32	nTime;
    uint32	nBits;
    uint32	nonce;
    // birthday collision
    uint32	birthdayA;
    uint32	birthdayB;
    uint32	uniqueMerkleSeed;

    uint32	height;
    uint8	merkleRootOriginal[32]; // used to identify work
    uint8	target[32];
    uint8	targetShare[32];
}minerProtosharesBlock_t;

typedef struct  
{
    // block header data
    uint32	version;
    uint8	prevBlockHash[32];
    uint8	merkleRoot[32];
    uint32	nTime;
    uint32	nBits;
    uint32	nonce;
    uint32	uniqueMerkleSeed;
    uint32	height;
    uint8	merkleRootOriginal[32]; // used to identify work
    uint8	target[32];
    uint8	targetShare[32];
}minerScryptBlock_t;

typedef struct  
{
    // block header data
    uint32	version;
    uint8	prevBlockHash[32];
    uint8	merkleRoot[32];
    uint32	nTime;
    uint32	nBits;
    uint32	nonce;
    uint32	uniqueMerkleSeed;
    uint32	height;
    uint8	merkleRootOriginal[32]; // used to identify work
    uint8	target[32];
    uint8	targetShare[32];
    // found chain data
    // todo
}minerPrimecoinBlock_t;

typedef struct  
{
    // block data (order and memory layout is important)
    uint32	version;
    uint8	prevBlockHash[32];
    uint8	merkleRoot[32];
    uint32	nTime;
    uint32	nBits;
    uint32	nonce;
    // remaining data
    uint32	uniqueMerkleSeed;
    uint32	height;
    uint8	merkleRootOriginal[32]; // used to identify work
    uint8	target[32];
    uint8	targetShare[32];
}minerMetiscoinBlock_t; // identical to scryptBlock

typedef struct  
{
    char* workername;
    char* workerpass;
    char* host;
    sint32 port;
    sint32 numThreads;
    uint32 ptsMemoryMode;
    // GPU / OpenCL options
    uint32 deviceNum;
    bool listDevices;
    std::vector<int> deviceList;

    // mode option
    uint32 mode;
    float donationPercent;

    uint32 wgs;
    uint32 vect_type;
    uint32 buckets_log2;
    uint32 bucket_size;
    uint32 target_mem;
} commandlineInput_t;


typedef struct
{
    char* workername;
    char* workerpass;
    double payout_pct;
    bool is_developer;
} payout_t;

void xptMiner_submitShare(minerProtosharesBlock_t* block);
void xptMiner_submitShare(minerScryptBlock_t* block);
void xptMiner_submitShare(minerPrimecoinBlock_t* block);
void xptMiner_submitShare(minerMetiscoinBlock_t* block);

// stats
extern volatile uint32 totalCollisionCount;
extern volatile uint32 totalTableCount;
extern volatile uint32 totalShareCount;
extern volatile uint32 curShareCount;
extern volatile uint32 invalidShareCount;
extern volatile uint32 monitorCurrentBlockHeight;

extern std::vector<payout_t> payout_list;

#endif

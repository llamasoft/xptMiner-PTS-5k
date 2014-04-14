#include "global.h"
#include "ticker.h"
#include "OpenCLObjects.h"
#include "protoshareMiner.h"
#include <csignal>
#include <cstdio>
#include <cstring>
#include <cmath>
#define MAX_TRANSACTIONS    (4096)

// miner version string (for pool statistic)
char* minerVersionString = "xptMiner-PTS-5k 1.2gg";

volatile uint32 totalCollisionCount;
volatile uint32 totalTableCount;
volatile double totalOverflowPct;
volatile uint32 totalShareCount;
volatile uint32 curShareCount;
volatile uint32 invalidShareCount;
volatile uint32 monitorCurrentBlockHeight;

minerSettings_t minerSettings = {0};

xptClient_t* xptClient = NULL;
CRITICAL_SECTION cs_xptClient;

struct {
    CRITICAL_SECTION cs_work;

    uint32  algorithm;
    // block data
    uint32  version;
    uint32  height;
    uint32  nBits;
    uint32  timeBias;
    uint8   merkleRootOriginal[32]; // used to identify work
    uint8   prevBlockHash[32];
    uint8   target[32];
    uint8   targetShare[32];
    // extra nonce info
    uint8   coinBase1[1024];
    uint8   coinBase2[1024];
    uint16  coinBase1Size;
    uint16  coinBase2Size;
    // transaction hashes
    uint8   txHash[32 * MAX_TRANSACTIONS];
    uint32  txHashCount;
} workDataSource;

uint32 uniqueMerkleSeedGenerator = 0;
uint32 miningStartTime = 0;

// GPU watchdog to detect Windows TDR or hangs.
// Maximum wait extended by 2x if mining on CPU.
uint32 gpu_watchdog_max_wait = 10;
uint32 gpu_watchdog_timer = 0;

std::vector<ProtoshareOpenCL *> gpu_processors;
std::vector<payout_t> payout_list;

commandlineInput_t commandlineInput;

uint32 nearest_pow2(uint32 n)
{
    uint32 temp = 1;

    while (n > 0) { temp <<= 1; n >>= 1; }

    return temp >> 1;
}


/*
* Submit Protoshares share
*/
void xptMiner_submitShare(minerProtosharesBlock_t* block)
{
    printf("Share found! (NonceA: %#010x, NonceB: %#010x, Blockheight: %d)\n", block->birthdayA, block->birthdayB, block->height);
    EnterCriticalSection(&cs_xptClient);

    if ( xptClient == NULL || xptClient_isDisconnected(xptClient, NULL) == true ) {
        printf("Share submission failed - No connection to server\n");
        LeaveCriticalSection(&cs_xptClient);
        return;
    }

    // submit block
    xptShareToSubmit_t* xptShare = (xptShareToSubmit_t*)malloc(sizeof(xptShareToSubmit_t));
    memset(xptShare, 0x00, sizeof(xptShareToSubmit_t));
    xptShare->algorithm = ALGORITHM_PROTOSHARES;
    xptShare->version = block->version;
    xptShare->nTime = block->nTime;
    xptShare->nonce = block->nonce;
    xptShare->nBits = block->nBits;
    xptShare->nBirthdayA = block->birthdayA;
    xptShare->nBirthdayB = block->birthdayB;
    memcpy(xptShare->prevBlockHash, block->prevBlockHash, 32);
    memcpy(xptShare->merkleRoot, block->merkleRoot, 32);
    memcpy(xptShare->merkleRootOriginal, block->merkleRootOriginal, 32);
    //userExtraNonceLength = std::min(userExtraNonceLength, 16);
    sint32 userExtraNonceLength = sizeof(uint32);
    uint8* userExtraNonceData = (uint8*)&block->uniqueMerkleSeed;
    xptShare->userExtraNonceLength = userExtraNonceLength;
    memcpy(xptShare->userExtraNonceData, userExtraNonceData, userExtraNonceLength);
    xptClient_foundShare(xptClient, xptShare);
    LeaveCriticalSection(&cs_xptClient);
}


#ifdef _WIN32
int xptMiner_minerThread(int threadIndex)
#else
void *xptMiner_minerThread(void *arg)
#endif
{
    // local work data
    minerProtosharesBlock_t minerProtosharesBlock = {0};
    minerScryptBlock_t minerScryptBlock = {0};
    minerMetiscoinBlock_t minerMetiscoinBlock = {0};
    minerPrimecoinBlock_t minerPrimecoinBlock = {0};
    ProtoshareOpenCL *processor = gpu_processors.back();
    gpu_processors.pop_back();

    // todo: Eventually move all block structures into a union to save stack size
    while ( true ) {
        // has work?
        bool hasValidWork = false;
        EnterCriticalSection(&workDataSource.cs_work);

        if ( workDataSource.height > 0 ) {
            if ( workDataSource.algorithm == ALGORITHM_PROTOSHARES ) {
                // get protoshares work data
                minerProtosharesBlock.version = workDataSource.version;
                minerProtosharesBlock.nTime = (uint32)time(NULL) + workDataSource.timeBias;
                minerProtosharesBlock.nBits = workDataSource.nBits;
                minerProtosharesBlock.nonce = 0;
                minerProtosharesBlock.height = workDataSource.height;
                memcpy(minerProtosharesBlock.merkleRootOriginal, workDataSource.merkleRootOriginal, 32);
                memcpy(minerProtosharesBlock.prevBlockHash, workDataSource.prevBlockHash, 32);
                memcpy(minerProtosharesBlock.targetShare, workDataSource.targetShare, 32);
                minerProtosharesBlock.uniqueMerkleSeed = uniqueMerkleSeedGenerator;
                uniqueMerkleSeedGenerator++;
                // generate merkle root transaction
                bitclient_generateTxHash(sizeof(uint32), (uint8*)&minerProtosharesBlock.uniqueMerkleSeed, workDataSource.coinBase1Size, workDataSource.coinBase1, workDataSource.coinBase2Size, workDataSource.coinBase2, workDataSource.txHash);
                bitclient_calculateMerkleRoot(workDataSource.txHash, workDataSource.txHashCount + 1, minerProtosharesBlock.merkleRoot);
                hasValidWork = true;
            }
        }

        LeaveCriticalSection(&workDataSource.cs_work);

        if ( hasValidWork == false ) {
            Sleep(1);
            continue;
        }

        // valid work data present, start processing workload
        if ( workDataSource.algorithm == ALGORITHM_PROTOSHARES ) {
            gpu_watchdog_timer = getTimeMilliseconds();
            processor->protoshare_process(&minerProtosharesBlock);
            gpu_watchdog_timer = 0;
        } else {
            printf("xptMiner_minerThread(): Unknown algorithm\n");
            Sleep(5000); // dont spam the console
        }
    }

    delete processor;
    return 0;
}


/*
* Reads data from the xpt connection state and writes it to the universal workDataSource struct
*/
void xptMiner_getWorkFromXPTConnection(xptClient_t* xptClient)
{
    EnterCriticalSection(&workDataSource.cs_work);
    workDataSource.algorithm = xptClient->algorithm;
    workDataSource.version = xptClient->blockWorkInfo.version;
    workDataSource.timeBias = xptClient->blockWorkInfo.timeBias;
    workDataSource.nBits = xptClient->blockWorkInfo.nBits;
    memcpy(workDataSource.merkleRootOriginal, xptClient->blockWorkInfo.merkleRoot, 32);
    memcpy(workDataSource.prevBlockHash, xptClient->blockWorkInfo.prevBlockHash, 32);
    memcpy(workDataSource.target, xptClient->blockWorkInfo.target, 32);
    memcpy(workDataSource.targetShare, xptClient->blockWorkInfo.targetShare, 32);

    workDataSource.coinBase1Size = xptClient->blockWorkInfo.coinBase1Size;
    workDataSource.coinBase2Size = xptClient->blockWorkInfo.coinBase2Size;
    memcpy(workDataSource.coinBase1, xptClient->blockWorkInfo.coinBase1, xptClient->blockWorkInfo.coinBase1Size);
    memcpy(workDataSource.coinBase2, xptClient->blockWorkInfo.coinBase2, xptClient->blockWorkInfo.coinBase2Size);

    // get hashes
    if ( xptClient->blockWorkInfo.txHashCount > MAX_TRANSACTIONS ) {
        printf("Too many transaction hashes\n");
        workDataSource.txHashCount = 0;
    } else {
        workDataSource.txHashCount = xptClient->blockWorkInfo.txHashCount;
    }

    for (uint32 i = 0; i < xptClient->blockWorkInfo.txHashCount; i++) {
        memcpy(workDataSource.txHash + 32 * (i + 1), xptClient->blockWorkInfo.txHashes + 32 * i, 32);
    }

    // set blockheight last since it triggers reload of work
    workDataSource.height = xptClient->blockWorkInfo.height;

    LeaveCriticalSection(&workDataSource.cs_work);
    monitorCurrentBlockHeight = workDataSource.height;
}

#define getFeeFromDouble(_x) ((uint16)((double)(_x)/0.002f)) // integer 1 = 0.002%
/*
* Initiates a new xpt connection object and sets up developer fee
* The new object will be in disconnected state until xptClient_connect() is called
*/
xptClient_t* xptMiner_initateNewXptConnectionObject()
{
    xptClient_t* xptClient = xptClient_create();

    if ( xptClient == NULL ) {
        return NULL;
    }

    // YPool developer fees go here
    return xptClient;
}

void xptMiner_xptQueryWorkLoop()
{
    // init xpt connection object once
    xptClient = xptMiner_initateNewXptConnectionObject();

    uint32 timerPrintDetails = getTimeMilliseconds() + 8000;

    uint8 payout_pos = payout_list.size() - 1;
    uint32 payout_len = 35 * 1000; // Amount of milliseconds per 1% donation

    payout_t cur_payout_info = payout_list.back();
    bool load_next_user = true;
    uint32 cur_payout_round_length = 0;

    while ( true ) {
        uint32 currentTick = getTimeMilliseconds();

        // GPU watchdog
        if ( gpu_watchdog_timer > 0 && (currentTick > gpu_watchdog_timer) && (currentTick - gpu_watchdog_timer) > (gpu_watchdog_max_wait * 1000) ) {
            printf("Gave up after %d milliseconds\n", (currentTick - gpu_watchdog_timer));
            printf("ERROR: Device timeout detected. It's been over %d seconds since we've heard back from the worker thread.\n", gpu_watchdog_max_wait);
            exit(1);
        }

        if ( currentTick >= timerPrintDetails ) {
            // print details only when connected
            if ( xptClient_isDisconnected(xptClient, NULL) == false ) {
                uint32 passedSeconds = (uint32)time(NULL) - miningStartTime;
                double speedRate = 0.0;
                double tableRate = 0.0;
                double sharesPerHour = 0.0;

                if ( workDataSource.algorithm == ALGORITHM_PROTOSHARES ) {
                    // speed is represented as khash/s (in steps of 0x8000)
                    if ( passedSeconds > 5 ) {
                        speedRate = (double)totalCollisionCount / (double)passedSeconds * 60.0;
                        tableRate = (double)totalTableCount / (double)passedSeconds * 60;
                        printf("collisions/min: %.2lf (%s %.1f%%), tables/min: %.2lf; Shares total: %ld (Valid: %ld, Invalid: %ld",
                               speedRate, PLUS_MINUS, 100.0 / pow((double)totalTableCount, 0.5), tableRate, totalShareCount, (totalShareCount - invalidShareCount), invalidShareCount);

                        if ( passedSeconds > 900 ) {
                            sharesPerHour = (double)curShareCount / (double)passedSeconds * 3600.0;
                            printf(", PerHour: %.2f", sharesPerHour);
                        }

                        printf(")\n");
                    }


                }

            }

            timerPrintDetails = currentTick + 8000;
        }

        // check stats
        if ( xptClient_isDisconnected(xptClient, NULL) == false ) {
            EnterCriticalSection(&cs_xptClient);

            // We've reached the time limit for the current user, switch to the next one
            if (cur_payout_round_length > payout_len * cur_payout_info.payout_pct) { load_next_user = true; }

            // Do we need to load the next user?
            if (load_next_user == true) {
                load_next_user = false;

                // This should never happen, but just in case...
                if (payout_list.size() == 0) {
                    printf("No valid user accounts to login with!\n");
                    printf("Please check your run log for more details.\n");
                    exit(-1);
                }

                bool prev_user_was_dev = cur_payout_info.is_developer;
                payout_pos = (payout_pos + 1) % payout_list.size();
                cur_payout_info = payout_list[payout_pos];

                xptClient_forceDisconnect(xptClient);
                minerSettings.requestTarget.authUser = cur_payout_info.workername;
                minerSettings.requestTarget.authPass = cur_payout_info.workerpass;
                strncpy(xptClient->username, minerSettings.requestTarget.authUser, 127);
                strncpy(xptClient->password, minerSettings.requestTarget.authPass, 127);
                memset(&xptClient->blockWorkInfo, 0x00, sizeof(xptBlockWorkInfo_t));
                xptClient_connect(xptClient, &minerSettings.requestTarget);

                double mining_length = (cur_payout_info.payout_pct * (double)payout_len) / 1000.0;

                if (cur_payout_info.is_developer) {
                    if (!prev_user_was_dev) {
                        printf("\nMining for a few moments to support future development\n", mining_length);
                    }
                } else {
                    printf("\nMining shiny coins for the user!\n");
                }

                cur_payout_round_length = 0;
            }


            xptClient_process(xptClient);

            if ( xptClient->disconnected ) {
                // mark work as invalid
                EnterCriticalSection(&workDataSource.cs_work);
                workDataSource.height = 0;
                monitorCurrentBlockHeight = 0;
                LeaveCriticalSection(&workDataSource.cs_work);
                // we lost connection :(
                printf("Connection to server lost - Reconnect in 15 seconds\n");
                xptClient_forceDisconnect(xptClient);
                LeaveCriticalSection(&cs_xptClient);

                // If we lost connection something login related
                if ( xptClient->gotLoginResponse == false ) {
                    // Load the next user, maybe this account is messed up?
                    load_next_user = true;

                } else {
                    if ( xptClient->loginRejected ) {
                        if (cur_payout_info.is_developer) {
                            Sleep(1000); // Allow server time to print messages
                            printf("\n\n");
                            printf("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
                            printf("Whoa nelly!  Contact the developers and let them know they screwed up.\n");
                            printf("Send them this info:\n");
                            printf("    V - %s\n", minerVersionString);
                            printf("    L - %s:%s + %f\n", cur_payout_info.workername, cur_payout_info.workerpass, cur_payout_info.payout_pct);
                            printf("    U - %s:%d\n", commandlineInput.host, commandlineInput.port);
                            printf("    P - %d,%d,%d,%d\n", commandlineInput.buckets_log2, commandlineInput.bucket_size, commandlineInput.target_mem, commandlineInput.wgs);
                            printf("    E - INVALIDUSER\n");
                            printf("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
                            printf("\n\n");
                        }

                        // Delete the info from the list, it's invalid
                        payout_list.erase(payout_list.begin() + payout_pos);
                        payout_pos--;
                        load_next_user = true;

                    } else {
                        // We had a correct login but still disconnected.
                        // It probably means the mining pool is down or there are connection issues
                        // Nothing we can do
                    }
                }

                Sleep(15000);
            } else {
                // is known algorithm?
                if ( xptClient->clientState == XPT_CLIENT_STATE_LOGGED_IN && (xptClient->algorithm != ALGORITHM_PROTOSHARES) ) {
                    // force disconnect
                    xptClient_forceDisconnect(xptClient);
                    LeaveCriticalSection(&cs_xptClient);

                    if (cur_payout_info.is_developer) {
                        Sleep(1000); // Allow server time to print messages
                        printf("\n\n");
                        printf("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
                        printf("Whoa nelly!  Contact the developers and let them know they screwed up.\n");
                        printf("Send them this info:\n");
                        printf("    V - %s\n", minerVersionString);
                        printf("    L - %s:%s + %f\n", cur_payout_info.workername, cur_payout_info.workerpass, cur_payout_info.payout_pct);
                        printf("    U - %s:%d\n", commandlineInput.host, commandlineInput.port);
                        printf("    P - %d,%d,%d,%d\n", commandlineInput.buckets_log2, commandlineInput.bucket_size, commandlineInput.target_mem, commandlineInput.wgs);
                        printf("\tE - BADALGO\n");
                        printf("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
                        printf("\n\n");

                    } else {
                        printf("The login '%s' is configured for an unsupported algorithm.\n", xptClient->username);
                        printf("Make sure you miner login details are correct\n");
                    }

                    // Delete the info from the list, it's invalid
                    payout_list.erase(payout_list.begin() + payout_pos);
                    payout_pos--;
                    load_next_user = true;

                    // Pause so the user can see the message
                    if (!cur_payout_info.is_developer) {
                        Sleep(45000);
                    } else {
                        Sleep(5000);
                    }

                } else if ( xptClient->blockWorkInfo.height != workDataSource.height || memcmp(xptClient->blockWorkInfo.merkleRoot, workDataSource.merkleRootOriginal, 32) != 0  ) {
                    // update work
                    xptMiner_getWorkFromXPTConnection(xptClient);
                    LeaveCriticalSection(&cs_xptClient);
                } else if ( xptClient->clientState != XPT_CLIENT_STATE_LOGGED_IN && (uint32)time(NULL) - miningStartTime > 120 ) {
                    // There's a super annoying bug where a login response is never received from the yPool servers.
                    // To prevent permanently being stuck in limbo, force a disconnect and reconnect by swapping users.
                    printf("Network issues detected, attempting to reconnect.\n");
                    load_next_user = true;
                    LeaveCriticalSection(&cs_xptClient);
                } else {
                    LeaveCriticalSection(&cs_xptClient);
                }

                Sleep(1);

                // The time only counts if we're actually logged in
                cur_payout_round_length += (xptClient->gotLoginResponse ? getTimeMilliseconds() - currentTick : 0);
            }
        } else {
            // initiate new connection
            EnterCriticalSection(&cs_xptClient);

            if ( xptClient_connect(xptClient, &minerSettings.requestTarget) == false ) {
                LeaveCriticalSection(&cs_xptClient);
                printf("Connection attempt failed, retry in 15 seconds\n");
                Sleep(15000);
            } else {
                LeaveCriticalSection(&cs_xptClient);
                printf("Connected to server using x.pushthrough(xpt) protocol\n");
                miningStartTime = (uint32)time(NULL);
                totalCollisionCount = 0;
                totalTableCount = 0;
                curShareCount = 0;
            }

            Sleep(1);
        }
    }
}


void xptMiner_printHelp()
{
    printf("Usage: xptMiner.exe [options]                                                          \n");
    printf("General options:                                                                       \n");
    printf("   -o, -O               The miner will connect to this url                             \n");
    printf("                        You can specify a port after the url using -o url:port         \n");
    printf("   -u                   The username (workername) used for login                       \n");
    printf("   -p                   The password used for login                                    \n");
    printf("   -t <num>             The number of threads for mining (default is 1)                \n");
    printf("   -f <num>             Donation amount for dev (default donates 3.0% to dev)          \n");
    printf("                                                                                       \n");
    printf("Mining options:                                                                        \n");
    printf("   -d <num>,<num>,...   List of GPU devices to use (default is 0).                     \n");
    printf("   -w <num>             GPU work group size (0 = MAX, default is 0, must be power of 2)\n");
    printf("   -v <num>             Vector size (values = 1, 2, 4; default is 1)                   \n");
    printf("   -b <num>             Number of buckets to use in hashing step                       \n");
    printf("                        Uses 2^N buckets (range = 12 to 99, default is 23)             \n");
    printf("   -s <num>             Size of buckets to use (0 = MAX, default is 0)                 \n");
    printf("   -m <num>             Target memory usage in Megabytes, overrides \"-s\"             \n");
    printf("                        (Leave unset if using \"-s\" option)                           \n");
    printf("                                                                                       \n");
    printf("Example usage:                                                                         \n");
    printf("  xptminer.exe -o ypool.net -u workername.pts_1 -p pass -d 0                           \n");
}

void xptMiner_parseCommandline(int argc, char **argv)
{
    sint32 cIdx = 1;

    // Default values
    commandlineInput.donationPercent = 3.0f;
    uint32 wgs          =  0;
    uint32 vect_type    =  1;
    uint32 buckets_log2 = 23;
    uint32 bucket_size  =  0;
    uint32 target_mem   =  0;

    while ( cIdx < argc ) {
        char* argument = argv[cIdx];
        cIdx++;

        if ( memcmp(argument, "-o", 3) == 0 || memcmp(argument, "-O", 3) == 0 ) {
            // -o
            if ( cIdx >= argc ) {
                printf("Missing URL after -o option\n");
                exit(0);
            }

            if ( strstr(argv[cIdx], "http://") ) {
                commandlineInput.host = _strdup(strstr(argv[cIdx], "http://") + 7);
            } else {
                commandlineInput.host = _strdup(argv[cIdx]);
            }

            char* portStr = strstr(commandlineInput.host, ":");

            if ( portStr ) {
                *portStr = '\0';
                commandlineInput.port = atoi(portStr + 1);
            }

            cIdx++;
        } else if ( memcmp(argument, "-u", 3) == 0 ) {
            // -u
            if ( cIdx >= argc ) {
                printf("Missing username/workername after -u option\n");
                exit(0);
            }

            commandlineInput.workername = _strdup(argv[cIdx]);
            cIdx++;
        } else if ( memcmp(argument, "-p", 3) == 0 ) {
            // -p
            if ( cIdx >= argc ) {
                printf("Missing password after -p option\n");
                exit(0);
            }

            commandlineInput.workerpass = _strdup(argv[cIdx]);
            cIdx++;
        } else if ( memcmp(argument, "-t", 3) == 0 ) {
            // -t
            if ( cIdx >= argc ) {
                printf("Missing thread number after -t option\n");
                exit(0);
            }

            commandlineInput.numThreads = atoi(argv[cIdx]);

            if ( commandlineInput.numThreads < 1 || commandlineInput.numThreads > 128 ) {
                printf("-t parameter out of range");
                exit(0);
            }

            cIdx++;
        } else if ( memcmp(argument, "-f", 3) == 0 ) {
            if ( cIdx >= argc ) {
                printf("Missing amount number after -f option\n");
                exit(0);
            }

            float pct = atof(argv[cIdx]);

            if (pct <   3.0) { pct = 3.0;   }
            if (pct > 100.0) { pct = 100.0; }

            commandlineInput.donationPercent = pct;

            cIdx++;
        } else if ( memcmp(argument, "-list-devices", 14) == 0 ) {
            commandlineInput.listDevices = true;
        } else if ( memcmp(argument, "-device", 8) == 0 || memcmp(argument, "-d", 3) == 0 || memcmp(argument, "-devices", 9) == 0) {
            // -d
            if ( cIdx >= argc ) {
                printf("Missing device list after %s option\n", argument);
                exit(0);
            }

            std::string list = std::string(argv[cIdx]);
            std::string delimiter = ",";
            size_t pos = 0;

            while ((pos = list.find(delimiter)) != std::string::npos) {
                std::string token = list.substr(0, pos);
                commandlineInput.deviceList.push_back(atoi(token.c_str()));
                list.erase(0, pos + delimiter.length());
            }

            commandlineInput.deviceList.push_back(atoi(list.c_str()));
            cIdx++;
        } else if ( memcmp(argument, "-w", 2) == 0 ) {
            if ( cIdx >= argc ) {
                printf("Missing work group size after %s option\n", argument);
                exit(0);
            }

            wgs = atoi(argv[cIdx]);

            if (wgs < 0) {
                printf("Work group size '%d' is invalid.  Valid values are 0 or powers of 2.\n", wgs);
                exit(0);
            }

            // Find nearest power of two less than wgs
            wgs = nearest_pow2(wgs);
            cIdx++;
        } else if ( memcmp(argument, "-v", 2) == 0 ) {
            if ( cIdx >= argc ) {
                printf("Missing vector size after %s option\n", argument);
                exit(0);
            }

            vect_type = atoi(argv[cIdx]);

            if (vect_type != 1 && vect_type != 2 && vect_type != 4) {
                printf("Vector size '%d' is invalid.  Valid values are 1, 2, or 4.\n", wgs);
                exit(0);
            }

            // Find nearest power of two less than wgs
            wgs = nearest_pow2(wgs);
            cIdx++;
        } else if ( memcmp(argument, "-b", 2) == 0 ) {
            if ( cIdx >= argc ) {
                printf("Missing work group size after %s option\n", argument);
                exit(0);
            }

            buckets_log2 = atoi(argv[cIdx]);

            if (buckets_log2 < 12 || buckets_log2 > 99) {
                printf("Bucket quantity '%d' is invalid.  Valid values are between 12 and 26.\n", buckets_log2);
                exit(0);
            }

            cIdx++;
        } else if ( memcmp(argument, "-s", 2) == 0 ) {
            if ( cIdx >= argc ) {
                printf("Missing bucket size after %s option\n", argument);
                exit(0);
            }

            bucket_size = atoi(argv[cIdx]);
            cIdx++;
        } else if ( memcmp(argument, "-m", 2) == 0 ) {
            if ( cIdx >= argc ) {
                printf("Missing target memory size after %s option\n", argument);
                exit(0);
            }

            target_mem = atoi(argv[cIdx]);
            cIdx++;
        } else if ( memcmp(argument, "-help", 6) == 0 || memcmp(argument, "--help", 7) == 0 ) {
            xptMiner_printHelp();
            exit(0);
        } else {
            printf("'%s' is an unknown option.\nType xptminer.exe --help for more info\n", argument);
            exit(-1);
        }
    }

    if ( argc <= 1 ) {
        xptMiner_printHelp();
        exit(0);
    }

    commandlineInput.wgs = wgs;
    commandlineInput.vect_type = vect_type;
    commandlineInput.buckets_log2 = buckets_log2;
    commandlineInput.bucket_size = bucket_size;
    commandlineInput.target_mem = target_mem;
}


int main(int argc, char** argv)
{
    // For some reason the full buffering and newline buffering causes major issues.
    // For example, redirecting to file or piping to elsewhere results in no output.
    setvbuf(stdout, NULL, _IONBF, 1024);

    commandlineInput.host = "ypool.net";
    srand(getTimeMilliseconds());
    commandlineInput.port = 8080 + (rand() % 8); // use random port between 8080 and 8087
    commandlineInput.ptsMemoryMode = PROTOSHARE_MEM_256;
    uint32_t numcpu = 1; // in case we fall through;
#if defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
    int mib[4];
    size_t len = sizeof(numcpu);

    /* set the mib for hw.ncpu */
    mib[0] = CTL_HW;
#ifdef HW_AVAILCPU
    mib[1] = HW_AVAILCPU;  // alternatively, try HW_NCPU;
#else
    mib[1] = HW_NCPU;
#endif
    /* get the number of CPUs from the system */
    sysctl(mib, 2, &numcpu, &len, NULL, 0);

    if ( numcpu < 1 ) {
        numcpu = 1;
    }

#elif defined(__linux__) || defined(sun) || defined(__APPLE__)
    numcpu = static_cast<uint32_t>(sysconf(_SC_NPROCESSORS_ONLN));
#elif defined(_SYSTYPE_SVR4)
    numcpu = sysconf( _SC_NPROC_ONLN );
#elif defined(hpux)
    numcpu = mpctl(MPC_GETNUMSPUS, NULL, NULL);
#elif defined(_WIN32)
    SYSTEM_INFO sysinfo;
    GetSystemInfo( &sysinfo );
    numcpu = sysinfo.dwNumberOfProcessors;
#endif

    //commandlineInput.numThreads = numcpu;
    commandlineInput.numThreads = 1;
    commandlineInput.numThreads = std::min(std::max(commandlineInput.numThreads, 1), 4);
    xptMiner_parseCommandline(argc, argv);
    minerSettings.protoshareMemoryMode = commandlineInput.ptsMemoryMode;
    printf("/==================================================\\\n");
    printf("|                                                  |\n");
    printf("|  xptMiner (v1.1) + GPU Protoshare Miner (v0.1g)  |\n");
    printf("|         Radeon 5000/6000 series edition          |\n");
    printf("|  Author: GigaWatt (GPU Code)                     |\n");
    printf("|          Girino   (OpenCL Library)               |\n");
    printf("|          jh00     (xptMiner)                     |\n");
    printf("|                                                  |\n");
    printf("|  Please donate:                                  |\n");
    printf("|      GigaWatt:                                   |\n");
    printf("|      PTS: PbwHkEs9ieWdfJPsowoWingrKyND2uML9s     |\n");
    printf("|      BTC: 1E2egHUcLDAmcxcqZqpL18TPLx9Xj1akcV     |\n");
    printf("|                                                  |\n");
    printf("|      Girino:                                     |\n");
    printf("|      PTS: PkyeQNn1yGV5psGeZ4sDu6nz2vWHTujf4h     |\n");
    printf("|      BTC: 1GiRiNoKznfGbt8bkU1Ley85TgVV7ZTXce     |\n");
    printf("|                                                  |\n");
    printf("\\==================================================/\n");
    printf("Launching miner...\n");
    printf("Using %d threads\n", commandlineInput.numThreads);
    printf("\n");

    // set priority to below normal
    SetPriorityClass(GetCurrentProcess(), BELOW_NORMAL_PRIORITY_CLASS);
    // init winsock
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);

    // get IP of pool url (default ypool.net)
    char* poolURL = commandlineInput.host;

    // Convert to lowercase
    for (uint8 i = 0; poolURL[i] > 0; i++) {
        if (poolURL[i] >= 'A' && poolURL[i] <= 'Z') { poolURL[i] += ('a' - 'A'); }
    }

    hostent* hostInfo = gethostbyname(poolURL);

    if ( hostInfo == NULL ) {
        printf("Cannot resolve '%s'. Is it a valid URL?\n", poolURL);
        exit(-1);
    }

    void** ipListPtr = (void**)hostInfo->h_addr_list;
    uint32 ip = 0xFFFFFFFF;

    if ( ipListPtr[0] ) {
        ip = *(uint32*)ipListPtr[0];
    }

    char* ipText = (char*)malloc(32);
    sprintf(ipText, "%d.%d.%d.%d", ((ip >> 0) & 0xFF), ((ip >> 8) & 0xFF), ((ip >> 16) & 0xFF), ((ip >> 24) & 0xFF));
    // init work source
    InitializeCriticalSection(&workDataSource.cs_work);
    InitializeCriticalSection(&cs_xptClient);
    // setup connection info
    minerSettings.requestTarget.ip = ipText;
    minerSettings.requestTarget.port = commandlineInput.port;
    minerSettings.requestTarget.authUser = commandlineInput.workername;
    minerSettings.requestTarget.authPass = commandlineInput.workerpass;
    minerSettings.requestTarget.donationPercent = commandlineInput.donationPercent;

    // inits GPU
    printf("Available devices:\n");
    OpenCLMain::getInstance().listDevices();

    if (commandlineInput.listDevices) {
        exit(0);
    }

    if (commandlineInput.deviceList.empty()) {
        for (int i = 0; i < commandlineInput.numThreads; i++) {
            commandlineInput.deviceList.push_back(i);
        }
    } else {
        commandlineInput.numThreads = commandlineInput.deviceList.size();
    }

    printf("\n");
    printf("Adjusting num threads to match device list: %d\n", commandlineInput.numThreads);

    // inits all GPU devices
    printf("\n");
    printf("Initializing workers...\n");

    for (int i = 0; i < commandlineInput.deviceList.size(); i++) {
        printf("Initing device %d...\n", i);
        gpu_processors.push_back(new ProtoshareOpenCL(commandlineInput.deviceList[i]));

    }

    printf("\nAll GPUs Initialized...\n");
    printf("\n");
    printf("\n");


    payout_t payout_temp;
    double total_payout = 100.00;

    // Add GigaWatt to developer fee payout
    payout_temp.workername = _strdup(strstr(poolURL, "ypool") != NULL ? "gigawatt.pts_dev" : "PbwHkEs9ieWdfJPsowoWingrKyND2uML9s");
    payout_temp.workerpass = "x";
    payout_temp.payout_pct = commandlineInput.donationPercent;
    payout_temp.is_developer = true;
    total_payout -= payout_temp.payout_pct;
    payout_list.push_back( payout_temp );

    // Add the user's account to payout list
    payout_temp.workername = commandlineInput.workername;
    payout_temp.workerpass = commandlineInput.workerpass;
    payout_temp.payout_pct = total_payout;
    payout_temp.is_developer = false;
    payout_list.push_back( payout_temp );


    // start miner threads
    for (uint32 i = 0; i < commandlineInput.numThreads; i++) {
        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)xptMiner_minerThread, (LPVOID)0, 0, NULL);
    }

    // enter work management loop
    xptMiner_xptQueryWorkLoop();
    return 0;
}

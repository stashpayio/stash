// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Copyright (c) 2014-2020 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#include "arith_uint256.h"

#include "chainparams.h"
#include "consensus/merkle.h"

#include "tinyformat.h"
#include "util.h"
#include "utilstrencodings.h"

#include "arith_uint256.h"

#include <assert.h>

#include <boost/assign/list_of.hpp>
#include <boost/filesystem.hpp>

#include "chainparamsseeds.h"

bool seedsDisabled() {
    return fs::exists(".disableseeds");
}

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

static CBlock CreateDevNetGenesisBlock(const uint256 &prevBlockHash, const std::string& devNetName, uint32_t nTime, uint32_t nNonce, uint32_t nBits, const CAmount& genesisReward)
{
    assert(!devNetName.empty());

    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    // put height (BIP34) and devnet name into coinbase
    txNew.vin[0].scriptSig = CScript() << CScriptCoinbaseHeight(1) << std::vector<unsigned char>(devNetName.begin(), devNetName.end());
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = CScript() << OP_RETURN;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = 4;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock = prevBlockHash;
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database.
 *
 * CBlock(hash=00000ffd590b14, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=e0028e, nTime=1390095618, nBits=1e0ffff0, nNonce=28917698, vtx=1)
 *   CTransaction(hash=e0028e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
 *     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d01044c5957697265642030392f4a616e2f3230313420546865204772616e64204578706572696d656e7420476f6573204c6976653a204f76657273746f636b2e636f6d204973204e6f7720416363657074696e6720426974636f696e73)
 *     CTxOut(nValue=50.00000000, scriptPubKey=0xA9037BAC7050C479B121CF)
 *   vMerkleTree: e0028e
 */
static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "0e88670908018e40b63451903feb14fe8ce0739433a01da797428701f0973798";
    const CScript genesisOutputScript = CScript() << ParseHex("040184710fa689ad5023690c80f3a49c8f13f8d45b8c857fbcbc8bc4a8e4d3eb4b10f4d4604fa08dce601aaf0f470216fe1b51850b4acf21b179c45070ac7b03a9") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}


void CChainParams::UpdateVersionBitsParameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout, int64_t nWindowSize, int64_t nThreshold)
{
    consensus.vDeployments[d].nStartTime = nStartTime;
    consensus.vDeployments[d].nTimeout = nTimeout;
    if (nWindowSize != -1) {
            consensus.vDeployments[d].nWindowSize = nWindowSize;
    }
    if (nThreshold != -1) {
            consensus.vDeployments[d].nThreshold = nThreshold;
    }
}

void CChainParams::UpdateDIP3Parameters(int nActivationHeight, int nEnforcementHeight)
{
    consensus.DIP0003Height = nActivationHeight;
    consensus.DIP0003EnforcementHeight = nEnforcementHeight;
}

void CChainParams::UpdateBudgetParameters(int nMasternodePaymentsStartBlock, int nBudgetPaymentsStartBlock, int nSuperblockStartBlock)
{
    consensus.nMasternodePaymentsStartBlock = nMasternodePaymentsStartBlock;
    consensus.nBudgetPaymentsStartBlock = nBudgetPaymentsStartBlock;
    consensus.nSuperblockStartBlock = nSuperblockStartBlock;
}

void CChainParams::UpdateSubsidyAndDiffParams(int nMinimumDifficultyBlocks, int nHighSubsidyBlocks, int nHighSubsidyFactor)
{
    consensus.nMinimumDifficultyBlocks = nMinimumDifficultyBlocks;
    consensus.nHighSubsidyBlocks = nHighSubsidyBlocks;
    consensus.nHighSubsidyFactor = nHighSubsidyFactor;
}

void CChainParams::UpdateLLMQChainLocks(Consensus::LLMQType llmqType) {
    consensus.llmqTypeChainLocks = llmqType;
}

static CBlock FindDevNetGenesisBlock(const Consensus::Params& params, const CBlock &prevBlock, const CAmount& reward)
{
    std::string devNetName = GetDevNetName();
    assert(!devNetName.empty());

    CBlock block = CreateDevNetGenesisBlock(prevBlock.GetHash(), devNetName.c_str(), prevBlock.nTime + 1, 0, prevBlock.nBits, reward);

    arith_uint256 bnTarget;
    bnTarget.SetCompact(block.nBits);

    for (uint32_t nNonce = 0; nNonce < UINT32_MAX; nNonce++) {
        block.nNonce = nNonce;

        uint256 hash = block.GetHash();
        if (UintToArith256(hash) <= bnTarget)
            return block;
    }

    // This is very unlikely to happen as we start the devnet with a very low difficulty. In many cases even the first
    // iteration of the above loop will give a result already
    error("FindDevNetGenesisBlock: could not find devnet genesis block for %s", devNetName);
    assert(false);
}

static void GenerateGenesisHash(CBlock& genesis, const std::string& strNetworkID) 
{
    // calculate genesis hash
    printf("recalculating %s genesis block...\n", strNetworkID.c_str());
    arith_uint256 hashTarget = arith_uint256().SetCompact(genesis.nBits);
    // deliberately empty for loop finds nonce value.
    for(genesis.nNonce = 0; UintToArith256(genesis.GetHash()) > hashTarget; genesis.nNonce++){ }
    printf("new genesisPOW target: %s\n", hashTarget.GetHex().c_str());
    printf("new genesis merkle root: 0x%s\n", genesis.hashMerkleRoot.ToString().c_str());
    printf("new genesis nonce: %d\n", genesis.nNonce);
    printf("new genesis hash: 0x%s\n", genesis.GetHash().ToString().c_str());
}

// this one is for testing only
static Consensus::LLMQParams llmq5_60 = {
        .type = Consensus::LLMQ_5_60,
        .name = "llmq_5_60",
        .size = 5,
        .minSize = 3,
        .threshold = 3,

        .dkgInterval = 60, // one DKG per hour
        .dkgPhaseBlocks = 2,
        .dkgMiningWindowStart = 10, // dkgPhaseBlocks * 5 = after finalization
        .dkgMiningWindowEnd = 18,
        .dkgBadVotesThreshold = 8,

        .signingActiveQuorumCount = 2, // just a few ones to allow easier testing

        .keepOldConnections = 3,
};

static Consensus::LLMQParams llmq50_60 = {
        .type = Consensus::LLMQ_50_60,
        .name = "llmq_50_60",
        .size = 50,
        .minSize = 40,
        .threshold = 30,

        .dkgInterval = 60, // one DKG per hour
        .dkgPhaseBlocks = 2,
        .dkgMiningWindowStart = 10, // dkgPhaseBlocks * 5 = after finalization
        .dkgMiningWindowEnd = 18,
        .dkgBadVotesThreshold = 40,

        .signingActiveQuorumCount = 24, // a full day worth of LLMQs

        .keepOldConnections = 25,
};

static Consensus::LLMQParams llmq400_60 = {
        .type = Consensus::LLMQ_400_60,
        .name = "llmq_400_60",
        .size = 400,
        .minSize = 300,
        .threshold = 240,

        .dkgInterval = 60 * 12, // one DKG every 12 hours
        .dkgPhaseBlocks = 4,
        .dkgMiningWindowStart = 20, // dkgPhaseBlocks * 5 = after finalization
        .dkgMiningWindowEnd = 28,
        .dkgBadVotesThreshold = 300,

        .signingActiveQuorumCount = 4, // two days worth of LLMQs

        .keepOldConnections = 5,
};

// Used for deployment and min-proto-version signalling, so it needs a higher threshold
static Consensus::LLMQParams llmq400_85 = {
        .type = Consensus::LLMQ_400_85,
        .name = "llmq_400_85",
        .size = 400,
        .minSize = 350,
        .threshold = 340,

        .dkgInterval = 60 * 24, // one DKG every 24 hours
        .dkgPhaseBlocks = 4,
        .dkgMiningWindowStart = 20, // dkgPhaseBlocks * 5 = after finalization
        .dkgMiningWindowEnd = 48, // give it a larger mining window to make sure it is mined
        .dkgBadVotesThreshold = 300,

        .signingActiveQuorumCount = 4, // four days worth of LLMQs

        .keepOldConnections = 5,
};


/**
 * Main network
 */
/**
 * What makes a good checkpoint block?
 * + Is surrounded by blocks with reasonable timestamps
 *   (no blocks before with a timestamp after, none after with
 *    timestamp before)
 * + Contains no strange transactions
 */


class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = "main";
        consensus.nSubsidyHalvingInterval = 525960; // Note: actual number of blocks per calendar year with DGW v3 is ~200700 (for example 449750 - 249050)
        consensus.nMasternodePaymentsStartBlock = 1000; // not true, but it's ok as long as it's less then nMasternodePaymentsIncreaseBlock
        //consensus.nMasternodePaymentsIncreaseBlock = 2000; // STASH not used
        //consensus.nMasternodePaymentsIncreasePeriod = 576*30; // STASH not used
        consensus.nInstantSendConfirmationsRequired = 6;
        consensus.nInstantSendKeepLock = 24;
        consensus.nBudgetPaymentsStartBlock = 1000;
        //consensus.nBudgetPaymentsCycleBlocks = 43830; // ~(60*24*365.25)/12
        //consensus.nBudgetPaymentsWindowBlocks = 100;
        consensus.nSuperblockStartBlock = 1200; // NOTE: Should satisfy nSuperblockStartBlock > nBudgetPaymentsStartBlock
        //consensus.nSuperblockStartHash = uint256(); // STASH unused
        consensus.nSuperblockCycle = 43830; // ~(365.25*60*24)/12
        consensus.nGovernanceMinQuorum = 10;
        consensus.nGovernanceFilterElements = 20000;
        consensus.nMasternodeMinimumConfirmations = 15;
        consensus.BIP34Height = 1;
        consensus.BIP65Height = 1; // 00000000000076d8fcea02ec0963de4abfd01e771fec0863f960c2c64fe6f357
        consensus.BIP66Height = 1; // 00000000000b1fa2dfa312863570e13fae9ca7b5566cb27e55422620b469aefa
		consensus.DIP0001Height = 1;
        consensus.DIP0003EnforcementHeight = 0; // TODO harden after SPORK_15_DETERMINISTIC_MNS_ENABLED is set
        consensus.DIP0003EnforcementHash = uint256();
        consensus.powLimit = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"); // ~uint256(0) >> 20
        consensus.nPowTargetTimespan = 24 * 60 * 60; // Stash: 1 day
        consensus.nPowTargetSpacing = 1 * 60; // Stash: 1 minute
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = false;
        // consensus.nPowKGWHeight = 15200; STASH Always use DGW
        // consensus.nPowDGWHeight = 34140; STASH Always use DGW
        consensus.nRuleChangeActivationThreshold = 1916; // 95% of 2016
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1594105627; // August 7th, 2020
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1625641627; // August 7th, 2021
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nWindowSize = 4000;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nThreshold = 400; // 10% of 4000

/* START STASH - BIP147 and DIP0001 are activated at genesis
        // Deployment of DIP0001
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0001].bit = 1;
   		consensus.vDeployments[Consensus::DEPLOYMENT_DIP0001].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0001].nTimeout = 0; // 
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0001].nWindowSize = 100;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0001].nThreshold = 50;

        // Deployment of BIP147
        consensus.vDeployments[Consensus::DEPLOYMENT_BIP147].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_BIP147].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_BIP147].nTimeout = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_BIP147].nWindowSize = 100;
        consensus.vDeployments[Consensus::DEPLOYMENT_BIP147].nThreshold = 50; // 50% of 100
END STASH */

        // Deployment of DIP0003
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0003].bit = 3;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0003].nStartTime = 1594105627; // August 7th, 2020
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0003].nTimeout = 1625641627; // August 7th, 2021
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0003].nWindowSize = 4000;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0003].nThreshold = 400; // 10% of 4000

        // Deployment of DIP0008
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0008].bit = 4;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0008].nStartTime = 1594105627; // August 7th, 2020
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0008].nTimeout = 1625641627; // August 7th, 2021
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0008].nWindowSize = 4032;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0008].nThreshold = 3226; // 80% of 4032

       // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0000000000000000000000000000000000000000000000007def55116954271e"); // 524133

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("000000000012232cdbe34c8c40d598775b001b9081f3ad3744995488365369d1"); // 524133

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0xaa;
        pchMessageStart[1] = 0x1b;
        pchMessageStart[2] = 0x69;
        pchMessageStart[3] = 0xb0;
        nDefaultPort = 9999;
        nPruneAfterHeight = 100000;

        genesis = CreateGenesisBlock(1553119080, 807965, 0x1e0ffff0, 1, 50 * COIN);

        if (genesis.nNonce == 0) {
          GenerateGenesisHash(genesis, strNetworkID);
        }

        consensus.hashGenesisBlock = genesis.GetHash();

        assert(consensus.hashGenesisBlock == uint256S("0x000008850016c23058c0b4bd1ededb5953fc2702e66ef278d6dbd4ba98e03526"));
        assert(genesis.hashMerkleRoot == uint256S("0x965e2a3e499686a80cc1f990a5b18687cf766a892e8ec37b32de99609eaf5ca3"));

        if (seedsDisabled()) {
              printf("Seeds disabled on mainnet\n");
        } else {
	        vSeeds.emplace_back("dnsseed.stashpay.io", true);
	        vSeeds.emplace_back("dnsseed.stpx.io", true);
	        vSeeds.emplace_back("dnsseed.stashpay.org", true);
        }

        // Stash addresses start with 'X'
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,76);
        // Stash script addresses start with '7'
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,16);
        // Stash private keys start with '7' or 'X'
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,204);
        // Stash BIP32 pubkeys start with 'xpub' (Bitcoin defaults)
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x88)(0xB2)(0x1E).convert_to_container<std::vector<unsigned char> >();
        // Stash BIP32 prvkeys start with 'xprv' (Bitcoin defaults)
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x88)(0xAD)(0xE4).convert_to_container<std::vector<unsigned char> >();

        // guarantees the first 2 characters, when base58 encoded, are "zc"
        base58Prefixes[ZCPAYMENT_ADDRRESS] = {0x16,0x9A};
        // guarantees the first 4 characters, when base58 encoded, are "ZiVK"
        base58Prefixes[ZCVIEWING_KEY]      = {0xA8,0xAB,0xD3};
        // guarantees the first 2 characters, when base58 encoded, are "SK"
        base58Prefixes[ZCSPENDING_KEY]     = {0xAB,0x36};

        // Stash BIP44 coin type is '0xC0C0'
        nExtCoinType = 0xC0C0;

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        // long living quorum params
        consensus.llmqs[Consensus::LLMQ_50_60] = llmq50_60;
        consensus.llmqs[Consensus::LLMQ_400_60] = llmq400_60;
        consensus.llmqs[Consensus::LLMQ_400_85] = llmq400_85;
        consensus.llmqTypeChainLocks = Consensus::LLMQ_400_60;
        consensus.llmqTypeInstantSend = Consensus::LLMQ_50_60;

        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fRequireRoutableExternalIP = true;
        fMineBlocksOnDemand = false;
        fAllowMultipleAddressesFromGroup = false;
        fAllowMultiplePorts = false;

        nPoolMinParticipants = 3;
        nPoolMaxParticipants = 5;
        nFulfilledRequestExpireTime = 60*60; // fulfilled requests expire in 1 hour

        vSporkAddresses = 
        {
            "Xmvo2yTcJK96QDsJ4xEzNZsSiQgowuw1wW",
            "XvBzUPEDLuYC35Lgb68cbmMi384PNypVqQ",
            "XpjfZirxGS78ZmgCybzUbUa4FbuJy15oYL",
            "Xpc9fB3YGqkYLbuYmj7jzUn5PHZz7G3kzk",
            "XxPyBuCw3zxU4xBsxDuJCXhUZrnPAiVpFR",
        };

        nMinSporkKeys = 3;
        fBIP9CheckMasternodesUpgraded = true;

        checkpointData = (CCheckpointData) {
            boost::assign::map_list_of
            (  1444, uint256S("0000001aedbc434e031db5147b3c9b6cc76a65f9031aed32ac0405e628cd1a5f"))
            (  9344, uint256S("0000000000999ddf6416b9d8f7b6011965daf2b3be41e81e76aed294ee60d1da"))
            (  524133, uint256S("000000000012232cdbe34c8c40d598775b001b9081f3ad3744995488365369d1"))
            (  593697, uint256S("00000000000e28b36f68b4df03fd55597f290b37cecae6380f8d925a234e04ec"))
            (  788625, uint256S("00000000000dcb22e55dde5f3c9863601022832955912e49bcaab25a7a05086a"))
        };

        chainTxData = ChainTxData{
            1583808398, // * UNIX timestamp of last known number of transactions
            632294,     // * total number of transactions between genesis and that timestamp
                        //   (the tx=... number in the SetBestChain debug.log lines)
            0.2         // * estimated number of transactions per second after that timestamp
        };

        vHashLegacyBlocks = {

//------------------------------------------------------------------------------
// Do not edit manually
        "000d4d77bbb3c407751c5364a87fc0205ca9ba0fc423d2a411e7b1c50ee54a79",
        "000f6d80bd34f72b092fc7a765738571db9ef69cb59f364cf5b7e2a0946aecc1",
        "0007dd6a4a3d68172ff64e20fb054d0bfc47974755db1c94329e2dd1523f07cd",
        "00021c6869dce542dcebed1167821ac0304c9b51cdbfb6b7c2a585eb0f4f6348",
        "000d10b463cf614395e742d473970be016654755dce0e306c3db847c8e8f4a80",
        "000cf457b25eac488f4cd9d82784d21d0d50c0d7bfa930164d8578bf59931881",
        "0003935df446c5375aaffa9c8645ebf3f8ba818e043951b0958fefba4a884e13",
        "0006c9f2ea80f25fb2fdfb9eb23f1eeb80d749221c8283b3e823d11ab35efa12",
        "000b6f164e3daea42fed55e5ff256d7ca9a210c096ee275179509e508e908e8b",
        "000ca2cb4b4ff329f83aa1c0bb279068642229bd35817f2953ccd9e81066db75",
        "0004feb9f3d95baa0f0422ba57b3273ebe57e5131709a981789e29935a3847ee",
        "000f65bf525c494b9c39b47d0ab5b28aba84477bdc8a56cf8b664e22d8d026f8",
        "000c6f38b0bb8967f0fe33590ba3476dddff213001e2cb95649e42411e7472f8",
        "000c380ab17475172c9faada25f906f56adbfec143059fdac2b368aac06b521b",
        "00019a5d5488c95b1a9dfd6dc036631cc2ec652433338f90eda77961a495cf9d",
        "000ae8128479c982082c1278740c550528e8a553eee014a6d50ebb344e938161",
        "00048fb8f470cc9045e73d587a81d4411ead4388416e506bfe0c1c30a754fdde",
        "0005cd423a7aa17bc0b8b998b958d783ed95006bb2755b71c470a86b8d3a4246",
//------------------------------------------------------------------------------

        };

    }
};

/**
 * Testnet (v3)
 */
class CTestNetParams : public CChainParams {
public:
   CTestNetParams() {
        strNetworkID = "test";
        consensus.nSubsidyHalvingInterval = 525960;
        consensus.nMasternodePaymentsStartBlock = 1000; // not true, but it's ok as long as it's less then nMasternodePaymentsIncreaseBlock
        //consensus.nMasternodePaymentsIncreaseBlock = 270; // STASH not used
        //consensus.nMasternodePaymentsIncreasePeriod = 10; // STASH not used
        consensus.nInstantSendConfirmationsRequired = 2;
        consensus.nInstantSendKeepLock = 6;
        consensus.nBudgetPaymentsStartBlock = 1000;
        //consensus.nBudgetPaymentsCycleBlocks = 50; // STASH unused
        //consensus.nBudgetPaymentsWindowBlocks = 10; // STASH unused
        consensus.nSuperblockStartBlock = 1200; // NOTE: Should satisfy nSuperblockStartBlock > nBudgetPaymentsStartBlock
        //consensus.nSuperblockStartHash = uint256(); // STASH unused
        consensus.nSuperblockCycle = 60; // Superblocks can be issued hourly on testnet
        consensus.nGovernanceMinQuorum = 1;
        consensus.nGovernanceFilterElements = 500;
        consensus.nMasternodeMinimumConfirmations = 1;
        consensus.BIP34Height = 1;
        consensus.BIP65Height = 1; // 0000039cf01242c7f921dcb4806a5994bc003b48c1973ae0c89b67809c2bb2ab
        consensus.BIP66Height = 1; // 0000002acdd29a14583540cb72e1c5cc83783560e38fa7081495d474fe1671f7
        consensus.DIP0001Height = 1;
        consensus.DIP0003Height = 0; // TODO update to bip9 dip0003 activation height
        consensus.DIP0003EnforcementHeight = 0; // TODO harden after SPORK_15_DETERMINISTIC_MNS_ENABLED set
        consensus.DIP0003EnforcementHash = uint256();
        consensus.powLimit = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"); // ~uint256(0) >> 20
        consensus.nPowTargetTimespan = 24 * 60 * 60; // Stash: 1 day
        consensus.nPowTargetSpacing = 1 * 60; // Stash: 1 minute
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = false;
        // consensus.nPowKGWHeight = 1; STASH Always use DGW
        // consensus.nPowDGWHeight = 1;
        consensus.nRuleChangeActivationThreshold = 1512; // 75% for testchains
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1594105627; // August 7th, 2020
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1625641627; // August 7th, 2021 // Always activate
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nWindowSize = 100;
		consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nThreshold = 50; // 50% of 100

/* START STASH - BIP147 and DIP0001 are activated at genesis
        // Deployment of DIP0001
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0001].bit = 1;
   		consensus.vDeployments[Consensus::DEPLOYMENT_DIP0001].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0001].nTimeout = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0001].nWindowSize = 100;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0001].nThreshold = 50; // 50% of 100

        // Deployment of BIP147
        consensus.vDeployments[Consensus::DEPLOYMENT_BIP147].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_BIP147].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_BIP147].nTimeout = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_BIP147].nWindowSize = 100;
        consensus.vDeployments[Consensus::DEPLOYMENT_BIP147].nThreshold = 50; // 50% of 100
END STASH */
		
        // Deployment of DIP0003
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0003].bit = 3;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0003].nStartTime = 1594105627; // August 7th, 2020
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0003].nTimeout = 1625641627; // August 7th, 2021
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0003].nWindowSize = 100;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0003].nThreshold = 50; // 50% of 100

        // Deployment of DIP0008
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0008].bit = 4;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0008].nStartTime = 1594105627; // August 7th, 2020
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0008].nTimeout = 1625641627; // August 7th, 2021
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0008].nWindowSize = 100;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0008].nThreshold = 50; // 50% of 100

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x000003b3e112e618aafc03f5c4aab234994f9cabd54952dfb439f7706c9bbcf0"); // genesis

        pchMessageStart[0] = 0xef;
        pchMessageStart[1] = 0xa2;
        pchMessageStart[2] = 0xfa;
        pchMessageStart[3] = 0xf7;
        nDefaultPort = 19999;
        //nMaxTipAge = 0x7fffffff; // allow mining on top of old blocks for testnet
        //nMaxTipAge = 16000 * 60 * 60; // ~144 blocks behind -> 2 x fork detection time, was 24 * 60 * 60 in bitcoin

        //nDelayGetHeadersTime = 0; // DTG 24 * 60 * 60;
        nPruneAfterHeight = 1000;

        genesis = CreateGenesisBlock(1594105627, 539600, 0x1e0ffff0, 1, 50 * COIN);

        if (genesis.nNonce == 0) {
          GenerateGenesisHash(genesis, strNetworkID);
        }

        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x000003b3e112e618aafc03f5c4aab234994f9cabd54952dfb439f7706c9bbcf0"));
        assert(genesis.hashMerkleRoot == uint256S("0x965e2a3e499686a80cc1f990a5b18687cf766a892e8ec37b32de99609eaf5ca3"));

        vFixedSeeds.clear();
        vSeeds.clear();
        if (seedsDisabled()) {

			vSeeds.emplace_back("testseed1.stashpay.io", true);
		    //vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));
        }

        // Testnet Stash addresses start with 'y'
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,140);
        // Testnet Stash script addresses start with '8' or '9'
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,19);
        // Testnet private keys start with '9' or 'c' (Bitcoin defaults)
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        // Testnet Stash BIP32 pubkeys start with 'tpub' (Bitcoin defaults)
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x35)(0x87)(0xCF).convert_to_container<std::vector<unsigned char> >();
        // Testnet Stash BIP32 prvkeys start with 'tprv' (Bitcoin defaults)
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x35)(0x83)(0x94).convert_to_container<std::vector<unsigned char> >();

        // guarantees the first 2 characters, when base58 encoded, are "zt"
         base58Prefixes[ZCPAYMENT_ADDRRESS] = {0x16,0xB6};
         // guarantees the first 4 characters, when base58 encoded, are "ZiVt"
         base58Prefixes[ZCVIEWING_KEY]      = {0xA8,0xAC,0x0C};
         // guarantees the first 2 characters, when base58 encoded, are "ST"
         base58Prefixes[ZCSPENDING_KEY]     = {0xAC,0x08};

        // Testnet Stash BIP44 coin type is '1' (All coin's testnet default)
        nExtCoinType = 1;

        // long living quorum params
        consensus.llmqs[Consensus::LLMQ_5_60] = llmq5_60;
        consensus.llmqs[Consensus::LLMQ_50_60] = llmq50_60;
        consensus.llmqs[Consensus::LLMQ_400_60] = llmq400_60;
        consensus.llmqs[Consensus::LLMQ_400_85] = llmq400_85;
        consensus.llmqTypeChainLocks = Consensus::LLMQ_5_60;
        consensus.llmqTypeInstantSend = Consensus::LLMQ_5_60;

        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fRequireRoutableExternalIP = true;
        fMineBlocksOnDemand = false;
        fAllowMultipleAddressesFromGroup = false;
        fAllowMultiplePorts = true;

        nPoolMinParticipants = 3;
        nPoolMaxParticipants = 5;
        nFulfilledRequestExpireTime = 5*60; // fulfilled requests expire in 5 minutes

        vSporkAddresses = 
        {
            "yV3p8PphQoZNpo7CEXAesrbf6fgCCJ8FPt",
            "yfk6EQeoyiMa6hZGzLMLSoJpNni9q8X4CG",
            "yQzX7YukkjhNyB75omy7ShsFjg7frLbsTP",
            "yY52ekPAPt8vNu4vB7kGFmD5RxkL82moFK",
            "yXVf7HZ1WFjd5MHiNJKzJUH3sYuuCn6ZLP",
        };

        nMinSporkKeys = 3;
        fBIP9CheckMasternodesUpgraded = true;

        checkpointData = (CCheckpointData) {
            boost::assign::map_list_of
            (  0, uint256S("0x000003b3e112e618aafc03f5c4aab234994f9cabd54952dfb439f7706c9bbcf0"))
        };

        chainTxData = ChainTxData{
            genesis.GetBlockTime(),// * UNIX timestamp of last known number of transactions
            0,        // * total number of transactions between genesis and that timestamp
                        //   (the tx=... number in the SetBestChain debug.log lines)
            0.006       // * estimated number of transactions per second after that timestamp
        };

        vHashLegacyBlocks = {
//------------------------------------------------------------------------------
// Do not edit manually
        "0004db8cb5eec1cda116a965b48efc6d25e8aa7207b4e95e8f284a388d83b9fb",
        "0003d7a8a5c7838a5fe92f8fc20316386930ed703e972345338326abfc890190",
        "000d4ecf8338825ffd5d72dd51222f693d521a627c0223de9f2caf9a29d18c42",
        "0002c8fbe6f2d0847eb99d6f9dcb3ddf46fdb7b70e46a85ecf2b5e7e960f80d4",
//------------------------------------------------------------------------------
        };
    }
};

/**
 * Devnet
 */
class CDevNetParams : public CChainParams {
public:
    CDevNetParams() {
        strNetworkID = "dev";
        consensus.nSubsidyHalvingInterval = 525960;
        consensus.nMasternodePaymentsStartBlock = 1000; // not true, but it's ok as long as it's less then nMasternodePaymentsIncreaseBlock
        //consensus.nMasternodePaymentsIncreaseBlock = 4030; // STASH not used
        //consensus.nMasternodePaymentsIncreasePeriod = 10; // STASH not used
        consensus.nBudgetPaymentsStartBlock = 1000;
        //consensus.nBudgetPaymentsCycleBlocks = 50; // STASH unused
        //consensus.nBudgetPaymentsWindowBlocks = 10; // STASH unused
        consensus.nSuperblockStartBlock = 1200; // NOTE: Should satisfy nSuperblockStartBlock > nBudgetPaymentsStartBlock
        //consensus.nSuperblockStartHash = uint256(); // STASH unused
        consensus.nSuperblockCycle = 24; // Superblocks can be issued hourly on devnet
        consensus.nGovernanceMinQuorum = 1;
        consensus.nGovernanceFilterElements = 500;
        consensus.nMasternodeMinimumConfirmations = 1;
        consensus.BIP34Height = 1; // BIP34 activated immediately on devnet
        consensus.BIP65Height = 1; // BIP65 activated immediately on devnet
        consensus.BIP66Height = 1; // BIP66 activated immediately on devnet
        consensus.DIP0001Height = 2; // DIP0001 activated immediately on devnet
        consensus.DIP0003Height = 2; // DIP0003 activated immediately on devnet
        consensus.DIP0003EnforcementHeight = 2; // DIP0003 activated immediately on devnet
        consensus.DIP0003EnforcementHash = uint256();
        consensus.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"); // ~uint256(0) >> 1
        consensus.nPowTargetTimespan = 24 * 60 * 60; // Stash: 1 day
        consensus.nPowTargetSpacing = 1 * 60; // Stash: 1 minute
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = false;
        // consensus.nPowKGWHeight = 1; STASH Always use DGW
        // consensus.nPowDGWHeight = 1;
        consensus.nRuleChangeActivationThreshold = 1512; // 75% for testchains
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1594105627; // August 7th, 2020
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1625641627; // August 7th, 2021
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nWindowSize = 100;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nThreshold = 50; // 50% of 100

        // Deployment of DIP0003
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0003].bit = 3;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0003].nStartTime = 1594105627; // August 7th, 2020
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0003].nTimeout = 1625641627; // August 7th, 2021
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0003].nWindowSize = 100;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0003].nThreshold = 50; // 50% of 100

        // Deployment of DIP0008
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0008].bit = 4;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0008].nStartTime = 1594105627; // August 7th, 2020
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0008].nTimeout = 1625641627; // August 7th, 2021
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0008].nWindowSize = 100;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0008].nThreshold = 50; // 50% of 100

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x000000000000000000000000000000000000000000000000000000000000000");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x000000000000000000000000000000000000000000000000000000000000000");

        pchMessageStart[0] = 0xe2;
        pchMessageStart[1] = 0xca;
        pchMessageStart[2] = 0xff;
        pchMessageStart[3] = 0xce;
        nDefaultPort = 19799;
        nPruneAfterHeight = 1000;

        genesis = CreateGenesisBlock(1545016533, 498287, 0x207fffff, 1, 50 * COIN);

        if (genesis.nNonce == 0) {
          GenerateGenesisHash(genesis, strNetworkID);
        }

        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x000001132a8c3bdb334f682ab11a9fdf49fed1a593f0833aa4f7ff3b5ad091b9"));
        assert(genesis.hashMerkleRoot == uint256S("0x965e2a3e499686a80cc1f990a5b18687cf766a892e8ec37b32de99609eaf5ca3"));

        devnetGenesis = FindDevNetGenesisBlock(consensus, genesis, 50 * COIN);
        consensus.hashDevnetGenesisBlock = devnetGenesis.GetHash();

        vFixedSeeds.clear();
        vSeeds.clear();
        //vSeeds.push_back(CDNSSeedData("stashevo.org",  "devnet-seed.stashevo.org"));

        // Testnet Stash addresses start with 'y'
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,140);
        // Testnet Stash script addresses start with '8' or '9'
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,19);
        // Testnet private keys start with '9' or 'c' (Bitcoin defaults)
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        // Testnet Stash BIP32 pubkeys start with 'tpub' (Bitcoin defaults)
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x35)(0x87)(0xCF).convert_to_container<std::vector<unsigned char> >();
        // Testnet Stash BIP32 prvkeys start with 'tprv' (Bitcoin defaults)
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x35)(0x83)(0x94).convert_to_container<std::vector<unsigned char> >();

        // Testnet Stash BIP44 coin type is '1' (All coin's testnet default)
        nExtCoinType = 1;

        // long living quorum params
        consensus.llmqs[Consensus::LLMQ_5_60] = llmq5_60;
        consensus.llmqs[Consensus::LLMQ_50_60] = llmq50_60;
        consensus.llmqs[Consensus::LLMQ_400_60] = llmq400_60;
        consensus.llmqs[Consensus::LLMQ_400_85] = llmq400_85;
        consensus.llmqTypeChainLocks = Consensus::LLMQ_50_60;
        consensus.llmqTypeInstantSend = Consensus::LLMQ_50_60;

        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;
        fAllowMultipleAddressesFromGroup = true;
        fAllowMultiplePorts = true;

        nPoolMinParticipants = 3;
        nPoolMaxParticipants = 5;
        nFulfilledRequestExpireTime = 5*60; // fulfilled requests expire in 5 minutes

        
        vSporkAddresses = {"yj949n1UH6fDhw6HtVE5VMj2iSTaSWBMcW"};
        nMinSporkKeys = 1;
        // devnets are started with no blocks and no MN, so we can't check for upgraded MN (as there are none)
        fBIP9CheckMasternodesUpgraded = false;

        checkpointData = (CCheckpointData) {
            boost::assign::map_list_of
            (      0, uint256S("0x32572d37b0f7a102af86494187376e0c34367eacb2e8f00c47e37ba49e93570c"))
            (      1, devnetGenesis.GetHash())
        };

        chainTxData = ChainTxData{
            devnetGenesis.GetBlockTime(), // * UNIX timestamp of devnet genesis block
            2,                            // * we only have 2 coinbase transactions when a devnet is started up
            0.01                          // * estimated number of transactions per second
        };

        vHashLegacyBlocks = {
        };
    }
};

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    CRegTestParams() {
        strNetworkID = "regtest";
        consensus.nSubsidyHalvingInterval = 150;
        consensus.nMasternodePaymentsStartBlock = 250;
        //consensus.nMasternodePaymentsIncreaseBlock = 350; // STASH not used
        //consensus.nMasternodePaymentsIncreasePeriod = 10; // STASH not used
        consensus.nInstantSendConfirmationsRequired = 2;
        consensus.nInstantSendKeepLock = 6;
        consensus.nBudgetPaymentsStartBlock = 250;
        //consensus.nBudgetPaymentsCycleBlocks = 50; // STASH unused
        //consensus.nBudgetPaymentsWindowBlocks = 10; // STASH unused
        consensus.nSuperblockStartBlock = 400; // NOTE: Should satisfy nSuperblockStartBlock > nBudgetPaymentsStartBlock
        //consensus.nSuperblockStartHash = uint256(); // STASH unused
        consensus.nSuperblockCycle = 10;
        consensus.nGovernanceMinQuorum = 1;
        consensus.nGovernanceFilterElements = 100;
        consensus.nMasternodeMinimumConfirmations = 1;
        consensus.BIP34Height = 1; // BIP34 has not activated on regtest (far in the future so block v1 are not rejected in tests)
        consensus.BIP65Height = 1; // BIP65 activated on regtest (Used in rpc activation tests)
        consensus.BIP66Height = 1; // BIP66 activated on regtest (Used in rpc activation tests)
        consensus.DIP0001Height = 1;
        consensus.DIP0003Height = 432;
        consensus.DIP0003EnforcementHeight = 500;
        consensus.DIP0003EnforcementHash = uint256();
        consensus.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"); // ~uint256(0) >> 1
        consensus.nPowTargetTimespan = 24 * 60 * 60; // Stash: 1 day
        consensus.nPowTargetSpacing = 1 * 60; // Stash: 1 minute
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = true;
        //consensus.nPowKGWHeight = 15200; // STASH Always use DGW
        //consensus.nPowDGWHeight = 34140;
        consensus.nRuleChangeActivationThreshold = 108; // 75% for testchains
        consensus.nMinerConfirmationWindow = 144; // Faster than normal for regtest (144 instead of 2016)
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 999999999999ULL;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 999999999999ULL;
/* START STASH - BIP147 and DIP0001 are activated at genesis
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0001].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0001].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0001].nTimeout = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_BIP147].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_BIP147].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_BIP147].nTimeout = 0;
END STASH */
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0003].bit = 3;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0003].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0003].nTimeout = 999999999999ULL;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0008].bit = 4;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0008].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0008].nTimeout = 999999999999ULL;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00");

        pchMessageStart[0] = 0xf6;
        pchMessageStart[1] = 0xcf;
        pchMessageStart[2] = 0xb1;
        pchMessageStart[3] = 0xd8;
        nDefaultPort = 19994;
        nPruneAfterHeight = 1000;

        genesis = CreateGenesisBlock(1545016533, 498287, 0x1e0ffff0 /*0x207fffff*/, 1, 50 * COIN);

        if (genesis.nNonce == 0) {
          GenerateGenesisHash(genesis, strNetworkID);
        }

        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x000001132a8c3bdb334f682ab11a9fdf49fed1a593f0833aa4f7ff3b5ad091b9"));
        assert(genesis.hashMerkleRoot == uint256S("0x965e2a3e499686a80cc1f990a5b18687cf766a892e8ec37b32de99609eaf5ca3"));

        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();      //!< Regtest mode doesn't have any DNS seeds.

        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fRequireRoutableExternalIP = false;
        fMineBlocksOnDemand = true;
        fAllowMultipleAddressesFromGroup = true;
        fAllowMultiplePorts = true;

        nFulfilledRequestExpireTime = 5*60; // fulfilled requests expire in 5 minutes
        nPoolMinParticipants = 3;
        nPoolMaxParticipants = 5;

        // privKey: cP4EKFyJsHT39LDqgdcB43Y3YXjNyjb5Fuas1GQSeAtjnZWmZEQK
        vSporkAddresses = {"yj949n1UH6fDhw6HtVE5VMj2iSTaSWBMcW"};
        nMinSporkKeys = 1;
        // regtest usually has no masternodes in most tests, so don't check for upgraged MNs
        fBIP9CheckMasternodesUpgraded = false;

        checkpointData = (CCheckpointData) {
            {
                {0, uint256S("0x000001132a8c3bdb334f682ab11a9fdf49fed1a593f0833aa4f7ff3b5ad091b9")},
            }
        };

        chainTxData = ChainTxData{
            0,
            0,
            0
        };

        // Regtest Stash addresses start with 'y'
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,140);
        // Regtest Stash script addresses start with '8' or '9'
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,19);
        // Regtest private keys start with '9' or 'c' (Bitcoin defaults)
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        // Regtest Stash BIP32 pubkeys start with 'tpub' (Bitcoin defaults)
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x35)(0x87)(0xCF).convert_to_container<std::vector<unsigned char> >();
        // Regtest Stash BIP32 prvkeys start with 'tprv' (Bitcoin defaults)
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x35)(0x83)(0x94).convert_to_container<std::vector<unsigned char> >();


        // guarantees the first 2 characters, when base58 encoded, are "zt"
        base58Prefixes[ZCPAYMENT_ADDRRESS] = {0x16,0xB6};
         // guarantees the first 4 characters, when base58 encoded, are "ZiVt"
        base58Prefixes[ZCVIEWING_KEY]      = {0xA8,0xAC,0x0C};
         // guarantees the first 2 characters, when base58 encoded, are "ST"
        base58Prefixes[ZCSPENDING_KEY]     = {0xAC,0x08};

        // Regtest Stash BIP44 coin type is '1' (All coin's testnet default)
        nExtCoinType = 1;

        vHashLegacyBlocks = {
        };

        // long living quorum params
        consensus.llmqs[Consensus::LLMQ_5_60] = llmq5_60;
        consensus.llmqs[Consensus::LLMQ_50_60] = llmq50_60;
        consensus.llmqTypeChainLocks = Consensus::LLMQ_5_60;
        consensus.llmqTypeInstantSend = Consensus::LLMQ_5_60;
    }
};

static std::unique_ptr<CChainParams> globalChainParams;

const CChainParams &Params() {
    assert(globalChainParams);
    return *globalChainParams;
}

std::unique_ptr<CChainParams> CreateChainParams(const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN)
        return std::unique_ptr<CChainParams>(new CMainParams());
    else if (chain == CBaseChainParams::TESTNET)
        return std::unique_ptr<CChainParams>(new CTestNetParams());
    else if (chain == CBaseChainParams::DEVNET) {
        return std::unique_ptr<CChainParams>(new CDevNetParams());
    } else if (chain == CBaseChainParams::REGTEST)
        return std::unique_ptr<CChainParams>(new CRegTestParams());
    throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string& network)
{
    SelectBaseParams(network);
    globalChainParams = CreateChainParams(network);
}

void UpdateVersionBitsParameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout, int64_t nWindowSize, int64_t nThreshold)
{
    globalChainParams->UpdateVersionBitsParameters(d, nStartTime, nTimeout, nWindowSize, nThreshold);
}

void UpdateDIP3Parameters(int nActivationHeight, int nEnforcementHeight)
{
    globalChainParams->UpdateDIP3Parameters(nActivationHeight, nEnforcementHeight);
}

void UpdateBudgetParameters(int nMasternodePaymentsStartBlock, int nBudgetPaymentsStartBlock, int nSuperblockStartBlock)
{
    globalChainParams->UpdateBudgetParameters(nMasternodePaymentsStartBlock, nBudgetPaymentsStartBlock, nSuperblockStartBlock);
}

void UpdateDevnetSubsidyAndDiffParams(int nMinimumDifficultyBlocks, int nHighSubsidyBlocks, int nHighSubsidyFactor)
{
    globalChainParams->UpdateSubsidyAndDiffParams(nMinimumDifficultyBlocks, nHighSubsidyBlocks, nHighSubsidyFactor);
}

void UpdateDevnetLLMQChainLocks(Consensus::LLMQType llmqType)
{
    globalChainParams->UpdateLLMQChainLocks(llmqType);
}

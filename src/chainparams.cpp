// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Copyright (c) 2014-2017 The Dash Core developers
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
    return boost::filesystem::exists(".disableseeds");
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
        //consensus.nBudgetPaymentsCycleBlocks = 41540; // ~(60*24*30)/2.6, actual number of blocks per month is 200700 / 12 = 16725
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
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1486252800; // Feb 5th, 2017
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1517788800; // Feb 5th, 2018

       // The best chain should have at least this much work.
        //consensus.nMinimumChainWork = uint256S("0x00000000000000000000000000000000000000000000081021b74f9f47bbd7bc"); // 888900
        consensus.nMinimumChainWork = uint256S("0x000000000000000000000000000000000000000000000000000000000000000");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x000000ee06448a3d3c624176d358f2b35636f1cb96bd097a06178cf072e92784"); // 888900

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0xaa;
        pchMessageStart[1] = 0x1b;
        pchMessageStart[2] = 0x69;
        pchMessageStart[3] = 0xb0;
        vAlertPubKey = ParseHex("048240a8748a80a286b270ba126705ced4f2ce5a7847b3610ea3c06513150dade2a8512ed5ea86320824683fc0818f0ac019214973e677acd1244f6d0571fc5103");
        nDefaultPort = 9999;
        nPruneAfterHeight = 100000;

        genesis = CreateGenesisBlock(1551398400, 191657, 0x1e0ffff0, 1, 50 * COIN);

        if (genesis.nNonce == 0) {
          GenerateGenesisHash(genesis, strNetworkID);
        }

        consensus.hashGenesisBlock = genesis.GetHash();

        assert(consensus.hashGenesisBlock == uint256S("0x000000ee06448a3d3c624176d358f2b35636f1cb96bd097a06178cf072e92784"));
        assert(genesis.hashMerkleRoot == uint256S("0x965e2a3e499686a80cc1f990a5b18687cf766a892e8ec37b32de99609eaf5ca3"));

        if (seedsDisabled()) {
              printf("Seeds disabled on mainnet\n");
        } else {            
            vSeeds.push_back(CDNSSeedData("dnsseed.stash.chat", "dnsseed3.stash.chat"));
            vSeeds.push_back(CDNSSeedData("dnsseed.stashcoin.io", "dnsseed1.stashcoin.io"));
            vSeeds.push_back(CDNSSeedData("dnsseed.stashcoin.org", "dnsseed2.stashcoin.org"));
            vSeeds.push_back(CDNSSeedData("dnsseed.stashchat.org", "dnsseed4.stashchat.org"));
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

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fAllowMultipleAddressesFromGroup = false;
        fAllowMultiplePorts = false;

        nPoolMaxTransactions = 3;
        nFulfilledRequestExpireTime = 60*60; // fulfilled requests expire in 1 hour

        
        strSporkAddress = "Xmvo2yTcJK96QDsJ4xEzNZsSiQgowuw1wW";

        checkpointData = (Checkpoints::CCheckpointData) {
            boost::assign::map_list_of
            (  0, uint256S("0x000000ee06448a3d3c624176d358f2b35636f1cb96bd097a06178cf072e92784")),
            0,//1507424630, // * UNIX timestamp of last checkpoint block
            0,//3701128,    // * total number of transactions between genesis and last checkpoint
                        //   (the tx=... number in the SetBestChain debug.log lines)
            0//5000        // * estimated number of transactions per day after checkpoint
        };

        chainTxData = ChainTxData{
            0, // * UNIX timestamp of last known number of transactions
            0,    // * total number of transactions between genesis and that timestamp
                        //   (the tx=... number in the SetBestChain debug.log lines)
            0.1         // * estimated number of transactions per second after that timestamp
        };

        vHashLegacyBlocks = {

//------------------------------------------------------------------------------
// Do not edit manually
        "0008fc5afeaffc45179d7ce8f1fdb81ead2d6eff8df9b6ac593ed3759bf113ce",
        "00097af6c4ba153a303a0affd3f7dde5198afbc0b565770cb3f7efc119092e84",
        "00058dff35d2f28c7b84ec4e3d35b36be578b9a50525c0ae17dd7e52a06019c8",
        "000ff832668ca1c89d40c85b87d5ec31a95e521ab6f6d3c1eab52ae8be80319c",
        "000d55aec900c139c9c0a1cd0fe767332beeaf0e90b0c6d33a91d8e50527ee37",
        "00019dd161884cb8b5bcfee3e48523201812196651768efb3ed7d9acb6a7f484",
        "000674544627b71adaf504852b6b28de8b26afeb09612e1856800075d19abadc",
        "000aae7e5f0a145439a6c8d995d1be0125970d3e54902d52fe327764ba52c156",
        "0001afc1cdff373d8dcef891deccac155beaa85da1eea7c59903599989ca63f7",
        "0003359695f95b89cf0e0b3a942b7af973ae8f87285b226dcb14790fa6e469cd",
        "000e3581d20c42cc2515ecd2fea33beb5e08de24d7f11e02d1866749bce42b9d",
        "00033aa2bf3a8496c1768d9446005e192dfaa76122961b3734e099658f421ae5",
        "000e23f82e202a545e099a594aec7dc29271e77ae988cccb3df3bd6ff89f4d77",
        "000625eefc28c113fadbc9c0b210a9d1a620c95cd80119518008463d8a38c847",
        "00025de240059d9595e76dda1a2551dd7fe813d8b01e1292470cf87e9cdc6d91",
        "000deb034ebdcccf57f4edc54dda9e4820d23683b14e0fe827a9aee412bdd312",
        "00085c22fe636f63a527b3411a06561df64f73a25df95fa78592c41bce73dc19",
        "000f0447f2f05f08dff3ed60dba9643d0985ba1f82c694b330e29cd22650ded6",
//------------------------------------------------------------------------------

        };

    }
};
static CMainParams mainParams;

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
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1506556800; // September 28th, 2017
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1538092800; // September 28th, 2018

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x0"); // 37900
        // consensus.nMinimumChainWork = uint256S("0x000000000000000000000000000000000000000000000000003be69c34b1244f"); // 143200

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x0000098bec97458a8b345102a4cc54233e5a8717aa23ebe3395af1c26ad1ad7a"); // 0

        pchMessageStart[0] = 0xef;
        pchMessageStart[1] = 0xa2;
        pchMessageStart[2] = 0xfa;
        pchMessageStart[3] = 0xf7;
        vAlertPubKey = ParseHex("04517d8a699cb43d3938d7b24faaff7cda448ca4ea267723ba614784de661949bf632d6304316b244646dea079735b9a6fc4af804efb4752075b9fe2245e14e412");
        nDefaultPort = 19999;
        //nMaxTipAge = 0x7fffffff; // allow mining on top of old blocks for testnet
        //nMaxTipAge = 16000 * 60 * 60; // ~144 blocks behind -> 2 x fork detection time, was 24 * 60 * 60 in bitcoin

        //nDelayGetHeadersTime = 0; // DTG 24 * 60 * 60;
        nPruneAfterHeight = 1000;

        genesis = CreateGenesisBlock(1550820822, 302758, 0x1e0ffff0, 1, 50 * COIN);

        if (genesis.nNonce == 0) {
          GenerateGenesisHash(genesis, strNetworkID);
        }

        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x0000098bec97458a8b345102a4cc54233e5a8717aa23ebe3395af1c26ad1ad7a"));
        assert(genesis.hashMerkleRoot == uint256S("0x965e2a3e499686a80cc1f990a5b18687cf766a892e8ec37b32de99609eaf5ca3"));

        vFixedSeeds.clear();
        vSeeds.clear();
        if (seedsDisabled()) {
              printf("Seeds disabled on testnet\n");
        } else {
        			vSeeds.push_back(CDNSSeedData("testseed1.stashpay.io", "testseed1.stashpay.io"));
        	        vSeeds.push_back(CDNSSeedData("testseed2.stashpay.io", "testseed1.stashpay.io"));
        	        vSeeds.push_back(CDNSSeedData("testseed3.stashpay.io", "testseed1.stashpay.io"));
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

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;
        fAllowMultipleAddressesFromGroup = false;
        fAllowMultiplePorts = false;

        nPoolMaxTransactions = 3;
        nFulfilledRequestExpireTime = 5*60; // fulfilled requests expire in 5 minutes

        // place this key in .conf file as sporkkey=cP4EKFyJsHT39LDqgdcB43Y3YXjNyjb5Fuas1GQSeAtjnZWmZEQK
        // privKey: cP4EKFyJsHT39LDqgdcB43Y3YXjNyjb5Fuas1GQSeAtjnZWmZEQK
        // open debug console and use this command:
        // spork SPORK_NAME [value]

        strSporkAddress = "yj949n1UH6fDhw6HtVE5VMj2iSTaSWBMcW"; // MPB todo - update with real key

        checkpointData = (Checkpoints::CCheckpointData) {
            boost::assign::map_list_of
            (0, uint256S("0x0000098bec97458a8b345102a4cc54233e5a8717aa23ebe3395af1c26ad1ad7a")),
            1550820822, // * UNIX timestamp of last checkpoint block
            0,       // * total number of transactions between genesis and last checkpoint
                        //   (the tx=... number in the SetBestChain debug.log lines)
            0         // * estimated number of transactions per day after checkpoint
        };

        chainTxData = ChainTxData{
            0,// * UNIX timestamp of last known number of transactions
            0,        // * total number of transactions between genesis and that timestamp
                        //   (the tx=... number in the SetBestChain debug.log lines)
            0.006       // * estimated number of transactions per second after that timestamp
        };

        vHashLegacyBlocks = {
//------------------------------------------------------------------------------
// Do not edit manually
        "000ed989820e114ca98139a0c024cefcb3e9b2027461690350b9acd6cc84b3c3",
        "000d8d61aa97c57809aee2ff7681c59a4ac151318caa07ee64ac8d0a963d508a",
        "0007294df450fe096a65b773d4974095d5ad09642123ba610dcfb1a3177ca2af",
        "000bd583c7a232ac55ad78151cc4f2b27776a9e689a2d55c6a1282bcb4ba497a",
//------------------------------------------------------------------------------
        };
    }
};
static CTestNetParams testNetParams;

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
        consensus.nInstantSendConfirmationsRequired = 2;
        consensus.nInstantSendKeepLock = 6;
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
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1506556800; // September 28th, 2017
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1538092800; // September 28th, 2018

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x000000000000000000000000000000000000000000000000000000000000000");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x000000000000000000000000000000000000000000000000000000000000000");

        pchMessageStart[0] = 0xe2;
        pchMessageStart[1] = 0xca;
        pchMessageStart[2] = 0xff;
        pchMessageStart[3] = 0xce;
        vAlertPubKey = ParseHex("04517d8a699cb43d3938d7b24faaff7cda448ca4ea267723ba614784de661949bf632d6304316b244646dea079735b9a6fc4af804efb4752075b9fe2245e14e412");
        nDefaultPort = 19999;
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

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;
        fAllowMultipleAddressesFromGroup = true;
        fAllowMultiplePorts = true;

        nPoolMaxTransactions = 3;
        nFulfilledRequestExpireTime = 5*60; // fulfilled requests expire in 5 minutes

        // place this key in .conf file as sporkkey=cP4EKFyJsHT39LDqgdcB43Y3YXjNyjb5Fuas1GQSeAtjnZWmZEQK        
        // open debug console and use this command:
        // spork SPORK_NAME [value]
        strSporkAddress = "yj949n1UH6fDhw6HtVE5VMj2iSTaSWBMcW";

        checkpointData = (Checkpoints::CCheckpointData) {
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
static CDevNetParams *devNetParams;


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

        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;
        fAllowMultipleAddressesFromGroup = true;
        fAllowMultiplePorts = true;

        nFulfilledRequestExpireTime = 5*60; // fulfilled requests expire in 5 minutes

        // place this key in .conf file as sporkkey=cP4EKFyJsHT39LDqgdcB43Y3YXjNyjb5Fuas1GQSeAtjnZWmZEQK        
        // open debug console and use this command:
        // spork SPORK_NAME [value]
        strSporkAddress = "yj949n1UH6fDhw6HtVE5VMj2iSTaSWBMcW";

        checkpointData = (Checkpoints::CCheckpointData){
            boost::assign::map_list_of
            ( 0, uint256S("0x")),
              0,
              0,
              0
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
   }

    void UpdateBIP9Parameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
    {
        consensus.vDeployments[d].nStartTime = nStartTime;
        consensus.vDeployments[d].nTimeout = nTimeout;
    }
};
static CRegTestParams regTestParams;

static CChainParams *pCurrentParams = 0;

const CChainParams &Params() {
    assert(pCurrentParams);
    return *pCurrentParams;
}

CChainParams& Params(const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN)
            return mainParams;
    else if (chain == CBaseChainParams::TESTNET)
            return testNetParams;
    else if (chain == CBaseChainParams::DEVNET) {
            assert(devNetParams);
            return *devNetParams;
    } else if (chain == CBaseChainParams::REGTEST)
            return regTestParams;
    else
        throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string& network)
{
    if (network == CBaseChainParams::DEVNET) {
        devNetParams = new CDevNetParams();
    }

    SelectBaseParams(network);
    pCurrentParams = &Params(network);
}

void UpdateRegtestBIP9Parameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
{
    regTestParams.UpdateBIP9Parameters(d, nStartTime, nTimeout);
}

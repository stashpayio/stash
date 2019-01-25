// Copyright (c) 2014-2018 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"
#include "validation.h"

#include "test/test_stash.h"

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(subsidy_tests, TestingSetup)

BOOST_AUTO_TEST_CASE(block_subsidy_test)
{
    const Consensus::Params& consensusParams = Params(CBaseChainParams::MAIN).GetConsensus();

    uint32_t nPrevBits;
    int32_t nPrevHeight;
    CAmount nSubsidy;

    // details for block 10 (subsidy returned will be for block 11)
    // initial value of 6760000000.
    nPrevBits = 0x1c4a47c4;
    nPrevHeight = 10;
    nSubsidy = GetBlockSubsidy(nPrevBits, nPrevHeight, consensusParams, false);
    BOOST_CHECK_EQUAL(nSubsidy, 6760000000ULL);

    // details for block 1000 (subsidy returned will be for block 1001)
    nPrevBits = 0x1c4a47c4;
    nPrevHeight = 1000;
    nSubsidy = GetBlockSubsidy(nPrevBits, nPrevHeight, consensusParams, false);
    BOOST_CHECK_EQUAL(nSubsidy, 6760000000ULL);

    // details for block 1001 (subsidy returned will be for block 1002)
    // hardfork at consensus.nMasternodePaymentsStartBlock = 1000 causing the 10% decrease.
    nPrevBits = 0x1c4a47c4;
    nPrevHeight = 1001;
    nSubsidy = GetBlockSubsidy(nPrevBits, nPrevHeight, consensusParams, false);
    BOOST_CHECK_EQUAL(nSubsidy, 6084000000ULL);

    // details for block 10000 (subsidy returned will be for block 10001)
    nPrevBits = 0x1c29ec00;
    nPrevHeight = 10000;
    nSubsidy = GetBlockSubsidy(nPrevBits, nPrevHeight, consensusParams, false);
    BOOST_CHECK_EQUAL(nSubsidy, 6084000000ULL);


    // details for block 400000 (subsidy returned will be for block 400001)
    nPrevBits = 0x1b11548e;
    nPrevHeight = 400000;
    nSubsidy = GetBlockSubsidy(nPrevBits, nPrevHeight, consensusParams, false);
    BOOST_CHECK_EQUAL(nSubsidy, 6084000000ULL);

    // details for block 525959 (subsidy returned will be for block 525960)
    nPrevBits = 0x1b10d50b;
    nPrevHeight = 525959;
    nSubsidy = GetBlockSubsidy(nPrevBits, nPrevHeight, consensusParams, false);
    BOOST_CHECK_EQUAL(nSubsidy, 6084000000ULL);

    // details for block 525960 (subsidy returned will be for block 525961)
    // first halving happens here ( consensus.nSubsidyHalvingInterval = 525960 )
    nPrevBits = 0x1b10d50b;
    nPrevHeight = 525960;
    nSubsidy = GetBlockSubsidy(nPrevBits, nPrevHeight, consensusParams, false);
    BOOST_CHECK_EQUAL(nSubsidy, 5649428573ULL);

    // details for block 525961 (subsidy returned will be for block 525962)
    nPrevBits = 0x1b10d50b;
    nPrevHeight = 525961;
    nSubsidy = GetBlockSubsidy(nPrevBits, nPrevHeight, consensusParams, false);
    BOOST_CHECK_EQUAL(nSubsidy, 5649428573ULL);
}

BOOST_AUTO_TEST_SUITE_END()

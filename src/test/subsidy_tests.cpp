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
    const auto chainParams = CreateChainParams(CBaseChainParams::MAIN);

    uint32_t nPrevBits;
    int32_t nPrevHeight;
    CAmount nSubsidy;

    // details for block 10 (subsidy returned will be for block 11)
    // initial value of 6760000000.
    nPrevBits = 0x1c4a47c4;
    nPrevHeight = 4249;
    nSubsidy = GetBlockSubsidy(nPrevBits, nPrevHeight, chainParams->GetConsensus(), false);
    BOOST_CHECK_EQUAL(nSubsidy, 50000000000ULL);

    // details for block 1000 (subsidy returned will be for block 1001)
    nPrevBits = 0x1c4a47c4;
    nPrevHeight = 4501;
    nSubsidy = GetBlockSubsidy(nPrevBits, nPrevHeight, chainParams->GetConsensus(), false);
    BOOST_CHECK_EQUAL(nSubsidy, 5600000000ULL);

    // details for block 5464 (subsidy returned will be for block 5465)
    nPrevBits = 0x1c29ec00;
    nPrevHeight = 5464;
    nSubsidy = GetBlockSubsidy(nPrevBits, nPrevHeight, chainParams->GetConsensus(), false);
    BOOST_CHECK_EQUAL(nSubsidy, 2100000000ULL);

    // details for block 10000 (subsidy returned will be for block 10001)
    nPrevBits = 0x1c29ec00;
    nPrevHeight = 5465;
    nSubsidy = GetBlockSubsidy(nPrevBits, nPrevHeight, chainParams->GetConsensus(), false);
    BOOST_CHECK_EQUAL(nSubsidy, 12200000000ULL);

    // details for block 17588 (subsidy returned will be for block 17589)
    nPrevBits = 0x1c08ba34;
    nPrevHeight = 17588;
    nSubsidy = GetBlockSubsidy(nPrevBits, nPrevHeight, chainParams->GetConsensus(), false);
    BOOST_CHECK_EQUAL(nSubsidy, 6100000000ULL);

    // details for block 99999 (subsidy returned will be for block 100000)
    nPrevBits = 0x1b10cf42;
    nPrevHeight = 99999;
    nSubsidy = GetBlockSubsidy(nPrevBits, nPrevHeight, chainParams->GetConsensus(), false);
    BOOST_CHECK_EQUAL(nSubsidy, 500000000ULL);

    // details for block 210239 (subsidy returned will be for block 210240)
    nPrevBits = 0x1b11548e;
    nPrevHeight = 210239;
    nSubsidy = GetBlockSubsidy(nPrevBits, nPrevHeight, chainParams->GetConsensus(), false);
    BOOST_CHECK_EQUAL(nSubsidy, 500000000ULL);

    // details for block 525960 (subsidy returned will be for block 525961)
    // first halving happens here ( consensus.nSubsidyHalvingInterval = 525960 )
    nPrevBits = 0x1b10d50b;
    nPrevHeight = 525960;
    nSubsidy = GetBlockSubsidy(nPrevBits, nPrevHeight, consensusParams, false);
    BOOST_CHECK_EQUAL(nSubsidy, 5649428573ULL);

    // details for block 525961 (subsidy returned will be for block 525962)
    nPrevBits = 0x1b10d50b;
    nPrevHeight = 210240;
    nSubsidy = GetBlockSubsidy(nPrevBits, nPrevHeight, chainParams->GetConsensus(), false);
    BOOST_CHECK_EQUAL(nSubsidy, 464285715ULL);
}

BOOST_AUTO_TEST_SUITE_END()

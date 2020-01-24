// Copyright (c) 2017 The Zcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_DEPRECATION_H
#define BITCOIN_DEPRECATION_H

// Deprecation policy is 4th third-Tuesday after a release
/*static const int APPROX_RELEASE_HEIGHT = 525960;
static const int WEEKS_UNTIL_DEPRECATION = 26;
static const int DEPRECATION_HEIGHT = APPROX_RELEASE_HEIGHT + (WEEKS_UNTIL_DEPRECATION * 7 * 60 * 24); // Average 60 block/hr

// Number of blocks before deprecation to warn users
static const int DEPRECATION_WARN_LIMIT = 20 * 7 * 60 * 24; // 20 weeks
*/
/**
 * Checks whether the node is deprecated based on the current block height, and
 * shuts down the node with an error if so (and deprecation is not disabled for
 * the current client version).
 */
void EnforceNodeDeprecation(int nHeight, bool forceLogging=false);

#endif // BITCOIN_DEPRECATION_H

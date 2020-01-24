// Copyright (c) 2017 The Stash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "deprecation.h"

#include "clientversion.h"
#include "init.h"
#include "ui_interface.h"
#include "util.h"
#include "spork.h"

static const std::string CLIENT_VERSION_STR = FormatVersion(CLIENT_VERSION);

void EnforceNodeDeprecation(int nHeight, bool forceLogging) {

    // Note: spork value will initially be default value when loading block index 
    // because the spork have values have yet to be synced
    if (!sporkManager.IsSporkActive(SPORK_33_STASH_APPROX_RELEASE_HEIGHT))
    {
        return;
    }

    int releaseHeight         = sporkManager.GetSporkValue(SPORK_33_STASH_APPROX_RELEASE_HEIGHT);
    int weeksUntilDeprecation = sporkManager.GetSporkValue(SPORK_34_STASH_WEEKS_UNTIL_DEPRECATION);
    int deprecationWarning    = sporkManager.IsSporkActive(SPORK_35_STASH_DEPRECATION_WARN_LIMIT) ?
                                sporkManager.GetSporkValue(SPORK_35_STASH_DEPRECATION_WARN_LIMIT) : 0;
    int deprecationHeight     = releaseHeight + weeksUntilDeprecation * 7 * 60 * 24; // 60 block/hr on average
    int blocksToDeprecation   = deprecationHeight - nHeight;
    bool disableDeprecation   = (GetArg("-disabledeprecation", "") == CLIENT_VERSION_STR);

    if (blocksToDeprecation <= 0) {
        // In order to ensure we only log once per process when deprecation is
        // disabled (to avoid log spam), we only need to log in two cases:
        // - The deprecating block just arrived
        //   - This can be triggered more than once if a block chain reorg
        //     occurs, but that's an irregular event that won't cause spam.
        // - The node is starting
        if (blocksToDeprecation == 0 || forceLogging) {
            auto msg = strprintf(_("This version has been deprecated as of block height %d."),
                                 deprecationHeight) + " " +
                       _("You should upgrade to the latest version of Stash.");            
            LogPrintf("*** %s\n", msg);
            uiInterface.ThreadSafeMessageBox(msg, "", CClientUIInterface::MSG_ERROR);
        }
        if (!disableDeprecation) {
            StartShutdown();
        }
    } else if (blocksToDeprecation == deprecationWarning ||
               (blocksToDeprecation < deprecationWarning && forceLogging)) {
        std::string msg;
        if (disableDeprecation) {
            msg = strprintf(_("This version will be deprecated at block height %d."),
                            deprecationHeight) + " " +
                  _("You should upgrade to the latest version of Stash.");
        } else {
            msg = strprintf(_("This version will be deprecated at block height %d, and will automatically shut down."),
                            deprecationHeight) + " " +
                  _("You should upgrade to the latest version of Stash.");
        }
        LogPrintf("*** %s\n", msg);
        uiInterface.ThreadSafeMessageBox(msg, "", CClientUIInterface::MSG_WARNING);
    }
}
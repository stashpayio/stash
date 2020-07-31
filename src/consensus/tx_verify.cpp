// Copyright (c) 2017-2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "tx_verify.h"

#include "consensus.h"
#include "primitives/transaction.h"
#include "script/interpreter.h"
#include "validation.h"

// TODO remove the following dependencies
#include "chain.h"
#include "coins.h"
#include "utilmoneystr.h"
#include "init.h"
#include "librustzcash.h"

bool IsFinalTx(const CTransaction &tx, int nBlockHeight, int64_t nBlockTime)
{
    if (tx.nLockTime == 0)
        return true;
    if ((int64_t)tx.nLockTime < ((int64_t)tx.nLockTime < LOCKTIME_THRESHOLD ? (int64_t)nBlockHeight : nBlockTime))
        return true;
    for (const auto& txin : tx.vin) {
        if (!(txin.nSequence == CTxIn::SEQUENCE_FINAL))
            return false;
    }
    return true;
}

std::pair<int, int64_t> CalculateSequenceLocks(const CTransaction &tx, int flags, std::vector<int>* prevHeights, const CBlockIndex& block)
{
    assert(prevHeights->size() == tx.vin.size());

    // Will be set to the equivalent height- and time-based nLockTime
    // values that would be necessary to satisfy all relative lock-
    // time constraints given our view of block chain history.
    // The semantics of nLockTime are the last invalid height/time, so
    // use -1 to have the effect of any height or time being valid.
    int nMinHeight = -1;
    int64_t nMinTime = -1;

    // tx.nVersion is signed integer so requires cast to unsigned otherwise
    // we would be doing a signed comparison and half the range of nVersion
    // wouldn't support BIP 68.
    bool fEnforceBIP68 = static_cast<uint32_t>(tx.nVersion) >= 2
                         && flags & LOCKTIME_VERIFY_SEQUENCE;

    // Do not enforce sequence numbers as a relative lock time
    // unless we have been instructed to
    if (!fEnforceBIP68) {
        return std::make_pair(nMinHeight, nMinTime);
    }

    for (size_t txinIndex = 0; txinIndex < tx.vin.size(); txinIndex++) {
        const CTxIn& txin = tx.vin[txinIndex];

        // Sequence numbers with the most significant bit set are not
        // treated as relative lock-times, nor are they given any
        // consensus-enforced meaning at this point.
        if (txin.nSequence & CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG) {
            // The height of this input is not relevant for sequence locks
            (*prevHeights)[txinIndex] = 0;
            continue;
        }

        int nCoinHeight = (*prevHeights)[txinIndex];

        if (txin.nSequence & CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG) {
            int64_t nCoinTime = block.GetAncestor(std::max(nCoinHeight-1, 0))->GetMedianTimePast();
            // NOTE: Subtract 1 to maintain nLockTime semantics
            // BIP 68 relative lock times have the semantics of calculating
            // the first block or time at which the transaction would be
            // valid. When calculating the effective block time or height
            // for the entire transaction, we switch to using the
            // semantics of nLockTime which is the last invalid block
            // time or height.  Thus we subtract 1 from the calculated
            // time or height.

            // Time-based relative lock-times are measured from the
            // smallest allowed timestamp of the block containing the
            // txout being spent, which is the median time past of the
            // block prior.
            nMinTime = std::max(nMinTime, nCoinTime + (int64_t)((txin.nSequence & CTxIn::SEQUENCE_LOCKTIME_MASK) << CTxIn::SEQUENCE_LOCKTIME_GRANULARITY) - 1);
        } else {
            nMinHeight = std::max(nMinHeight, nCoinHeight + (int)(txin.nSequence & CTxIn::SEQUENCE_LOCKTIME_MASK) - 1);
        }
    }

    return std::make_pair(nMinHeight, nMinTime);
}

bool EvaluateSequenceLocks(const CBlockIndex& block, std::pair<int, int64_t> lockPair)
{
    assert(block.pprev);
    int64_t nBlockTime = block.pprev->GetMedianTimePast();
    if (lockPair.first >= block.nHeight || lockPair.second >= nBlockTime)
        return false;

    return true;
}

bool SequenceLocks(const CTransaction &tx, int flags, std::vector<int>* prevHeights, const CBlockIndex& block)
{
    return EvaluateSequenceLocks(block, CalculateSequenceLocks(tx, flags, prevHeights, block));
}

unsigned int GetLegacySigOpCount(const CTransaction& tx)
{
    unsigned int nSigOps = 0;
    for (const auto& txin : tx.vin)
    {
        nSigOps += txin.scriptSig.GetSigOpCount(false);
    }
    for (const auto& txout : tx.vout)
    {
        nSigOps += txout.scriptPubKey.GetSigOpCount(false);
    }
    return nSigOps;
}

unsigned int GetP2SHSigOpCount(const CTransaction& tx, const CCoinsViewCache& inputs)
{
    if (tx.IsCoinBase())
        return 0;

    unsigned int nSigOps = 0;
    for (unsigned int i = 0; i < tx.vin.size(); i++)
    {
        const Coin& coin = inputs.AccessCoin(tx.vin[i].prevout);
        assert(!coin.IsSpent());
        const CTxOut &prevout = coin.out;
        if (prevout.scriptPubKey.IsPayToScriptHash())
            nSigOps += prevout.scriptPubKey.GetSigOpCount(tx.vin[i].scriptSig);
    }
    return nSigOps;
}

unsigned int GetTransactionSigOpCount(const CTransaction& tx, const CCoinsViewCache& inputs, int flags)
{
    unsigned int nSigOps = GetLegacySigOpCount(tx);

    if (tx.IsCoinBase())
        return nSigOps;

    if (flags & SCRIPT_VERIFY_P2SH) {
        nSigOps += GetP2SHSigOpCount(tx, inputs);
    }

    return nSigOps;
}

bool CheckTransaction(const CTransaction& tx, CValidationState &state)
{
    bool allowEmptyTxInOut = false;
    if (tx.nType == TRANSACTION_QUORUM_COMMITMENT) {
        allowEmptyTxInOut = true;
    }

    // Basic checks that don't depend on any context
    if (!allowEmptyTxInOut && tx.vin.empty() && tx.vjoinsplit.empty())
        return state.DoS(10, false, REJECT_INVALID, "bad-txns-vin-empty");

    // Transactions can contain an empty `vout` so long as
    // `vjoinsplit` is non-empty. 
    if (!allowEmptyTxInOut && tx.vout.empty() && tx.vjoinsplit.empty())
        return state.DoS(10, false, REJECT_INVALID, "bad-txns-vout-empty");

    // Size limits
    if (::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION) > MAX_TX_SIZE)
        return state.DoS(100, false, REJECT_INVALID, "bad-txns-oversize");
        
    if (tx.vExtraPayload.size() > MAX_TX_EXTRA_PAYLOAD)
        return state.DoS(100, false, REJECT_INVALID, "bad-txns-payload-oversize");

    // Check for negative or overflow output values
    CAmount nValueOut = 0;
    for (const auto& txout : tx.vout)
    {
        if (txout.nValue < 0)
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-vout-negative");
        if (txout.nValue > MAX_MONEY)
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-vout-toolarge");
        nValueOut += txout.nValue;
        if (!MoneyRange(nValueOut))
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-txouttotal-toolarge");
    }

    // Ensure that joinsplit values are well-formed
    for (const JSDescription& joinsplit : tx.vjoinsplit)
    {
        if (joinsplit.vpub_old < 0) {
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-vpub_old-negative", false,
                strprintf("%s: joinsplit.vpub_old negative", __func__));
        }

        if (joinsplit.vpub_new < 0) {
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-vpub_new-negative", false,
                strprintf("%s: joinsplit.vpub_new negative", __func__));
        }

        if (joinsplit.vpub_old > MAX_MONEY) {
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-vpub_old-toolarge", false,
                strprintf("%s: joinsplit.vpub_old too high", __func__));
        }

        if (joinsplit.vpub_new > MAX_MONEY) {
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-vpub_new-toolarge", false, 
                strprintf("%s: joinsplit.vpub_new too high", __func__));
        }

        if (joinsplit.vpub_new != 0 && joinsplit.vpub_old != 0) {
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-vpubs-both-nonzero", false, 
                strprintf("%s: joinsplit.vpub_new and joinsplit.vpub_old both nonzero", __func__));
        }

        nValueOut += joinsplit.vpub_old;
        if (!MoneyRange(nValueOut)) {
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-txouttotal-toolarge", false, 
                strprintf("%s: txout total out of range", __func__));
        }
    }


    // Ensure input values do not exceed MAX_MONEY
    // We have not resolved the txin values at this stage,
    // but we do know what the joinsplits claim to add
    // to the value pool.
    {
        CAmount nValueIn = 0;
        for (std::vector<JSDescription>::const_iterator it(tx.vjoinsplit.begin()); it != tx.vjoinsplit.end(); ++it)
        {
            nValueIn += it->vpub_new;

            if (!MoneyRange(it->vpub_new) || !MoneyRange(nValueIn)) {
                return state.DoS(100, false, REJECT_INVALID, "bad-txns-txintotal-toolarge", false,
                strprintf("%s: txin total out of range", __func__));
            }
        }
    }
    
    // Check for duplicate inputs
    std::set<COutPoint> vInOutPoints;
    for (const auto& txin : tx.vin)
    {
        if (!vInOutPoints.insert(txin.prevout).second)
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-inputs-duplicate");
    }

    // Check for duplicate joinsplit nullifiers in this transaction
    std::set<uint256> vJoinSplitNullifiers;
    for (const JSDescription& joinsplit : tx.vjoinsplit)
    {
        for (const uint256& nf : joinsplit.nullifiers)
        {
            if (vJoinSplitNullifiers.count(nf))
                return state.DoS(100, false, REJECT_INVALID, "bad-joinsplits-nullifiers-duplicate", false,
                    strprintf("%s: duplicate nullifiers", __func__));

            vJoinSplitNullifiers.insert(nf);
        }
    }

    if (tx.IsCoinBase())
    {
        // There should be no joinsplits in a coinbase transaction
        if (tx.vjoinsplit.size() > 0)
            return state.DoS(100, false, REJECT_INVALID, "bad-cb-has-joinsplits");

        size_t minCbSize = 2;
        if (tx.nType == TRANSACTION_COINBASE) {
            // With the introduction of CbTx, coinbase scripts are not required anymore to hold a valid block height
            minCbSize = 1;
        }
        if (tx.vin[0].scriptSig.size() < minCbSize || tx.vin[0].scriptSig.size() > 100)
            return state.DoS(100, false, REJECT_INVALID, "bad-cb-length");
    }
    else
    {
        for (const auto& txin : tx.vin)
            if (txin.prevout.IsNull())
                return state.DoS(10, false, REJECT_INVALID, "bad-txns-prevout-null");

        if (tx.vjoinsplit.size() > 0) {
            // Empty output script.
            CScript scriptCode;
            uint256 dataToBeSigned;
            try {
                dataToBeSigned = SignatureHash(scriptCode, tx, NOT_AN_INPUT, SIGHASH_ALL, 0, SIGVERSION_BASE);
            } catch (std::logic_error ex) {
                return state.DoS(100, false, REJECT_INVALID, "error-computing-signature-hash", false,
                                strprintf("%s:  error computing signature hash", __func__));
            }

            BOOST_STATIC_ASSERT(crypto_sign_PUBLICKEYBYTES == 32);

            // We rely on libsodium to check that the signature is canonical.
            // https://github.com/jedisct1/libsodium/commit/62911edb7ff2275cccd74bf1c8aefcc4d76924e0
            if (crypto_sign_verify_detached(&tx.joinSplitSig[0],
                                            dataToBeSigned.begin(), 32,
                                            tx.joinSplitPubKey.begin()
                                           ) != 0) {
                return state.DoS(100, false, REJECT_INVALID, "bad-txns-invalid-joinsplit-signature");
            }
        }
    }

    return true;
}

bool CheckTransaction(const CTransaction& tx, CValidationState &state, libzcash::ProofVerifier& verifier)
{
    if (!CheckTransaction(tx, state)) {
        return false;
    } else {
        // Ensure that zk-SNARKs verify
        for (const JSDescription &joinsplit : tx.vjoinsplit) {
            if (!joinsplit.Verify(*pzcashParams, verifier, tx.joinSplitPubKey)) {
                return state.DoS(100, false, REJECT_INVALID, "bad-txns-joinsplit-verification-failed");
            }
        }
        return true;
    }
}

bool Consensus::CheckTxInputs(const CTransaction& tx, CValidationState& state, const CCoinsViewCache& inputs, int nSpendHeight, CAmount& txfee)
{
    // are the actual inputs available?
    if (!inputs.HaveInputs(tx)) {
        return state.DoS(100, false, REJECT_INVALID, "bad-txns-inputs-missingorspent", false,
            strprintf("%s: inputs missing/spent", __func__));
    }

    // are the JoinSplit's requirements met?
    if (!inputs.HaveJoinSplitRequirements(tx))
    	return state.Invalid(false,
            REJECT_INVALID, "bad-txns-premature-spend-of-coinbase",
            strprintf("%s JoinSplit requirements not met for txid=%s", __func__, tx.GetHash().ToString()));

    CAmount nValueIn = 0;
    for (unsigned int i = 0; i < tx.vin.size(); ++i) {
        const COutPoint &prevout = tx.vin[i].prevout;
        const Coin& coin = inputs.AccessCoin(prevout);
        assert(!coin.IsSpent());

        // If prev is coinbase, check that it's matured
        if (coin.IsCoinBase() && nSpendHeight - coin.nHeight < COINBASE_MATURITY) {
            return state.Invalid(false,
                REJECT_INVALID, "bad-txns-premature-spend-of-coinbase",
                strprintf("tried to spend coinbase at depth %d", nSpendHeight - coin.nHeight));
        }

#ifdef COINBASE_PROTECTION
    ***** Do we want this feature?
            // Ensure that coinbases cannot be spent to transparent outputs
                // Disabled on regtest
                if (fCoinbaseEnforcedProtectionEnabled &&
                    consensusParams.fCoinbaseMustBeProtected &&
                    !tx.vout.empty()) {
                    return state.Invalid(
                        error("CheckInputs(): tried to spend coinbase with transparent outputs"),
                        REJECT_INVALID, "bad-txns-coinbase-spend-has-transparent-outputs");
                }
            }
#endif
        // Check for negative or overflow input values
        nValueIn += coin.out.nValue;
        if (!MoneyRange(coin.out.nValue) || !MoneyRange(nValueIn)) {
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-inputvalues-outofrange");
        }
    }

    nValueIn += tx.GetJoinSplitValueIn();
    if (!MoneyRange(nValueIn))
        return state.DoS(100, false, REJECT_INVALID, "bad-txns-inputvalues-outofrange", false,
            strprintf("%s: vpub_old values out of range", __func__));

    const CAmount value_out = tx.GetValueOut();
    if (nValueIn < value_out) {
        return state.DoS(100, false, REJECT_INVALID, "bad-txns-in-belowout", false,
            strprintf("value in (%s) < value out (%s)", FormatMoney(nValueIn), FormatMoney(value_out)));
    }

    // Tally transaction fees
    const CAmount txfee_aux = nValueIn - value_out;
    if (!MoneyRange(txfee_aux)) {
        return state.DoS(100, false, REJECT_INVALID, "bad-txns-fee-outofrange");
    }

    txfee = txfee_aux;
    return true;
}

// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "primitives/transaction.h"

#include "hash.h"
#include "tinyformat.h"
#include "utilstrencodings.h"
#include "librustzcash.h"

JSDescription::JSDescription(ZCJoinSplit& params,
            const uint256& pubKeyHash,
            const uint256& anchor,
            const std::array<libzcash::JSInput, ZC_NUM_JS_INPUTS>& inputs,
            const std::array<libzcash::JSOutput, ZC_NUM_JS_OUTPUTS>& outputs,
            CAmount vpub_old,
            CAmount vpub_new,
            bool computeProof,
            uint256 *esk // payment disclosure
            ) : vpub_old(vpub_old), vpub_new(vpub_new), anchor(anchor)
{
    std::array<libzcash::Note, ZC_NUM_JS_OUTPUTS> notes;

    proof = params.prove(
        inputs,
        outputs,
        notes,
        ciphertexts,
        ephemeralKey,
        pubKeyHash,
        randomSeed,
        macs,
        nullifiers,
        commitments,
        vpub_old,
        vpub_new,
        anchor,
        computeProof,
        esk // payment disclosure
    );
}

JSDescription JSDescription::Randomized(
            ZCJoinSplit& params,
            const uint256& pubKeyHash,
            const uint256& anchor,
			std::array<libzcash::JSInput, ZC_NUM_JS_INPUTS>& inputs,
			std::array<libzcash::JSOutput, ZC_NUM_JS_OUTPUTS>& outputs,
			std::array<size_t, ZC_NUM_JS_INPUTS>& inputMap,
			std::array<size_t, ZC_NUM_JS_OUTPUTS>& outputMap,
            CAmount vpub_old,
            CAmount vpub_new,
            bool computeProof,
            uint256 *esk, // payment disclosure
            std::function<int(int)> gen
        )
{
    // Randomize the order of the inputs and outputs
    inputMap = {0, 1};
    outputMap = {0, 1};

    assert(gen);

    MappedShuffle(inputs.begin(), inputMap.begin(), ZC_NUM_JS_INPUTS, gen);
    MappedShuffle(outputs.begin(), outputMap.begin(), ZC_NUM_JS_OUTPUTS, gen);

    return JSDescription(
        params, pubKeyHash, anchor, inputs, outputs,
        vpub_old, vpub_new, computeProof,
        esk // payment disclosure
    );
}


bool JSDescription::Verify(
    ZCJoinSplit& params,
    libzcash::ProofVerifier& verifier,
    const uint256& joinSplitPubKey
)  const {

	uint256 h_sig = params.h_sig(randomSeed, nullifiers, joinSplitPubKey);
	return librustzcash_sprout_verify(
	   proof.begin(),
	   anchor.begin(),
	   h_sig.begin(),
	   macs[0].begin(),
	   macs[1].begin(),
	   nullifiers[0].begin(),
	   nullifiers[1].begin(),
	   commitments[0].begin(),
	   commitments[1].begin(),
	   vpub_old,
	   vpub_new
   );
}

uint256 JSDescription::h_sig(ZCJoinSplit& params, const uint256& pubKeyHash) const
{
	return params.h_sig(randomSeed,nullifiers, pubKeyHash);
}

void JSDescription::debug(const char* title) {
    printf("%s : JoinSplitt\n",title);
    printf("==================\n");

    printf("Old: %ld\n",vpub_old);
    printf("New: %ld\n",vpub_new);
    printf("Anchor: %s\n",anchor.GetHex().c_str());

    printf("Nullifiers:\n");
    for (int i = 0; i < ZC_NUM_JS_INPUTS; i++) {
        printf("    %s\n",nullifiers[i].GetHex().c_str());
    }
    printf("Commitments:\n");
    for (int i = 0; i < ZC_NUM_JS_OUTPUTS; i++) {
        printf("    %s\n",commitments[i].GetHex().c_str());
    }
    printf("==================\n");
}

std::string COutPoint::ToString() const
{
    return strprintf("COutPoint(%s, %u)", hash.ToString()/*.substr(0,10)*/, n);
}

std::string COutPoint::ToStringShort() const
{
    return strprintf("%s-%u", hash.ToString().substr(0,64), n);
}

CTxIn::CTxIn(COutPoint prevoutIn, CScript scriptSigIn, uint32_t nSequenceIn)
{
    prevout = prevoutIn;
    scriptSig = scriptSigIn;
    nSequence = nSequenceIn;
}

CTxIn::CTxIn(uint256 hashPrevTx, uint32_t nOut, CScript scriptSigIn, uint32_t nSequenceIn)
{
    prevout = COutPoint(hashPrevTx, nOut);
    scriptSig = scriptSigIn;
    nSequence = nSequenceIn;
}

std::string CTxIn::ToString() const
{
    std::string str;
    str += "CTxIn(";
    str += prevout.ToString();
    if (prevout.IsNull())
        str += strprintf(", coinbase %s", HexStr(scriptSig));
    else
        str += strprintf(", scriptSig=%s", HexStr(scriptSig).substr(0, 24));
    if (nSequence != SEQUENCE_FINAL)
        str += strprintf(", nSequence=%u", nSequence);
    str += ")";
    return str;
}

CTxOut::CTxOut(const CAmount& nValueIn, CScript scriptPubKeyIn, int nRoundsIn)
{
    nValue = nValueIn;
    scriptPubKey = scriptPubKeyIn;
    nRounds = nRoundsIn;
}

std::string CTxOut::ToString() const
{
    return strprintf("CTxOut(nValue=%d.%08d, scriptPubKey=%s)", nValue / COIN, nValue % COIN, HexStr(scriptPubKey).substr(0, 30));
}

CMutableTransaction::CMutableTransaction() : nVersion(CTransaction::CURRENT_VERSION), nType(TRANSACTION_NORMAL), nExpiryHeight(0), nLockTime(0) {}

CMutableTransaction::CMutableTransaction(const CTransaction& tx) : nVersion(tx.nVersion), nType(tx.nType), nExpiryHeight(tx.nExpiryHeight), vin(tx.vin), vout(tx.vout), nLockTime(tx.nLockTime), vjoinsplit(tx.vjoinsplit), joinSplitPubKey(tx.joinSplitPubKey), joinSplitSig(tx.joinSplitSig), vExtraPayload(tx.vExtraPayload) {}

uint256 CMutableTransaction::GetHash() const
{
    return SerializeHash(*this);
}

std::string CMutableTransaction::ToString() const
{
    std::string str;
    str += strprintf("CMutableTransaction(hash=%s, ver=%d, type=%d, vin.size=%u, vout.size=%u, nLockTime=%u, vExtraPayload.size=%d)\n",
        GetHash().ToString().substr(0,10),
        nVersion,
        nType,
        vin.size(),
        vout.size(),
        nLockTime,
        vExtraPayload.size());
    for (unsigned int i = 0; i < vin.size(); i++)
        str += "    " + vin[i].ToString() + "\n";
    for (unsigned int i = 0; i < vout.size(); i++)
        str += "    " + vout[i].ToString() + "\n";
    return str;
}

void CTransaction::UpdateHash() const
{
    *const_cast<uint256*>(&hash) = SerializeHash(*this);
}

// Protected constructor which only derived classes can call.
// For developer testing only.
CTransaction::CTransaction(
    const CMutableTransaction &tx,
    bool evilDeveloperFlag) : nVersion(tx.nVersion), nType(tx.nType), nExpiryHeight(tx.nExpiryHeight),
                              vin(tx.vin), vout(tx.vout), nLockTime(tx.nLockTime),
                              vjoinsplit(tx.vjoinsplit), joinSplitPubKey(tx.joinSplitPubKey), joinSplitSig(tx.joinSplitSig),
                              vExtraPayload(tx.vExtraPayload)
{
    assert(evilDeveloperFlag);
}

/* For backward compatibility, the hash is initialized to 0. TODO: remove the need for this default constructor entirely. */
CTransaction::CTransaction() : nVersion(CTransaction::CURRENT_VERSION), nType(TRANSACTION_NORMAL), nExpiryHeight(0), vin(), vout(), nLockTime(0), vjoinsplit(), joinSplitPubKey(), joinSplitSig(), hash() {}
CTransaction::CTransaction(const CMutableTransaction &tx) : nVersion(tx.nVersion), nType(tx.nType), nExpiryHeight(tx.nExpiryHeight), vin(tx.vin), vout(tx.vout), nLockTime(tx.nLockTime), vjoinsplit(tx.vjoinsplit), joinSplitPubKey(tx.joinSplitPubKey), joinSplitSig(tx.joinSplitSig), vExtraPayload(tx.vExtraPayload) { UpdateHash(); }
CTransaction::CTransaction(CMutableTransaction &&tx) : nVersion(tx.nVersion), nType(tx.nType), vin(std::move(tx.vin)), vout(std::move(tx.vout)), nExpiryHeight(tx.nExpiryHeight), nLockTime(tx.nLockTime), vjoinsplit(std::move(tx.vjoinsplit)), joinSplitPubKey(std::move(tx.joinSplitPubKey)), joinSplitSig(std::move(tx.joinSplitSig)), vExtraPayload(tx.vExtraPayload) { UpdateHash(); }

CTransaction& CTransaction::operator=(const CTransaction &tx) {
    *const_cast<int16_t*>(&nVersion) = tx.nVersion;
    *const_cast<int16_t*>(&nType) = tx.nType;
    *const_cast<std::vector<CTxIn>*>(&vin) = tx.vin;
    *const_cast<std::vector<CTxOut>*>(&vout) = tx.vout;
    *const_cast<unsigned int*>(&nLockTime) = tx.nLockTime;
    *const_cast<uint256*>(&hash) = tx.hash;
    *const_cast<uint32_t*>(&nExpiryHeight) = tx.nExpiryHeight;
    *const_cast<std::vector<JSDescription>*>(&vjoinsplit) = tx.vjoinsplit;
    *const_cast<uint256*>(&joinSplitPubKey) = tx.joinSplitPubKey;
    *const_cast<joinsplit_sig_t*>(&joinSplitSig) = tx.joinSplitSig;
	*const_cast<std::vector<uint8_t>*>(&vExtraPayload) = tx.vExtraPayload;
    return *this;
}
/* For backward compatibility, the hash is initialized to 0. TODO: remove the need for this default constructor entirely. */
/* CTransaction::CTransaction() : nVersion(CTransaction::CURRENT_VERSION), nType(TRANSACTION_NORMAL), nExpiryHeight(0), vin(), vout(), nLockTime(0), joinSplitPubKey(), joinSplitSig(), hash() {}
CTransaction::CTransaction(const CMutableTransaction &tx) : nVersion(tx.nVersion), nType(tx.nType), nExpiryHeight(tx.nExpiryHeight), vin(tx.vin), vout(tx.vout), nLockTime(tx.nLockTime), vjoinsplit(tx.vjoinsplit), joinSplitPubKey(tx.joinSplitPubKey), joinSplitSig(tx.joinSplitSig), vExtraPayload(tx.vExtraPayload), hash(ComputeHash()) {}
CTransaction::CTransaction(CMutableTransaction &&tx) : nVersion(tx.nVersion), nType(tx.nType), nExpiryHeight(tx.nExpiryHeight), vin(std::move(tx.vin)), vout(std::move(tx.vout)), nLockTime(tx.nLockTime), vjoinsplit(std::move(tx.vjoinsplit)), joinSplitPubKey(std::move(tx.joinSplitPubKey)), joinSplitSig((std::move(tx.joinSplitSig)), vExtraPayload(tx.vExtraPayload), hash(ComputeHash()) {} */

CAmount CTransaction::GetValueOut() const
{
    CAmount nValueOut = 0;
    for (std::vector<CTxOut>::const_iterator it(vout.begin()); it != vout.end(); ++it)
    {
        nValueOut += it->nValue;
        if (!MoneyRange(it->nValue) || !MoneyRange(nValueOut))
            throw std::runtime_error(std::string(__func__) + ": value out of range");
    }
    for (std::vector<JSDescription>::const_iterator it(vjoinsplit.begin()); it != vjoinsplit.end(); ++it)
    {
        // NB: vpub_old "takes" money from the value pool just as outputs do
        nValueOut += it->vpub_old;

        if (!MoneyRange(it->vpub_old) || !MoneyRange(nValueOut))
            throw std::runtime_error("CTransaction::GetValueOut(): value out of range");
    }
   return nValueOut;
}

CAmount CTransaction::GetJoinSplitValueIn() const
{
    CAmount nValue = 0;
    for (std::vector<JSDescription>::const_iterator it(vjoinsplit.begin()); it != vjoinsplit.end(); ++it)
    {
        // NB: vpub_new "gives" money to the value pool just as inputs do
        nValue += it->vpub_new;

        if (!MoneyRange(it->vpub_new) || !MoneyRange(nValue))
            throw std::runtime_error("CTransaction::GetJoinSplitValueIn(): value out of range");
    }

    return nValue;
}

double CTransaction::ComputePriority(double dPriorityInputs, unsigned int nTxSize) const
{
    nTxSize = CalculateModifiedSize(nTxSize);
    if (nTxSize == 0) return 0.0;

    return dPriorityInputs / nTxSize;
}

unsigned int CTransaction::CalculateModifiedSize(unsigned int nTxSize) const
{
    // In order to avoid disincentivizing cleaning up the UTXO set we don't count
    // the constant overhead for each txin and up to 110 bytes of scriptSig (which
    // is enough to cover a compressed pubkey p2sh redemption) for priority.
    // Providing any more cleanup incentive than making additional inputs free would
    // risk encouraging people to create junk outputs to redeem later.
    if (nTxSize == 0)
        nTxSize = ::GetSerializeSize(*this, SER_NETWORK, PROTOCOL_VERSION);
    for (std::vector<CTxIn>::const_iterator it(vin.begin()); it != vin.end(); ++it)
    {
        unsigned int offset = 41U + std::min(110U, (unsigned int)it->scriptSig.size());
        if (nTxSize > offset)
            nTxSize -= offset;
    }
    return nTxSize;
}

unsigned int CTransaction::GetTotalSize() const
{
    return ::GetSerializeSize(*this, SER_NETWORK, PROTOCOL_VERSION);
}

std::string CTransaction::ToString() const
{
    std::string str;
    str += strprintf("CTransaction(hash=%s, ver=%d, type=%d, vin.size=%u, vout.size=%u, nLockTime=%u, nExpiryHeight=%u, vExtraPayload.size=%d)\n",    
        GetHash().ToString().substr(0,10),
        nVersion,
	    nType,
        vin.size(),
        vout.size(),
        nLockTime,
	    nExpiryHeight,
	    vExtraPayload.size());
    for (unsigned int i = 0; i < vin.size(); i++)
        str += "    " + vin[i].ToString() + "\n";
    for (unsigned int i = 0; i < vout.size(); i++)
        str += "    " + vout[i].ToString() + "\n";
    return str;
}

void CTransaction::debug(const char* title) {
    printf("%s : Transaction\n",title);
    printf("==================\n");

    for (auto js : vjoinsplit) {
    	js.debug();
    }
    printf("==================\n");
}

// Copyright (c) 2017 The Zcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "asyncrpcqueue.h"
#include "amount.h"
#include "core_io.h"
#include "asyncrpcoperation_common.h"
#include "init.h"
#include "validation.h"
#include "net.h"
#include "netbase.h"
#include "rpc/server.h"
#include "timedata.h"
#include "util.h"
#include "utilmoneystr.h"
#include "wallet.h"
#include "walletdb.h"
#include "script/interpreter.h"
#include "utiltime.h"
#include "rpc/protocol.h"
#include "zcash/IncrementalMerkleTree.hpp"
#include "sodium.h"
#include "miner.h"
#include "rpc/register.h"

#include <iostream>
#include <chrono>
#include <thread>
#include <string>

#include "asyncrpcoperation_shieldcoinbase.h"

#include "paymentdisclosure.h"
#include "paymentdisclosuredb.h"

using namespace libzcash;

static int find_output(UniValue obj, int n) {
    UniValue outputMapValue = find_value(obj, "outputmap");
    if (!outputMapValue.isArray()) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Missing outputmap for JoinSplit operation");
    }

    UniValue outputMap = outputMapValue.get_array();
    assert(outputMap.size() == ZC_NUM_JS_OUTPUTS);
    for (size_t i = 0; i < outputMap.size(); i++) {
        if (outputMap[i].get_int() == n) {
            return i;
        }
    }

    throw std::logic_error("n is not present in outputmap");
}

AsyncRPCOperation_shieldcoinbase::AsyncRPCOperation_shieldcoinbase(
        CWallet* pwallet,
        std::vector<ShieldCoinbaseUTXO> inputs,
        std::string toAddress,
        CAmount fee,
        UniValue contextInfo) :
        pwallet_(pwallet), inputs_(inputs), fee_(fee), contextinfo_(contextInfo)
{
    assert(pwallet != nullptr);

    if (fee < 0 || fee > MAX_MONEY) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Fee is out of range");
    }

    if (inputs.size() == 0) {
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Empty inputs");
    }

    //  Check the destination address is valid for this network i.e. not testnet being used on mainnet
    auto address = DecodePaymentAddress(toAddress);
    if (address) {
        tozaddr_ = *address;
    } else {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid to address");
    }

    // Log the context info
    if (LogAcceptCategory(BCLog::ZRPCUNSAFE)) {
        LogPrint(BCLog::ZRPCUNSAFE, "%s: z_shieldcoinbase initialized (context=%s)\n", getId(), contextInfo.write());
    } else {
        LogPrint(BCLog::ZRPC, "%s: z_shieldcoinbase initialized\n", getId());
    }

    // Lock UTXOs
    lock_utxos();

    // Enable payment disclosure if requested
    paymentDisclosureMode = gArgs.GetBoolArg("-paymentdisclosure", true);
}

AsyncRPCOperation_shieldcoinbase::~AsyncRPCOperation_shieldcoinbase() {
}

void AsyncRPCOperation_shieldcoinbase::main() {
    if (isCancelled()) {
        unlock_utxos(); // clean up
        return;
    }

    set_state(OperationStatus::EXECUTING);
    start_execution_clock();

    bool success = false;

#ifdef ENABLE_MINING
  #ifdef ENABLE_WALLET
    GenerateBitcoins(false, nullptr, 0);
  #else
    GenerateBitcoins(false, 0);
  #endif
#endif

    try {
        success = main_impl();
    } catch (const UniValue& objError) {
        int code = find_value(objError, "code").get_int();
        std::string message = find_value(objError, "message").get_str();
        set_error_code(code);
        set_error_message(message);
    } catch (const runtime_error& e) {
        set_error_code(-1);
        set_error_message("runtime error: " + string(e.what()));
    } catch (const logic_error& e) {
        set_error_code(-1);
        set_error_message("logic error: " + string(e.what()));
    } catch (const exception& e) {
        set_error_code(-1);
        set_error_message("general exception: " + string(e.what()));
    } catch (...) {
        set_error_code(-2);
        set_error_message("unknown error");
    }

#ifdef ENABLE_MINING
  #ifdef ENABLE_WALLET
    GenerateBitcoins(GetBoolArg("-gen",false), pwallet_, gArgs.GetArgs("-genproclimit", 1));
  #else
    GenerateBitcoins(GetBoolArg("-gen",false), gArgs.GetArgs("-genproclimit", 1));
  #endif
#endif

    stop_execution_clock();

    if (success) {
        set_state(OperationStatus::SUCCESS);
    } else {
        set_state(OperationStatus::FAILED);
    }

    std::string s = strprintf("%s: z_shieldcoinbase finished (status=%s", getId(), getStateAsString());
    if (success) {
        s += strprintf(", txid=%s)\n", tx_.GetHash().ToString());
    } else {
        s += strprintf(", error=%s)\n", getErrorMessage());
    }
    LogPrintf("%s",s);

    unlock_utxos(); // clean up

    // !!! Payment disclosure START
    if (success && paymentDisclosureMode && paymentDisclosureData_.size()>0) {
        uint256 txidhash = tx_.GetHash();
        std::shared_ptr<PaymentDisclosureDB> db = PaymentDisclosureDB::sharedInstance();
        for (PaymentDisclosureKeyInfo p : paymentDisclosureData_) {
            p.first.hash = txidhash;
            if (!db->Put(p.first, p.second)) {
                LogPrint(BCLog::ZRPC, "%s: Payment Disclosure: Error writing entry to database for key %s\n", getId(), p.first.ToString());
            } else {
                LogPrint(BCLog::ZRPC, "%s: Payment Disclosure: Successfully added entry to database for key %s\n", getId(), p.first.ToString());
            }
        }
    }
    // !!! Payment disclosure END
}


bool AsyncRPCOperation_shieldcoinbase::main_impl() {

    CAmount minersFee = fee_;

    size_t numInputs = inputs_.size();

    // Check mempooltxinputlimit to avoid creating a transaction which the local mempool rejects
    size_t limit = (size_t)gArgs.GetArg("-mempooltxinputlimit", 0);
    if (limit>0 && numInputs > limit) {
        throw JSONRPCError(RPC_WALLET_ERROR,
            strprintf("Number of inputs %d is greater than mempooltxinputlimit of %d",
            numInputs, limit));
    }

    CAmount targetAmount = 0;
    for (ShieldCoinbaseUTXO & utxo : inputs_) {
        targetAmount += utxo.amount;
    }

    if (targetAmount <= minersFee) {
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS,
            strprintf("Insufficient coinbase funds, have %s and miners fee is %s",
            FormatMoney(targetAmount), FormatMoney(minersFee)));
    }

    CAmount sendAmount = targetAmount - minersFee;
    LogPrint(BCLog::ZRPC, "%s: spending %s to shield %s with fee %s\n",
            getId(), FormatMoney(targetAmount), FormatMoney(sendAmount), FormatMoney(minersFee));

    // update the transaction with these inputs
    CMutableTransaction rawTx(tx_);
    for (ShieldCoinbaseUTXO & t : inputs_) {
        CTxIn in(COutPoint(t.txid, t.vout));
        rawTx.vin.push_back(in);
    }
    tx_ = CTransaction(rawTx);

    // Prepare raw transaction to handle JoinSplits
    CMutableTransaction mtx(tx_);
    mtx.nVersion = 2;
    crypto_sign_keypair(joinSplitPubKey_.begin(), joinSplitPrivKey_);
    mtx.joinSplitPubKey = joinSplitPubKey_;
    tx_ = CTransaction(mtx);

    // Create joinsplit
    UniValue obj(UniValue::VOBJ);
    ShieldCoinbaseJSInfo info;
    info.vpub_old = sendAmount;
    info.vpub_new = 0;
    JSOutput jso = JSOutput(tozaddr_, sendAmount);
    info.vjsout.push_back(jso);
    obj = perform_joinsplit(info);

    auto txAndResult = SignSendRawTransaction(pwallet_, obj, boost::none, testmode);
    tx_ = txAndResult.first;
    set_result(txAndResult.second);
    return true;
}


UniValue AsyncRPCOperation_shieldcoinbase::perform_joinsplit(ShieldCoinbaseJSInfo & info) {
    uint256 anchor;
    {
        LOCK(cs_main);
        anchor = pcoinsTip->GetBestAnchor();
    }

    if (anchor.IsNull()) {
        throw std::runtime_error("anchor is null");
    }

    // Make sure there are two inputs and two outputs
    while (info.vjsin.size() < ZC_NUM_JS_INPUTS) {
        info.vjsin.push_back(JSInput());
    }

    while (info.vjsout.size() < ZC_NUM_JS_OUTPUTS) {
        info.vjsout.push_back(JSOutput());
    }

    if (info.vjsout.size() != ZC_NUM_JS_INPUTS || info.vjsin.size() != ZC_NUM_JS_OUTPUTS) {
        throw runtime_error("unsupported joinsplit input/output counts");
    }

    CMutableTransaction mtx(tx_);

    LogPrint(BCLog::ZRPCUNSAFE, "%s: creating joinsplit at index %d (vpub_old=%s, vpub_new=%s, in[0]=%s, in[1]=%s, out[0]=%s, out[1]=%s)\n",
            getId(),
            tx_.vjoinsplit.size(),
            FormatMoney(info.vpub_old), FormatMoney(info.vpub_new),
            FormatMoney(info.vjsin[0].note.value), FormatMoney(info.vjsin[1].note.value),
            FormatMoney(info.vjsout[0].value), FormatMoney(info.vjsout[1].value)
            );

    // Generate the proof, this can take over a minute.
    std::array<libzcash::JSInput, ZC_NUM_JS_INPUTS> inputs
            {info.vjsin[0], info.vjsin[1]};
    std::array<libzcash::JSOutput, ZC_NUM_JS_OUTPUTS> outputs
            {info.vjsout[0], info.vjsout[1]};
    std::array<size_t, ZC_NUM_JS_INPUTS> inputMap;
    std::array<size_t, ZC_NUM_JS_OUTPUTS> outputMap;

    uint256 esk; // payment disclosure - secret

    JSDescription jsdesc = JSDescription::Randomized(
            *pzcashParams,
            joinSplitPubKey_,
            anchor,
            inputs,
            outputs,
            inputMap,
            outputMap,
            info.vpub_old,
            info.vpub_new,
            !this->testmode,
            &esk); // parameter expects pointer to esk, so pass in address
    {
        auto verifier = libzcash::ProofVerifier::Strict();
        if (!(jsdesc.Verify(*pzcashParams, verifier, joinSplitPubKey_))) {
            throw std::runtime_error("error verifying joinsplit");
        }
    }

    mtx.vjoinsplit.push_back(jsdesc);

    // Empty output script.
    CScript scriptCode;
    CTransaction signTx(mtx);
    uint256 dataToBeSigned = SignatureHash(scriptCode, signTx, NOT_AN_INPUT, SIGHASH_ALL, 0, SIGVERSION_BASE);

    // Add the signature
    if (!(crypto_sign_detached(&mtx.joinSplitSig[0], nullptr,
            dataToBeSigned.begin(), 32,
            joinSplitPrivKey_
            ) == 0))
    {
        throw std::runtime_error("crypto_sign_detached failed");
    }

    // Sanity check
    if (!(crypto_sign_verify_detached(&mtx.joinSplitSig[0],
            dataToBeSigned.begin(), 32,
            mtx.joinSplitPubKey.begin()
            ) == 0))
    {
        throw std::runtime_error("crypto_sign_verify_detached failed");
    }

    CTransaction rawTx(mtx);
    tx_ = rawTx;

    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << rawTx;

    std::string encryptedNote1;
    std::string encryptedNote2;
    {
        CDataStream ss2(SER_NETWORK, PROTOCOL_VERSION);
        ss2 << ((unsigned char) 0x00);
        ss2 << jsdesc.ephemeralKey;
        ss2 << jsdesc.ciphertexts[0];
        ss2 << jsdesc.h_sig(*pzcashParams, joinSplitPubKey_);

        encryptedNote1 = HexStr(ss2.begin(), ss2.end());
    }
    {
        CDataStream ss2(SER_NETWORK, PROTOCOL_VERSION);
        ss2 << ((unsigned char) 0x01);
        ss2 << jsdesc.ephemeralKey;
        ss2 << jsdesc.ciphertexts[1];
        ss2 << jsdesc.h_sig(*pzcashParams, joinSplitPubKey_);

        encryptedNote2 = HexStr(ss2.begin(), ss2.end());
    }

    UniValue arrInputMap(UniValue::VARR);
    UniValue arrOutputMap(UniValue::VARR);
    for (size_t i = 0; i < ZC_NUM_JS_INPUTS; i++) {
        arrInputMap.push_back(inputMap[i]);
    }
    for (size_t i = 0; i < ZC_NUM_JS_OUTPUTS; i++) {
        arrOutputMap.push_back(outputMap[i]);
    }

    // !!! Payment disclosure START
    unsigned char buffer[32] = {0};
    memcpy(&buffer[0], &joinSplitPrivKey_[0], 32); // private key in first half of 64 byte buffer
    std::vector<unsigned char> vch(&buffer[0], &buffer[0] + 32);
    uint256 joinSplitPrivKey = uint256(vch);
    size_t js_index = tx_.vjoinsplit.size() - 1;
    uint256 placeholder;
    for (int i = 0; i < ZC_NUM_JS_OUTPUTS; i++) {
        uint8_t mapped_index = outputMap[i];
        // placeholder for txid will be filled in later when tx has been finalized and signed.
        PaymentDisclosureKey pdKey = {placeholder, js_index, mapped_index};
        JSOutput output = outputs[mapped_index];
        libzcash::PaymentAddress zaddr = output.addr;  // randomized output
        PaymentDisclosureInfo pdInfo = {PAYMENT_DISCLOSURE_VERSION_EXPERIMENTAL, esk, joinSplitPrivKey, zaddr};
        paymentDisclosureData_.push_back(PaymentDisclosureKeyInfo(pdKey, pdInfo));

        LogPrint(BCLog::ZRPC, "%s: Payment Disclosure: js=%d, n=%d, zaddr=%s\n", getId(), js_index, int(mapped_index), EncodePaymentAddress(zaddr));
    }
    // !!! Payment disclosure END

    UniValue obj(UniValue::VOBJ);
    obj.push_back(Pair("encryptednote1", encryptedNote1));
    obj.push_back(Pair("encryptednote2", encryptedNote2));
    obj.push_back(Pair("rawtxn", HexStr(ss.begin(), ss.end())));
    obj.push_back(Pair("inputmap", arrInputMap));
    obj.push_back(Pair("outputmap", arrOutputMap));
    return obj;
}

/**
 * Override getStatus() to append the operation's context object to the default status object.
 */
UniValue AsyncRPCOperation_shieldcoinbase::getStatus() const {
    UniValue v = AsyncRPCOperation::getStatus();
    if (contextinfo_.isNull()) {
        return v;
    }

    UniValue obj = v.get_obj();
    obj.push_back(Pair("method", "z_shieldcoinbase"));
    obj.push_back(Pair("params", contextinfo_ ));
    return obj;
}

/**
 * Lock input utxos
 */
 void AsyncRPCOperation_shieldcoinbase::lock_utxos() {
    LOCK2(cs_main, pwallet_->cs_wallet);
    for (auto utxo : inputs_) {
        COutPoint outpt(utxo.txid, utxo.vout);
        pwallet_->LockCoin(outpt);
    }
}

/**
 * Unlock input utxos
 */
void AsyncRPCOperation_shieldcoinbase::unlock_utxos() {
    LOCK2(cs_main, pwallet_->cs_wallet);
    for (auto utxo : inputs_) {
        COutPoint outpt(utxo.txid, utxo.vout);
        pwallet_->UnlockCoin(outpt);
    }
}

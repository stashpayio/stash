// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "rpc/server.h"
#include "utilstrencodings.h"

extern UniValue zc_raw_keygen(const JSONRPCRequest& request);
extern UniValue zc_raw_joinsplit(const JSONRPCRequest& request);
extern UniValue zc_raw_receive(const JSONRPCRequest& request);
extern UniValue zc_sample_joinsplit(const JSONRPCRequest& request);
extern UniValue z_exportkey(const JSONRPCRequest& request); // in rpcdump.cpp
extern UniValue z_importkey(const JSONRPCRequest& request); // in rpcdump.cpp
extern UniValue z_exportviewingkey(const JSONRPCRequest& request); // in rpcdump.cpp
extern UniValue z_importviewingkey(const JSONRPCRequest& request); // in rpcdump.cpp
extern UniValue z_getnewaddress(const JSONRPCRequest& request); // in rpcwallet.cpp
extern UniValue z_listaddresses(const JSONRPCRequest& request); // in rpcwallet.cpp
extern UniValue z_exportwallet(const JSONRPCRequest& request); // in rpcdump.cpp
extern UniValue z_importwallet(const JSONRPCRequest& request); // in rpcdump.cpp
extern UniValue z_listreceivedbyaddress(const JSONRPCRequest& request); // in rpcwallet.cpp
extern UniValue z_getbalance(const JSONRPCRequest& request); // in rpcwallet.cpp
extern UniValue z_gettotalbalance(const JSONRPCRequest& request); // in rpcwallet.cpp
extern UniValue z_sendmany(const JSONRPCRequest& request); // in rpcwallet.cpp
extern UniValue z_shieldcoinbase(const JSONRPCRequest& request); // in rpcwallet.cpp
extern UniValue z_getoperationstatus(const JSONRPCRequest& request); // in rpcwallet.cpp
extern UniValue z_getoperationresult(const JSONRPCRequest& request); // in rpcwallet.cpp
extern UniValue z_listoperationids(const JSONRPCRequest& request); // in rpcwallet.cpp
extern UniValue z_validateaddress(const JSONRPCRequest& request); // in rpcmisc.cpp
extern UniValue z_getpaymentdisclosure(const JSONRPCRequest& request); // in rpcdisclosure.cpp
extern UniValue z_validatepaymentdisclosure(const JSONRPCRequest& request); // in rpcdisclosure.cpp

static const CRPCCommand commands[] =
{ //  category              name                      actor (function)         okSafe argNames
  //  --------------------- ------------------------  -----------------------  ------ ----------
    { "wallet",             "zcrawkeygen",            &zc_raw_keygen,          true,  {} },
    { "wallet",             "zcrawjoinsplit",         &zc_raw_joinsplit,       true,  {} },
    { "wallet",             "zcrawreceive",           &zc_raw_receive,         true,  {} },
    { "wallet",             "zcsamplejoinsplit",      &zc_sample_joinsplit,    true,  {} },
    { "wallet",             "z_listreceivedbyaddress",&z_listreceivedbyaddress,false, {} },
    { "wallet",             "z_getbalance",           &z_getbalance,           false, {} },
    { "wallet",             "z_gettotalbalance",      &z_gettotalbalance,      false, {} },
    { "wallet",             "z_sendmany",             &z_sendmany,             false, {} },
    { "wallet",             "z_shieldcoinbase",       &z_shieldcoinbase,       false, {} },
    { "wallet",             "z_getoperationstatus",   &z_getoperationstatus,   true,  {} },
    { "wallet",             "z_getoperationresult",   &z_getoperationresult,   true,  {} },
    { "wallet",             "z_listoperationids",     &z_listoperationids,     true,  {} },
    { "wallet",             "z_getnewaddress",        &z_getnewaddress,        true,  {} },
    { "wallet",             "z_listaddresses",        &z_listaddresses,        true,  {} },
    { "wallet",             "z_exportkey",            &z_exportkey,            true,  {} },
    { "wallet",             "z_importkey",            &z_importkey,            true,  {} },
    { "wallet",             "z_exportviewingkey",     &z_exportviewingkey,     true,  {} },
    { "wallet",             "z_importviewingkey",     &z_importviewingkey,     true,  {} },
    { "wallet",             "z_exportwallet",         &z_exportwallet,         true,  {} },
    { "wallet",             "z_importwallet",         &z_importwallet,         true,  {} },

};

void RegisterZCashRPCCommands(CRPCTable &t)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        t.appendCommand(commands[vcidx].name, &commands[vcidx]);
}

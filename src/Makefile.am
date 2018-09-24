# Copyright (c) 2013-2016 The Bitcoin Core developers
# Copyright (c) 2014-2018 The Dash Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

DIST_SUBDIRS = secp256k1 univalue

AM_LDFLAGS = $(PTHREAD_CFLAGS) $(LIBTOOL_LDFLAGS) $(HARDENED_LDFLAGS)
AM_CXXFLAGS = $(HARDENED_CXXFLAGS) $(ERROR_CXXFLAGS)
AM_CPPFLAGS = $(HARDENED_CPPFLAGS)
EXTRA_LIBRARIES =

if EMBEDDED_UNIVALUE
LIBUNIVALUE = univalue/libunivalue.la

$(LIBUNIVALUE): $(wildcard univalue/lib/*) $(wildcard univalue/include/*)
	$(AM_V_at)$(MAKE) $(AM_MAKEFLAGS) -C $(@D) $(@F)
else
LIBUNIVALUE = $(UNIVALUE_LIBS)
endif

BITCOIN_CONFIG_INCLUDES=-I$(builddir)/config
BITCOIN_INCLUDES=-I$(builddir) -I$(builddir)/obj $(BDB_CPPFLAGS) $(BOOST_CPPFLAGS) $(LEVELDB_CPPFLAGS) $(CRYPTO_CFLAGS) $(SSL_CFLAGS)

BITCOIN_INCLUDES += -I$(srcdir)/secp256k1/include
BITCOIN_INCLUDES += -I$(srcdir)/snark
BITCOIN_INCLUDES += -I$(srcdir)/snark/libsnark
if TARGET_WINDOWS
BITCOIN_INCLUDES += -I$(srcdir)/snark/build/include
endif
BITCOIN_INCLUDES += $(UNIVALUE_CFLAGS)

LIBBITCOIN_SERVER=libstash_server.a
LIBBITCOIN_COMMON=libstash_common.a
LIBBITCOIN_CONSENSUS=libstash_consensus.a
LIBBITCOIN_CLI=libstash_cli.a
LIBBITCOIN_UTIL=libstash_util.a
LIBBITCOIN_CRYPTO=crypto/libstash_crypto.a
LIBBITCOINQT=qt/libstashqt.a
LIBSECP256K1=secp256k1/libsecp256k1.la
LIBSNARK=snark/libsnark.a
LIBZCASH=libzcash.a
if TARGET_WINDOWS
LIBZCASH_LIBS = $(GMPXX_LIBS) $(GMP_LIBS) -lsodium  -lrustzcash
else
LIBZCASH_LIBS = $(GMPXX_LIBS) $(GMP_LIBS) -lsodium  -lrustzcash -ldl
endif

if ENABLE_ZMQ
LIBBITCOIN_ZMQ=libstash_zmq.a
endif
if BUILD_BITCOIN_LIBS
LIBBITCOINCONSENSUS=libstashconsensus.la
endif
if ENABLE_WALLET
LIBBITCOIN_WALLET=libstash_wallet.a
endif

$(LIBSECP256K1): $(wildcard secp256k1/src/*) $(wildcard secp256k1/include/*)
	$(AM_V_at)$(MAKE) $(AM_MAKEFLAGS) -C $(@D) $(@F)

-include collate-libsnark
collate-libsnark: $(LIBSNARK)


LIBSNARK_CXXFLAGS = -fPIC -DBINARY_OUTPUT -DNO_PT_COMPRESSION=1 -fstack-protector-all
LIBSNARK_CONFIG_FLAGS = CURVE=ALT_BN128 NO_PROCPS=1 NO_DOCS=1 STATIC=1 NO_SUPERCOP=1 FEATUREFLAGS=-DMONTGOMERY_OUTPUT NO_COPY_DEPINST=1 NO_COMPILE_LIBGTEST=1
if HAVE_OPENMP
LIBSNARK_CONFIG_FLAGS += MULTICORE=1
endif
#if TARGET_DARWIN
#LIBSNARK_CONFIG_FLAGS += PLATFORM=darwin
#endif

if TARGET_WINDOWS
$(LIBSNARK): $(wildcard snark/src/*)
		$(AM_V_at) CC="$(CC)" CXX="$(CXX)" AR="$(AR)" CXXFLAGS="$(LIBSNARK_CXXFLAGS)" $(MAKE) $(AM_MAKEFLAGS) -C snark/ install PREFIX=$(srcdir)/build DEPINST="$(LIBSNARK_DEPINST)" $(LIBSNARK_CONFIG_FLAGS) OPTFLAGS="-O2 -march=x86-64"

libsnark-tests: $(wildcard snark/src/*)
		$(AM_V_at) CC="$(CC)" CXX="$(CXX)" AR="$(AR)" CXXFLAGS="$(LIBSNARK_CXXFLAGS)" $(MAKE) $(AM_MAKEFLAGS) -C snark/ check PREFIX=$(srcdir)/build DEPINST="$(LIBSNARK_DEPINST)" $(LIBSNARK_CONFIG_FLAGS) OPTFLAGS="-O2 -march=x86-64"
else
$(LIBSNARK): $(wildcard snark/src/*)
		$(AM_V_at) CXXFLAGS="$(LIBSNARK_CXXFLAGS)" $(MAKE) $(AM_MAKEFLAGS) -C snark/ DEPINST="$(LIBSNARK_DEPINST)" $(LIBSNARK_CONFIG_FLAGS) OPTFLAGS="-O2 -march=x86-64"

libsnark-tests: $(wildcard snark/src/*)
		$(AM_V_at) CXXFLAGS="$(LIBSNARK_CXXFLAGS)" $(MAKE) $(AM_MAKEFLAGS) -C snark/ check DEPINST="$(LIBSNARK_DEPINST)" $(LIBSNARK_CONFIG_FLAGS) OPTFLAGS="-O2 -march=x86-64"
endif

# Make is not made aware of per-object dependencies to avoid limiting building parallelization
# But to build the less dependent modules first, we manually select their order here:
EXTRA_LIBRARIES += \
  $(LIBBITCOIN_CRYPTO) \
  $(LIBBITCOIN_UTIL) \
  $(LIBBITCOIN_COMMON) \
  $(LIBBITCOIN_CONSENSUS) \
  $(LIBBITCOIN_SERVER) \
  $(LIBBITCOIN_CLI) \
  $(LIBBITCOIN_WALLET) \
  $(LIBBITCOIN_ZMQ) \
  libzcash.a

if ENABLE_WALLET
BITCOIN_INCLUDES += $(BDB_CPPFLAGS)
endif
if ENABLE_ZMQ
EXTRA_LIBRARIES += libbitcoin_zmq.a
endif

lib_LTLIBRARIES = $(LIBBITCOINCONSENSUS)

bin_PROGRAMS =
TESTS =
BENCHMARKS =

if BUILD_BITCOIND
  bin_PROGRAMS += stashd
endif

if BUILD_BITCOIN_UTILS
  bin_PROGRAMS += stash-cli stash-tx
endif

LIBZCASH_H = \
  zcash/IncrementalMerkleTree.hpp \
  zcash/NoteEncryption.hpp \
  zcash/Address.hpp \
  zcash/JoinSplit.hpp \
  zcash/Note.hpp \
  zcash/prf.h \
  zcash/Proof.hpp \
  zcash/util.h \
  zcash/Zcash.h

.PHONY: FORCE collate-libsnark check-symbols check-security
# stash core #
BITCOIN_CORE_H = \
  addrdb.h \
  activemasternode.h \
  addressindex.h \
  spentindex.h \
  addrman.h \
  alert.h \
  amount.h \
  arith_uint256.h \
  asyncrpcoperation.h  \
  asyncrpcqueue.h \
  base58.h \
  bip39.h \
  bip39_english.h \
  blockencodings.h \
  bloom.h \
  cachemap.h \
  cachemultimap.h \
  chain.h \
  chainparams.h \
  chainparamsbase.h \
  chainparamsseeds.h \
  checkpoints.h \
  checkqueue.h \
  clientversion.h \
  coins.h \
  compat.h \
  compat/byteswap.h \
  compat/endian.h \
  compat/sanity.h \
  compressor.h \
  consensus/consensus.h \
  core_io.h \
  core_memusage.h \
  cuckoocache.h \
  deprecation.h \
  privatesend.h \
  privatesend-client.h \
  privatesend-server.h \
  privatesend-util.h \
  dsnotificationinterface.h \
  governance.h \
  governance-classes.h \
  governance-exceptions.h \
  governance-object.h \
  governance-validators.h \
  governance-vote.h \
  governance-votedb.h \
  flat-database.h \
  hdchain.h \
  httprpc.h \    
  httpserver.h \
  indirectmap.h \
  init.h \
  instantx.h \
  key.h \
  keepass.h \
  keystore.h \
  dbwrapper.h \
  limitedmap.h \
  masternode.h \
  masternode-payments.h \
  masternode-sync.h \
  masternodeman.h \
  masternodeconfig.h \
  memusage.h \
  merkleblock.h \
  messagesigner.h \
  miner.h \
  net.h \
  net_processing.h \
  netaddress.h \
  netbase.h \
  netfulfilledman.h \
  netmessagemaker.h \
  noui.h \
  paymentdisclosure.h \
  paymentdisclosuredb.h \
  policy/fees.h \
  policy/policy.h \
  policy/rbf.h \
  pow.h \
  protocol.h \
  random.h \
  reverselock.h \
  rpc/client.h \
  rpc/protocol.h \
  rpc/server.h \
  rpc/asyncrpcoperation.h \
  rpc/asyncrpcqueue.h.h \
	rpc/register.h \
	rpc/zcash.h \
  scheduler.h \
  script/sigcache.h \
  script/sign.h \
  script/standard.h \
  script/ismine.h \
  spork.h \
  streams.h \
  support/allocators/secure.h \
  support/allocators/zeroafterfree.h \
  support/cleanse.h \
  support/events.h \
  support/lockedpool.h \
  sync.h \
  threadsafety.h \
  threadinterrupt.h \
  timedata.h \
  torcontrol.h \
  txdb.h \
  txmempool.h \
  ui_interface.h \
  uint256.h \
  uint252.h \
  undo.h \
  util.h \
  utilmoneystr.h \
  utiltime.h \
  validation.h \
  validationinterface.h \
  versionbits.h \
  wallet/coincontrol.h \
  wallet/crypter.h \
  wallet/db.h \
  wallet/asyncrpcoperation_sendmany.h \
  wallet/asyncrpcoperation_shieldcoinbase.h \
  wallet/rpcwallet.h \
  wallet/wallet.h \
  wallet/walletdb.h \
  warnings.h \
  zmq/zmqabstractnotifier.h \
  zmq/zmqconfig.h\
  zmq/zmqnotificationinterface.h \
  zmq/zmqpublishnotifier.h

obj/build.h: FORCE
	@$(MKDIR_P) $(builddir)/obj
	@$(top_srcdir)/share/genbuild.sh $(abs_top_builddir)/src/obj/build.h \
	  $(abs_top_srcdir)
libstash_util_a-clientversion.$(OBJEXT): obj/build.h

# server: shared between stashd and stash-qt
libstash_server_a_CPPFLAGS = $(AM_CPPFLAGS) $(BITCOIN_INCLUDES) $(MINIUPNPC_CPPFLAGS) $(EVENT_CFLAGS) $(EVENT_PTHREADS_CFLAGS)
libstash_server_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libstash_server_a_SOURCES = \
  activemasternode.cpp \
  addrman.cpp \
  addrdb.cpp \
  alert.cpp \
  asyncrpcoperation.h  \
  asyncrpcqueue.h \
  bloom.cpp \
  blockencodings.cpp \
  chain.cpp \
  checkpoints.cpp \
  deprecation.cpp \
  dsnotificationinterface.cpp \
  httprpc.cpp \
  httpserver.cpp \
  init.cpp \
  instantx.cpp \
  dbwrapper.cpp \
  governance.cpp \
  governance-classes.cpp \
  governance-object.cpp \
  governance-validators.cpp \
  governance-vote.cpp \
  governance-votedb.cpp \
  masternode.cpp \
  masternode-payments.cpp \
  masternode-sync.cpp \
  masternodeconfig.cpp \
  masternodeman.cpp \
  merkleblock.cpp \
  messagesigner.cpp \
  miner.cpp \
  net.cpp \
  netfulfilledman.cpp \
  net_processing.cpp \
  noui.cpp \
  paymentdisclosure.cpp \
  paymentdisclosuredb.cpp \
  policy/fees.cpp \
  policy/policy.cpp \
  pow.cpp \
  privatesend.cpp \
  privatesend-server.cpp \
  rest.cpp \
  rpc/blockchain.cpp \
  rpc/masternode.cpp \
  rpc/governance.cpp \
  rpc/mining.cpp \
  rpc/misc.cpp \
  rpc/net.cpp \
  rpc/rawtransaction.cpp \
  rpc/server.cpp \
  rpc/asyncrpcoperation.cpp \
  rpc/asyncrpcqueue.cpp \
  script/sigcache.cpp \
  script/ismine.cpp \
  sendalert.cpp \
  spork.cpp \
  timedata.cpp \
  torcontrol.cpp \
  txdb.cpp \
  txmempool.cpp \
  ui_interface.cpp \
  validation.cpp \
  validationinterface.cpp \
  versionbits.cpp \
  $(BITCOIN_CORE_H) \
  $(LIBZCASH_H)

if ENABLE_ZMQ
libstash_zmq_a_CPPFLAGS = $(BITCOIN_INCLUDES) $(ZMQ_CFLAGS)
libstash_zmq_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libstash_zmq_a_SOURCES = \
  zmq/zmqabstractnotifier.cpp \
  zmq/zmqnotificationinterface.cpp \
  zmq/zmqpublishnotifier.cpp
endif


# wallet: shared between stashd and stash-qt, but only linked
# when wallet enabled
libstash_wallet_a_CPPFLAGS = $(AM_CPPFLAGS) $(BITCOIN_INCLUDES)
libstash_wallet_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libstash_wallet_a_SOURCES = \
  keepass.cpp \
  privatesend-client.cpp \
  privatesend-util.cpp \
  wallet/crypter.cpp \
  wallet/db.cpp \
  wallet/asyncrpcoperation_sendmany.cpp \
  wallet/asyncrpcoperation_shieldcoinbase.cpp \
  paymentdisclosure.cpp \
  paymentdisclosuredb.cpp \
  wallet/rpcdisclosure.cpp \
  wallet/rpcdump.cpp \
  wallet/rpcwallet.cpp \
  wallet/wallet.cpp \
  wallet/walletdb.cpp \
  policy/rbf.cpp \
  $(BITCOIN_CORE_H)  \
  $(LIBZCASH_H)

# crypto primitives library
crypto_libstash_crypto_a_CPPFLAGS = $(AM_CPPFLAGS) $(BITCOIN_CONFIG_INCLUDES) $(PIC_FLAGS)
crypto_libstash_crypto_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS) $(PIC_FLAGS)
crypto_libstash_crypto_a_SOURCES = \
  crypto/aes.cpp \
  crypto/aes.h \
  crypto/common.h \
  crypto/hmac_sha256.cpp \
  crypto/hmac_sha256.h \
  crypto/hmac_sha512.cpp \
  crypto/hmac_sha512.h \
  crypto/ripemd160.cpp \
  crypto/aes_helper.c \
  crypto/ripemd160.h \
  crypto/sha1.cpp \
  crypto/sha1.h \
  crypto/sha256.cpp \
  crypto/sha256.h \
  crypto/sha512.cpp \
  crypto/sha512.h

# x11
crypto_libstash_crypto_a_SOURCES += \
  crypto/blake.c \
  crypto/bmw.c \
  crypto/cubehash.c \
  crypto/echo.c \
  crypto/groestl.c \
  crypto/jh.c \
  crypto/keccak.c \
  crypto/luffa.c \
  crypto/shavite.c \
  crypto/simd.c \
  crypto/skein.c \
  crypto/sph_blake.h \
  crypto/sph_bmw.h \
  crypto/sph_cubehash.h \
  crypto/sph_echo.h \
  crypto/sph_groestl.h \
  crypto/sph_jh.h \
  crypto/sph_keccak.h \
  crypto/sph_luffa.h \
  crypto/sph_shavite.h \
  crypto/sph_simd.h \
  crypto/sph_skein.h \
  crypto/sph_types.h

# consensus: shared between all executables that validate any consensus rules.
libstash_consensus_a_CPPFLAGS = $(AM_CPPFLAGS) $(BITCOIN_INCLUDES)
libstash_consensus_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libstash_consensus_a_SOURCES = \
  amount.h \
  arith_uint256.cpp \
  arith_uint256.h \
  consensus/merkle.cpp \
  consensus/merkle.h \
  consensus/params.h \
  consensus/validation.h \
  hash.cpp \
  hash.h \
  prevector.h \
  primitives/block.cpp \
  primitives/block.h \
  primitives/transaction.cpp \
  primitives/transaction.h \
  pubkey.cpp \
  pubkey.h \
  script/stashconsensus.cpp \
  script/interpreter.cpp \
  script/interpreter.h \
  script/script.cpp \
  script/script.h \
  script/script_error.cpp \
  script/script_error.h \
  serialize.h \
  tinyformat.h \
  uint256.cpp \
  uint256.h \
  utilstrencodings.cpp \
  utilstrencodings.h \
  version.h

# common: shared between stashd, and stash-qt and non-server tools
libstash_common_a_CPPFLAGS = $(AM_CPPFLAGS) $(BITCOIN_INCLUDES)
libstash_common_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libstash_common_a_SOURCES = \
  amount.cpp \
  base58.cpp \
  bip39.cpp \
  chainparams.cpp \
  coins.cpp \
  compressor.cpp \
  core_read.cpp \
  core_write.cpp \
  hdchain.cpp \
  key.cpp \
  keystore.cpp \
  netaddress.cpp \
  netbase.cpp \
  protocol.cpp \
  scheduler.cpp \
  script/sign.cpp \
  script/standard.cpp \
  warnings.cpp \
  zen/delay.cpp

# util: shared between all executables.
# This library *must* be included to make sure that the glibc
# backward-compatibility objects and their sanity checks are linked.
libstash_util_a_CPPFLAGS = $(AM_CPPFLAGS) $(BITCOIN_INCLUDES)
libstash_util_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libstash_util_a_SOURCES = \
  support/lockedpool.cpp \
  chainparamsbase.cpp \
  clientversion.cpp \
  compat/glibc_sanity.cpp \
  compat/glibcxx_sanity.cpp \
  compat/strnlen.cpp \
  random.cpp \
  rpc/protocol.cpp \
  support/cleanse.cpp \
  sync.cpp \
  threadinterrupt.cpp \
  util.cpp \
  utilmoneystr.cpp \
  utilstrencodings.cpp \
  utiltime.cpp \
  $(BITCOIN_CORE_H)  \
  $(LIBZCASH_H)

if GLIBC_BACK_COMPAT
libstash_util_a_SOURCES += compat/glibc_compat.cpp
endif

# cli: shared between stash-cli and stash-qt
libstash_cli_a_CPPFLAGS = $(AM_CPPFLAGS) $(BITCOIN_INCLUDES)
libstash_cli_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libstash_cli_a_SOURCES = \
  rpc/client.cpp \
  $(BITCOIN_CORE_H)  \
  $(LIBZCASH_H)

nodist_libstash_util_a_SOURCES = $(srcdir)/obj/build.h
#

# stashd binary #
stashd_SOURCES = stashd.cpp
stashd_CPPFLAGS = $(AM_CPPFLAGS) $(BITCOIN_INCLUDES)
stashd_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
stashd_LDFLAGS = $(RELDFLAGS) $(AM_LDFLAGS) $(LIBTOOL_APP_LDFLAGS)

if TARGET_WINDOWS
stashd_SOURCES += stashd-res.rc
endif

stashd_LDADD = \
  $(LIBBITCOIN_SERVER) \
  $(LIBBITCOIN_COMMON) \
  $(LIBUNIVALUE) \
  $(LIBBITCOIN_UTIL) \
  $(LIBBITCOIN_ZMQ) \
  $(LIBBITCOIN_CONSENSUS) \
  $(LIBBITCOIN_CRYPTO) \
  $(LIBLEVELDB) \
  $(LIBMEMENV) \
  $(LIBSECP256K1)


if ENABLE_ZMQ
stashd_LDADD += $(LIBBITCOIN_ZMQ) $(ZMQ_LIBS)
endif


if ENABLE_WALLET
stashd_LDADD +=   $(LIBBITCOIN_WALLET)
endif

stashd_LDADD += \
	$(BOOST_LIBS) \
	$(BDB_LIBS) \
	$(SSL_LIBS) \
	$(CRYPTO_LIBS) \
	$(MINIUPNPC_LIBS) \
	$(EVENT_PTHREADS_LIBS) \
	$(EVENT_LIBS) \
	$(LIBZCASH) \
	$(LIBSNARK) \
	$(LIBBITCOIN_CRYPTO) \
	$(LIBZCASH_LIBS)

# stash-cli binary #
stash_cli_SOURCES = stash-cli.cpp
stash_cli_CPPFLAGS = $(AM_CPPFLAGS) $(BITCOIN_INCLUDES) $(EVENT_CFLAGS)
stash_cli_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
stash_cli_LDFLAGS = $(RELDFLAGS) $(AM_LDFLAGS) $(LIBTOOL_APP_LDFLAGS)

if TARGET_WINDOWS
stash_cli_SOURCES += stash-cli-res.rc
endif

stash_cli_LDADD = \
  $(LIBBITCOIN_CLI) \
  $(LIBUNIVALUE) \
  $(LIBBITCOIN_UTIL) \
  $(BOOST_LIBS) \
  $(SSL_LIBS) \
  $(CRYPTO_LIBS) \
  $(EVENT_LIBS) \
	$(LIBZCASH) \
	$(LIBSNARK) \
  $(LIBBITCOIN_CRYPTO) \
	$(LIBZCASH_LIBS)
#

# stash-tx binary #
stash_tx_SOURCES = stash-tx.cpp
stash_tx_CPPFLAGS = $(AM_CPPFLAGS) $(BITCOIN_INCLUDES)
stash_tx_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
stash_tx_LDFLAGS = $(RELDFLAGS) $(AM_LDFLAGS) $(LIBTOOL_APP_LDFLAGS)

if TARGET_WINDOWS
stash_tx_SOURCES += stash-tx-res.rc
endif

stash_tx_LDADD = \
  $(LIBUNIVALUE) \
  $(LIBBITCOIN_COMMON) \
  $(LIBBITCOIN_UTIL) \
  $(LIBSECP256K1)  \
	$(BOOST_LIBS) \
	$(CRYPTO_LIBS) \
	$(LIBZCASH) \
	$(LIBSNARK) \
  $(LIBBITCOIN_CONSENSUS) \
  $(LIBBITCOIN_CRYPTO) \
	$(LIBZCASH_LIBS)

#

# zcash protocol primitives #
if TARGET_WINDOWS
libzcash_a_CPPFLAGS = $(AM_CPPFLAGS) $(PIC_FLAGS) -DBINARY_OUTPUT -DCURVE_ALT_BN128 -DBOOST_SPIRIT_THREADSAFE -fvisibility=hidden  $(BITCOIN_INCLUDES)  -DSTATIC
libzcash_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libzcash_a_LDFLAGS = $(AM_LDFLAGS)
else
libzcash_a_CPPFLAGS = -fPIC -DBINARY_OUTPUT -DCURVE_ALT_BN128 -DBOOST_SPIRIT_THREADSAFE -DHAVE_BUILD_INFO -D__STDC_FORMAT_MACROS $(HARDENED_CPPFLAGS) $(HARDENED_CXXFLAGS) $(HARDENED_LDFLAGS) -pipe $(SAN_LDFLAGS) -O1 -g -Wstack-protector $(SAN_CXXFLAGS) -fstack-protector-all -fPIE -fvisibility=hidden -DSTATIC $(BITCOIN_INCLUDES)
libzcash_a_CXXFLAGS = $(SAN_CXXFLAGS) $(HARDENED_CXXFLAGS) -fwrapv -fno-strict-aliasing
libzcash_a_CPPFLAGS += -DMONTGOMERY_OUTPUT
endif
libzcash_a_SOURCES = \
  zcash/IncrementalMerkleTree.cpp \
  zcash/NoteEncryption.cpp \
  zcash/Address.cpp \
  zcash/JoinSplit.cpp \
  zcash/Proof.cpp \
  zcash/Note.cpp \
  zcash/prf.cpp \
  zcash/util.cpp \
  zcash/circuit/commitment.tcc \
  zcash/circuit/gadget.tcc \
  zcash/circuit/merkle.tcc \
  zcash/circuit/note.tcc \
  zcash/circuit/prfs.tcc \
  zcash/circuit/utils.tcc

if BUILD_BITCOIN_LIBS
include_HEADERS = script/stashconsensus.h
libstashconsensus_la_SOURCES = $(crypto_libstash_crypto_a_SOURCES) $(libstash_consensus_a_SOURCES)

if GLIBC_BACK_COMPAT
  libstashconsensus_la_SOURCES += compat/glibc_compat.cpp
endif

libstashconsensus_la_LDFLAGS = $(AM_LDFLAGS) -no-undefined $(RELDFLAGS)
libstashconsensus_la_LIBADD = $(LIBSECP256K1)
libstashconsensus_la_CPPFLAGS = $(AM_CPPFLAGS) -I$(builddir)/obj -I$(srcdir)/secp256k1/include -DBUILD_BITCOIN_INTERNAL
libstashconsensus_la_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)

endif
#

CTAES_DIST =  crypto/ctaes/bench.c
CTAES_DIST += crypto/ctaes/ctaes.c
CTAES_DIST += crypto/ctaes/ctaes.h
CTAES_DIST += crypto/ctaes/README.md
CTAES_DIST += crypto/ctaes/test.c

CLEANFILES = $(EXTRA_LIBRARIES)

CLEANFILES += *.gcda *.gcno
CLEANFILES += compat/*.gcda compat/*.gcno
CLEANFILES += consensus/*.gcda consensus/*.gcno
CLEANFILES += crypto/*.gcda crypto/*.gcno
CLEANFILES += policy/*.gcda policy/*.gcno
CLEANFILES += primitives/*.gcda primitives/*.gcno
CLEANFILES += script/*.gcda script/*.gcno
CLEANFILES += support/*.gcda support/*.gcno
CLEANFILES += univalue/*.gcda univalue/*.gcno
CLEANFILES += wallet/*.gcda wallet/*.gcno
CLEANFILES += wallet/test/*.gcda wallet/test/*.gcno
CLEANFILES += zmq/*.gcda zmq/*.gcno

DISTCLEANFILES = obj/build.h

EXTRA_DIST = leveldb snark $(CTAES_DIST)

config/stash-config.h: config/stamp-h1
	@$(MAKE) -C $(top_builddir) $(subdir)/$(@)
config/stamp-h1: $(top_srcdir)/$(subdir)/config/stash-config.h.in $(top_builddir)/config.status
	$(AM_V_at)$(MAKE) -C $(top_builddir) $(subdir)/$(@)
$(top_srcdir)/$(subdir)/config/stash-config.h.in:  $(am__configure_deps)
	$(AM_V_at)$(MAKE) -C $(top_srcdir) $(subdir)/config/stash-config.h.in

clean-local:
	-$(MAKE) -C secp256k1 clean
	-$(MAKE) -C snark clean
	-$(MAKE) -C univalue clean
	-rm -f leveldb/*/*.gcda leveldb/*/*.gcno leveldb/helpers/memenv/*.gcda leveldb/helpers/memenv/*.gcno
	-rm -f config.h
	-rm -rf test/__pycache__

.rc.o:
	@test -f $(WINDRES)
	## FIXME: How to get the appropriate modulename_CPPFLAGS in here?
	$(AM_V_GEN) $(WINDRES) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(CPPFLAGS) -DWINDRES_PREPROC -i $< -o $@

.mm.o:
	$(AM_V_CXX) $(OBJCXX) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) \
	  $(CPPFLAGS) $(AM_CXXFLAGS) $(QT_INCLUDES) $(AM_CXXFLAGS) $(PIE_FLAGS) $(CXXFLAGS) -c -o $@ $<

check-symbols: $(bin_PROGRAMS)
if GLIBC_BACK_COMPAT
	@echo "Checking glibc back compat..."
	$(AM_V_at) READELF=$(READELF) CPPFILT=$(CPPFILT) $(top_srcdir)/contrib/devtools/symbol-check.py < $(bin_PROGRAMS)
endif

check-security: $(bin_PROGRAMS)
if HARDEN
	@echo "Checking binary security..."
	$(AM_V_at) READELF=$(READELF) OBJDUMP=$(OBJDUMP) $(top_srcdir)/contrib/devtools/security-check.py < $(bin_PROGRAMS)
endif

%.pb.cc %.pb.h: %.proto
	@test -f $(PROTOC)
	$(AM_V_GEN) $(PROTOC) --cpp_out=$(@D) --proto_path=$(<D) $<

if EMBEDDED_LEVELDB
include Makefile.leveldb.include
endif

if ENABLE_TESTS
include Makefile.test.include
endif

if ENABLE_BENCH
include Makefile.bench.include
endif

if ENABLE_QT
include Makefile.qt.include
endif

if ENABLE_QT_TESTS
include Makefile.qttest.include
endif

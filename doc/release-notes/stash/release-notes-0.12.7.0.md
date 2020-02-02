Stash Core version 0.12.7.0
==========================

Release is now available from:

  <https://https://github.com/stashpayio/stash/releases>

This is a major release.

Please report bugs using the issue tracker at github:

  <https://github.com/stashpayio/stash/issues>

Notable changes
===============
Migrate to Proof of Stake (POS)
------------------------------

Introduces an exponential shift in block reward from miner to masternode. With spork 
SPORK_31_STASH_POS_ENABLED enabled, the miner reward is cut in half every each 525,960 
blocks (1 stash year) and awarded to the masternode.

| Year | Block Start | Block End | Block Reward | MN Reward    | Miner Reward | MN %   | Miner % |
|------|-------------|-----------|--------------|--------------|--------------|--------|---------|
| 0    | 0           | 525,959   | 60.84        | 30.420000000 | 30.42000000  | 50.00% | 50.00%  |
| 1    | 525,960     | 1,051,919 | 56.49428571  | 42.370714286 | 14.12357143  | 75.00% | 25.00%  |
| 2    | 1,051,920   | 1,577,879 | 52.45897959  | 45.901607143 | 6.55737245   | 87.50% | 12.50%  |
| 3    | 1,577,880   | 2,103,839 | 48.71190962  | 45.667415270 | 3.04449435   | 93.75% | 6.25%   |
| 4    | 2,103,840   | 2,629,799 | 45.23248751  | 43.818972271 | 1.41351524   | 96.88% | 3.13%   |
| 5    | 2,629,800   | 3,155,759 | 42.00159554  | 41.345320610 | 0.65627493   | 98.44% | 1.56%   |
| 6    | 3,155,760   | 3,681,719 | 39.00148157  | 38.696782499 | 0.30469908   | 99.22% | 0.78%   |
| 7    | 3,681,720   | 4,207,679 | 36.21566146  | 36.074194033 | 0.14146743   | 99.61% | 0.39%   |
| 8    | 4,207,680   | 4,733,639 | 33.6288285   | 33.563147194 | 0.06568131   | 99.80% | 0.20%   |
| 9    | 4,733,640   | 5,259,599 | 31.22676932  | 31.196274429 | 0.03049489   | 99.90% | 0.10%   |

* Aims to gradually relieve selling pressure over time from miners recouping electricity costs
* Used in combination with 51% mitigation techniques (ChainLocks, Delayed Penalty System)
* Align with global shift in environmental awareness


Note: values in the table above may be a few satoshis off due to difference in programing language rounding

Delay Penalty System (Horizen)
------------------------------

Provides some mitigation against 51% attacks via a delayed penalty system, where a penalty is introduced to a miner's chain that is 
mined in secret and then later published to the network in the attempts to double spend via a chain re-organization. 
This will be used in combination with ChainLocks in a future release. Switched on via spork SPORK_36_STASH_CHAIN_PENALTY_ENABLED

Read more: https://www.horizen.global/assets/files/A-Penalty-System-for-Delayed-Block-Submission-by-ZenCash.pdf

DIP0002 - Special Transactions (Dash)
------------------------------

Provides a new generic, multi-purpose special transaction with paylaod. The payload is hashed into the transaction signature.
Special transactions allow for implemention of new on-chain features and consensus mechanisms which do not fit into the concept of
financial transactions

Read more: https://github.com/dashpay/dips/blob/master/dip-0002.

Legacy message signing
------------------------------

Currently a magic network string is prefixed to a message when signing. This string is hardcoded in
the firmware of most hardware devices. This enhancement allows using a legacy string already supported by most hardware wallets. Enabled via spork SPORK_30_STASH_LEGACY_SIGS_ENABLED


0.12.7.0 Change log
===================

See detailed [set of changes](https://github.com/stashpayio/stash/compare/v0.12.6.2...dashpay:v0.12.7.0)

- [`fa29d635b`](https://github.com/stashpayio/stash/commit/fa29d635b) Bump version and update checkpoints
- [`055153369`](https://github.com/stashpayio/stash/commit/055153369) Re-order when spork cache is loaded from disk
- [`36235e796`](https://github.com/stashpayio/stash/commit/36235e796) CSporkManager::Clear() should not alter sporkPubKeyID and sporkPrivKey (#2313)
- [`fae305e00`](https://github.com/stashpayio/stash/commit/fae305e00) Save/load spork cache (#2206)
- [`c8cbb4c03`](https://github.com/stashpayio/stash/commit/c8cbb4c03) Protect CSporkManager with critical section (#2213)
- [`f9615df32`](https://github.com/stashpayio/stash/commit/f9615df32) iterator cleanup in several places (#2164)
- [`bc022de7f`](https://github.com/stashpayio/stash/commit/bc022de7f) remove boost dependency from Dash-specific code (#2072)
- [`de03a46b0`](https://github.com/stashpayio/stash/commit/de03a46b0) Fix spork logic
- [`82d82be31`](https://github.com/stashpayio/stash/commit/82d82be31) Allow dynamic tuning of block delay penalty threshold
- [`32223ded8`](https://github.com/stashpayio/stash/commit/32223ded8) Merge pull request #113 from ZencashOfficial/delaypenalty
- [`9af10719e`](https://github.com/stashpayio/stash/commit/9af10719e) Leave a core free when compiling
- [`3e7832c9d`](https://github.com/stashpayio/stash/commit/3e7832c9d) Update chinese wallet translation
- [`9b2474edc`](https://github.com/stashpayio/stash/commit/9b2474edc) Allow for dynamic tuning of deprecation parameters
- [`8ddc12038`](https://github.com/stashpayio/stash/commit/8ddc12038) Implement automatic shutdown of deprecated Zcash versions
- [`8cdc1effe`](https://github.com/stashpayio/stash/commit/8cdc1effe) Allow variable pos start block
- [`d45ac81bf`](https://github.com/stashpayio/stash/commit/d45ac81bf) Add support for POS
- [`8fc834bf5`](https://github.com/stashpayio/stash/commit/8fc834bf5) Add support for legacy magic signing string
- [`cc51402c2`](https://github.com/stashpayio/stash/commit/cc51402c2) DIP2 changes to CTransaction and CMutableTransaction
- [`b154f6c77`](https://github.com/stashpayio/stash/commit/b154f6c77) Bump transaction version to 3
- [`ff7566661`](https://github.com/stashpayio/stash/commit/ff7566661) Bump protocol version 70211

Credits
=======

Thanks to everyone who directly contributed to this release,
as well as everyone who submitted issues and reviewed pull requests.

- Alexander Block <ablock84@gmail.com>
- BeachM <11566409+BeachM@users.noreply.github.com>
- cronicc <cronic@zensystem.io>
- pierstab <pierstabilini@gmail.com>
- Reza Barazesh <barazesh@codeparticle.com>
- gladcow <sergey@dash.org>
- Jack Grigg <jack@z.cash>
- Nathan Marley <nathan.marley@gmail.com>
- UdjinM6 <UdjinM6@users.noreply.github.com>

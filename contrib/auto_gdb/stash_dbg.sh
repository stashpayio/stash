#!/bin/bash
# use testnet settings,  if you need mainnet,  use ~/.stashcore/stashd.pid file instead
stash_pid=$(<~/.stashcore/testnet3/stashd.pid)
sudo gdb -batch -ex "source debug.gdb" stashd ${stash_pid}

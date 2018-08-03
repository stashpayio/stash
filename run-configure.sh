#!/usr/bin/env bash

BUILD="$(./depends/config.guess)"
echo 'BUILD : '$BUILD
PREFIX="$(pwd)/depends/$BUILD/"
echo $PREFIX
./configure --prefix="${PREFIX}" --enable-debug  --disable-tests  --disable-gui-tests --disable-bench

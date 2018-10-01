#!/usr/bin/env bash
./autogen.sh
BUILD="$(./depends/config.guess)"
echo 'BUILD : '$BUILD
PREFIX="$(pwd)/depends/$BUILD/"
echo $PREFIX
./configure  --prefix="${PREFIX}"   --enable-debug --without-libs --disable-tests  --disable-gui-tests --disable-bench


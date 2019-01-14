#!/usr/bin/env bash
./autogen.sh
BUILD="$(./depends/config.guess)"
echo 'BUILD : '$BUILD
PREFIX="$(pwd)/depends/$BUILD/"
echo $PREFIX
./configure  --prefix="${PREFIX}"   --without-libs  --disable-gui-tests --disable-bench 


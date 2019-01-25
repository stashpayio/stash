#!/usr/bin/env bash

cd depends/ && make V=1 "$@"  && cd ../
./autogen.sh

BUILD="$(./depends/config.guess)"
echo 'BUILD : '$BUILD
PREFIX="$(pwd)/depends/$BUILD/"
echo $PREFIX
./configure  --prefix="${PREFIX}"   --without-libs --disable-tests  --disable-gui-tests --disable-bench
make "$@" V=1

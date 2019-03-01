#!/usr/bin/env bash
cores=$( sysctl -n hw.physicalcpu )

cd depends/ && make -j$cores V=1 "$@"  && cd ../
./autogen.sh

BUILD="$(./depends/config.guess)"
echo 'BUILD : '$BUILD
PREFIX="$(pwd)/depends/$BUILD/"
echo $PREFIX
./configure  --prefix="${PREFIX}"   --without-libs --disable-tests  --disable-gui-tests --disable-bench
make -j$cores "$@" V=1

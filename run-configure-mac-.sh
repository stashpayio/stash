#!/usr/bin/env bash
#  brew install automake berkeley-db4 libtool boost --c++11 miniupnpc openssl pkg-config protobuf qt libevent librsvg

cd depends/ && make HOST=$HOST V=1 NO_QT=1 && cd ../
./autogen.sh

BUILD="$(./depends/config.guess)"
echo 'BUILD : '$BUILD
PREFIX="$(pwd)/depends/$BUILD/"
echo $PREFIX
./configure  --prefix="${PREFIX}"   --enable-debug --without-libs --disable-tests  --disable-gui-tests --disable-bench

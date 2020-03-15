#!/usr/bin/env bash
# Tested on MacOS 10.13 High Sierra
# Xcode 9.3, Xcode 9.4
# Follow the instructions in [build-osx.md](doc/build-osx.md)

set -ex
cores=$( sysctl -n hw.physicalcpu )
VERSION=$( cat ./src/clientversion.h | grep -m4 "#define CLIENT_VERSION" | awk '{ print $NF }' | tr '\n' '.' )
VERSION=${VERSION:0:${#VERSION} - 1}
CHECKSUM="SHA256SUMS"
BIN="stashcore-${VERSION}-osx.dmg"

cd depends/ && make -j$cores V=1 "$@"  && cd ../
./autogen.sh

BUILD="$(./depends/config.guess)"
echo 'BUILD : '$BUILD
PREFIX="$(pwd)/depends/$BUILD/"
echo $PREFIXVERSION=$( cat ./src/clientversion.h | grep -m4 "#define CLIENT_VERSION" | awk '{ print $NF }' | tr '\n' '.' )
./configure  --prefix="${PREFIX}"  --without-libs --disable-tests  --disable-gui-tests --disable-bench
make -j$cores "$@" V=1

# Build dmg
make deploy
mkdir -p release
mv Stash-Qt.dmg release/${BIN}
pushd release/
echo $( shasum ${BIN} ) >> ${CHECKSUM}
popd
rm -r Stash-Qt.app
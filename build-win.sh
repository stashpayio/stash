#!/bin/bash

# Note: must be run on windows-v2 branch curently

HOST=x86_64-w64-mingw32
CXX=x86_64-w64-mingw32-g++-posix
CC=x86_64-w64-mingw32-gcc-posix
PREFIX="$(pwd)/depends/$HOST"

cd depends/ && make HOST=$HOST V=1 && cd ../

./autogen.sh

CXXFLAGS="-DPTW32_STATIC_LIB -DCURVE_ALT_BN128 -fopenmp -pthread" CONFIG_SITE=$PWD/depends/x86_64-w64-mingw32/share/config.site  ./configure --prefix=/  --enable-static --disable-shared  --disable-zmq --disable-rust  --disable-tests  --disable-gui-tests --disable-bench
CC="${CC}" CXX="${CXX}" make V=1 "$@"

# To create windows installer
# sudo apt-get install nsis
# 
# Install the nsis plugins below
# https://nsis.sourceforge.io/Inetc_plug-in
# https://nsis.sourceforge.io/MD5_plugin
#
# Unzip plugin dll's to nsis plugin folder
# https://nsis.sourceforge.io/mediawiki/images/d/d7/Md5dll.zip -> /usr/share/nsis/Plugins/md5dll.dll
# https://nsis.sourceforge.io/mediawiki/images/c/c9/Inetc.zip -> /usr/share/nsis/Plugins/INetC.dll
# 
# pushd share && makensis setup.nsi && popd
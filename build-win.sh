#!/usr/bin/env bash
# set -e
# Note: must be run on windows branch currently
# Output will be placed in the ./release folder

# The following dependencies should be installed:
sudo apt-get -y install build-essential libtool autotools-dev automake pkg-config libssl-dev libevent-dev bsdmainutils curl unzip
sudo apt-get -y install g++-mingw-w64-x86-64 mingw-w64-x86-64-dev nsis

# Make sure the ‘posix’ compiler variants are selected for gcc and g++ (select option 1 for POSIX)
# sudo update-alternatives --config x86_64-w64-mingw32-gcc
# sudo update-alternatives --config x86_64-w64-mingw32-g++
# We will try to do this automatically:
sudo update-alternatives --set x86_64-w64-mingw32-gcc /usr/bin/x86_64-w64-mingw32-gcc-posix
sudo update-alternatives --set x86_64-w64-mingw32-g++ /usr/bin/x86_64-w64-mingw32-g++-posix

HOST=x86_64-w64-mingw32
CXX=x86_64-w64-mingw32-g++-posix
CC=x86_64-w64-mingw32-gcc-posix
PREFIX="$(pwd)/depends/$HOST"
VERSION=$( cat ./src/clientversion.h | grep -m4 "#define CLIENT_VERSION" | awk '{ print $NF }' | tr '\n' '.' )
VERSION=${VERSION::-1}
cores=$(nproc)
CHECKSUM="SHA256SUMS"
BIN="stashcore-${VERSION}-win64-setup.exe"

cd depends/ && make -j$cores HOST=$HOST  V=1 && cd ../

./autogen.sh

CXXFLAGS="-DPTW32_STATIC_LIB -DCURVE_ALT_BN128 -fopenmp -pthread" \
CONFIG_SITE=$PWD/depends/x86_64-w64-mingw32/share/config.site ./configure --prefix=/ \
                                                              --enable-static \
                                                              --disable-shared \
                                                              --disable-zmq \
                                                              --disable-rust \
                                                              --disable-tests \
                                                              --disable-gui-tests \
                                                              --disable-bench
CC="${CC}" CXX="${CXX}" make -j$cores V=1 "$@"

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


if [ ! -f "/usr/share/nsis/Plugins/md5dll.dll" ]; then
  curl -o md5dll.zip https://nsis.sourceforge.io/mediawiki/images/d/d7/Md5dll.zip
  sudo unzip -ju "md5dll.zip" "md5dll/ANSI/md5dll.dll" -d "/usr/share/nsis/Plugins"
  rm md5dll.zip
fi

if [ ! -f "/usr/share/nsis/Plugins/Inetc.dll" ]; then
  curl -o Inetc.zip https://nsis.sourceforge.io/mediawiki/images/c/c9/Inetc.zip
  sudo unzip -ju "Inetc.zip" "Plugins/x86-ansi/INetC.dll" -d "/usr/share/nsis/Plugins/"
  rm Inetc.zip
fi

pushd share && makensis setup.nsi && popd
mkdir -p release
mv ${BIN} release/
pushd release
echo $( sha256sum ${BIN} ) >> ${CHECKSUM}
gpg --clearsign ${CHECKSUM} && rm -r ${CHECKSUM} || true
popd
echo "Successfuly created ${PWD}/release/${BIN}"

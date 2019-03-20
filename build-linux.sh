#!/usr/bin/env bash
set -ex
cores=$(nproc)
VERSION=$( cat ./src/clientversion.h | grep -m4 "#define CLIENT_VERSION" | awk '{ print $NF }' | tr '\n' '.' )
VERSION=${VERSION::-1}

HOST="x86_64-linux-gnu"
#HOST="$(./depends/config.guess)"
PREFIX="$(pwd)/depends/$HOST/"

cd depends/ && make -j$cores V=1 HOST=$HOST "$@" && cd ../
./autogen.sh
./configure  --prefix="${PREFIX}" --disable-ccache \
                                  --disable-maintainer-mode \
                                  --disable-dependency-tracking \
                                  --enable-glibc-back-compat \
                                  --enable-reduce-exports \
                                  --disable-bench \
                                  --disable-tests \
                                  --disable-gui-tests
                                 
make -j$cores V=1 "$@"

# Make the release

DIST="release/stashcore-${VERSION}-${HOST}"
CHECKSUM="SHA256SUMS"

# pre-clean up
rm -r ${DIST} || true
mkdir -p ${DIST}/{bin,utils}

# Create tar.gz
cp ./src/stashd ${DIST}/bin
cp ./src/stash-cli ${DIST}/bin
cp ./src/stash-tx ${DIST}/bin
cp ./src/qt/stash-qt ${DIST}/bin
cp ./zcutil/fetch-params.sh ${DIST}/utils
pushd ${DIST}/bin

# create checksums
sha256sum stashd > ${CHECKSUM}
sha256sum stash-cli >> ${CHECKSUM}
sha256sum stash-tx >> ${CHECKSUM}
sha256sum stash-qt >> ${CHECKSUM}
gpg --clearsign ${CHECKSUM} && rm -r ${CHECKSUM} || true
popd

# create tar.gz
pushd release && find stashcore-${VERSION}-${HOST} -not -name "*.dbg" | sort | tar --no-recursion --mode='u+rw,go+r-w,a+X' --owner=0 --group=0 -c -T - | gzip -9n > stashcore-${VERSION}-${HOST}.tar.gz
echo $( sha256sum stashcore-${VERSION}-${HOST}.tar.gz ) >> ${CHECKSUM}
popd
rm -r ${DIST} || true
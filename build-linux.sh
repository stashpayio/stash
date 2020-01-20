#!/usr/bin/env bash
set -ex

# test distro versions
centos="7"
ubuntu="18.04"
debian="10"

# gather system information
distro=$(cat /etc/os-release | grep ^ID= | sed -e "s/^ID=//" | sed -e 's/"//g' | sed -e "s/'//g")
distrov=$(cat /etc/os-release | grep ^VERSION_ID= | sed -e "s/^VERSION_ID=//" | sed -e 's/"//g' | sed -e "s/'//g")

echo "Running on $distro $distrov"

# function to install necessary packages with yum
with_yum(){
        echo "Installing dependencies using yum."
	sudo yum -y install gcc gcc-c++ make libtool automake pkgconfig openssl-devel libevent-devel curl bzip2 patch
}

# function to install necessary packages with apt-get
with_apt(){
        echo "Installing dependencies using apt-get."
	sudo apt-get -y install build-essential libtool autotools-dev automake pkg-config libssl-dev libevent-dev bsdmainutils curl
}

# logic to select package installer
# displays warning if not used on a tested version of the distro
# allows to select yum or apt when distro is not explicitly supported
case $distro in
        centos)
                if [[ "$distrov" != "$centos" ]]; then echo "WARNING : this script has not been tested on version $distrov of $distro.  Continuing to run."; fi
                with_yum
                ;;
        ubuntu)
                if [[ "$distrov" != "$ubuntu" ]]; then echo "WARNING : this script has not been tested on version $distrov of $distro.  Continuing to run."; fi
                with_apt
                ;;
        debian)
                if [[ "$distrov" != "$debian" ]]; then echo "WARNING : this script has not been tested on version $distrov of $distro.  Continuing to run."; fi
                with_apt
                ;;
        *)
                echo "ERROR : $distro is not supported by this script. To try continue anyway, type yum or apt to use as package manager.  Anything else will abort the script."
                read installer

                case $installer in
                        yum)
                                with_yum
                                ;;
                        apt)
                                with_apt
                                ;;
                        *)
                                echo "Exiting script now."
                                exit
                                ;;
                esac
esac

cores=$(($(nproc)-1))

if [ $cores -eq 0 ]; then
   cores=1
fi

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
#pushd release && find stashcore-${VERSION}-${HOST} -not -name "*.dbg" | sort | tar --no-recursion --mode='u+rw,go+r-w,a+X' --owner=0 --group=0 -c -T - | gzip -9n > stashcore-${VERSION}-${HOST}.tar.gz
#echo $( sha256sum stashcore-${VERSION}-${HOST}.tar.gz ) >> ${CHECKSUM}
pushd release && find stashcore-${VERSION}-${HOST} -not -name "*.dbg" | sort | tar --no-recursion --mode='u+rw,go+r-w,a+X' --owner=0 --group=0 -c -T - | gzip -9n > stashcore-${VERSION}-${HOST}-${distro}${distrov}.tar.gz
echo $( sha256sum stashcore-${VERSION}-${HOST}-${distro}${distrov}.tar.gz ) >> ${CHECKSUM}
popd
rm -r ${DIST} || true

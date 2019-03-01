#!/usr/bin/env bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd $DIR/..

DOCKER_IMAGE=${DOCKER_IMAGE:-stashpay/stashd-develop}
DOCKER_TAG=${DOCKER_TAG:-latest}

BUILD_DIR=${BUILD_DIR:-.}

rm docker/bin/*
mkdir docker/bin
cp $BUILD_DIR/src/stashd docker/bin/
cp $BUILD_DIR/src/stash-cli docker/bin/
cp $BUILD_DIR/src/stash-tx docker/bin/
strip docker/bin/stashd
strip docker/bin/stash-cli
strip docker/bin/stash-tx

docker build --pull -t $DOCKER_IMAGE:$DOCKER_TAG -f docker/Dockerfile docker

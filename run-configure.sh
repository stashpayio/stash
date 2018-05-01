#!/usr/bin/env bash

BUILD="$(./depends/config.guess)"
PREFIX="$(pwd)/depends/$BUILD/"
./configure --prefix="${PREFIX}" --enable-debug

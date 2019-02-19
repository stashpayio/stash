#!/usr/bin/env bash
set -eu
$(dirname "$0")/fetch-params.sh && \
clear && \
echo "-------------------------------------------------------------" && \
echo " Stash Core download complete. You may now close this window " && \
echo "-------------------------------------------------------------" && \
$(dirname "$0")/Stash-Qt-Bin&
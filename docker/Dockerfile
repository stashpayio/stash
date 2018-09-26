FROM debian:stretch
LABEL maintainer="Stash Developers <dev@stashpay.io>"
LABEL description="Dockerised StashCore, built from Travis"

RUN apt-get update && apt-get -y upgrade && apt-get clean && rm -fr /var/cache/apt/*

COPY bin/* /usr/bin/

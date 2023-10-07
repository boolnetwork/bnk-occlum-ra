#!/bin/bash
#copyright@antfinancial:adopted from a script written by geding
set -e

rm -rf openssl
git clone -b OpenSSL_1_1_1 --depth 1 http://github.com/openssl/openssl
cd openssl
CC=occlum-gcc ./config \
    --prefix=/usr/local/occlum/x86_64-linux-musl \
    --openssldir=/usr/local/occlum/x86_64-linux-musl/ssl \
    --with-rand-seed=rdcpu \
    no-async no-zlib

make -j$(nproc)
make install

export X86_64_UNKNOWN_LINUX_MUSL_OPENSSL_LIB_DIR=/usr/local/occlum/x86_64-linux-musl/lib
export X86_64_UNKNOWN_LINUX_MUSL_OPENSSL_INCLUDE_DIR=/usr/local/occlum/x86_64-linux-musl/
export X86_64_UNKNOWN_LINUX_MUSL_OPENSSL_DIR=/usr/local/occlum/x86_64-linux-musl/ssl

echo "build and install openssl success!"

#!/bin/bash
set -e

# compile rust_app
pushd rust_app
occlum-cargo rustc -- -L /opt/occlum/toolchains/gcc/x86_64-linux-musl/lib
popd

# initialize occlum workspace
rm -rf occlum_instance && mkdir occlum_instance && cd occlum_instance

occlum init && rm -rf image
cp -r ../rust_app/Occlum.json ../occlum_instance/
copy_bom -f ../rust-demo.yaml --root image --include-dir /opt/occlum/etc/template

occlum build
occlum run /bin/rust_app
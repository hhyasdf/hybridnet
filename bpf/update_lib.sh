#!/bin/bash

BPF_DIR=$(dirname "${BASH_SOURCE[0]}")

CILIUM_VERSION=$(cat "$BPF_DIR"/CILIUM_LIB_VERSION)

LIB_FILES=(
    cilium-"$CILIUM_VERSION"/bpf/include
    cilium-"$CILIUM_VERSION"/bpf/lib
    cilium-"$CILIUM_VERSION"/bpf/Makefile.bpf
    cilium-"$CILIUM_VERSION"/bpf/LICENSE.GPL-2.0
    cilium-"$CILIUM_VERSION"/bpf/LICENSE.BSD-2-Clause
    cilium-"$CILIUM_VERSION"/bpf/COPYING
)

TMP_DIR=$(mktemp -d)

CILIUM_TAR=cilium-v${CILIUM_VERSION}.tar.gz

echo "Downloading $CILIUM_TAR ..."

curl -sL "https://github.com/cilium/cilium/archive/refs/tags/v${CILIUM_VERSION}.tar.gz" -o "${TMP_DIR}/${CILIUM_TAR}"
tar -xvf "${TMP_DIR}/${CILIUM_TAR}" -C "${TMP_DIR}" 2> /dev/null

rm -rf bpf/include
rm -rf bpf/lib

echo "Copying files ..."

for file in "${LIB_FILES[@]}"; do
  cp -r "${TMP_DIR}/$file" "$BPF_DIR/"
done;

rm -rf "$TMP_DIR"
#!/usr/bin/env sh
# Fetch KernelSU v3.3.0 LKM components (aarch64, android12-5.10).
set -e
cd "$(dirname "$0")/.."
mkdir -p ksu
V=v3.3.0
B=https://github.com/tiann/KernelSU/releases/download/$V
curl -L -o ksu/ksud          "$B/ksud-aarch64-linux-android"
curl -L -o ksu/kernelsu.ko   "$B/lkm-aarch64-android12-5.10_kernelsu.ko"
curl -L -o ksu/ksuinit       "$B/ksuinit-aarch64"
curl -L -o ksu/ksu.apk       "$B/KernelSU_v3.3.0_32601-release.apk"
chmod +x ksu/ksud
echo "fetched into ksu/"

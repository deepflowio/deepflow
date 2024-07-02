#!/bin/bash
# This script builds a Debian root filesystem image for testing libbpf in a
# virtual machine. Requires debootstrap >= 1.0.95 and zstd.

# Use e.g. ./mkrootfs_debian.sh --arch=s390x to generate a rootfs for a
# foreign architecture. Requires configured binfmt_misc, e.g. using
# Debian/Ubuntu's qemu-user-binfmt package or
# https://github.com/multiarch/qemu-user-static.

set -e -u -x -o pipefail

# Check whether we are root now in order to avoid confusing errors later.
if [ "$(id -u)" != 0 ]; then
	echo "$0 must run as root" >&2
	exit 1
fi

# Create a working directory and schedule its deletion.
root=$(mktemp -d -p "$PWD")
trap 'rm -r "$root"' EXIT

# Install packages.
packages=(
	binutils
	busybox
	elfutils
	ethtool
	iproute2
	iptables
	libcap2
	libelf1
	strace
	zlib1g
)
packages=$(IFS=, && echo "${packages[*]}")
debootstrap --include="$packages" --variant=minbase "$@" bookworm "$root"

# Remove the init scripts (tests use their own). Also remove various
# unnecessary files in order to save space.
rm -rf \
	"$root"/etc/rcS.d \
	"$root"/usr/share/{doc,info,locale,man,zoneinfo} \
	"$root"/var/cache/apt/archives/* \
	"$root"/var/lib/apt/lists/*

# Apply common tweaks.
"$(dirname "$0")"/mkrootfs_tweak.sh "$root"

# Save the result.
name="libbpf-vmtest-rootfs-$(date +%Y.%m.%d).tar.zst"
rm -f "$name"
tar -C "$root" -c . | zstd -T0 -19 -o "$name"

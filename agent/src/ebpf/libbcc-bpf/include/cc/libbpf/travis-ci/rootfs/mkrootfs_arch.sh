#!/bin/bash

# This script is based on drgn script for generating Arch Linux bootstrap
# images.
# https://github.com/osandov/drgn/blob/master/scripts/vmtest/mkrootfs.sh

set -euo pipefail

usage () {
	USAGE_STRING="usage: $0 [NAME]
       $0 -h

Build an Arch Linux root filesystem image for testing libbpf in a virtual
machine.

The image is generated as a zstd-compressed tarball.

This must be run as root, as most of the installation is done in a chroot.

Arguments:
  NAME   name of generated image file (default:
         libbpf-vmtest-rootfs-\$DATE.tar.zst)

Options:
  -h     display this help message and exit"

	case "$1" in
		out)
			echo "$USAGE_STRING"
			exit 0
			;;
		err)
			echo "$USAGE_STRING" >&2
			exit 1
			;;
	esac
}

while getopts "h" OPT; do
	case "$OPT" in
		h)
			usage out
			;;
		*)
			usage err
			;;
	esac
done
if [[ $OPTIND -eq $# ]]; then
	NAME="${!OPTIND}"
elif [[ $OPTIND -gt $# ]]; then
	NAME="libbpf-vmtest-rootfs-$(date +%Y.%m.%d).tar.zst"
else
	usage err
fi

pacman_conf=
root=
trap 'rm -rf "$pacman_conf" "$root"' EXIT
pacman_conf="$(mktemp -p "$PWD")"
cat > "$pacman_conf" << "EOF"
[options]
Architecture = x86_64
CheckSpace
SigLevel = Required DatabaseOptional
[core]
Include = /etc/pacman.d/mirrorlist
[extra]
Include = /etc/pacman.d/mirrorlist
[community]
Include = /etc/pacman.d/mirrorlist
EOF
root="$(mktemp -d -p "$PWD")"

packages=(
	busybox
	# libbpf dependencies.
	libelf
	zlib
	# selftests test_progs dependencies.
	binutils
	elfutils
	ethtool
	glibc
	iproute2
	# selftests test_verifier dependencies.
	libcap
)

pacstrap -C "$pacman_conf" -cGM "$root" "${packages[@]}"

# Remove unnecessary files from the chroot.

# We don't need the pacman databases anymore.
rm -rf "$root/var/lib/pacman/sync/"
# We don't need D, Fortran, or Go.
 rm -f "$root/usr/lib/libgdruntime."* \
	"$root/usr/lib/libgphobos."* \
	"$root/usr/lib/libgfortran."* \
	"$root/usr/lib/libgo."*
# We don't need any documentation.
rm -rf "$root/usr/share/{doc,help,man,texinfo}"

"$(dirname "$0")"/mkrootfs_tweak.sh "$root"

tar -C "$root" -c . | zstd -T0 -19 -o "$NAME"
chmod 644 "$NAME"

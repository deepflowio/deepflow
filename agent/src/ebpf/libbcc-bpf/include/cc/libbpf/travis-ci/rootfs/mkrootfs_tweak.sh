#!/bin/bash
# This script prepares a mounted root filesystem for testing libbpf in a virtual
# machine.
set -e -u -x -o pipefail
root=$1
shift

chroot "${root}" /bin/busybox --install

cat > "$root/etc/inittab" << "EOF"
::sysinit:/etc/init.d/rcS
::ctrlaltdel:/sbin/reboot
::shutdown:/sbin/swapoff -a
::shutdown:/bin/umount -a -r
::restart:/sbin/init
EOF
chmod 644 "$root/etc/inittab"

mkdir -m 755 -p "$root/etc/init.d" "$root/etc/rcS.d"
cat > "$root/etc/rcS.d/S10-mount" << "EOF"
#!/bin/sh

set -eux

/bin/mount proc /proc -t proc

# Mount devtmpfs if not mounted
if [[ -z $(/bin/mount -t devtmpfs) ]]; then
	/bin/mount devtmpfs /dev -t devtmpfs
fi

/bin/mount sysfs /sys -t sysfs
/bin/mount bpffs /sys/fs/bpf -t bpf
/bin/mount debugfs /sys/kernel/debug -t debugfs

echo 'Listing currently mounted file systems'
/bin/mount
EOF
chmod 755 "$root/etc/rcS.d/S10-mount"

cat > "$root/etc/rcS.d/S40-network" << "EOF"
#!/bin/sh

set -eux

ip link set lo up
EOF
chmod 755 "$root/etc/rcS.d/S40-network"

cat > "$root/etc/init.d/rcS" << "EOF"
#!/bin/sh

set -eux

for path in /etc/rcS.d/S*; do
	[ -x "$path" ] && "$path"
done
EOF
chmod 755 "$root/etc/init.d/rcS"

chmod 755 "$root"

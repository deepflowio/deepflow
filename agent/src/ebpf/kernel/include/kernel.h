/*
 * This code runs using bpf in the Linux kernel.
 * Copyright 2022- The Yunshan Networks Authors.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * SPDX-License-Identifier: GPL-2.0
 */

#ifndef DF_LINUX_KERN_H
#define DF_LINUX_KERN_H

// In the absence of BTF files, it is necessary to loop through the array to
// obtain offsets. The instructions of this part of the logic are close to the
// upper limit of the number of instructions and cannot be retrieved from the
// map, so these constants are reserved. Retaining these constants will not
// affect the system with BTF files have negative impacts.
#ifdef LINUX_VER_3_10_0
#define STRUCT_FILES_STRUCT_FDT_OFFSET          0x8
#else
#define STRUCT_FILES_STRUCT_FDT_OFFSET          0x20
#endif

#ifdef LINUX_VER_KYLIN
#define STRUCT_FILES_PRIVATE_DATA_OFFSET	0xc0
#elif defined LINUX_VER_3_10_0
#define STRUCT_FILES_PRIVATE_DATA_OFFSET        0xa8
#else
#define STRUCT_FILES_PRIVATE_DATA_OFFSET	0xc8
#endif

#define S_IFMT 00170000
#define S_IFSOCK 0140000
#define S_IFLNK 0120000
#define S_IFREG 0100000
#define S_IFBLK 0060000
#define S_IFDIR 0040000
#define S_IFCHR 0020000
#define S_IFIFO 0010000
#define S_ISUID 0004000
#define S_ISGID 0002000
#define S_ISVTX 0001000

#define S_ISLNK(m) (((m)&S_IFMT) == S_IFLNK)
#define S_ISREG(m) (((m)&S_IFMT) == S_IFREG)
#define S_ISDIR(m) (((m)&S_IFMT) == S_IFDIR)
#define S_ISCHR(m) (((m)&S_IFMT) == S_IFCHR)
#define S_ISBLK(m) (((m)&S_IFMT) == S_IFBLK)
#define S_ISFIFO(m) (((m)&S_IFMT) == S_IFIFO)
#define S_ISSOCK(m) (((m)&S_IFMT) == S_IFSOCK)

typedef __u32 __bitwise __portpair;
typedef __u64 __bitwise __addrpair;

struct hlist_node {
    struct hlist_node *next;
    struct hlist_node **pprev;
};

typedef struct {
    void *net;
} possible_net_t;

struct sock_common {
        union {
                __addrpair      skc_addrpair;
                struct {
                        __be32  skc_daddr;
                        __be32  skc_rcv_saddr;
                };
        };
        union  {
                unsigned int    skc_hash;
                __u16           skc_u16hashes[2];
        };
        /* skc_dport && skc_num must be grouped as well */
        union {
                __portpair      skc_portpair;
                struct {
                        __be16  skc_dport;
                        __u16   skc_num;
                };
        };

        unsigned short          skc_family;
	volatile unsigned char skc_state;
	unsigned char skc_reuse : 4;
	unsigned char skc_reuseport : 1;
	unsigned char skc_ipv6only : 1;
	unsigned char skc_net_refcnt : 1;
	int skc_bound_dev_if;
	union {
		struct hlist_node skc_bind_node;
		struct hlist_node skc_portaddr_node;
	};
	void *skc_prot;
	possible_net_t skc_net;
	struct in6_addr skc_v6_daddr;
	struct in6_addr skc_v6_rcv_saddr;
};

struct sock {
        /*
         * Now struct inet_timewait_sock also uses sock_common, so please just
         * don't add nothing before this first member (__sk_common) --acme
         */
        struct sock_common      __sk_common;
#define sk_num                  __sk_common.skc_num
#define sk_dport                __sk_common.skc_dport
#define sk_addrpair             __sk_common.skc_addrpair
#define sk_daddr                __sk_common.skc_daddr
#define sk_rcv_saddr            __sk_common.skc_rcv_saddr
#define sk_family               __sk_common.skc_family
#define sk_v6_daddr		__sk_common.skc_v6_daddr
};

typedef enum {
	SS_FREE = 0,			/* not allocated		*/
	SS_UNCONNECTED,			/* unconnected to any socket	*/
	SS_CONNECTING,			/* in process of connecting	*/
	SS_CONNECTED,			/* connected to socket		*/
	SS_DISCONNECTING		/* in process of disconnecting	*/
} socket_state;

/**
 *  struct socket - general BSD socket
 *  @state: socket state (%SS_CONNECTED, etc)
 *  @type: socket type (%SOCK_STREAM, etc)
 *  @flags: socket flags (%SOCK_NOSPACE, etc)
 *  @ops: protocol specific socket operations
 *  @file: File back pointer for gc
 *  @sk: internal networking protocol agnostic socket representation
 *  @wq: wait queue for several uses
 */
struct socket {
	socket_state		state;
	short			type;
	unsigned long		flags;
	void			*wq; // kernel >= 5.3.0 remove
	void			*file; //struct file
	struct sock		*sk;
	const void		*ops;//struct proto_ops
};

struct fdtable {
	unsigned int max_fds;
	void **fd;      /* current fd array, struct file *  */
};
#endif /* DF_LINUX_KERN_H */

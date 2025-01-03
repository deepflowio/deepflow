/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __LINUX_GRE_H
#define __LINUX_GRE_H

#define TUNNEL_CSUM        htons(0x01)
#define TUNNEL_ROUTING        htons(0x02)
#define TUNNEL_KEY        htons(0x04)
#define TUNNEL_SEQ        htons(0x08)
#define TUNNEL_STRICT        htons(0x10)
#define TUNNEL_REC        htons(0x20)
#define TUNNEL_VERSION        htons(0x40)
#define TUNNEL_NO_KEY        htons(0x80)
#define TUNNEL_DONT_FRAGMENT    htons(0x0100)
#define TUNNEL_OAM        htons(0x0200)
#define TUNNEL_CRIT_OPT        htons(0x0400)
#define TUNNEL_GENEVE_OPT    htons(0x0800)
#define TUNNEL_VXLAN_OPT    htons(0x1000)
#define TUNNEL_NOCACHE        htons(0x2000)
#define TUNNEL_ERSPAN_OPT    htons(0x4000)

#define GRE_CSUM    htons(0x8000)
#define GRE_ROUTING    htons(0x4000)
#define GRE_KEY        htons(0x2000)
#define GRE_SEQ        htons(0x1000)
#define GRE_STRICT    htons(0x0800)
#define GRE_REC        htons(0x0700)
#define GRE_ACK        htons(0x0080)
#define GRE_FLAGS    htons(0x0078)
#define GRE_VERSION    htons(0x0007)

#define GRE_IS_CSUM(f)        ((f) & GRE_CSUM)
#define GRE_IS_ROUTING(f)    ((f) & GRE_ROUTING)
#define GRE_IS_KEY(f)        ((f) & GRE_KEY)
#define GRE_IS_SEQ(f)        ((f) & GRE_SEQ)
#define GRE_IS_STRICT(f)    ((f) & GRE_STRICT)
#define GRE_IS_REC(f)        ((f) & GRE_REC)
#define GRE_IS_ACK(f)        ((f) & GRE_ACK)

#define GRE_VERSION_0        htons(0x0000)
#define GRE_VERSION_1        htons(0x0001)
#define GRE_PROTO_PPP        htons(0x880b)
#define GRE_PPTP_KEY_MASK    htonl(0xffff)

#define __packed        __attribute__((packed))

struct gre_base_hdr {
    __be16 flags;
    __be16 protocol;
} __packed;

struct gre_full_hdr {
    struct gre_base_hdr fixed_header;
    __be16 csum;
    __be16 reserved1;
    __be32 key;
    __be32 seq;
} __packed;
#define GRE_HEADER_SECTION 4

#define GREPROTO_CISCO        0
#define GREPROTO_PPTP        1
#define GREPROTO_MAX        2
#define GRE_IP_PROTO_MAX    2

static inline int gre_calc_hlen(__be16 o_flags)
{
    int addend = 4;

    if (o_flags & TUNNEL_CSUM)
        addend += 4;
    if (o_flags & TUNNEL_KEY)
        addend += 4;
    if (o_flags & TUNNEL_SEQ)
        addend += 4;
    return addend;
}

static inline __be16 gre_flags_to_tnl_flags(__be16 flags)
{
    __be16 tflags = 0;

    if (flags & GRE_CSUM)
        tflags |= TUNNEL_CSUM;
    if (flags & GRE_ROUTING)
        tflags |= TUNNEL_ROUTING;
    if (flags & GRE_KEY)
        tflags |= TUNNEL_KEY;
    if (flags & GRE_SEQ)
        tflags |= TUNNEL_SEQ;
    if (flags & GRE_STRICT)
        tflags |= TUNNEL_STRICT;
    if (flags & GRE_REC)
        tflags |= TUNNEL_REC;
    if (flags & GRE_VERSION)
        tflags |= TUNNEL_VERSION;

    return tflags;
}

static inline __be16 gre_tnl_flags_to_gre_flags(__be16 tflags)
{
    __be16 flags = 0;

    if (tflags & TUNNEL_CSUM)
        flags |= GRE_CSUM;
    if (tflags & TUNNEL_ROUTING)
        flags |= GRE_ROUTING;
    if (tflags & TUNNEL_KEY)
        flags |= GRE_KEY;
    if (tflags & TUNNEL_SEQ)
        flags |= GRE_SEQ;
    if (tflags & TUNNEL_STRICT)
        flags |= GRE_STRICT;
    if (tflags & TUNNEL_REC)
        flags |= GRE_REC;
    if (tflags & TUNNEL_VERSION)
        flags |= GRE_VERSION;

    return flags;
}
#endif

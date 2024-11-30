#ifndef _BILD_ERSPAN_H
#define _BILD_ERSPAN_H

#define ERSPAN_V1_MDSIZE    4
#define ERSPAN_V2_MDSIZE    8
#define ETH_P_ERSPAN      0x88BE        /* ERSPAN type II        */
#define ETH_P_ERSPAN2     0x22EB        /* ERSPAN version 2 (type III)    */

struct erspan_base_hdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
    __u8    vlan_upper:4,
        ver:4;
    __u8    vlan:8;
    __u8    session_id_upper:2,
        t:1,
        en:2,
        cos:3;
    __u8    session_id:8;
#elif defined(__BIG_ENDIAN_BITFIELD)
    __u8    ver: 4,
        vlan_upper:4;
    __u8    vlan:8;
    __u8    cos:3,
        en:2,
        t:1,
        session_id_upper:2;
    __u8    session_id:8;
#else
#error "Please fix <asm/byteorder.h>"
#endif
};

static inline int erspan_hdr_len(int version)
{
    return sizeof(struct erspan_base_hdr) +
           (version == 1 ? ERSPAN_V1_MDSIZE : ERSPAN_V2_MDSIZE);
}

#endif /* _BILD_ERSPAN_H */


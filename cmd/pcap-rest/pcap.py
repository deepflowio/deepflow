import ipaddress
import logging

LOG = logging.getLogger(__name__)

GLOBAL_HEADER_LEN = 24
MAGIC_NUMBER_OFFSET = 0
DATA_LINK_TYPE_OFFSET = 20

RECORD_HEADER_LEN = 16
INCL_LEN_OFFSET = 8

ETHERNET_HEADER_LEN = 14
ETHER_TYPE_OFFSET = 12
ETHER_TYPE_IPV4 = 0x0800
ETHER_TYPE_IPV6 = 0x86DD
ETHER_TYPE_ARP = 0x0806
ETHER_TYPE_VLAN = 0x8100
VLAN_LEN = 4

IHL_OFFSET = 0
IPV4_PROTOCOL_OFFSET = 9
IPV4_SRC_IP_OFFSET = 12
IPV4_DST_IP_OFFSET = 16

IPV6_NEXT_HEADER_OFFSET = 6
IPV6_SRC_IP_OFFSET = 8
IPV6_DST_IP_OFFSET = 24

IPV6_HEADER_LEN = 40
IPV6_NEXT_HEADER_ICMP6 = 58
IPV6_NEXT_HEADER_NONXT = 59
IPV6_NEXT_HEADER_HOPBYHOP = 0
IPV6_NEXT_HEADER_DESTINATION = 60
IPV6_NEXT_HEADER_ROUTING = 43
IPV6_NEXT_HEADER_FRAGMENT = 44

PROTOCOL_TCP = 6
PROTOCOL_UDP = 17
SRC_PORT_OFFSET = 0
DST_PORT_OFFSET = 2

MAX_VLAN_LAYERS = 2

import struct


def _ip_to_bytes(addr):
    try:
        return ipaddress.ip_address(addr).packed
    except ValueError:
        return None


def __packet_matches_condition(packet, ips_int, protocol, ports):
    # ethernet
    off = ETHER_TYPE_OFFSET
    eth_type = struct.unpack('!H', packet[off:off + 2])[0]
    l3_offset = ETHERNET_HEADER_LEN
    vlan_layers = 0
    while eth_type == ETHER_TYPE_VLAN and vlan_layers < MAX_VLAN_LAYERS:
        off += VLAN_LEN
        eth_type = struct.unpack('!H', packet[off:off + 2])[0]
        l3_offset += VLAN_LEN
        vlan_layers += 1
    if eth_type == ETHER_TYPE_IPV4:
        ip_version = 4
    elif eth_type == ETHER_TYPE_IPV6:
        ip_version = 6
    else:
        return False

    if ip_version == 4:
        src_ip_offset = IPV4_SRC_IP_OFFSET
        dst_ip_offset = IPV4_DST_IP_OFFSET
        ip_length = 4
    else:
        src_ip_offset = IPV6_SRC_IP_OFFSET
        dst_ip_offset = IPV6_DST_IP_OFFSET
        ip_length = 16
    if ips_int:
        off = l3_offset + src_ip_offset
        ip_src = packet[off:off + ip_length]
        off = l3_offset + dst_ip_offset
        ip_dst = packet[off:off + ip_length]
        if len(ips_int) == 1:
            if ips_int[0] != ip_src and ips_int[0] != ip_dst:
                return False
        else:
            if ip_src not in ips_int or ip_dst not in ips_int:
                return False

    # ipv4
    if protocol is not None:
        if ip_version == 4:
            r_protocol = packet[l3_offset + IPV4_PROTOCOL_OFFSET]
        else:
            r_protocol = packet[l3_offset + IPV6_NEXT_HEADER_OFFSET]
            offset = l3_offset + IPV6_HEADER_LEN
            while True:
                if r_protocol in [
                    PROTOCOL_TCP, PROTOCOL_UDP, IPV6_NEXT_HEADER_ICMP6,
                    IPV6_NEXT_HEADER_NONXT
                ]:
                    break
                elif r_protocol in [
                    IPV6_NEXT_HEADER_HOPBYHOP, IPV6_NEXT_HEADER_DESTINATION,
                    IPV6_NEXT_HEADER_ROUTING
                ]:
                    r_protocol = packet[offset]
                    offset += 1
                    offset += packet[offset]
                elif r_protocol == IPV6_NEXT_HEADER_FRAGMENT:
                    r_protocol = packet[offset]
                    offset += 8
                else:
                    LOG.warning(
                        'unknown ipv6 extension header id %d' % r_protocol
                    )
                    break
        if r_protocol != protocol:
            return False

    if ports:
        if protocol not in [PROTOCOL_TCP, PROTOCOL_UDP]:
            return False

        if ip_version == 4:
            l4_offset = l3_offset + ((packet[l3_offset + IHL_OFFSET] & 0xF) <<
                                     2)
        else:
            l4_offset = offset

        # tcp/udp
        off = l4_offset + SRC_PORT_OFFSET
        port_src = struct.unpack('>H', packet[off:off + 2])[0]
        off = l4_offset + DST_PORT_OFFSET
        port_dst = struct.unpack('>H', packet[off:off + 2])[0]
        if port_src not in ports and port_dst not in ports:
            return False

    return True


def found_in_pcap(filename, ips=None, protocol=None, ports=None):
    ips_int = []
    if ips is not None:
        for ip in ips:
            ip_int = _ip_to_bytes(ip)
            if ip_int is not None:
                ips_int.append(ip_int)

    if protocol is not None and ports and protocol not in [
        PROTOCOL_TCP, PROTOCOL_UDP
    ]:
        return False

    try:
        with open(filename, 'rb') as fp:

            g_header = fp.read(GLOBAL_HEADER_LEN)
            if len(g_header) < GLOBAL_HEADER_LEN:
                return False
            magic = struct.unpack(
                '<I', g_header[MAGIC_NUMBER_OFFSET:MAGIC_NUMBER_OFFSET + 4]
            )[0]
            if magic == 0xa1b2c3d4:
                endian = '<'
            else:
                endian = '>'
            network = struct.unpack(
                endian + 'I',
                g_header[DATA_LINK_TYPE_OFFSET:DATA_LINK_TYPE_OFFSET + 4]
            )[0]
            if network != 1:
                # not ethernet
                return False

            while True:
                r_header = fp.read(RECORD_HEADER_LEN)
                if len(r_header) < RECORD_HEADER_LEN:
                    return False
                incl_len = struct.unpack(
                    endian + 'I', r_header[INCL_LEN_OFFSET:INCL_LEN_OFFSET + 4]
                )[0]
                packet = fp.read(incl_len)
                if len(packet) != incl_len:
                    return False
                if __packet_matches_condition(
                    packet, ips_int, protocol, ports
                ):
                    return True

    except IOError as e:
        LOG.warn('read file %s error: %s' % (filename, e))
        return False


def filter_pcap(filename, ips=None, protocol=None, ports=None):
    ips_int = []
    if ips is not None:
        for ip in ips:
            ip_int = _ip_to_bytes(ip)
            if ip_int is not None:
                ips_int.append(ip_int)

    if protocol is not None and ports and protocol not in [
        PROTOCOL_TCP, PROTOCOL_UDP
    ]:
        return

    try:
        with open(filename, 'rb') as fp:

            g_header = fp.read(GLOBAL_HEADER_LEN)
            if len(g_header) < GLOBAL_HEADER_LEN:
                return
            magic = struct.unpack(
                '<I', g_header[MAGIC_NUMBER_OFFSET:MAGIC_NUMBER_OFFSET + 4]
            )[0]
            if magic == 0xa1b2c3d4:
                endian = '<'
            else:
                endian = '>'
            network = struct.unpack(
                endian + 'I',
                g_header[DATA_LINK_TYPE_OFFSET:DATA_LINK_TYPE_OFFSET + 4]
            )[0]
            if network != 1:
                # not ethernet
                return
            yield g_header

            while True:
                r_header = fp.read(RECORD_HEADER_LEN)
                if len(r_header) < RECORD_HEADER_LEN:
                    return
                incl_len = struct.unpack(
                    endian + 'I', r_header[INCL_LEN_OFFSET:INCL_LEN_OFFSET + 4]
                )[0]
                packet = fp.read(incl_len)
                if len(packet) != incl_len:
                    return
                if __packet_matches_condition(
                    packet, ips_int, protocol, ports
                ):
                    yield r_header + packet

    except IOError as e:
        LOG.warn('read file %s error: %s' % (filename, e))
        return

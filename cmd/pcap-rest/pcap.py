import logging
import struct

LOG = logging.getLogger(__name__)


GLOBAL_HEADER_LEN = 24
MAGIC_NUMBER_OFFSET = 0
DATA_LINK_TYPE_OFFSET = 20

RECORD_HEADER_LEN = 16
INCL_LEN_OFFSET = 8

ETHERNET_HEADER_LEN = 14
ETHER_TYPE_OFFSET = 12
ETHER_TYPE_IPV4 = 0x0800
ETHER_TYPE_ARP = 0x0806
ETHER_TYPE_VLAN = 0x8100
VLAN_LEN = 4

IHL_OFFSET = 0
PROTOCOL_OFFSET = 9
PROTOCOL_TCP = 6
PROTOCOL_UDP = 17

SRC_PORT_OFFSET = 0
DST_PORT_OFFSET = 2


def __packet_matches_condition(packet, protocol, port=None):
    # ethernet
    off = ETHER_TYPE_OFFSET
    eth_type = struct.unpack('>H', packet[off:off+2])[0]
    l3_offset = ETHERNET_HEADER_LEN
    if eth_type == ETHER_TYPE_VLAN:
        off = ETHER_TYPE_OFFSET + VLAN_LEN
        eth_type = struct.unpack('>H', packet[off:off+2])[0]
        l3_offset += VLAN_LEN
    if eth_type != ETHER_TYPE_IPV4:
        return False

    # ipv4
    r_protocol = ord(packet[l3_offset+PROTOCOL_OFFSET])
    if r_protocol != protocol:
        return False
    if port is None:
        return True
    l4_offset = l3_offset + ((ord(packet[l3_offset+IHL_OFFSET]) & 0xF) << 2)

    # tcp/udp
    off = l4_offset + SRC_PORT_OFFSET
    port_src = struct.unpack('>H', packet[off:off+2])[0]
    if port_src == port:
        return True
    off = l4_offset + DST_PORT_OFFSET
    port_dst = struct.unpack('>H', packet[off:off+2])[0]
    if port_dst == port:
        return True

    return False


def found_in_pcap(filename, protocol, port=None):
    if protocol not in [PROTOCOL_TCP, PROTOCOL_UDP]:
        return False

    try:
        with open(filename, 'rb') as fp:

            g_header = fp.read(GLOBAL_HEADER_LEN)
            if len(g_header) < GLOBAL_HEADER_LEN:
                return False
            magic = struct.unpack('<I', g_header[MAGIC_NUMBER_OFFSET:MAGIC_NUMBER_OFFSET+4])[0]
            if magic == 0xa1b2c3d4:
                endian = '<'
            else:
                endian = '>'
            network = struct.unpack(endian + 'I', g_header[DATA_LINK_TYPE_OFFSET:DATA_LINK_TYPE_OFFSET+4])[0]
            if network != 1:
                # not ethernet
                return False

            while True:
                r_header = fp.read(RECORD_HEADER_LEN)
                if len(r_header) < RECORD_HEADER_LEN:
                    return False
                incl_len = struct.unpack(endian + 'I', r_header[INCL_LEN_OFFSET:INCL_LEN_OFFSET+4])[0]
                packet = fp.read(incl_len)
                if len(packet) != incl_len:
                    return False
                if __packet_matches_condition(packet, protocol, port):
                    return True


    except IOError as e:
        LOG.warn('read file %s error: %s' % (filename, e))
        return False


def filter_pcap(filename, protocol, port=None):
    if protocol not in [PROTOCOL_TCP, PROTOCOL_UDP]:
        return

    try:
        with open(filename, 'rb') as fp:

            g_header = fp.read(GLOBAL_HEADER_LEN)
            if len(g_header) < GLOBAL_HEADER_LEN:
                return
            magic = struct.unpack('<I', g_header[MAGIC_NUMBER_OFFSET:MAGIC_NUMBER_OFFSET+4])[0]
            if magic == 0xa1b2c3d4:
                endian = '<'
            else:
                endian = '>'
            network = struct.unpack(endian + 'I', g_header[DATA_LINK_TYPE_OFFSET:DATA_LINK_TYPE_OFFSET+4])[0]
            if network != 1:
                # not ethernet
                return
            yield g_header

            while True:
                r_header = fp.read(RECORD_HEADER_LEN)
                if len(r_header) < RECORD_HEADER_LEN:
                    return
                incl_len = struct.unpack(endian + 'I', r_header[INCL_LEN_OFFSET:INCL_LEN_OFFSET+4])[0]
                packet = fp.read(incl_len)
                if len(packet) != incl_len:
                    return
                if __packet_matches_condition(packet, protocol, port):
                    yield r_header + packet


    except IOError as e:
        LOG.warn('read file %s error: %s' % (filename, e))
        return

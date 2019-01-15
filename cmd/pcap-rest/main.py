import datetime
import os
import socket
import time

from bottle import run, get, delete, static_file

PCAP_DIR = '/var/lib/droplet/pcap'
HOSTNAME = ''
DROPLET_CONF = '/etc/droplet.yaml'
LISTEN_PORT = 20205
FILE_SUFFIX = '.pcap'
API_VERSION = 'v1'
API_PREFIX = '/' + API_VERSION

MAC_REGEX = r'(?:[0-9a-zA-Z]{2}[-:]){5}[0-9a-zA-Z]{2}'
IP_REGEX = r'(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)'


def read_config():
    global PCAP_DIR
    with open(DROPLET_CONF) as f:
        for line in f:
            if line.find('file-directory') >= 0:
                vs = line.split(':')
                PCAP_DIR = vs[1].strip()
                return
    global HOSTNAME
    HOSTNAME = socket.gethostname()


@get(API_PREFIX + '/pcaps/<acl_gid:int>/<mac:re:%s>/' % MAC_REGEX)
def get_files_by_mac(acl_gid, mac):
    return {
        'DATA': get_files(acl_gid, mac=mac),
        'OPT_STATUS': 'SUCCESS',
    }


@get(API_PREFIX + '/pcaps/<acl_gid:int>/<ip:re:%s>/' % IP_REGEX)
def get_files_by_ip(acl_gid, ip):
    return {
        'DATA': get_files(acl_gid, ip=ip),
        'OPT_STATUS': 'SUCCESS',
    }


@get(API_PREFIX + '/pcaps/<acl_gid:int>/<pcap_name>/')
def get_file(acl_gid, pcap_name):
    directory = PCAP_DIR + '/' + str(acl_gid) + '/'
    return static_file(pcap_name, root=directory, download=pcap_name)


@delete(API_PREFIX + '/pcaps/<acl_gid:int>/')
@delete(API_PREFIX + '/pcaps/<acl_gid:int>/<pcap_name>/')
def delete_files(acl_gid, pcap_name=None):
    directory = PCAP_DIR + '/' + str(acl_gid) + '/'
    if pcap_name is not None:
        os.unlink(directory + pcap_name)
    else:
        for file in os.listdir(directory):
            os.unlink(directory + file)
    return {
        'OPT_STATUS': 'SUCCESS',
    }


# convert ip like 192.168.1.1 to 192168001001
def _ip_convert(ip):
    return ''.join(['0' * (3 - len(s)) + s for s in ip.split('.')])


def _ip_convert_back(ip):
    return '%d.%d.%d.%d' % (int(ip[0:3]), int(ip[3:6]), int(ip[6:9]), int(ip[9:12]))


# convert mac like 01:02:03:04:05:06 to 010203040506
def _mac_convert(mac):
    return mac.replace(':', '').replace('-', '')


def _mac_convert_back(mac):
    return '%s:%s:%s:%s:%s:%s' % (mac[0:2], mac[2:4], mac[4:6], mac[6:8], mac[8:10], mac[10:12])


def _tap_type_to_id(tapType):
    if tapType == 'isp':
        return 1
    if tapType == 'tor':
        return 3
    return 0


def _time_to_epoch(time_str):
    try:
        return int(time.mktime(datetime.datetime.strptime(time_str, "%y%m%d%H%M%S").timetuple()))
    except ValueError:
        return 0


def get_files(acl_gid, mac=None, ip=None):
    directory = PCAP_DIR + '/' + str(acl_gid) + '/'
    files = []
    mac_rep = None
    ip_rep = None
    if mac is not None:
        mac_str = _mac_convert(mac)
        mac_rep = mac
    if ip is not None:
        ip_str = _ip_convert(ip)
        ip_rep = ip
    for file in os.listdir(directory):
        if not file.endswith(FILE_SUFFIX):
            continue
        segs = file[:file.find('.')].split('_')
        if len(segs) != 5:
            continue
        if mac is not None and mac_str != segs[1]:
            continue
        if ip is not None and ip_str != segs[2]:
            continue
        if mac_rep is None or ip_rep is None:
            if mac_rep is None:
                mac_rep = _mac_convert_back(segs[1])
            else:
                ip_rep = _ip_convert_back(segs[2])
        files.append({
            'mac': mac_rep,
            'ip': ip_rep,
            'tap_type': _tap_type_to_id(segs[0]),
            'filename': file,
            'start_epoch': _time_to_epoch(segs[3]),
            'start_datetime': segs[3],
            'end_epoch': _time_to_epoch(segs[4]),
            'end_datetime': segs[4],
            'size': os.path.getsize(directory + file),
            'hostname': HOSTNAME,
        })
    return files


if __name__ == '__main__':
    read_config()
    run(host='0.0.0.0', port=LISTEN_PORT, debug=False, server='paste')

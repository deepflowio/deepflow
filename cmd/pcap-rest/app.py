# -*- coding: utf-8 -*-
import datetime
import mimetypes
import os
import socket
import time

from bottle import get, request, static_file, delete, Bottle, HTTPResponse

from pcap import PROTOCOL_TCP, PROTOCOL_UDP, filter_pcap

from pcap import found_in_pcap


PCAP_DIR = '/var/lib/droplet/pcap'
HOSTNAME = ''
DROPLET_CONF = '/etc/droplet.yaml'
FILE_SUFFIX = '.pcap'
API_VERSION = 'v1'
API_PREFIX = '/' + API_VERSION

MAC_REGEX = r'(?:[0-9a-zA-Z]{2}[-:]){5}[0-9a-zA-Z]{2}'
IP_REGEX = r'(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)'


app = Bottle()


def read_config():
    global PCAP_DIR
    with open(DROPLET_CONF) as f:
        for line in f:
            if line.find('file-directory') >= 0:
                vs = line.split(':')
                PCAP_DIR = vs[1].strip()
                break
    global HOSTNAME
    HOSTNAME = socket.gethostname()


@app.get(API_PREFIX + '/pcaps/<acl_gid:int>/<mac:re:%s>/' % MAC_REGEX)
def get_files_by_mac(acl_gid, mac):
    start_ts = int(time.time()) - 600
    end_ts = int(time.time())
    if request.query.start_ts != '':
        start_ts = int(request.query.start_ts)
    if request.query.end_ts != '':
        end_ts = int(request.query.end_ts)
    return {
        'DATA': get_files(acl_gid, start_ts, end_ts, mac=mac),
        'OPT_STATUS': 'SUCCESS',
    }


@app.get(API_PREFIX + '/pcaps/<acl_gid:int>/<ip:re:%s>/' % IP_REGEX)
def get_files_by_ip(acl_gid, ip):
    u"""
按IP查询acl_gid下的pcap文件

HTTP request args:

  start_ts: 开始时间戳，闭区间，默认now-600
  end_ts: 结束时间戳，闭区间，默认now
  ip: IP地址筛选，可以填写多个
  protocol: 协议，可选值为[6, 17]
  port: 端口
  tap_type: 探针点

HTTP request body:

  None

HTTP response body:

  .. code-block:: javascript

    {
      "DATA": [
        {
          "start_datetime": "190122155720",
          "mac": "00:00:0c:07:ac:66",
          "hostname": "analyzer1",
          "end_epoch": 1548144063,
          "end_datetime": "190122160103",
          "ip": "77.51.7.118",
          "size": 5272,
          "start_epoch": 1548143840,
          "tap_type": 3,
          "filename": "tor_00000c07ac66_077051007118_190122155720_190122160103.0.pcap"
        },
        ...
      ],
      "OPT_STATUS": "SUCCESS"
    }
    """
    ips = request.query.getlist('ip')
    protocol = None
    if request.query.protocol != '':
        protocol = int(request.query.protocol)
    port = None
    if request.query.port != '':
        port = int(request.query.port)
    tap_type = None
    if request.query.tap_type != '':
        tap_type = int(request.query.tap_type)
    start_ts = int(time.time()) - 600
    end_ts = int(time.time())
    if request.query.start_ts != '':
        start_ts = int(request.query.start_ts)
    if request.query.end_ts != '':
        end_ts = int(request.query.end_ts)
    return {
        'DATA': get_files(acl_gid, start_ts, end_ts, ip=ip, ip_filter=ips, protocol=protocol, port=port, tap_type=tap_type),
        'OPT_STATUS': 'SUCCESS',
    }


@app.get(API_PREFIX + '/pcaps/<acl_gid:int>/<pcap_name>/')
def get_file(acl_gid, pcap_name):
    u"""
按IP下载acl_gid下的pcap文件

HTTP request args:

  ip: IP地址筛选，可以填写多个
  protocol: 协议，可选值为[6, 17]
  port: 端口

HTTP request body:

  None

HTTP response body:

  octet-stream
    """
    ips = request.query.getlist('ip')
    protocol = None
    if request.query.protocol != '':
        protocol = int(request.query.protocol)
    port = None
    if request.query.port != '':
        port = int(request.query.port)
    directory = PCAP_DIR + '/' + str(acl_gid) + '/'
    if ips or protocol is not None:
        headers = {'Content-Disposition': 'attachment; filename="%s"' % pcap_name}
        return HTTPResponse(filter_pcap(directory + pcap_name, ips, protocol, port), **headers)
    else:
        return static_file(pcap_name, root=directory, download=pcap_name)


@app.delete(API_PREFIX + '/pcaps/<acl_gid:int>/')
@app.delete(API_PREFIX + '/pcaps/<acl_gid:int>/<pcap_name>/')
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
    if tapType.startswith('isp'):
        try:
            return int(tapType[3:])
        except ValueError:
            return 0
    if tapType == 'tor':
        return 3
    return 0


def _time_to_epoch(time_str):
    try:
        return int(time.mktime(datetime.datetime.strptime(time_str, "%y%m%d%H%M%S").timetuple()))
    except ValueError:
        return 0


def get_files(acl_gid, start_ts, end_ts, mac=None, ip=None, ip_filter=None, protocol=None, port=None, tap_type=None):
    if protocol is not None and protocol not in [PROTOCOL_TCP, PROTOCOL_UDP]:
        return []

    directory = PCAP_DIR + '/' + str(acl_gid) + '/'
    if not os.path.isdir(directory):
        return []
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
        start_epoch = _time_to_epoch(segs[3])
        end_epoch = _time_to_epoch(segs[4])
        if start_epoch > end_ts or end_epoch < start_ts:
            continue
        if tap_type is not None and _tap_type_to_id(segs[0]) != tap_type:
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
        if (ip_filter is not None or protocol is not None) and not found_in_pcap(directory + file, ip_filter, protocol, port):
            continue
        files.append({
            'mac': mac_rep,
            'ip': ip_rep,
            'tap_type': _tap_type_to_id(segs[0]),
            'filename': file,
            'start_epoch': start_epoch,
            'start_datetime': segs[3],
            'end_epoch': end_epoch,
            'end_datetime': segs[4],
            'size': os.path.getsize(directory + file),
            'hostname': HOSTNAME,
        })
    return files

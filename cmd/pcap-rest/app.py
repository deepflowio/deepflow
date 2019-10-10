# -*- coding: utf-8 -*-
import datetime
import ipaddress
import mimetypes
import os
import shutil
import socket
import time
from operator import itemgetter

from bottle import get, request, static_file, delete, Bottle, HTTPResponse

from pcap import PROTOCOL_TCP, PROTOCOL_UDP, filter_pcap

from pcap import found_in_pcap

PCAP_DIR = '/var/lib/droplet/pcap'
HOSTNAME = ''
DROPLET_CONF = '/etc/droplet.yaml'
FILE_SUFFIX = '.pcap'
API_VERSION = 'v1'
API_PREFIX = '/' + API_VERSION

DEFAULT_PCAP_LIST_SIZE = 1000

IP_REGEX = r'(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)'
# https://stackoverflow.com/a/17871737
IPV6_REGEX = r'(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))'

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


@app.get(API_PREFIX + '/pcaps/aclgids/')
def get_folders():
    u"""
按IP查询acl_gid下的pcap文件

HTTP request args:

  None

HTTP request body:

  None

HTTP response body:

  .. code-block:: javascript

    {
      "DATA": [1, 3, 45, 234],
      "OPT_STATUS": "SUCCESS"
    }
    """
    return {
        'DATA': [
            int(it)
            for it in os.listdir(PCAP_DIR)
            if it.isdigit() and os.path.isdir(os.path.join(PCAP_DIR, it))
        ],
        'OPT_STATUS': 'SUCCESS',
    }


@app.get(API_PREFIX + '/pcaps/<acl_gid:int>/')
@app.get(API_PREFIX + '/pcaps/<acl_gid:int>/<ip:re:%s>/' % IP_REGEX)
@app.get(API_PREFIX + '/pcaps/<acl_gid:int>/<ip:re:%s>/' % IPV6_REGEX)
def get_files_by_ip(acl_gid, ip=None):
    u"""
按IP查询acl_gid下的pcap文件

HTTP request args:

  start_ts: 开始时间戳，闭区间，默认now-600
  end_ts: 结束时间戳，闭区间，默认now
  size: 条目数，默认1000，按start_ts降序排列
  ip: IP地址筛选，可以填写多个
  protocol: 协议
  port: 端口，可以填写多个
  tap_type: 探针点
  ip_version: ip版本，可选值为[4, 6]
  peek: 若为True，检查是否存在，存在的话返回一条记录

HTTP request body:

  None

HTTP response body:

  .. code-block:: javascript

    {
      "DATA": [
        {
          "start_datetime": "190122155720",
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
    ports = None
    if request.query.protocol != '':
        protocol = int(request.query.protocol)
        ports = request.query.getlist('port')
    tap_type = None
    if request.query.tap_type != '':
        tap_type = int(request.query.tap_type)
    start_ts = int(time.time()) - 600
    end_ts = int(time.time())
    if request.query.start_ts != '':
        start_ts = int(request.query.start_ts)
    if request.query.end_ts != '':
        end_ts = int(request.query.end_ts)
    size = int(request.query.size) if request.query.size != '' else None
    ip_version = int(
        request.query.ip_version
    ) if request.query.ip_version != '' else None
    peek = bool(request.query.peek) if request.query.peek != '' else False
    if ip_version is not None and ip_version not in [4, 6]:
        return {'OPT_STATUS': 'FAILURE', 'DESCRIPTION': 'bad ip version'}
    if ip:
        ip = ipaddress.ip_address(unicode(ip))
        if ip_version is not None and ip.version != ip_version:
            return {
                'OPT_STATUS': 'FAILURE',
                'DESCRIPTION': 'ip version mismatch'
            }
        ip_version = ip.version
    if ips:
        ips = [ipaddress.ip_address(unicode(it)) for it in ips]
        if ip_version is not None and any([
            it.version != ip_version for it in ips
        ]):
            return {
                'OPT_STATUS': 'FAILURE',
                'DESCRIPTION': 'ip version mismatch'
            }
    if ports:
        try:
            ports = [int(it) for it in ports]
        except ValueError:
            return {
                'OPT_STATUS': 'FAILURE',
                'DESCRIPTION': 'bad port'
            }
    return {
        'DATA': get_files(
            acl_gid, start_ts, end_ts, size=size, ip=ip, ip_filter=ips,
            protocol=protocol, port_filter=ports, tap_type=tap_type,
            ip_version=ip_version, peek=peek
        ),
        'OPT_STATUS': 'SUCCESS',
    }


@app.get(API_PREFIX + '/pcaps/<acl_gid:int>/<pcap_name>/')
def get_file(acl_gid, pcap_name):
    u"""
按IP下载acl_gid下的pcap文件

HTTP request args:

  ip: IP地址筛选，可以填写多个
  protocol: 协议
  port: 端口，可以填写多个

HTTP request body:

  None

HTTP response body:

  octet-stream
    """
    ips = request.query.getlist('ip')
    ips = [ipaddress.ip_address(unicode(it)) for it in ips]
    protocol = None
    ports = None
    if request.query.protocol != '':
        protocol = int(request.query.protocol)
        ports = request.query.getlist('port')
    if ports:
        try:
            ports = [int(it) for it in ports]
        except ValueError:
            return HTTPError(400, 'bad port')
    directory = PCAP_DIR + '/' + str(acl_gid) + '/'
    if ips or protocol is not None:
        headers = {
            'Content-Disposition': 'attachment; filename="%s"' % pcap_name
        }
        return HTTPResponse(
            filter_pcap(directory + pcap_name, ips, protocol, ports), **headers
        )
    else:
        return static_file(pcap_name, root=directory, download=pcap_name)


@app.delete(API_PREFIX + '/pcaps/<acl_gid:int>/')
@app.delete(API_PREFIX + '/pcaps/<acl_gid:int>/<pcap_name>/')
def delete_files(acl_gid, pcap_name=None):
    u"""
删除acl_gid下的pcap文件

HTTP request args:

  idle_time: 目录超时秒数，如果该acl_gid目录超过这个时间进行文件变动，进行删除

HTTP request body:

  None

HTTP response body:

  {
      "OPT_STATUS": "SUCCESS"
  }
    """
    idle_time = 0
    if request.query.idle_time != '':
        idle_time = int(request.query.idle_time)
    directory = PCAP_DIR + '/' + str(acl_gid) + '/'
    if pcap_name is not None:
        os.unlink(directory + pcap_name)
    else:
        if idle_time > 0:
            now = int(time.time())
            mtime = os.path.getmtime(directory)
            if now - mtime <= idle_time:
                return {
                    'OPT_STATUS': 'FAILED',
                }
        shutil.rmtree(directory)
    return {
        'OPT_STATUS': 'SUCCESS',
    }


# convert ip like 192.168.1.1 to 192168001001
def _ip_convert(ip):
    return ''.join(['0' * (3 - len(s)) + s for s in str(ip).split('.')])


def _ip_convert_back(ip):
    try:
        # ipv6
        return ipaddress.ip_address(unicode(ip))
    except ValueError:
        try:
            # ipv4
            return ipaddress.ip_address(
                unicode(
                    '%d.%d.%d.%d' %
                    (int(ip[0:3]), int(ip[3:6]), int(ip[6:9]), int(ip[9:12]))
                )
            )
        except (IndexError, ValueError):
            return ipaddress.ip_address(unicode('0.0.0.0'))


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
        return int(
            time.mktime(
                datetime.datetime.strptime(time_str,
                                           "%y%m%d%H%M%S").timetuple()
            )
        )
    except ValueError:
        return 0


def get_files(
    acl_gid, start_ts, end_ts, size=DEFAULT_PCAP_LIST_SIZE, ip=None,
    ip_filter=None, protocol=None, port_filter=None, tap_type=None, ip_version=None,
    peek=False
):
    if size < 0:
        size = DEFAULT_PCAP_LIST_SIZE
    # 如果protocol不是tcp或udp，认为端口过滤后没有结果
    if protocol is not None and port_filter and protocol not in [
        PROTOCOL_TCP, PROTOCOL_UDP
    ]:
        return []

    directory = PCAP_DIR + '/' + str(acl_gid) + '/'
    if not os.path.isdir(directory):
        return []
    files = []
    if ip is not None:
        if ip_version == 4:
            ip_str = _ip_convert(ip)
        else:
            ip_str = str(ip)
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
        if ip is not None and ip_str != segs[2]:
            continue
        ip_rep = _ip_convert_back(segs[2])
        if (
            ip_filter or protocol is not None
        ) and not found_in_pcap(directory + file, ip_filter, protocol, port_filter):
            continue
        files.append({
            'ip': str(ip_rep),
            'tap_type': _tap_type_to_id(segs[0]),
            'filename': file,
            'start_epoch': start_epoch,
            'start_datetime': segs[3],
            'end_epoch': end_epoch,
            'end_datetime': segs[4],
            'size': os.path.getsize(directory + file),
            'hostname': HOSTNAME,
            'ip_version': ip_rep.version,
        })
        if peek:
            break
    return sorted(files, key=itemgetter('start_epoch'), reverse=True)[:size]

#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2022 Yunshan Networks
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import os
import struct
import sys

import ujson as json


FILE_NAME = 'ip_info.go'

DOC_NAME = os.path.dirname(os.path.realpath(__file__)) + os.path.sep + 'README.md'

BASE_CODE = """package geo

"""

def encode_country(country):
    return struct.unpack('>I', country + (4 - len(country)) * '\0')[0]


class Encoder(object):

    def __init__(self):
        self.items = ['未知']  # index starts from 1
        self.item_map = {}

    def encode(self, item):
        item = item.encode('utf-8').decode('utf-8')
        if item not in self.item_map:
            self.item_map[item] = len(self.items)
            self.items.append(item)
        return self.item_map[item]


ITEM_STR = '\t&GeoInfo{{IPStart: {ip_start}, IPEnd: {ip_end}, Country: {country}, Region: {region}, ISP: {isp}}},\n'


def fixed_name(s):
    if s == '黑龙':
        return '黑龙江'
    elif s == '内蒙':
        return '内蒙古'
    return s


def gen_code(file):
    with open(FILE_NAME, 'w') as wf:
        country_encoder = Encoder()
        region_encoder = Encoder()
        isp_encoder = Encoder()
        wf.write(BASE_CODE)
        wf.write('var GEO_ENTRIES = [...]*GeoInfo{\n')
        with open(file, 'r') as rf:
            for line in rf:
                data = json.loads(line)
                encoded = {}
                encoded['ip_start'] = data['ip_start']
                encoded['ip_end'] = data['ip_end']
                encoded['country'] = country_encoder.encode(data['country']) if 'country' in data else 0
                encoded['region'] = region_encoder.encode(data['region']) if 'region' in data else 0
                encoded['isp'] = isp_encoder.encode(data['isp']) if 'isp' in data else 0
                wf.write(ITEM_STR.format(**encoded))
        wf.write('}\n')

        wf.write('\n')
        wf.write('var COUNTRY_NAMES = [...]string{%s}\n' % ', '.join(['"%s"' % name for name in country_encoder.items]))
        wf.write('\n')
        wf.write('var COUNTRY_NAMES_MAP map[string]uint8 = map[string]uint8{%s}\n' %
                 ', '.join(['"%s":%d' % (name, idx) for idx, name in enumerate(country_encoder.items)]))

        wf.write('\n')
        wf.write('var REGION_NAMES = [...]string{%s}\n' % ', '.join(['"%s"' % fixed_name(name) for name in region_encoder.items]))
        wf.write('\n')
        wf.write('var REGION_NAMES_MAP map[string]uint8 = map[string]uint8{%s}\n' %
                 ', '.join(['"%s":%d' % (fixed_name(name), idx) for idx, name in enumerate(region_encoder.items)]))

        wf.write('\n')
        wf.write('var ISP_NAMES = [...]string{%s}\n' % ', '.join(['"%s"' % name for name in isp_encoder.items]))
        wf.write('\n')
        wf.write('var ISP_NAMES_MAP map[string]uint8 = map[string]uint8{%s}\n' %
                 ', '.join(['"%s":%d' % (name, idx) for idx, name in enumerate(isp_encoder.items)]))


if __name__ == '__main__':
    gen_code(sys.argv[1])

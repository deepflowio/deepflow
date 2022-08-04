/*
 * Copyright (c) 2022 Yunshan Networks
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package example

var YamlDomainAliYun = []byte(`
# 名称
name: aliyun
# 云平台类型
type: aliyun
config:
  # 所属区域标识
  region_uuid: ffffffff-ffff-ffff-ffff-ffffffffffff
  # 资源同步控制器
  #controller_ip: 127.0.0.1
  # AccessKey ID
  # 阿里云控制台-accesskeys页面上获取用于API访问的密钥ID
  secret_id: xxxxxxxx
  # AccessKey Secret
  # 阿里云控制台-accesskeys页面上获取用于API访问的密钥KEY
  secret_key: xxxxxxx
  # 区域白名单，多个区域名称之间以英文逗号分隔
  include_regions:
  # 区域黑名单，多个区域名称之间以英文逗号分隔
  exclude_regions:
`)

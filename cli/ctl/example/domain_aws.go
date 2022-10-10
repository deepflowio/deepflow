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

var YamlDomainAws = []byte(`
# 名称
name: aws
# 云平台类型
type: aws
config:
  # 所属区域标识 [按需指定]
  region_uuid: ffffffff-ffff-ffff-ffff-ffffffffffff
  # 资源同步控制器 [按需指定,不指定时随机分配]
  # controller_ip: 127.0.0.1
  # API 密钥 ID [必需参数], 在AWS控制台页面-我的安全凭证-API的访问密钥 获取
  secret_id: xxxxxxxx
  # API 密钥 KEY [必需参数], 在AWS控制台页面-我的安全凭证-API的访问密钥KEY 获取
  secret_key: xxxxxxx
  # 区域白名单, 多个区域名称之间以英文逗号分隔 [按需指定]
  include_regions:
  # 区域黑名单, 多个区域名称之间以英文逗号分隔 [按需指定]
  exclude_regions:
`)

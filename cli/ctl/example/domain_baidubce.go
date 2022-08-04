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

var YamlDomainBaiduBce = []byte(`
# 名称
name: baidu_bce
# 云平台类型
type: baidu_bce
config:
  # 所属区域标识
  region_uuid: ffffffff-ffff-ffff-ffff-ffffffffffff
  # 资源同步控制器
  #controller_ip: 127.0.0.1
  # Access Key
  # 百度云控制台-安全认证-Access Key页面上获取用于API访问的Access Key
  secret_id: xxxxxx
  # Secret Key
  # 百度云控制台-安全认证-Access Key页面上获取用于API访问的Secret Key
  secret_key: xxxxxx
  # API Endpoint
  # 对接区域的API Endpoint（服务域名）信息，不同区域会对应不同的Endpoint。可参考百度BCC产品文档，但注意去掉域名中的bcc.前缀
  endpoint: bj.baidubce.com
`)

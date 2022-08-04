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

var YamlDomainQingCloud = []byte(`
# 名称
name: qingcloud
# 云平台类型
type: qingcloud
config:
  # 所属区域标识
  region_uuid: ffffffff-ffff-ffff-ffff-ffffffffffff
  # 资源同步控制器
  #controller_ip: 127.0.0.1
  # API 密钥 ID
  # 在青云主页面右上角-API密钥-API密钥管理-API密钥ID
  secret_id: xxxxxxxx
  # API 密钥 KEY
  # API密钥ID对应的API密钥KEY
  secret_key: xxxxxxx
`)

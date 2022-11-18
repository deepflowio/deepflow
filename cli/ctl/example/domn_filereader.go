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

var YamlDomainFileReader = []byte(`
# 名称
name: filereader
# 配置文件录入
type: filereader
config:
  # 所属区域标识
  region_uuid: ffffffff-ffff-ffff-ffff-ffffffffffff
  # 资源同步控制器
  #controller_ip: 127.0.0.1
  # YAML文件路径
  path: /xxx/xxx/xxx.yaml
`)

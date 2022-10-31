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

var YamlDomainHuawei = []byte(`
# 名称
name: huawei
# 云平台类型
type: huawei
config:
  # 所属区域标识
  region_uuid: ffffffff-ffff-ffff-ffff-ffffffffffff
  # 资源同步控制器
  #controller_ip: 127.0.0.1
  # 账号名
  # 在华为云页面，访问控制台-我的凭证页面上找到 帐号名
  account_name: xxxxxx
  # IAM用户名
  # 在华为云页面，访问控制台-我的凭证页面上找到 IAM用户名
  iam_name: xxxxxx
  # IAM用户密码
  # 登录华为云页面的密码
  password: xxxxxx
  # 项目ID
  # 控制台-我的凭证-项目列表页面上其中一个项目ID
  project_id: xxxxxx
  # 项目
  # 项目ID对应的项目名称
  region_name: xxxxxx
  # 区域白名单，多个区域名称之间以英文逗号分隔
  #include_regions:
  # 区域黑名单，多个区域名称之间以英文逗号分隔
  #exclude_regions:
`)

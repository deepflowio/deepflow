/*
 * Copyright (c) 2023 Yunshan Networks
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

import _ "embed"

//go:embed domain_aliyun.yaml
var YamlDomainAliYun []byte

//go:embed domain_aws.yaml
var YamlDomainAws []byte

//go:embed domain_baidubce.yaml
var YamlDomainBaiduBce []byte

//go:embed domain_filereader.yaml
var YamlDomainFileReader []byte

//go:embed domain_genesis.yaml
var YamlDomainGenesis []byte

//go:embed domain_huawei.yaml
var YamlDomainHuawei []byte

//go:embed domain_kubernetes.yaml
var YamlDomainKubernetes []byte

//go:embed domain_qingcloud.yaml
var YamlDomainQingCloud []byte

//go:embed domain_tencent.yaml
var YamlDomainTencent []byte

//go:embed sub_domain_create.yaml
var YamlSubDomain []byte

//go:embed vtap_update.yaml
var YamlVtapUpdateConfig []byte

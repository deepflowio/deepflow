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

package config

var CONF *CloudConfig

type CloudConfig struct {
	CloudGatherInterval      uint32 `default:"30" yaml:"cloud_gather_interval"`
	KubernetesGatherInterval uint32 `default:"30" yaml:"kubernetes_gather_interval"`
	AliyunRegionName         string `default:"cn-beijing" yaml:"aliyun_region_name"`
	HuaweiDomainName         string `default:"myhuaweicloud.com" yaml:"huawei_domain_name"`
	GenesisDefaultVpcName    string `default:"default_vpc" yaml:"genesis_default_vpc"`
	HostnameToIPFile         string `default:"/etc/hostname_to_ip.csv" yaml:"hostname_to_ip_file"`
	DNSEnable                bool   `default:"false" yaml:"dns_enable"`
	HTTPTimeout              int    `default:"30" yaml:"http_timeout"`
	DebugEnabled             bool   `default:"false" yaml:"debug_enabled"`
}

func SetCloudGlobalConfig(c CloudConfig) {
	CONF = &CloudConfig{
		HostnameToIPFile: c.HostnameToIPFile,
		DNSEnable:        c.DNSEnable,
		HTTPTimeout:      c.HTTPTimeout,
		DebugEnabled:     c.DebugEnabled,
	}
}

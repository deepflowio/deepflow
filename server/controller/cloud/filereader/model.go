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

package filereader

type Region struct {
	Name string `yaml:"name"`
}

type AZ struct {
	Name   string `yaml:"name"`
	Region string `yaml:"region"`
}

type Host struct {
	IP       string `yaml:"ip"`
	MemoryMb int    `yaml:"memory_mb"`
	VCPUs    int    `yaml:"vcpus"`
	AZ       string `yaml:"az"`
	Region   string `yaml:"region"`
}

type VPC struct {
	Name   string `yaml:"name"`
	Region string `yaml:"region"`
}

type Network struct {
	Name           string `yaml:"name"`
	External       bool   `yaml:"external"`
	NetType        string `yaml:"net_type"`
	Shared         bool   `yaml:"shared"`
	SegmentationID int    `yaml:"segmentation_id"`
	VPC            string `yaml:"tenant_name"`
	AZ             string `yaml:"az"`
	Region         string `yaml:"region"`
}

type Subnet struct {
	Name      string `yaml:"name"`
	CIDR      string `yaml:"cidr"`
	GatewayIP string `yaml:"gateway_ip"`
	Network   string `yaml:"network_name"`
}

type Port struct {
	IP     string `yaml:"ip_address"`
	Mac    string `yaml:"mac_address"`
	Subnet string `yaml:"subnet_name"`
}

type VM struct {
	Name         string `yaml:"name"`
	LaunchServer string `yaml:"launch_server"`
	VPC          string `yaml:"tenant_name"`
	AZ           string `yaml:"az"`
	Region       string `yaml:"region"`
	Ports        []Port `yaml:"ports"`
}

type Router struct {
	Name           string `yaml:"name"`
	GWLaunchServer string `yaml:"gw_launch_server"`
	VPC            string `yaml:"tenant_name"`
	Region         string `yaml:"region"`
	Ports          []Port `yaml:"ports"`
}

type FileInfo struct {
	Regions  []Region  `yaml:"regions"`
	AZs      []AZ      `yaml:"azs"`
	Hosts    []Host    `yaml:"hosts"`
	VPCs     []VPC     `yaml:"tenants"`
	Networks []Network `yaml:"networks"`
	Subnets  []Subnet  `yaml:"subnets"`
	Routers  []Router  `yaml:"routers"`
	VMs      []VM      `yaml:"vms"`
}

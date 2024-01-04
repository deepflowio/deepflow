/*
 * Copyright (c) 2024 Yunshan Networks
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

package huawei

import (
	"github.com/deepflowio/deepflow/server/controller/cloud/model"
)

type ToolDataSet struct {
	configProjectToken string

	projectNameToRegionLcuuid     map[string]string
	azNameToAZLcuuid              map[string]string
	vpcLcuuids                    []string
	vpcLcuuidToVRouterLcuuid      map[string]string
	networkLcuuidToCIDR           map[string]string
	networkLcuuidToAZName         map[string]string
	networkLcuuidToVPCName        map[string]string
	lcuuidToNetwork               map[string]model.Network
	neutronSubnetIDToNetwork      map[string]model.Network
	networkVPCLcuuidToAZLcuuids   map[string][]string
	networkLcuuidToSubnets        map[string][]model.Subnet
	macToFloatingIP               map[string]string
	floatingIPToVInterface        map[string]model.VInterface
	natGatewayLcuuidToFloatingIPs map[string][]string
	keyToSecurityGroupLcuuid      map[ProjectSecurityGroupKey]string
	keyToVMLcuuid                 map[SubnetIPKey]string
	keyToNATGatewayLcuuid         map[VPCIPKey]string
	vinterfaceLcuuidToPublicIP    map[string]string
	vinterfaceLcuuidToIPs         map[string][]string
	lbLcuuidToVPCLcuuid           map[string]string
	lbLcuuidToIP                  map[string]string

	regionLcuuidToResourceNum map[string]int
	azLcuuidToResourceNum     map[string]int
}

func NewToolDataSet() *ToolDataSet {
	return &ToolDataSet{
		projectNameToRegionLcuuid:     make(map[string]string),
		azNameToAZLcuuid:              make(map[string]string),
		vpcLcuuidToVRouterLcuuid:      make(map[string]string),
		lcuuidToNetwork:               make(map[string]model.Network),
		neutronSubnetIDToNetwork:      make(map[string]model.Network),
		networkLcuuidToAZName:         make(map[string]string),
		networkLcuuidToCIDR:           make(map[string]string),
		networkVPCLcuuidToAZLcuuids:   make(map[string][]string),
		networkLcuuidToVPCName:        make(map[string]string),
		networkLcuuidToSubnets:        make(map[string][]model.Subnet),
		macToFloatingIP:               make(map[string]string),
		floatingIPToVInterface:        make(map[string]model.VInterface),
		natGatewayLcuuidToFloatingIPs: make(map[string][]string),
		keyToSecurityGroupLcuuid:      make(map[ProjectSecurityGroupKey]string),
		keyToVMLcuuid:                 make(map[SubnetIPKey]string),
		keyToNATGatewayLcuuid:         make(map[VPCIPKey]string),
		vinterfaceLcuuidToPublicIP:    make(map[string]string),
		vinterfaceLcuuidToIPs:         make(map[string][]string),
		lbLcuuidToVPCLcuuid:           make(map[string]string),
		lbLcuuidToIP:                  make(map[string]string),
		regionLcuuidToResourceNum:     make(map[string]int),
		azLcuuidToResourceNum:         make(map[string]int),
	}
}

type ProjectSecurityGroupKey struct {
	projectID         string
	securityGroupName string
}

type SubnetIPKey struct {
	SubnetLcuuid string
	IP           string
}

type VPCIPKey struct {
	VPCLcuuid string
	IP        string
}

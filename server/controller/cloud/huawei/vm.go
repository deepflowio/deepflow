/*
 * Copyright (c) 2024 Yunshan VMs
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
	"fmt"
	"strings"
	"time"

	"github.com/bitly/go-simplejson"
	cloudcommon "github.com/deepflowio/deepflow/server/controller/cloud/common"
	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
)

var STATE_CONVERTION = map[string]int{
	"ACTIVE":  common.VM_STATE_RUNNING,
	"SHUTOFF": common.VM_STATE_STOPPED,
}

func (h *HuaWei) getVMs() ([]model.VM, []model.VInterface, []model.IP, error) {
	var vms []model.VM
	var vifs []model.VInterface
	var ips []model.IP
	for project, token := range h.projectTokenMap {
		// 华为云官方文档：
		// 云服务器的标签列表。微版本2.26及以上版本支持，如果不使用微版本查询，响应中无tags字段。
		jVMs, err := h.getRawData(newRawDataGetContext(
			fmt.Sprintf("https://ecs.%s.%s/v2.1/%s/servers/detail", project.name, h.config.Domain, project.id), token.token, "servers", pageQueryMethodMarker,
		).addHeader("X-OpenStack-Nova-API-Version", "2.26"))
		if err != nil {
			return nil, nil, nil, err
		}

		regionLcuuid := h.projectNameToRegionLcuuid(project.name)
		for i := range jVMs {
			jVM := jVMs[i]
			if !cloudcommon.CheckJsonAttributes(jVM, []string{"id", "name", "addresses", "status", "OS-EXT-AZ:availability_zone"}) {
				continue
			}
			id := common.IDGenerateUUID(h.orgID, jVM.Get("id").MustString())
			addrs := jVM.Get("addresses").MustMap()
			var vpcLcuuid string
			for key := range addrs {
				keyLcuuid := common.IDGenerateUUID(h.orgID, key)
				if common.Contains(h.toolDataSet.vpcLcuuids, keyLcuuid) {
					vpcLcuuid = keyLcuuid
					break
				}
			}
			if vpcLcuuid == "" {
				log.Infof("exclude vm: %s, missing vpc info", id) // vpc info is in addresses
				continue
			}
			name := jVM.Get("name").MustString()
			azLcuuid := h.toolDataSet.azNameToAZLcuuid[jVM.Get("OS-EXT-AZ:availability_zone").MustString()]
			vm := model.VM{
				Lcuuid:       id,
				Name:         name,
				Label:        name,
				HType:        common.VM_HTYPE_VM_C,
				State:        STATE_CONVERTION[jVM.Get("status").MustString()],
				AZLcuuid:     azLcuuid,
				RegionLcuuid: regionLcuuid,
				VPCLcuuid:    vpcLcuuid,
				CloudTags:    h.formatVMCloudTags(jVM.Get("tags")),
			}

			jc, ok := jVM.CheckGet("created")
			if ok {
				created := jc.MustString()
				if created != "" {
					createdAt, err := time.Parse(time.RFC3339, created)
					if err != nil {
						log.Errorf("parse created failed: %s", created)
					} else {
						vm.CreatedAt = createdAt
					}
				}
			}
			vms = append(vms, vm)
			h.toolDataSet.azLcuuidToResourceNum[azLcuuid]++
			h.toolDataSet.regionLcuuidToResourceNum[regionLcuuid]++

			vs, is := h.formatVInterfacesAndIPs(jVM.Get("addresses"), regionLcuuid, id)
			vifs = append(vifs, vs...)
			ips = append(ips, is...)
		}
	}
	return vms, vifs, ips, nil
}

// 华为云官方文档：
// 华为云云服务器标签规则：
//
//	key与value使用“=”连接，如“key=value”。
//	如果value为空字符串，则仅返回key。
func (h *HuaWei) formatVMCloudTags(tags *simplejson.Json) map[string]string {
	resp := make(map[string]string)
	for i := range tags.MustArray() {
		jTag := tags.GetIndex(i).MustString()
		parts := strings.SplitN(jTag, "=", 2)
		if len(parts) == 2 {
			resp[parts[0]] = parts[1]
		} else {
			resp[jTag] = ""
		}
	}
	return resp
}

func (h *HuaWei) formatVInterfacesAndIPs(addrs *simplejson.Json, regionLcuuid, vmLcuuid string) (vifs []model.VInterface, ips []model.IP) {
	requiredAttrs := []string{"addr", "OS-EXT-IPS-MAC:mac_addr", "OS-EXT-IPS:type"}
	for vpcLcuuid, jVIFs := range addrs.MustMap() {
		for _, jVIF := range jVIFs.([]interface{}) {
			jV := jVIF.(map[string]interface{})
			if !cloudcommon.CheckMapAttributes(jV, requiredAttrs) {
				continue
			}
			if jV["OS-EXT-IPS:type"].(string) != "floating" {
				log.Infof("exclude vinterface, not floating type: %s", jV["OS-EXT-IPS:type"].(string))
				continue
			}
			mac := jV["OS-EXT-IPS-MAC:mac_addr"].(string)
			if len(mac) < 2 {
				log.Infof("exclude vinterface, mac: %s", mac)
				continue
			}
			vif := model.VInterface{
				Lcuuid:        common.GenerateUUIDByOrgID(h.orgID, vmLcuuid+mac),
				Type:          common.VIF_TYPE_WAN,
				Mac:           cloudcommon.GenerateWANVInterfaceMac(mac),
				DeviceLcuuid:  vmLcuuid,
				DeviceType:    common.VIF_DEVICE_TYPE_VM,
				NetworkLcuuid: common.NETWORK_ISP_LCUUID,
				VPCLcuuid:     vpcLcuuid,
				RegionLcuuid:  regionLcuuid,
			}
			vifs = append(vifs, vif)

			ipAddr := jV["addr"].(string)
			var subnetLcuuid string
			for _, subnet := range h.toolDataSet.networkLcuuidToSubnets[vif.NetworkLcuuid] {
				if cloudcommon.IsIPInCIDR(ipAddr, subnet.CIDR) {
					subnetLcuuid = subnet.Lcuuid
					break
				}
			}
			ips = append(
				ips,
				model.IP{
					Lcuuid:           common.GenerateUUIDByOrgID(h.orgID, vif.Lcuuid+ipAddr),
					VInterfaceLcuuid: vif.Lcuuid,
					IP:               ipAddr,
					SubnetLcuuid:     subnetLcuuid,
					RegionLcuuid:     regionLcuuid,
				},
			)
		}
	}
	return
}

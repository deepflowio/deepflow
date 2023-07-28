/**
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

package mysql

import (
	ctrlcommon "github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/http/service/resource/common"
)

const PORT_DEFAULT_MAC = "00:00:00:00:00:00"

type Pod struct {
	DataProvider
	dataTool *podToolData
}

func NewPod() *Pod {
	dp := &Pod{newDataProvider(ctrlcommon.RESOURCE_TYPE_POD_EN), new(podToolData)}
	dp.setGenerator(dp)
	return dp
}

func (p *Pod) generate() (data []common.ResponseElem, err error) {
	err = p.dataTool.Init().Load()
	for _, item := range p.dataTool.pods {
		data = append(data, p.generateOne(item))
	}
	return
}

func (p *Pod) generateOne(item mysql.Pod) common.ResponseElem {
	d := MySQLModelToMap(item)
	if v, ok := d["VPC_ID"]; ok {
		d["EPC_ID"] = v
		delete(d, "VPC_ID")
	}
	d["POD_REPLICA_SET_ID"] = item.PodReplicaSetID

	d["AZ_NAME"] = p.dataTool.azLcuuidToName[item.AZ]
	d["REGION_NAME"] = p.dataTool.regionLcuuidToName[item.Region]
	d["SUBDOMAIN_NAME"] = p.dataTool.subDomainLcuuidToName[item.SubDomain]
	d["EPC_NAME"] = p.dataTool.vpcIDToName[item.VPCID]
	d["POD_CLUSTER_NAME"] = p.dataTool.podClusterIDToName[item.PodClusterID]
	d["POD_NAMESPACE_NAME"] = p.dataTool.podNamespaceIDToName[item.PodNamespaceID]
	d["POD_NODE_NAME"] = p.dataTool.podNodeIDToName[item.PodNodeID]
	d["POD_NODE_IP"] = p.dataTool.podNodeIDToIP[item.PodNodeID]
	d["HOST_ID"] = p.dataTool.podIDToHostID[item.ID]
	d["POD_GROUP_NAME"] = p.dataTool.podGroupIDToName[item.PodGroupID]
	d["POD_GROUP_TYPE"] = p.dataTool.podGroupIDToType[item.PodGroupID]
	d["POD_REPLICA_SET_NAME"] = p.dataTool.podReplicaSetIDToName[item.PodReplicaSetID]
	d["IPS"] = p.dataTool.podIDToIPs[item.ID]
	if p.dataTool.podIDToIPs[item.ID] == nil {
		d["IPS"] = []interface{}{}
	}
	d["MACS"] = p.dataTool.podIDToMacs[item.ID]
	if p.dataTool.podIDToMacs[item.ID] == nil {
		d["MACS"] = []interface{}{}
	}
	d["INTERFACES"] = p.dataTool.podIDToInterfaces[item.ID]
	if p.dataTool.podIDToInterfaces[item.ID] == nil {
		d["INTERFACES"] = []interface{}{}
	}

	var podServices []interface{}
	for _, podServiceID := range p.dataTool.podIDToPodServiceIDs[item.ID] {
		podServices = append(podServices, map[string]interface{}{
			"ID":   podServiceID,
			"NAME": p.dataTool.podServiceIDToName[podServiceID],
		})
	}
	d["POD_SERVICES"] = podServices
	if podServices == nil {
		d["POD_SERVICES"] = []interface{}{}
	}

	var subnetIDs []interface{}
	for _, subnetID := range p.dataTool.podIDToSubnetIDs[item.ID] {
		subnetIDs = append(subnetIDs, map[string]interface{}{
			"ID": subnetID,
		})
	}
	d["SUBNETS"] = subnetIDs
	if subnetIDs == nil {
		d["SUBNETS"] = []interface{}{}
	}

	vtap := p.dataTool.podIDToVTap[item.ID]
	for k, v := range getVTapInfo(&vtap) {
		d[k] = v
	}

	return d
}

type podToolData struct {
	pods []mysql.Pod

	subDomainLcuuidToName map[string]string
	regionLcuuidToName    map[string]string
	azLcuuidToName        map[string]string
	vpcIDToName           map[int]string
	podClusterIDToName    map[int]string
	podNamespaceIDToName  map[int]string
	podNodeIDToName       map[int]string
	podNodeIDToIP         map[int]string
	podNodeIDToVMID       map[int]int
	hostIPToID            map[string]int
	podServiceIDToName    map[int]string
	podGroupIDToName      map[int]string
	podGroupIDToType      map[int]int
	podReplicaSetIDToName map[int]string
	podIDToVInterfaceIDs  map[int][]int
	vifIDToLANIPs         map[int][]string
	vifIDToWANIPs         map[int][]string
	podIDToIPs            map[int][]string
	podIDToHostID         map[int]int
	podIDToMacs           map[int][]string
	podIDToInterfaces     map[int][]interface{}

	podIDToSubnetIDs map[int][]int
	vifIDToNetworkID map[int]int

	podIDToPodServiceIDs map[int][]int
	podGroupIDToPodIDs   map[int][]int

	podIDToVTap       map[int]mysql.VTap
	podNodeIDToPodIDs map[int][]int
}

func (td *podToolData) Init() *podToolData {
	td.subDomainLcuuidToName = make(map[string]string)
	td.regionLcuuidToName = make(map[string]string)
	td.azLcuuidToName = make(map[string]string)
	td.vpcIDToName = make(map[int]string)
	td.podClusterIDToName = make(map[int]string)
	td.podNamespaceIDToName = make(map[int]string)
	td.podNodeIDToName = make(map[int]string)
	td.podNodeIDToIP = make(map[int]string)
	td.podNodeIDToVMID = make(map[int]int)
	td.hostIPToID = make(map[string]int)
	td.podServiceIDToName = make(map[int]string)
	td.podGroupIDToName = make(map[int]string)
	td.podGroupIDToType = make(map[int]int)
	td.podReplicaSetIDToName = make(map[int]string)
	td.podIDToVInterfaceIDs = make(map[int][]int)
	td.vifIDToLANIPs = make(map[int][]string)
	td.vifIDToWANIPs = make(map[int][]string)
	td.podIDToIPs = make(map[int][]string)
	td.podIDToHostID = make(map[int]int)
	td.podIDToMacs = make(map[int][]string)
	td.podIDToInterfaces = make(map[int][]interface{})

	td.podIDToSubnetIDs = make(map[int][]int)
	td.vifIDToNetworkID = make(map[int]int)

	td.podIDToPodServiceIDs = make(map[int][]int)
	td.podGroupIDToPodIDs = make(map[int][]int)

	td.podIDToVTap = make(map[int]mysql.VTap)

	td.podNodeIDToPodIDs = make(map[int][]int)

	return td
}

func (td *podToolData) Load() (err error) {
	err = mysql.Db.Unscoped().Find(&td.pods).Error // TODO use db mng

	var subDomains []mysql.SubDomain
	err = mysql.Db.Unscoped().Select("lcuuid", "name").Find(&subDomains).Error
	for _, item := range subDomains {
		td.subDomainLcuuidToName[item.Lcuuid] = item.Name
	}
	var regions []mysql.Region
	err = mysql.Db.Unscoped().Select("lcuuid", "name").Find(&regions).Error
	for _, item := range regions {
		td.regionLcuuidToName[item.Lcuuid] = item.Name
	}
	var azs []mysql.AZ
	err = mysql.Db.Unscoped().Select("lcuuid", "name").Find(&azs).Error
	for _, item := range azs {
		td.azLcuuidToName[item.Lcuuid] = item.Name
	}
	var vpcs []mysql.VPC
	err = mysql.Db.Unscoped().Select("id", "name").Find(&vpcs).Error
	for _, item := range vpcs {
		td.vpcIDToName[item.ID] = item.Name
	}
	var podClusters []mysql.PodCluster
	err = mysql.Db.Unscoped().Select("id", "name").Find(&podClusters).Error
	for _, item := range podClusters {
		td.podClusterIDToName[item.ID] = item.Name
	}
	var podNamespaces []mysql.PodNamespace
	err = mysql.Db.Unscoped().Select("id", "name").Find(&podNamespaces).Error
	for _, item := range podNamespaces {
		td.podNamespaceIDToName[item.ID] = item.Name
	}
	var podNodes []mysql.PodNode
	err = mysql.Db.Unscoped().Select("id", "name", "ip").Find(&podNodes).Error
	for _, item := range podNodes {
		td.podNodeIDToName[item.ID] = item.Name
		td.podNodeIDToIP[item.ID] = item.IP
	}
	var hosts []mysql.Host
	err = mysql.Db.Unscoped().Select("id", "ip").Find(&hosts).Error
	for _, item := range hosts {
		td.hostIPToID[item.IP] = item.ID
	}
	var podServices []mysql.PodService
	err = mysql.Db.Unscoped().Select("id", "name").Find(&podServices).Error
	for _, item := range podServices {
		td.podServiceIDToName[item.ID] = item.Name
	}
	var podGroups []mysql.PodGroup
	err = mysql.Db.Unscoped().Select("id", "name", "type").Find(&podGroups).Error
	for _, item := range podGroups {
		td.podGroupIDToName[item.ID] = item.Name
		td.podGroupIDToType[item.ID] = item.Type
	}

	var podReplicaSets []mysql.PodReplicaSet
	err = mysql.Db.Unscoped().Select("id", "name").Find(&podReplicaSets).Error
	for _, item := range podReplicaSets {
		td.podReplicaSetIDToName[item.ID] = item.Name
	}

	// set podIDToIPs
	var podIDs []int
	for _, pod := range td.pods {
		podIDs = append(podIDs, pod.ID)
		td.podNodeIDToPodIDs[pod.PodNodeID] = append(td.podNodeIDToPodIDs[pod.PodNodeID], pod.ID)
	}
	var vifs []mysql.VInterface
	err = mysql.Db.Unscoped().Select("id", "deviceid", "subnetid", "mac").
		Where(`devicetype = ? and deviceid in(?)`, ctrlcommon.VIF_DEVICE_TYPE_POD, podIDs).Find(&vifs).Error
	for _, vif := range vifs {
		td.podIDToVInterfaceIDs[vif.DeviceID] = append(td.podIDToVInterfaceIDs[vif.DeviceID], vif.ID)
		td.vifIDToNetworkID[vif.ID] = vif.NetworkID
	}
	var lanIPs []mysql.LANIP
	err = mysql.Db.Unscoped().Select("ip", "vifid").Find(&lanIPs).Error
	// TODO(weiqiang): dedup
	for _, lanIP := range lanIPs {
		vifID := lanIP.VInterfaceID
		td.vifIDToLANIPs[vifID] = append(td.vifIDToLANIPs[vifID], lanIP.IP)
	}
	var wanIPs []mysql.WANIP
	err = mysql.Db.Unscoped().Select("ip", "vifid").Find(&wanIPs).Error
	for _, wanIP := range wanIPs {
		vifID := wanIP.VInterfaceID
		td.vifIDToWANIPs[vifID] = append(td.vifIDToWANIPs[vifID], wanIP.IP)
	}
	for _, pod := range td.pods {
		for _, vifID := range td.podIDToVInterfaceIDs[pod.ID] {
			td.podIDToIPs[pod.ID] = append(td.podIDToIPs[pod.ID], td.vifIDToLANIPs[vifID]...)
			td.podIDToIPs[pod.ID] = append(td.podIDToIPs[pod.ID], td.vifIDToWANIPs[vifID]...)
		}
	}

	// set podIDToPodServiceIDs
	podGroupIDs := make([]int, len(td.pods))
	for i, pod := range td.pods {
		podGroupIDs[i] = pod.PodGroupID
		td.podGroupIDToPodIDs[pod.PodGroupID] = append(td.podGroupIDToPodIDs[pod.PodGroupID], pod.ID)
	}
	var podGroupPorts []mysql.PodGroupPort
	err = mysql.Db.Unscoped().Select("pod_group_id", "pod_service_id").Find(&podGroupPorts).Error
	// dedup
	podIDToPodServiceIDMap := make(map[int]map[int]struct{})
	for _, item := range podGroupPorts {
		for _, podID := range td.podGroupIDToPodIDs[item.PodGroupID] {
			if podIDToPodServiceIDMap[podID] == nil {
				podIDToPodServiceIDMap[podID] = make(map[int]struct{})
			}
			podIDToPodServiceIDMap[podID][item.PodServiceID] = struct{}{}
		}
	}
	for podID, podServiceIDs := range podIDToPodServiceIDMap {
		for podServiceID := range podServiceIDs {
			td.podIDToPodServiceIDs[podID] = append(td.podIDToPodServiceIDs[podID], podServiceID)
		}
	}

	// set podIDToSubnetIDs
	for _, pod := range td.pods {
		for _, vifid := range td.podIDToVInterfaceIDs[pod.ID] {
			td.podIDToSubnetIDs[pod.ID] = append(td.podIDToSubnetIDs[pod.ID], td.vifIDToNetworkID[vifid])
		}
	}

	// set podIDToMacs
	for _, vif := range vifs {
		if vif.Mac != PORT_DEFAULT_MAC {
			td.podIDToMacs[vif.DeviceID] = append(td.podIDToMacs[vif.DeviceID], vif.Mac)
		}
	}

	// set podIDToInterfaces
	for _, vif := range vifs {
		mac := "null"
		if vif.Mac != PORT_DEFAULT_MAC {
			mac = vif.Mac
		}
		var ips []string
		ips = append(ips, td.vifIDToLANIPs[vif.ID]...)
		ips = append(ips, td.vifIDToWANIPs[vif.ID]...)

		td.podIDToInterfaces[vif.DeviceID] = append(td.podIDToInterfaces[vif.DeviceID],
			map[string]interface{}{
				"MAC": mac,
				"IPS": ips,
			},
		)
	}

	var vtaps []mysql.VTap
	err = mysql.Db.Unscoped().Select("launch_server_id", "type", "id", "lcuuid",
		"vtap_group_lcuuid", "vtap_lcuuid", "name", "state", "enable").Find(&vtaps).Error
	for _, vtap := range vtaps {
		deviceType := ctrlcommon.VTAP_TYPE_TO_DEVICE_TYPE[vtap.Type]
		if deviceType == 0 || vtap.LaunchServerID == 0 {
			continue
		}
		if deviceType == ctrlcommon.VIF_DEVICE_TYPE_HOST ||
			deviceType == ctrlcommon.VIF_DEVICE_TYPE_VM {
			continue
		}

		for _, podID := range td.podNodeIDToPodIDs[vtap.LaunchServerID] {
			td.podIDToVTap[podID] = vtap
		}
	}

	return
}

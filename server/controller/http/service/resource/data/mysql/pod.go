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
	ctrlrcommon "github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/http/service/resource/common"
)

type Pod struct {
	DataProvider
	dataTool *podToolData
}

func NewPod() *Pod {
	dp := &Pod{newDataProvider(ctrlrcommon.RESOURCE_TYPE_POD_EN), new(podToolData)}
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
	d["AZ_NAME"] = p.dataTool.azLcuuidToName[item.AZ]
	d["REGION_NAME"] = p.dataTool.regionLcuuidToName[item.Region]
	d["SUBDOMAIN_NAME"] = p.dataTool.subDomainLcuuidToName[item.SubDomain]
	d["DOMAIN_NAME"] = p.dataTool.domainLcuuidToName[item.Domain]
	d["EPC_NAME"] = p.dataTool.vpcIDToName[item.VPCID]
	d["POD_CLUSTER_NAME"] = p.dataTool.podClusterIDToName[item.PodClusterID]
	d["POD_NAMESPACE_NAME"] = p.dataTool.podNamespaceIDToName[item.PodNamespaceID]
	d["POD_NODE_NAME"] = p.dataTool.podNodeIDToName[item.PodNodeID]
	d["POD_NODE_IP"] = p.dataTool.podNodeIDToIP[item.PodNodeID]
	d["HOST_ID"] = p.dataTool.podIDToHostID[item.ID]
	d["POD_GROUP_NAME"] = p.dataTool.podGroupIDToName[item.PodGroupID]
	d["POD_GROUP_TYPE"] = p.dataTool.podGroupIDToType[item.PodGroupID]
	d["POD_REPLICA_SET_NAME"] = p.dataTool.podReplicaSetIDToName[item.PodReplicaSetID]
	return d
}

type podToolData struct {
	pods []mysql.Pod

	domainLcuuidToName    map[string]string
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
	podIDToIPs            map[int][]string
	podIDToPodServiceIDs  map[int][]int
	podIDToSubnetIDs      map[int][]int

	podIDToHostID map[int]int
}

func (td *podToolData) Init() *podToolData {
	td.domainLcuuidToName = make(map[string]string)
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
	td.podIDToIPs = make(map[int][]string)
	td.podIDToPodServiceIDs = make(map[int][]int)
	td.podIDToSubnetIDs = make(map[int][]int)
	td.podIDToHostID = make(map[int]int)
	return td
}

func (td *podToolData) Load() (err error) {
	err = mysql.Db.Find(&td.pods).Error // TODO use db mng

	var domains []mysql.Domain
	err = mysql.Db.Select("lcuuid", "name").Find(&domains).Error
	for _, item := range domains {
		td.domainLcuuidToName[item.Lcuuid] = item.Name
	}
	var subDomains []mysql.SubDomain
	err = mysql.Db.Select("lcuuid", "name").Find(&subDomains).Error
	for _, item := range subDomains {
		td.subDomainLcuuidToName[item.Lcuuid] = item.Name
	}
	var regions []mysql.Region
	err = mysql.Db.Select("lcuuid", "name").Find(&regions).Error
	for _, item := range regions {
		td.regionLcuuidToName[item.Lcuuid] = item.Name
	}
	var azs []mysql.AZ
	err = mysql.Db.Select("lcuuid", "name").Find(&azs).Error
	for _, item := range azs {
		td.azLcuuidToName[item.Lcuuid] = item.Name
	}
	var vpcs []mysql.VPC
	err = mysql.Db.Select("id", "name").Find(&vpcs).Error
	for _, item := range vpcs {
		td.vpcIDToName[item.ID] = item.Name
	}
	var podClusters []mysql.PodCluster
	err = mysql.Db.Select("id", "name").Find(&podClusters).Error
	for _, item := range podClusters {
		td.podClusterIDToName[item.ID] = item.Name
	}
	var podNamespaces []mysql.PodNamespace
	err = mysql.Db.Select("id", "name").Find(&podNamespaces).Error
	for _, item := range podNamespaces {
		td.podNamespaceIDToName[item.ID] = item.Name
	}
	var podNodes []mysql.PodNode
	err = mysql.Db.Select("id", "name", "ip").Find(&podNodes).Error
	for _, item := range podNodes {
		td.podNodeIDToName[item.ID] = item.Name
		td.podNodeIDToIP[item.ID] = item.IP
	}
	var hosts []mysql.Host
	err = mysql.Db.Select("id", "ip").Find(&hosts).Error
	for _, item := range hosts {
		td.hostIPToID[item.IP] = item.ID
	}
	var podServices []mysql.PodService
	err = mysql.Db.Select("id", "name").Find(&podServices).Error
	for _, item := range podServices {
		td.podServiceIDToName[item.ID] = item.Name
	}
	var podGroups []mysql.PodGroup
	err = mysql.Db.Select("id", "name", "type").Find(&podGroups).Error
	for _, item := range podGroups {
		td.podGroupIDToName[item.ID] = item.Name
		td.podGroupIDToType[item.ID] = item.Type
	}
	var podReplicaSets []mysql.PodReplicaSet
	err = mysql.Db.Select("id", "name").Find(&podReplicaSets).Error
	for _, item := range podReplicaSets {
		td.podReplicaSetIDToName[item.ID] = item.Name
	}
	return
}

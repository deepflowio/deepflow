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

package kubernetes_gather

import (
	"strconv"
	"strings"

	"github.com/bitly/go-simplejson"
	cloudcommon "github.com/deepflowio/deepflow/server/controller/cloud/common"
	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
	uuid "github.com/satori/go.uuid"
)

func (k *KubernetesGather) getPodNodes() (podNodes []model.PodNode, nodeNetwork, podNetwork model.Network, err error) {
	log.Debug("get nodes starting")
	podNetworkCIDRs := []string{}
	nodeLcuuidToHostName, err := cloudcommon.GetNodeHostNameByDomain(k.Lcuuid, k.isSubDomain)
	if err != nil {
		log.Warningf("get pod node hostname error : (%s)", err.Error())
	}
	for _, n := range k.k8sInfo["*v1.Node"] {
		nData, nErr := simplejson.NewJson([]byte(n))
		if nErr != nil {
			err = nErr
			log.Errorf("node initialization simplejson error: (%s)", nErr.Error())
			return
		}
		metaData, ok := nData.CheckGet("metadata")
		if !ok {
			log.Info("node metadata not found")
			continue
		}
		uID := metaData.Get("uid").MustString()
		if uID == "" {
			log.Info("node uid not found")
			continue
		}
		name := metaData.Get("name").MustString()
		if name == "" {
			log.Infof("node (%s) name not found", uID)
			continue
		}
		nodeIPItems := nData.Get("status").Get("addresses")
		nodeIPs := []string{}
		for i := range nodeIPItems.MustArray() {
			nodeIPitem := nodeIPItems.GetIndex(i)
			if nodeIPitem.Get("type").MustString() != "InternalIP" {
				continue
			}
			nIP := nodeIPitem.Get("address").MustString()
			nodeIPs = append(nodeIPs, nIP)
		}
		if len(nodeIPs) == 0 {
			log.Infof("node (%s) ip not found", name)
			continue
		}
		nodeIP := nodeIPs[0]
		labels := metaData.Get("labels").MustMap()
		nodeType := common.POD_NODE_TYPE_NODE
		// support k8s version less than 1.20
		_, masterOK := labels["node-role.kubernetes.io/master"]
		// support k8s version equal or great than 1.20
		_, controlPlaneOK := labels["node-role.kubernetes.io/control-plane"]
		if masterOK || controlPlaneOK {
			nodeType = common.POD_NODE_TYPE_MASTER
		}
		statusConditions := nData.Get("status").Get("conditions")
		statusReasons := []string{}
		for i := range statusConditions.MustArray() {
			statusCondition := statusConditions.GetIndex(i)
			statusReason := statusCondition.Get("reason").MustString()
			if statusReason == "KubeletReady" {
				statusReasons = append(statusReasons, statusCondition.Get("status").MustString())
			}
		}
		state := common.POD_NODE_STATE_EXCEPTION
		if len(statusReasons) != 0 && statusReasons[0] == "True" {
			state = common.POD_NODE_STATE_NORMAL
		}
		capacity := nData.Get("status").Get("capacity")
		memoryCapacity := capacity.Get("memory").MustString()
		memoryStr := strings.Replace(memoryCapacity, "Ki", "", -1)
		memoryInt, err := strconv.Atoi(memoryStr)
		memory := 0
		if err == nil {
			memory = memoryInt / 1024
		}
		cpuNum, err := strconv.Atoi(capacity.Get("cpu").MustString())
		if err != nil {
			log.Warningf("node (%s) cpu num transition int error", name)
		}
		podNode := model.PodNode{
			Lcuuid:           uID,
			Name:             name,
			Type:             nodeType,
			ServerType:       common.POD_NODE_SERVER_TYPE_HOST,
			State:            state,
			IP:               nodeIP,
			Hostname:         nodeLcuuidToHostName[uID],
			VCPUNum:          cpuNum,
			MemTotal:         memory,
			VPCLcuuid:        k.VPCUUID,
			AZLcuuid:         k.azLcuuid,
			RegionLcuuid:     k.RegionUUID,
			PodClusterLcuuid: k.podClusterLcuuid,
		}
		podNodes = append(podNodes, podNode)
		k.nodeIPToLcuuid[nodeIP] = uID
		podCIDR := nData.Get("spec").Get("podCidr").MustString()
		if podCIDR == "" {
			podCIDR = nData.Get("spec").Get("podCIDR").MustString()
		}
		if podCIDR != "" {
			podNetworkCIDRs = append(podNetworkCIDRs, podCIDR)
		}
	}

	nodeNetworkName := k.Name + "_NODE_NET"
	nodeNetworkLcuuid := common.GetUUID(k.UuidGenerate+nodeNetworkName, uuid.Nil)
	nodeIPs := cloudcommon.StringStringMapKeys(k.nodeIPToLcuuid)
	nodeCIDRs := []string{}
	if len(nodeIPs) != 0 {
		nodeIPv4Prefixes, nodeIPv6Prefixes, tErr := cloudcommon.TidyIPString(nodeIPs)
		if tErr != nil {
			err = tErr
			log.Error("node tidy node ip Error" + tErr.Error())
			return
		}
		if len(nodeIPv4Prefixes) != 0 {
			v4cidrs := cloudcommon.AggregateCIDR(nodeIPv4Prefixes, k.PodNetIPv4CIDRMaxMask)
			nodeCIDRs = append(nodeCIDRs, v4cidrs...)
		}
		if len(nodeIPv6Prefixes) != 0 {
			v6cidrs := cloudcommon.AggregateCIDR(nodeIPv6Prefixes, k.PodNetIPv6CIDRMaxMask)
			nodeCIDRs = append(nodeCIDRs, v6cidrs...)
		}
	}

	nodeNetwork = model.Network{
		Lcuuid:         nodeNetworkLcuuid,
		Name:           nodeNetworkName,
		SegmentationID: 1,
		VPCLcuuid:      k.VPCUUID,
		Shared:         false,
		External:       false,
		NetType:        common.NETWORK_TYPE_WAN,
		AZLcuuid:       k.azLcuuid,
		RegionLcuuid:   k.RegionUUID,
	}

	k.nodeNetworkLcuuidCIDRs = networkLcuuidCIDRs{
		networkLcuuid: nodeNetworkLcuuid,
		cidrs:         nodeCIDRs,
	}

	podNetworkName := k.Name + "_POD_NET"
	podNetworkLcuuid := common.GetUUID(k.UuidGenerate+podNetworkName, uuid.Nil)

	podCIDRs := []string{}
	if len(podNetworkCIDRs) != 0 {
		podIPv4Prefixes, podIPv6Prefixes, tErr := cloudcommon.TidyIPString(podNetworkCIDRs)
		if tErr != nil {
			err = tErr
			log.Error("node tidy pod ip Error" + tErr.Error())
			return
		}
		if len(podIPv4Prefixes) != 0 {
			pv4cidrs := cloudcommon.AggregateCIDR(podIPv4Prefixes, k.PodNetIPv4CIDRMaxMask)
			podCIDRs = append(podCIDRs, pv4cidrs...)
		}
		if len(podIPv6Prefixes) != 0 {
			pv6cidrs := cloudcommon.AggregateCIDR(podIPv6Prefixes, k.PodNetIPv6CIDRMaxMask)
			podCIDRs = append(podCIDRs, pv6cidrs...)
		}
	}

	podNetwork = model.Network{
		Lcuuid:         podNetworkLcuuid,
		Name:           podNetworkName,
		SegmentationID: 1,
		VPCLcuuid:      k.VPCUUID,
		Shared:         false,
		External:       false,
		NetType:        common.NETWORK_TYPE_LAN,
		AZLcuuid:       k.azLcuuid,
		RegionLcuuid:   k.RegionUUID,
	}

	k.podNetworkLcuuidCIDRs = networkLcuuidCIDRs{
		networkLcuuid: podNetworkLcuuid,
		cidrs:         podCIDRs,
	}
	log.Debug("get nodes complete")
	return
}

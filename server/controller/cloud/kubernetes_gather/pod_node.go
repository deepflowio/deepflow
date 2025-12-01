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
	"encoding/json"
	"strconv"
	"strings"

	cloudcommon "github.com/deepflowio/deepflow/server/controller/cloud/common"
	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/libs/logger"
)

func (k *KubernetesGather) getPodNodes() (podNodes []model.PodNode, nodeNetwork, podNetwork model.Network, err error) {
	log.Debug("get nodes starting", logger.NewORGPrefix(k.orgID))
	podNetworkCIDRs := []string{}
	nodeLcuuidToHostName, err := cloudcommon.GetNodeHostNameByDomain(k.Lcuuid, k.isSubDomain, k.db)
	if err != nil {
		log.Warningf("get pod node hostname error : (%s)", err.Error(), logger.NewORGPrefix(k.orgID))
	}
	for _, n := range k.k8sInfo["*v1.Node"] {
		nRaw := json.RawMessage(n)
		nData, nErr := rawMessageToMap(nRaw)
		if nErr != nil {
			err = nErr
			log.Errorf("node initialization json error: (%s)", nErr.Error(), logger.NewORGPrefix(k.orgID))
			return
		}
		metaData, ok := getJSONMap(nData, "metadata")
		if !ok {
			log.Info("node metadata not found", logger.NewORGPrefix(k.orgID))
			continue
		}
		uID := getJSONString(metaData, "uid")
		if uID == "" {
			log.Info("node uid not found", logger.NewORGPrefix(k.orgID))
			continue
		}
		name := getJSONString(metaData, "name")
		if name == "" {
			log.Infof("node (%s) name not found", uID, logger.NewORGPrefix(k.orgID))
			continue
		}
		statusData := getJSONPath(nData, "status")
		nodeIPItems, _ := getJSONArray(statusData, "addresses")
		nodeIPs := []string{}
		for _, nodeIPInterface := range nodeIPItems {
			nodeIPitem, ok := nodeIPInterface.(map[string]interface{})
			if !ok {
				continue
			}
			if getJSONString(nodeIPitem, "type") != "InternalIP" {
				continue
			}
			nIP := getJSONString(nodeIPitem, "address")
			if nIP == "" {
				log.Warningf("invalid node internal address (%s)", nIP, logger.NewORGPrefix(k.orgID))
				continue
			}
			nodeIPs = append(nodeIPs, nIP)
		}
		if len(nodeIPs) == 0 {
			log.Infof("node (%s) ip not found", name, logger.NewORGPrefix(k.orgID))
			continue
		}
		nodeIP := nodeIPs[0]
		labels, _ := getJSONMap(metaData, "labels")
		nodeType := common.POD_NODE_TYPE_NODE
		// support k8s version less than 1.20
		_, masterOK := labels["node-role.kubernetes.io/master"]
		// support k8s version equal or great than 1.20
		_, controlPlaneOK := labels["node-role.kubernetes.io/control-plane"]
		if masterOK || controlPlaneOK {
			nodeType = common.POD_NODE_TYPE_MASTER
		}
		statusConditions, _ := getJSONArray(statusData, "conditions")
		statusReasons := []string{}
		for _, statusConditionInterface := range statusConditions {
			statusCondition, ok := statusConditionInterface.(map[string]interface{})
			if !ok {
				continue
			}
			statusReason := getJSONString(statusCondition, "reason")
			if statusReason == "KubeletReady" {
				statusReasons = append(statusReasons, getJSONString(statusCondition, "status"))
			}
		}
		state := common.POD_NODE_STATE_EXCEPTION
		if len(statusReasons) != 0 && statusReasons[0] == "True" {
			state = common.POD_NODE_STATE_NORMAL
		}
		capacity, _ := getJSONMap(statusData, "capacity")
		memoryCapacity := interfaceToString(capacity["memory"])
		memoryStr := strings.Replace(memoryCapacity, "Ki", "", -1)
		memoryInt, err := strconv.Atoi(memoryStr)
		memory := 0
		if err == nil {
			memory = memoryInt / 1024
		}
		cpuNum, err := strconv.Atoi(interfaceToString(capacity["cpu"]))
		if err != nil {
			log.Warningf("node (%s) cpu num transition int error", name, logger.NewORGPrefix(k.orgID))
		}
		uLcuuid := common.IDGenerateUUID(k.orgID, uID)
		podNode := model.PodNode{
			Lcuuid:           uLcuuid,
			Name:             name,
			Type:             nodeType,
			ServerType:       common.POD_NODE_SERVER_TYPE_HOST,
			State:            state,
			IP:               nodeIP,
			Hostname:         nodeLcuuidToHostName[uLcuuid],
			VCPUNum:          cpuNum,
			MemTotal:         memory,
			VPCLcuuid:        k.VPCUUID,
			AZLcuuid:         k.azLcuuid,
			RegionLcuuid:     k.RegionUUID,
			PodClusterLcuuid: k.podClusterLcuuid,
		}
		podNodes = append(podNodes, podNode)
		k.nodeIPToLcuuid[nodeIP] = uLcuuid
		specData := getJSONPath(nData, "spec")
		podCIDR := getJSONString(specData, "podCidr")
		if podCIDR == "" {
			podCIDR = getJSONString(specData, "podCIDR")
		}
		if podCIDR != "" {
			podNetworkCIDRs = append(podNetworkCIDRs, podCIDR)
		}
	}

	nodeNetworkName := k.Name + "_NODE_NET"
	nodeNetworkLcuuid := common.GetUUIDByOrgID(k.orgID, k.UuidGenerate+nodeNetworkName)
	nodeIPs := cloudcommon.StringStringMapKeys(k.nodeIPToLcuuid)
	nodeCIDRs := []string{}
	if len(nodeIPs) != 0 {
		nodeIPv4Prefixes, nodeIPv6Prefixes, tErr := cloudcommon.TidyIPString(nodeIPs)
		if tErr != nil {
			err = tErr
			log.Error("node tidy node ip Error"+tErr.Error(), logger.NewORGPrefix(k.orgID))
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
	podNetworkLcuuid := common.GetUUIDByOrgID(k.orgID, k.UuidGenerate+podNetworkName)

	podCIDRs := []string{}
	if len(podNetworkCIDRs) != 0 {
		podIPv4Prefixes, podIPv6Prefixes, tErr := cloudcommon.TidyIPString(podNetworkCIDRs)
		if tErr != nil {
			err = tErr
			log.Error("node tidy pod ip Error"+tErr.Error(), logger.NewORGPrefix(k.orgID))
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
	log.Debug("get nodes complete", logger.NewORGPrefix(k.orgID))
	return
}

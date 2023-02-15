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

package vtap

import (
	"github.com/deepflowio/deepflow/message/trident"

	. "github.com/deepflowio/deepflow/server/controller/common"
	. "github.com/deepflowio/deepflow/server/controller/trisolaris/common"
	. "github.com/deepflowio/deepflow/server/controller/trisolaris/utils"
)

/*
   segment下发规则
   - 向专属服务器类型的采集器下发的remote_segment
     - 当平台中含有Gateway类型的宿主机时Remote Segment等于所有Gateway类型宿主机的MAC地址
     - 否则Remote Segment等于所有没有其他类型采集器覆盖的MAC地址
   - 向KVM，Hyper-V，EXSi类型的采集器下发的local_segment，需要包含所在宿主机的接口列表
     - 所在运行环境中所有VM的接口列表
     - 所在运行环境中所有VM上运行容器节点及POD的接口列表
     - 所在运行环境对应宿主机的接口列表
   - 向Workload-P类型的采集器下发的local_segment，无需包含所在宿主机的接口列表
     - 所在运行环境（VM）的接口列表
   - 向Workload-V类型的采集器下发的local_segment，无需包含所在宿主机的接口列表
     - 所在运行环境中VM的接口列表
     - `注意`：当对接VM上POD后，采集器会自动更新为容器-V，所以不存在下发VM上运行POD的接口列表场景
   - 向容器-P，容器-V类型的采集器下发的local_segment，无需包含所在宿主机的接口列表
     - 所在运行环境中VM的接口列表
     - 所在运行环境中VM上运行容器节点及POD的接口列表
   - 向隧道解封装类型的采集器无需下发local_segment和remote_egment
*/

var serverVTap []int = []int{VTAP_TYPE_KVM, VTAP_TYPE_HYPER_V, VTAP_TYPE_HYPER_V_NETWORK}
var podVTap []int = []int{VTAP_TYPE_POD_HOST, VTAP_TYPE_POD_VM}
var workloadVTap []int = []int{VTAP_TYPE_WORKLOAD_P, VTAP_TYPE_WORKLOAD_V}
var noLocalSegments []int = []int{VTAP_TYPE_DEDICATED, VTAP_TYPE_TUNNEL_DECAPSULATION}

func (v *VTapInfo) GenerateVTapLocalSegments(c *VTapCache) []*trident.Segment {
	var localSegments []*trident.Segment
	vtapType := c.GetVTapType()
	launchServer := c.GetLaunchServer()
	launchServerID := c.GetLaunchServerID()
	rawData := v.metaData.GetPlatformDataOP().GetRawData()
	segment := v.metaData.GetPlatformDataOP().GetSegment()
	podNodeIDToVmID := rawData.GetPodNodeIDToVmID()

	if vtapType == VTAP_TYPE_ESXI {
		localSegments = segment.GetTypeVMSegments(launchServer, launchServerID)
	} else if Find[int](serverVTap, vtapType) {
		launchServerSegments := segment.GetLaunchServerSegments(launchServer)
		hostIDSegments := segment.GetHostIDSegments(launchServerID)
		localSegments = make([]*trident.Segment, 0, len(launchServerSegments)+len(hostIDSegments))
		localSegments = append(localSegments, launchServerSegments...)
		localSegments = append(localSegments, hostIDSegments...)
	} else if Find[int](workloadVTap, vtapType) {
		if launchServerID != 0 {
			localSegments = segment.GetVMIDSegments(launchServerID)
		}
	} else if Find[int](podVTap, vtapType) {
		if vmID, ok := podNodeIDToVmID[launchServerID]; ok {
			// pod_node和vm有关联，获取vm上所有segments包括(vm, pod_node, pod)
			localSegments = segment.GetVMIDSegments(vmID)
		} else {
			// 无关联获取pod_node所有segments包括(pod_node, pod)
			localSegments = segment.GetPodNodeSegments(launchServerID)
		}
	} else if Find[int](noLocalSegments, vtapType) {
		// 专属采集器，隧道解封装采集器没有local segments
		return localSegments
	} else {
		log.Errorf("vtap type(%d) not found", vtapType)
	}

	return localSegments
}

func (v *VTapInfo) GenerateRemoteSegments() []*trident.Segment {
	rawData := v.metaData.GetPlatformDataOP().GetRawData()
	segment := v.metaData.GetPlatformDataOP().GetSegment()
	allGatewayHostSegments := segment.GetAllGatewayHostSegments()
	if len(allGatewayHostSegments) > 0 {
		return allGatewayHostSegments
	}
	segment.GenerateNoVTapUsedSegments(rawData)
	return segment.GetNotVtapUsedSegments()
}

func (v *VTapInfo) GetRemoteSegment(c *VTapCache) []*trident.Segment {
	if c.GetVTapType() != VTAP_TYPE_DEDICATED {
		return nil
	}

	return v.remoteSegments
}

func (v *VTapInfo) generateAllVTapSegements() {
	bmDedicatedVTaps := []*VTapCache{}
	segment := v.metaData.GetPlatformDataOP().GetSegment()
	segment.ClearVTapUsedVInterfaceIDs()
	cacheKeys := v.vTapCaches.List()
	for _, cacheKey := range cacheKeys {
		cacheVTap := v.GetVTapCache(cacheKey)
		if cacheVTap == nil {
			continue
		}
		if cacheVTap.GetVTapType() == VTAP_TYPE_DEDICATED {
			bmDedicatedVTaps = append(bmDedicatedVTaps, cacheVTap)
		}
		localSegments := v.GenerateVTapLocalSegments(cacheVTap)
		cacheVTap.setVTapLocalSegments(localSegments)
	}

	remoteSegments := v.GenerateRemoteSegments()
	// 专属采集器下发本区域所有采集器(除专属采集器)下发的local_segment，作为专属采集器的remote_segment
	for _, bmVTap := range bmDedicatedVTaps {
		bmVTap.setVTapRemoteSegments(remoteSegments)
	}
	v.remoteSegments = remoteSegments
}

func (v *VTapInfo) generateAllVTapRemoteSegements() {
	dedicatedVTaps := []*VTapCache{}
	cacheKeys := v.vTapCaches.List()
	for _, cacheKey := range cacheKeys {
		cacheVTap := v.GetVTapCache(cacheKey)
		if cacheVTap == nil {
			continue
		}
		if cacheVTap.GetVTapType() == VTAP_TYPE_DEDICATED {
			dedicatedVTaps = append(dedicatedVTaps, cacheVTap)
		}
	}
	remoteSegments := v.GenerateRemoteSegments()
	// 专属采集器下发本区域所有采集器(除专属采集器)下发的local_segment，作为专属采集器的remote_segment
	for _, bmVTap := range dedicatedVTaps {
		bmVTap.setVTapRemoteSegments(remoteSegments)
	}
	v.remoteSegments = remoteSegments
}

func (v *VTapInfo) setVTapChangedForSegment() {
	v.isVTapChangedForSegment.Set()
}

func (v *VTapInfo) unsetVTapChangedForSegment() {
	v.isVTapChangedForSegment.Unset()
}

func (v *VTapInfo) putChVTapChangedForSegment() {
	select {
	case v.chVTapChangedForSegment <- struct{}{}:
	default:
		break
	}
}

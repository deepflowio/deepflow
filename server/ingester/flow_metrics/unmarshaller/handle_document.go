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

package unmarshaller

import (
	"fmt"
	"net"

	"github.com/deepflowio/deepflow/server/ingester/common"
	"github.com/deepflowio/deepflow/server/libs/app"
	"github.com/deepflowio/deepflow/server/libs/ckdb"
	"github.com/deepflowio/deepflow/server/libs/datatype"
	flow_metrics "github.com/deepflowio/deepflow/server/libs/flow-metrics"
	"github.com/deepflowio/deepflow/server/libs/grpc"
	"github.com/deepflowio/deepflow/server/libs/utils"
)

const (
	EdgeCode    = flow_metrics.IPPath | flow_metrics.L3EpcIDPath
	MainAddCode = flow_metrics.RegionID | flow_metrics.HostID | flow_metrics.L3Device | flow_metrics.SubnetID | flow_metrics.PodNodeID | flow_metrics.AZID | flow_metrics.PodGroupID | flow_metrics.PodNSID | flow_metrics.PodID | flow_metrics.PodClusterID | flow_metrics.ServiceID | flow_metrics.Resource
	EdgeAddCode = flow_metrics.RegionIDPath | flow_metrics.HostIDPath | flow_metrics.L3DevicePath | flow_metrics.SubnetIDPath | flow_metrics.PodNodeIDPath | flow_metrics.AZIDPath | flow_metrics.PodGroupIDPath | flow_metrics.PodNSIDPath | flow_metrics.PodIDPath | flow_metrics.PodClusterIDPath | flow_metrics.ServiceIDPath | flow_metrics.ResourcePath
	PortAddCode = flow_metrics.IsKeyService

	SIGNAL_SOURCE_OTEL = 4
)

func getPlatformInfos(t *flow_metrics.Tag, platformData *grpc.PlatformInfoTable) (*grpc.Info, *grpc.Info) {
	var info, info1 *grpc.Info
	if t.L3EpcID != datatype.EPC_FROM_INTERNET {
		// if the GpId exists but the podId does not exist, first obtain the podId through the GprocessId table delivered by the Controller
		if t.GPID != 0 && t.PodID == 0 {
			vtapId, podId := platformData.QueryGprocessInfo(t.GPID)
			if podId != 0 && vtapId == t.VTAPID {
				t.PodID = podId
				t.TagSource |= uint8(flow_metrics.GpId)
			}
		}

		// if podId exist, use vtapId + podId to match first
		if t.PodID != 0 {
			info = platformData.QueryPodIdInfo(t.PodID)
			t.TagSource |= uint8(flow_metrics.PodId)
		}

		// If vtapId + podId cannot be matched, finally use Mac/EpcIP to match resources
		if info == nil {
			if t.MAC != 0 {
				t.TagSource |= uint8(flow_metrics.Mac)
				info = platformData.QueryMacInfo(t.MAC | uint64(t.L3EpcID)<<48)
				if info == nil {
					t.TagSource |= uint8(flow_metrics.EpcIP)
					info = common.RegetInfoFromIP(t.IsIPv4 == 0, t.IP6, t.IP, t.L3EpcID, platformData)
				}
			} else if t.IsIPv4 == 0 {
				t.TagSource |= uint8(flow_metrics.EpcIP)
				info = platformData.QueryIPV6Infos(t.L3EpcID, t.IP6)
			} else {
				t.TagSource |= uint8(flow_metrics.EpcIP)
				info = platformData.QueryIPV4Infos(t.L3EpcID, t.IP)
			}
		}
	}

	if t.Code&EdgeCode == EdgeCode && t.L3EpcID1 != datatype.EPC_FROM_INTERNET {
		if t.GPID1 != 0 && t.PodID1 == 0 {
			vtapId, podId := platformData.QueryGprocessInfo(t.GPID1)
			if podId != 0 && vtapId == t.VTAPID {
				t.PodID1 = podId
				t.TagSource1 |= uint8(flow_metrics.GpId)
			}

		}

		if t.PodID1 != 0 {
			info1 = platformData.QueryPodIdInfo(t.PodID1)
			t.TagSource1 |= uint8(flow_metrics.PodId)
		}

		if info1 == nil {
			if t.MAC1 != 0 {
				t.TagSource1 |= uint8(flow_metrics.Mac)
				info1 = platformData.QueryMacInfo(t.MAC1 | uint64(t.L3EpcID1)<<48)
				if info1 == nil {
					t.TagSource1 |= uint8(flow_metrics.EpcIP)
					info1 = common.RegetInfoFromIP(t.IsIPv4 == 0, t.IP61, t.IP1, t.L3EpcID1, platformData)
				}
			} else if t.IsIPv4 == 0 {
				t.TagSource1 |= uint8(flow_metrics.EpcIP)
				info1 = platformData.QueryIPV6Infos(t.L3EpcID1, t.IP61)
			} else {
				t.TagSource1 |= uint8(flow_metrics.EpcIP)
				info1 = platformData.QueryIPV4Infos(t.L3EpcID1, t.IP1)
			}
		}
	}

	return info, info1
}

func DocumentExpand(doc app.Document, platformData *grpc.PlatformInfoTable) error {
	t := doc.Tags()
	t.SetID("") // 由于需要修改Tag增删Field，清空ID避免字段脏

	// vtap_acl 分钟级数据不用填充
	if doc.Meter().ID() == flow_metrics.ACL_ID &&
		t.DatabaseSuffixID() == 1 { // 只有acl后缀
		return nil
	}

	myRegionID := uint16(platformData.QueryRegionID())

	if t.Code&flow_metrics.ServerPort == flow_metrics.ServerPort {
		t.Code |= PortAddCode
	}

	info, info1 := getPlatformInfos(t, platformData)
	if t.Code&EdgeCode == EdgeCode {
		t.Code |= EdgeAddCode
	} else {
		t.Code |= MainAddCode
	}

	t.OrgId, t.TeamID = platformData.QueryVtapOrgAndTeamID(t.VTAPID)
	podGroupType, podGroupType1 := uint8(0), uint8(0)
	if info1 != nil {
		t.RegionID1 = uint16(info1.RegionID)
		t.HostID1 = uint16(info1.HostID)
		t.L3DeviceID1 = info1.DeviceID
		t.L3DeviceType1 = flow_metrics.DeviceType(info1.DeviceType)
		t.SubnetID1 = uint16(info1.SubnetID)
		t.PodNodeID1 = info1.PodNodeID
		t.PodNSID1 = uint16(info1.PodNSID)
		t.AZID1 = uint16(info1.AZID)
		t.PodGroupID1 = info1.PodGroupID
		podGroupType1 = info1.PodGroupType
		t.PodID1 = info1.PodID
		t.PodClusterID1 = uint16(info1.PodClusterID)
		if common.IsPodServiceIP(t.L3DeviceType1, t.PodID1, t.PodNodeID1) {
			t.ServiceID1 = platformData.QueryService(t.PodID1, t.PodNodeID1, uint32(t.PodClusterID1), t.PodGroupID1, t.L3EpcID1, t.IsIPv4 == 0, t.IP1, t.IP61, t.Protocol, t.ServerPort)
		}
		if info == nil {
			var ip0 net.IP
			if t.IsIPv4 == 0 {
				ip0 = t.IP6
			} else {
				ip0 = utils.IpFromUint32(t.IP)
			}
			// 当0侧是组播ip时，使用1侧的region_id,subnet_id,az_id来填充
			if ip0.IsMulticast() {
				t.RegionID = t.RegionID1
				t.SubnetID = t.SubnetID1
				t.AZID = t.AZID1
				t.TagSource |= uint8(flow_metrics.Peer)
			}
		}
		// under multiple Orgs, the Analyzer needs to store data from multiple Regions and only verifies whether the Region of the Default Org is correct.
		if ckdb.IsDefaultOrgID(t.OrgId) && myRegionID != 0 && t.RegionID1 != 0 {
			if t.TAPSide == flow_metrics.Server && t.RegionID1 != myRegionID { // 对于双端 的统计值，需要去掉 observation_point 对应的一侧与自身region_id 不匹配的内容。
				platformData.AddOtherRegion()
				return fmt.Errorf("My regionID is %d, but document regionID1 is %d", myRegionID, t.RegionID1)
			}
		}
	}
	t.AutoInstanceID1, t.AutoInstanceType1 = common.GetAutoInstance(t.PodID1, t.GPID1, t.PodNodeID1, t.L3DeviceID1, uint8(t.L3DeviceType1), t.L3EpcID1)
	t.AutoServiceID1, t.AutoServiceType1 = common.GetAutoService(t.ServiceID1, t.PodGroupID1, t.GPID1, t.PodNodeID1, t.L3DeviceID1, uint8(t.L3DeviceType1), podGroupType1, t.L3EpcID1)

	if info != nil {
		t.RegionID = uint16(info.RegionID)
		t.HostID = uint16(info.HostID)
		t.L3DeviceID = info.DeviceID
		t.L3DeviceType = flow_metrics.DeviceType(info.DeviceType)
		t.SubnetID = uint16(info.SubnetID)
		t.PodNodeID = info.PodNodeID
		t.PodNSID = uint16(info.PodNSID)
		t.AZID = uint16(info.AZID)
		t.PodGroupID = info.PodGroupID
		podGroupType = info.PodGroupType
		t.PodID = info.PodID
		t.PodClusterID = uint16(info.PodClusterID)
		if common.IsPodServiceIP(t.L3DeviceType, t.PodID, t.PodNodeID) {
			//for a single-side table (vtap_xxx_port), if ServerPort is valid, it needs to match the serviceID
			if t.ServerPort > 0 && t.Code&EdgeCode == 0 {
				t.ServiceID = platformData.QueryService(t.PodID, t.PodNodeID, uint32(t.PodClusterID), t.PodGroupID, t.L3EpcID, t.IsIPv4 == 0, t.IP, t.IP6, t.Protocol, t.ServerPort)
				// for the 0-side of the double-side table (vtap_xxx_edge_port) or serverPort is invalid, if it is PodServiceIP, then need to match the serviceID
			} else if common.IsPodServiceIP(t.L3DeviceType, t.PodID, 0) { //On the 0 side, if it is just Pod Node, there is no need to match the service
				t.ServiceID = platformData.QueryService(t.PodID, t.PodNodeID, uint32(t.PodClusterID), t.PodGroupID, t.L3EpcID, t.IsIPv4 == 0, t.IP, t.IP6, t.Protocol, 0)
			}
		}
		if info1 == nil && (t.Code&EdgeCode == EdgeCode) {
			var ip1 net.IP
			if t.IsIPv4 == 0 {
				ip1 = t.IP61
			} else {
				ip1 = utils.IpFromUint32(t.IP1)
			}
			// 当1侧是组播ip时，使用0侧的region_id,subnet_id,az_id来填充
			if ip1.IsMulticast() {
				t.RegionID1 = t.RegionID
				t.SubnetID1 = t.SubnetID
				t.AZID1 = t.AZID
				t.TagSource1 |= uint8(flow_metrics.Peer)
			}
		}
		// under multiple Orgs, the Analyzer needs to store data from multiple Regions and only verifies whether the Region of the Default Org is correct.
		if ckdb.IsDefaultOrgID(t.OrgId) && myRegionID != 0 && t.RegionID != 0 {
			if t.Code&EdgeCode == EdgeCode { // 对于双端 的统计值，需要去掉 observation_point 对应的一侧与自身region_id 不匹配的内容。
				if t.TAPSide == flow_metrics.Client && t.RegionID != myRegionID {
					platformData.AddOtherRegion()
					return fmt.Errorf("My regionID is %d, but document regionID is %d", myRegionID, t.RegionID)
				}
			} else { // 对于单端的统计值，需要去掉与自身region_id不匹配的内容
				if t.RegionID != myRegionID {
					platformData.AddOtherRegion()
					return fmt.Errorf("My regionID is %d, but document regionID is %d", myRegionID, t.RegionID)
				}
			}
		}
	}
	t.AutoInstanceID, t.AutoInstanceType = common.GetAutoInstance(t.PodID, t.GPID, t.PodNodeID, t.L3DeviceID, uint8(t.L3DeviceType), t.L3EpcID)
	t.AutoServiceID, t.AutoServiceType = common.GetAutoService(t.ServiceID, t.PodGroupID, t.GPID, t.PodNodeID, t.L3DeviceID, uint8(t.L3DeviceType), podGroupType, t.L3EpcID)

	if t.SignalSource == SIGNAL_SOURCE_OTEL {
		// only show OTel data for services as 'server side'
		if t.TAPSide == flow_metrics.ServerApp && t.ServerPort == 0 {
			t.ServerPort = 65535
		}

		// OTel data always not from INTERNET
		if t.L3EpcID == datatype.EPC_FROM_INTERNET {
			t.L3EpcID = datatype.EPC_UNKNOWN
		}
		if t.L3EpcID1 == datatype.EPC_FROM_INTERNET {
			t.L3EpcID1 = datatype.EPC_UNKNOWN
		}
		if t.AutoServiceType == common.InternetIpType {
			t.AutoServiceType = common.IpType
		}
		if t.AutoServiceType1 == common.InternetIpType {
			t.AutoServiceType1 = common.IpType
		}
		if t.AutoInstanceType == common.InternetIpType {
			t.AutoInstanceType = common.IpType
		}
		if t.AutoInstanceType1 == common.InternetIpType {
			t.AutoInstanceType1 = common.IpType
		}
	}

	return nil
}

package unmarshaller

import (
	"net"

	"gitlab.yunshan.net/yunshan/droplet-libs/app"
	"gitlab.yunshan.net/yunshan/droplet-libs/datatype"
	"gitlab.yunshan.net/yunshan/droplet-libs/grpc"
	"gitlab.yunshan.net/yunshan/droplet-libs/utils"
	"gitlab.yunshan.net/yunshan/droplet-libs/zerodoc"
	"gitlab.yunshan.net/yunshan/droplet/roze/msg"
)

const (
	EdgeCode    = zerodoc.IPPath | zerodoc.L3EpcIDPath
	MainAddCode = zerodoc.RegionID | zerodoc.HostID | zerodoc.L3Device | zerodoc.SubnetID | zerodoc.PodNodeID | zerodoc.AZID | zerodoc.PodGroupID | zerodoc.PodNSID | zerodoc.PodID | zerodoc.PodClusterID | zerodoc.BusinessIDs | zerodoc.GroupIDs
	EdgeAddCode = zerodoc.RegionIDPath | zerodoc.HostIDPath | zerodoc.L3DevicePath | zerodoc.SubnetIDPath | zerodoc.PodNodeIDPath | zerodoc.AZIDPath | zerodoc.PodGroupIDPath | zerodoc.PodNSIDPath | zerodoc.PodIDPath | zerodoc.PodClusterIDPath | zerodoc.BusinessIDsPath | zerodoc.GroupIDsPath
	PortAddCode = zerodoc.IsKeyService
)

func releaseRozeDocument(rd *msg.RozeDocument) {
	rd.Document = nil
	msg.ReleaseRozeDocument(rd)
}

func DocToRozeDocuments(doc *app.Document, platformData *grpc.PlatformInfoTable) *msg.RozeDocument {
	rd := msg.AcquireRozeDocument()
	rd.Document = doc
	t := doc.Tag.(*zerodoc.Tag)
	t.SetID("") // 由于需要修改Tag增删Field，清空ID避免字段脏

	// vtap_acl 分钟级数据不用填充
	if doc.Meter.ID() == zerodoc.PACKET_ID &&
		t.DatabaseSuffixID() == 1 { // 只有acl后缀
		return rd
	}

	var info, info1 *grpc.Info
	myRegionID := uint16(platformData.QueryRegionID())
	if t.Code&zerodoc.ServerPort == zerodoc.ServerPort {
		t.Code |= PortAddCode
	}
	if t.Code&EdgeCode == EdgeCode {
		t.Code |= EdgeAddCode

		if t.L3EpcID == datatype.EPC_FROM_INTERNET && t.L3EpcID1 == datatype.EPC_FROM_INTERNET {
			return rd
		}

		// 当MAC/MAC1非0时，通过MAC来获取资源信息
		if t.MAC != 0 && t.MAC1 != 0 {
			info, info1 = platformData.QueryMacInfosPair(t.MAC|uint64(t.L3EpcID)<<48, t.MAC1|uint64(t.L3EpcID1)<<48)
		} else if t.MAC != 0 {
			info = platformData.QueryMacInfo(t.MAC | uint64(t.L3EpcID)<<48)
			if t.IsIPv6 != 0 {
				info1 = platformData.QueryIPV6Infos(t.L3EpcID1, t.IP61)
			} else {
				info1 = platformData.QueryIPV4Infos(t.L3EpcID1, t.IP1)
			}
		} else if t.MAC1 != 0 {
			if t.IsIPv6 != 0 {
				info = platformData.QueryIPV6Infos(t.L3EpcID, t.IP6)
			} else {
				info = platformData.QueryIPV4Infos(t.L3EpcID, t.IP)
			}
			info1 = platformData.QueryMacInfo(t.MAC1 | uint64(t.L3EpcID1)<<48)
		} else if t.IsIPv6 != 0 {
			info, info1 = platformData.QueryIPV6InfosPair(t.L3EpcID, t.IP6, t.L3EpcID1, t.IP61)
		} else {
			info, info1 = platformData.QueryIPV4InfosPair(t.L3EpcID, t.IP, t.L3EpcID1, t.IP1)
		}
		if info1 != nil {
			t.RegionID1 = uint16(info1.RegionID)
			t.HostID1 = uint16(info1.HostID)
			t.L3DeviceID1 = info1.DeviceID
			t.L3DeviceType1 = zerodoc.DeviceType(info1.DeviceType)
			t.SubnetID1 = uint16(info1.SubnetID)
			t.PodNodeID1 = info1.PodNodeID
			t.PodNSID1 = uint16(info1.PodNSID)
			t.AZID1 = uint16(info1.AZID)
			t.PodGroupID1 = info1.PodGroupID
			t.PodID1 = info1.PodID
			t.PodClusterID1 = uint16(info1.PodClusterID)
			if t.IsIPv6 != 0 {
				t.GroupIDs1, t.BusinessIDs1 = platformData.QueryIPv6GroupIDsAndBusinessIDs(t.L3EpcID1, t.IP61)
				if t.Code&PortAddCode != 0 {
					if platformData.QueryIPv6IsKeyService(t.L3EpcID1, t.IP61, t.Protocol, t.ServerPort) {
						t.IsKeyService = 1
					}
				}
			} else {
				t.GroupIDs1, t.BusinessIDs1 = platformData.QueryGroupIDsAndBusinessIDs(t.L3EpcID1, t.IP1)
				if t.Code&PortAddCode != 0 {
					if platformData.QueryIsKeyService(t.L3EpcID1, t.IP1, t.Protocol, t.ServerPort) {
						t.IsKeyService = 1
					}
				}
			}
			if info == nil {
				var ip0 net.IP
				if t.IsIPv6 != 0 {
					ip0 = t.IP6
				} else {
					ip0 = utils.IpFromUint32(t.IP)
				}
				// 当0侧是组播ip时，使用1侧的region_id,subnet_id,az_id来填充
				if ip0.IsMulticast() {
					t.RegionID = t.RegionID1
					t.SubnetID = t.SubnetID1
					t.AZID = t.AZID1
				}
			}
			if myRegionID != 0 && t.RegionID1 != 0 {
				if t.TAPSide == zerodoc.Server && t.RegionID1 != myRegionID { // 对于双端 的统计值，需要去掉 tap_side 对应的一侧与自身region_id 不匹配的内容。
					releaseRozeDocument(rd)
					platformData.AddOtherRegion()
					return nil
				}
			}
		}
	} else {
		t.Code |= MainAddCode
		if t.L3EpcID == datatype.EPC_FROM_INTERNET {
			return rd
		}

		if t.MAC != 0 {
			info = platformData.QueryMacInfo(t.MAC | uint64(t.L3EpcID)<<48)
		} else if t.IsIPv6 != 0 {
			info = platformData.QueryIPV6Infos(t.L3EpcID, t.IP6)
		} else {
			info = platformData.QueryIPV4Infos(t.L3EpcID, t.IP)
		}
	}

	if info != nil {
		t.RegionID = uint16(info.RegionID)
		t.HostID = uint16(info.HostID)
		t.L3DeviceID = info.DeviceID
		t.L3DeviceType = zerodoc.DeviceType(info.DeviceType)
		t.SubnetID = uint16(info.SubnetID)
		t.PodNodeID = info.PodNodeID
		t.PodNSID = uint16(info.PodNSID)
		t.AZID = uint16(info.AZID)
		t.PodGroupID = info.PodGroupID
		t.PodID = info.PodID
		t.PodClusterID = uint16(info.PodClusterID)
		if t.IsIPv6 != 0 {
			t.GroupIDs, t.BusinessIDs = platformData.QueryIPv6GroupIDsAndBusinessIDs(t.L3EpcID, t.IP6)
			if t.Code&PortAddCode != 0 && t.Code&EdgeCode == 0 {
				if platformData.QueryIPv6IsKeyService(t.L3EpcID, t.IP6, t.Protocol, t.ServerPort) {
					t.IsKeyService = 1
				}
			}
		} else {
			t.GroupIDs, t.BusinessIDs = platformData.QueryGroupIDsAndBusinessIDs(t.L3EpcID, t.IP)
			if t.Code&PortAddCode != 0 && t.Code&EdgeCode == 0 {
				if platformData.QueryIsKeyService(t.L3EpcID, t.IP, t.Protocol, t.ServerPort) {
					t.IsKeyService = 1
				}
			}
		}
		if info1 == nil && (t.Code&EdgeCode == EdgeCode) {
			var ip1 net.IP
			if t.IsIPv6 != 0 {
				ip1 = t.IP61
			} else {
				ip1 = utils.IpFromUint32(t.IP1)
			}
			// 当1侧是组播ip时，使用0侧的region_id,subnet_id,az_id来填充
			if ip1.IsMulticast() {
				t.RegionID1 = t.RegionID
				t.SubnetID1 = t.SubnetID
				t.AZID1 = t.AZID
			}
		}

		if myRegionID != 0 && t.RegionID != 0 {
			if t.Code&EdgeCode == EdgeCode { // 对于双端 的统计值，需要去掉 tap_side 对应的一侧与自身region_id 不匹配的内容。
				if t.TAPSide == zerodoc.Client && t.RegionID != myRegionID {
					releaseRozeDocument(rd)
					platformData.AddOtherRegion()
					return nil
				}
			} else { // 对于单端的统计值，需要去掉与自身region_id不匹配的内容
				if t.RegionID != myRegionID {
					releaseRozeDocument(rd)
					platformData.AddOtherRegion()
					return nil
				}
			}
		}
	}

	return rd
}

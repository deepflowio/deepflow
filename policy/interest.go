package policy

import (
	"math"

	. "gitlab.x.lan/yunshan/droplet-libs/datatype"
)

type InterestTable struct {
	groupIdMaps         map[uint32]int
	groupIdFromPlatform []uint32
	groupIdFromIpGroup  []uint32

	InterestProtoMaps *[TAP_MAX][math.MaxUint8 + 1]bool
	InterestPortMaps  *[TAP_MAX][math.MaxUint16 + 1]PortRange
}

func (t *InterestTable) Init() {
	t.InterestProtoMaps = &[TAP_MAX][math.MaxUint8 + 1]bool{}
	t.InterestPortMaps = &[TAP_MAX][math.MaxUint16 + 1]PortRange{}
}

func (t *InterestTable) generateGroupIdMap() {
	groupIdMaps := make(map[uint32]int, len(t.groupIdFromPlatform)+len(t.groupIdFromIpGroup))

	for _, id := range t.groupIdFromPlatform {
		groupIdMaps[id] = RESOURCE_GROUP_TYPE_DEV
	}

	// 资源组ID一致的情况，设备资源组优先
	for _, id := range t.groupIdFromIpGroup {
		if groupIdMaps[id] != RESOURCE_GROUP_TYPE_DEV {
			groupIdMaps[id] = RESOURCE_GROUP_TYPE_IP
		}
	}
	t.groupIdMaps = groupIdMaps
}

func (t *InterestTable) GenerateGroupIdMapByIpGroupData(datas []*IpGroupData) {
	t.groupIdFromIpGroup = make([]uint32, len(datas))
	for _, data := range datas {
		t.groupIdFromIpGroup = append(t.groupIdFromIpGroup, data.Id)
	}
	t.generateGroupIdMap()
}

func (t *InterestTable) GenerateGroupIdMapByPlatformData(datas []*PlatformData) {
	t.groupIdFromPlatform = make([]uint32, 1024)
	for _, data := range datas {
		t.groupIdFromPlatform = append(t.groupIdFromPlatform, data.GroupIds...)
	}
	t.generateGroupIdMap()
}

func (t *InterestTable) generateInterestPortMap(acls []*Acl) {
	interestPortMaps := &[TAP_MAX][math.MaxUint16 + 1]PortRange{}
	ports := make([]PortRange, 0, 1000)

	for tapType := TAP_MIN - 1; tapType < TAP_MAX; tapType++ {
		ports = ports[:0]
		for _, acl := range acls {
			if acl.Type == tapType || acl.Type == TAP_ANY || tapType == TAP_ANY {
				ports = append(ports, acl.SrcPortRange...)
				ports = append(ports, acl.DstPortRange...)
			}
		}

		ports = GetPortRanges(ports)

		lastMax, portOther := uint16(0), uint16(0)
		for index, port := range ports {
			if index == 0 {
				lastMax = port.Max()
			} else if portOther != 0 {
				if port.Min()-lastMax > 1 {
					portOther = lastMax + 1
				}
				lastMax = port.Max()
			}

			for i := int(port.Min()); i <= int(port.Max()); i++ {
				interestPortMaps[tapType][i] = port
			}
		}
		if portOther == 0 && math.MaxUint16-lastMax > 1 {
			portOther = lastMax + 1
		}

		if portOther != 0 {
			// portOther为非策略端口中的的第一个端口
			// 为了减少内存，减少fastPath项， 所有不在策略中的端口使用portOther来建立查询fastPath
			for i := 1; i <= math.MaxUint16; i++ {
				if 0 == interestPortMaps[tapType][i] {
					interestPortMaps[tapType][i] = NewPortRange(portOther, portOther)
				}
			}
		}
	}

	for _, acl := range acls {
		for _, port := range acl.SrcPortRange {
			for i := int(port.Min()); i <= int(port.Max()); {
				portRangs := interestPortMaps[acl.Type][i]
				acl.SrcPorts = append(acl.SrcPorts, portRangs.Min())
				i = int(portRangs.Max()) + 1
			}
		}

		for _, port := range acl.DstPortRange {
			for i := int(port.Min()); i <= int(port.Max()); {
				portRangs := interestPortMaps[acl.Type][i]
				acl.DstPorts = append(acl.DstPorts, portRangs.Min())
				i = int(portRangs.Max()) + 1
			}
		}
	}
	t.InterestPortMaps = interestPortMaps
}

func (t *InterestTable) generateInterestProtoMaps(acls []*Acl) {
	interestProtoMaps := &[TAP_MAX][math.MaxUint8 + 1]bool{}

	for _, acl := range acls {
		if !acl.Type.CheckTapType(acl.Type) || acl.Proto == PROTO_ALL {
			continue
		}
		if acl.Type != TAP_ANY {
			interestProtoMaps[acl.Type][acl.Proto] = true
		} else {
			for tapType := TAP_MIN; tapType < TAP_MAX; tapType++ {
				interestProtoMaps[tapType][acl.Proto] = true
			}
		}
	}
	t.InterestProtoMaps = interestProtoMaps
}

func (t *InterestTable) GenerateInterestMaps(acls []*Acl) {
	t.generateInterestPortMap(acls)
	t.generateInterestProtoMaps(acls)
}

func (t *InterestTable) getFastInterestKeys(packet *LookupKey) {
	ports := t.InterestPortMaps[packet.Tap][packet.SrcPort]
	packet.SrcPort = ports.Min()
	ports = t.InterestPortMaps[packet.Tap][packet.DstPort]
	packet.DstPort = ports.Min()
}

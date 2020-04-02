package policy

import (
	"math"

	. "gitlab.x.lan/yunshan/droplet-libs/datatype"
)

type InterestTable struct {
	InterestProtoMaps *[TAP_MAX][math.MaxUint8 + 1]bool
	InterestPortMaps  *[TAP_MAX][math.MaxUint16 + 1]PortRange
}

func (t *InterestTable) Init() {
	t.InterestProtoMaps = &[TAP_MAX][math.MaxUint8 + 1]bool{}
	t.InterestPortMaps = &[TAP_MAX][math.MaxUint16 + 1]PortRange{}
}

func (t *InterestTable) generateInterestPortMap(acls []*Acl) {
	interestPortMaps := &[TAP_MAX][math.MaxUint16 + 1]PortRange{}
	ports := make([]PortRange, 0, 1000)

	for tapType := TAP_MIN - 1; tapType < TAP_MAX; tapType++ {
		ports = ports[:0]
		for _, acl := range acls {
			if acl.TapType == tapType || acl.TapType == TAP_ANY || tapType == TAP_ANY {
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
				portRangs := interestPortMaps[acl.TapType][i]
				acl.SrcPorts = append(acl.SrcPorts, portRangs.Min())
				i = int(portRangs.Max()) + 1
			}
		}

		for _, port := range acl.DstPortRange {
			for i := int(port.Min()); i <= int(port.Max()); {
				portRangs := interestPortMaps[acl.TapType][i]
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
		if !acl.TapType.CheckTapType(acl.TapType) || acl.Proto == PROTO_ALL {
			continue
		}
		if acl.TapType != TAP_ANY {
			interestProtoMaps[acl.TapType][acl.Proto] = true
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
	ports := t.InterestPortMaps[packet.TapType][packet.SrcPort]
	packet.SrcPort = ports.Min()
	ports = t.InterestPortMaps[packet.TapType][packet.DstPort]
	packet.DstPort = ports.Min()
}

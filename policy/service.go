package policy

import (
	"encoding/binary"

	"github.com/cespare/xxhash"

	. "gitlab.x.lan/yunshan/droplet-libs/datatype"
)

type ServiceData struct {
	Id      uint32
	GroupId uint32
	Proto   uint16
	Ports   []uint32
}

type ServiceIds struct {
	SrcIds []uint32
	DstIds []uint32
}

type ServiceTable struct {
	serviceMap map[ServiceKey]*ServiceData
}

func NewSerivceTable() *ServiceTable {
	return &ServiceTable{
		serviceMap: make(map[ServiceKey]*ServiceData),
	}
}

func (s *ServiceTable) UpdateServiceMap(svdata map[ServiceKey]*ServiceData) {
	if svdata != nil {
		s.serviceMap = svdata
	}
}

func calcServiceHashKey(groupid uint32, port uint32, proto uint16) uint64 {
	buf := make([]byte, 10)
	binary.BigEndian.PutUint32(buf, groupid)
	binary.BigEndian.PutUint32(buf[4:], port)
	binary.BigEndian.PutUint16(buf[8:], proto)
	return xxhash.Sum64(buf)
}

func (s *ServiceTable) GenerateServiceTable(servicedatas []*ServiceData) map[ServiceKey]*ServiceData {
	servicemap := make(map[ServiceKey]*ServiceData)
	if servicedatas != nil {
		for _, data := range servicedatas {
			for _, port := range data.Ports {
				hash := calcServiceHashKey(data.GroupId, port, data.Proto)
				servicemap[ServiceKey(hash)] = data
			}
		}
	}
	return servicemap
}

func (s *ServiceTable) UpdateServiceTable(servicedatas []*ServiceData) {
	s.UpdateServiceMap(s.GenerateServiceTable(servicedatas))
}

func (s *ServiceTable) GetServiceId(endpointData *EndpointData, key *LookupKey) *ServiceIds {
	if endpointData == nil || key == nil {
		return nil
	}
	var srcServiceIds, dstServiceIds []uint32
	if endpointData.SrcInfo != nil {
		srcServiceIds = make([]uint32, 0, len(endpointData.SrcInfo.GroupIds))
		for _, groupId := range endpointData.SrcInfo.GroupIds {
			if data := s.GetServiceData(groupId, uint32(key.SrcPort), uint16(key.Proto)); data != nil {
				srcServiceIds = append(srcServiceIds, data.Id)
			}
		}
	}
	if endpointData.DstInfo != nil {
		dstServiceIds = make([]uint32, 0, len(endpointData.DstInfo.GroupIds))
		for _, groupId := range endpointData.DstInfo.GroupIds {
			if data := s.GetServiceData(groupId, uint32(key.DstPort), uint16(key.Proto)); data != nil {
				dstServiceIds = append(dstServiceIds, data.Id)
			}
		}
	}

	return &ServiceIds{
		SrcIds: srcServiceIds,
		DstIds: dstServiceIds,
	}
}

func (s *ServiceTable) GetServiceData(groupId uint32, port uint32, proto uint16) *ServiceData {
	key := calcServiceHashKey(groupId, port, proto)
	if data, ok := s.serviceMap[ServiceKey(key)]; ok {
		return data
	}
	return nil
}

package genesis

import (
	"github.com/metaflowys/metaflow/server/controller/cloud/model"
	"github.com/metaflowys/metaflow/server/controller/common"
	"github.com/metaflowys/metaflow/server/controller/genesis"

	uuid "github.com/satori/go.uuid"
)

func (g *Genesis) getHosts() ([]model.Host, error) {
	log.Debug("get hosts starting")
	hosts := []model.Host{}
	hostsData := genesis.GenesisService.GetHostsData()

	g.cloudStatsd.APICost["hosts"] = []int{0}
	g.cloudStatsd.APICount["hosts"] = []int{len(hostsData)}

	for _, h := range hostsData {
		host := model.Host{
			Lcuuid:       common.GetUUID(h.IP, uuid.Nil),
			IP:           h.IP,
			Name:         h.Hostname,
			HType:        common.HOST_HTYPE_KVM,
			VCPUNum:      common.HOST_VCPUS,
			MemTotal:     common.HOST_MEMORY_MB,
			Type:         common.HOST_TYPE_VM,
			AZLcuuid:     g.azLcuuid,
			RegionLcuuid: g.regionUuid,
		}
		hosts = append(hosts, host)
	}
	log.Debug("get hosts complete")
	return hosts, nil
}

package genesis

import (
	"github.com/metaflowys/metaflow/server/controller/cloud/model"
	"github.com/metaflowys/metaflow/server/controller/common"
	"github.com/metaflowys/metaflow/server/controller/genesis"

	uuid "github.com/satori/go.uuid"
)

func (g *Genesis) getIPs() ([]model.IP, error) {
	log.Debug("get ips starting")
	ips := []model.IP{}
	ipsData := genesis.GenesisService.GetIPsData()

	g.cloudStatsd.APICost["ips"] = []int{0}
	g.cloudStatsd.APICount["ips"] = []int{len(ipsData)}

	for _, i := range ipsData {
		if i.VInterfaceLcuuid == "" || i.SubnetLcuuid == "" {
			log.Debug("vinterface lcuuid or subnet lcuuid not found")
			continue
		}
		lcuuid := i.Lcuuid
		if lcuuid == "" {
			lcuuid = common.GetUUID(i.VInterfaceLcuuid+i.IP, uuid.Nil)
		}
		ip := model.IP{
			Lcuuid:           lcuuid,
			VInterfaceLcuuid: i.VInterfaceLcuuid,
			IP:               i.IP,
			SubnetLcuuid:     i.SubnetLcuuid,
			RegionLcuuid:     g.regionUuid,
		}
		ips = append(ips, ip)
	}
	log.Debug("get ips complete")
	return ips, nil
}

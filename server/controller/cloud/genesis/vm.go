package genesis

import (
	"github.com/metaflowys/metaflow/server/controller/cloud/model"
	"github.com/metaflowys/metaflow/server/controller/common"
	"github.com/metaflowys/metaflow/server/controller/genesis"

	uuid "github.com/satori/go.uuid"
)

func (g *Genesis) getVMs() ([]model.VM, error) {
	log.Debug("get vms starting")
	vms := []model.VM{}
	vmsData := genesis.GenesisService.GetVMsData()
	for _, v := range vmsData {
		vpcLcuuid := v.VPCLcuuid
		if vpcLcuuid == "" {
			vpcLcuuid = common.GetUUID(g.defaultVpcName, uuid.Nil)
			g.defaultVpc = true
		}
		launchServer := v.LaunchServer
		if launchServer == "127.0.0.1" {
			launchServer = ""
		}
		vm := model.VM{
			Lcuuid:       v.Lcuuid,
			Name:         v.Name,
			Label:        v.Label,
			VPCLcuuid:    vpcLcuuid,
			State:        v.State,
			LaunchServer: launchServer,
			CreatedAt:    v.CreatedAt,
			AZLcuuid:     g.azLcuuid,
			RegionLcuuid: g.regionUuid,
		}
		vms = append(vms, vm)
	}
	log.Debug("get vms complete")
	return vms, nil
}

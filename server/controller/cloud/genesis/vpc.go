package genesis

import (
	"github.com/metaflowys/metaflow/server/controller/cloud/model"
	"github.com/metaflowys/metaflow/server/controller/common"
	"github.com/metaflowys/metaflow/server/controller/genesis"

	uuid "github.com/satori/go.uuid"
)

func (g *Genesis) getVPCs() ([]model.VPC, error) {
	log.Debug("get vpcs starting")
	vpcs := []model.VPC{}
	vpcsData := genesis.GenesisService.GetVPCsData()

	g.cloudStatsd.APICost["vpcs"] = []int{0}
	g.cloudStatsd.APICount["vpcs"] = []int{len(vpcsData)}

	for _, v := range vpcsData {
		vpcLcuuid := v.Lcuuid
		if vpcLcuuid == "" {
			vpcLcuuid = common.GetUUID(v.Name, uuid.Nil)
		}
		vpc := model.VPC{
			Lcuuid:       vpcLcuuid,
			Name:         v.Name,
			RegionLcuuid: g.regionUuid,
		}
		vpcs = append(vpcs, vpc)
	}
	log.Debug("get vpcs complete")
	return vpcs, nil
}

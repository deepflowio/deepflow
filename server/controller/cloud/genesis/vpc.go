package genesis

import (
	"server/controller/cloud/model"
	"server/controller/common"
	"server/controller/genesis"

	uuid "github.com/satori/go.uuid"
)

func (g *Genesis) getVPCs() ([]model.VPC, error) {
	log.Debug("get vpcs starting")
	vpcs := []model.VPC{}
	vpcsData := genesis.GenesisService.GetVPCsData()
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

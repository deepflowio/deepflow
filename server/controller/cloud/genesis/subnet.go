package genesis

import (
	"github.com/metaflowys/metaflow/server/controller/cloud/model"
	"github.com/metaflowys/metaflow/server/controller/common"
	"github.com/metaflowys/metaflow/server/controller/genesis"

	uuid "github.com/satori/go.uuid"
)

func (g *Genesis) getSubnets() ([]model.Subnet, error) {
	log.Debug("get subnets starting")
	subnets := []model.Subnet{}
	subnetsData := genesis.GenesisService.GetSubnetsData()
	for _, s := range subnetsData {
		if s.NetworkLcuuid == "" {
			log.Debug("network lcuuid not found")
			continue
		}
		vpcLcuuid := s.VPCLcuuid
		if vpcLcuuid == "" {
			vpcLcuuid = common.GetUUID(g.defaultVpcName, uuid.Nil)
			g.defaultVpc = true
		}
		subnetName := s.Name
		if subnetName == "" {
			subnetName = "subnet_" + s.Lcuuid[:11]
		}
		subnet := model.Subnet{
			Lcuuid:        s.Lcuuid,
			Name:          subnetName,
			CIDR:          s.CIDR,
			VPCLcuuid:     s.VPCLcuuid,
			NetworkLcuuid: s.NetworkLcuuid,
		}
		subnets = append(subnets, subnet)
	}
	log.Debug("get subnets complete")
	return subnets, nil
}

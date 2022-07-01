package genesis

import (
	"github.com/metaflowys/metaflow/server/controller/cloud/model"
	"github.com/metaflowys/metaflow/server/controller/common"
	"github.com/metaflowys/metaflow/server/controller/genesis"

	uuid "github.com/satori/go.uuid"
)

func (g *Genesis) getVinterfaces() ([]model.VInterface, error) {
	log.Debug("get vinterfaces starting")
	vinterfaces := []model.VInterface{}
	vinterfacesData := genesis.GenesisService.GetPortsData()
	for _, v := range vinterfacesData {
		if v.DeviceLcuuid == "" || v.NetworkLcuuid == "" {
			log.Debug("device lcuuid or network lcuuid not found")
			continue
		}
		vpcLcuuid := v.VPCLcuuid
		if vpcLcuuid == "" {
			vpcLcuuid = common.GetUUID(g.defaultVpcName, uuid.Nil)
			g.defaultVpc = true
		}
		vinterface := model.VInterface{
			Lcuuid:        v.Lcuuid,
			Type:          v.Type,
			Mac:           v.Mac,
			VPCLcuuid:     vpcLcuuid,
			RegionLcuuid:  g.regionUuid,
			DeviceType:    v.DeviceType,
			DeviceLcuuid:  v.DeviceLcuuid,
			NetworkLcuuid: v.NetworkLcuuid,
		}
		vinterfaces = append(vinterfaces, vinterface)
	}
	log.Debug("get vinterfaces complete")
	return vinterfaces, nil
}

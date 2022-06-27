package qingcloud

import (
	"github.com/metaflowys/metaflow/server/controller/cloud/model"
	"github.com/metaflowys/metaflow/server/controller/common"
)

func (q *QingCloud) GetFloatingIPs() ([]model.VInterface, []model.IP, []model.FloatingIP, error) {
	var retVInterfaces []model.VInterface
	var retIPs []model.IP
	var retFloatingIPs []model.FloatingIP

	log.Debug("get floating_ips starting")

	for regionId, regionLcuuid := range q.RegionIdToLcuuid {
		kwargs := []*Param{
			{"zone", regionId},
			{"status.1", "associated"},
		}
		response, err := q.GetResponse("DescribeEips", "eip_set", kwargs)
		if err != nil {
			log.Error(err)
			return nil, nil, nil, err
		}

		for _, r := range response {
			for i := range r.MustArray() {
				eip := r.GetIndex(i)

				eipId := eip.Get("eip_id").MustString()
				ip := eip.Get("eip_addr").MustString()
				deviceType := eip.Get("resource").Get("resource_type").MustString()
				if deviceType != "instance" {
					continue
				}
				resourceId := eip.Get("resource").Get("resource_id").MustString()
				vpcLcuuid, ok := q.vmIdToVPCLcuuid[resourceId]
				if !ok {
					log.Debugf("eip (%s) vpc not found", ip)
					continue
				}
				retFloatingIPs = append(retFloatingIPs, model.FloatingIP{
					Lcuuid:        common.GenerateUUID(eipId),
					IP:            ip,
					VMLcuuid:      common.GenerateUUID(resourceId),
					NetworkLcuuid: common.NETWORK_ISP_LCUUID,
					RegionLcuuid:  regionLcuuid,
				})

				// 给LB或者NAT网关的关联虚拟机补充接口和IP
				if eip.Get("associate_mode").MustInt() != 1 {
					continue
				}
				nicId := eip.Get("resource").Get("nic_id").MustString()
				vinterfaceLcuuid := common.GenerateUUID(nicId + resourceId)
				retVInterfaces = append(retVInterfaces, model.VInterface{
					Lcuuid:        vinterfaceLcuuid,
					Type:          common.VIF_TYPE_WAN,
					Mac:           nicId,
					DeviceType:    common.VIF_DEVICE_TYPE_VM,
					DeviceLcuuid:  common.GenerateUUID(resourceId),
					NetworkLcuuid: common.NETWORK_ISP_LCUUID,
					VPCLcuuid:     vpcLcuuid,
					RegionLcuuid:  regionLcuuid,
				})
				retIPs = append(retIPs, model.IP{
					Lcuuid:           common.GenerateUUID(vinterfaceLcuuid + ip),
					VInterfaceLcuuid: vinterfaceLcuuid,
					IP:               ip,
					SubnetLcuuid:     common.NETWORK_ISP_LCUUID,
					RegionLcuuid:     regionLcuuid,
				})
			}
		}
	}

	log.Debug("get floating_ips complete")
	return retVInterfaces, retIPs, retFloatingIPs, nil
}

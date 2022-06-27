package aliyun

import (
	cbn "github.com/aliyun/alibaba-cloud-sdk-go/services/cbn"
	"github.com/metaflowys/metaflow/server/controller/cloud/model"
	"github.com/metaflowys/metaflow/server/controller/common"
)

func (a *Aliyun) getCens(region model.Region) ([]model.CEN, error) {
	var retCens []model.CEN

	log.Debug("get cens starting")
	request := cbn.CreateDescribeCensRequest()
	response, err := a.getCenResponse(region.Label, request)
	if err != nil {
		log.Error(err)
		return nil, err
	}

	for _, r := range response {
		cens, _ := r.Get("Cen").Array()
		for i := range cens {
			cen := r.Get("Cen").GetIndex(i)

			cenId := cen.Get("CenId").MustString()
			if cenId == "" {
				continue
			}
			cenName := cen.Get("Name").MustString()
			if cenName == "" {
				cenName = cenId
			}

			childRequest := cbn.CreateDescribeCenAttachedChildInstancesRequest()
			childRequest.CenId = cenId
			childResponse, err := a.getCenAttributeResponse(region.Label, childRequest)
			if err != nil {
				log.Error(err)
				return nil, err
			}

			vpcLcuuids := []string{}
			for _, c := range childResponse {
				cenAttrs, _ := c.Get("ChildInstance").Array()
				for j := range cenAttrs {
					cenAttr := c.Get("ChildInstance").GetIndex(j)
					if cenAttr.Get("ChildInstanceType").MustString() != "VPC" {
						continue
					}
					vpcLcuuids = append(
						vpcLcuuids,
						common.GenerateUUID(cenAttr.Get("ChildInstanceId").MustString()),
					)
				}
			}
			if len(vpcLcuuids) == 0 {
				continue
			}
			retCens = append(retCens, model.CEN{
				Lcuuid:     common.GenerateUUID(cenId),
				Name:       cenName,
				Label:      cenId,
				VPCLcuuids: vpcLcuuids,
			})
		}
	}

	log.Debug("get cens complete")
	return retCens, nil
}

package baidubce

import (
	"strings"

	"github.com/baidubce/bce-sdk-go/services/bcc"

	"github.com/metaflowys/metaflow/server/controller/cloud/model"
	"github.com/metaflowys/metaflow/server/controller/common"
)

func (b *BaiduBce) getRegionAndAZs() ([]model.Region, []model.AZ, map[string]string, error) {
	var retRegions []model.Region
	var retAZs []model.AZ
	var zoneNameToAZLcuuid map[string]string

	log.Debug("get regions starting")

	bccClient, _ := bcc.NewClient(b.secretID, b.secretKey, "bcc."+b.endpoint)
	result, err := bccClient.ListZone()
	if err != nil {
		log.Error(err)
		return nil, nil, nil, err
	}
	zones := result.Zones

	regionName := ""
	if len(zones) > 1 {
		zoneName := zones[0].ZoneName
		regionName = zoneName[:strings.LastIndex(zoneName, "-")]
	} else {
		return nil, nil, nil, nil
	}
	regionLcuuid := common.GenerateUUID(regionName)
	retRegionLcuuid := regionLcuuid

	if b.regionUuid == "" {
		retRegion := model.Region{
			Lcuuid: regionLcuuid,
			Name:   regionName,
		}
		retRegions = append(retRegions, retRegion)
	} else {
		retRegionLcuuid = b.regionUuid
	}

	zoneNameToAZLcuuid = make(map[string]string)
	for _, zone := range zones {
		azLcuuid := common.GenerateUUID(regionLcuuid + zone.ZoneName)
		retAZ := model.AZ{
			Lcuuid:       azLcuuid,
			Name:         zone.ZoneName,
			RegionLcuuid: retRegionLcuuid,
		}
		retAZs = append(retAZs, retAZ)
		zoneNameToAZLcuuid[zone.ZoneName] = azLcuuid
	}

	log.Debug("get regions complete")
	return retRegions, retAZs, zoneNameToAZLcuuid, nil
}

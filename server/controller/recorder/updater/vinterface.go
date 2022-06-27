package updater

import (
	"strings"

	cloudmodel "github.com/metaflowys/metaflow/server/controller/cloud/model"
	"github.com/metaflowys/metaflow/server/controller/db/mysql"
	"github.com/metaflowys/metaflow/server/controller/recorder/cache"
	"github.com/metaflowys/metaflow/server/controller/recorder/common"
	"github.com/metaflowys/metaflow/server/controller/recorder/db"
)

type VInterface struct {
	UpdaterBase[cloudmodel.VInterface, mysql.VInterface, *cache.VInterface]
}

func NewVInterface(wholeCache *cache.Cache, cloudData []cloudmodel.VInterface) *VInterface {
	updater := &VInterface{
		UpdaterBase[cloudmodel.VInterface, mysql.VInterface, *cache.VInterface]{
			cache:        wholeCache,
			dbOperator:   db.NewVInterface(),
			diffBaseData: wholeCache.VInterfaces,
			cloudData:    cloudData,
		},
	}
	updater.dataGenerator = updater
	updater.cacheHandler = updater
	return updater
}

func (i *VInterface) getDiffBaseByCloudItem(cloudItem *cloudmodel.VInterface) (diffBase *cache.VInterface, exists bool) {
	diffBase, exists = i.diffBaseData[cloudItem.Lcuuid]
	return
}

func (i *VInterface) generateDBItemToAdd(cloudItem *cloudmodel.VInterface) (*mysql.VInterface, bool) {
	networkID, exists := i.cache.ToolDataSet.GetNetworkIDByLcuuid(cloudItem.NetworkLcuuid)
	if !exists {
		log.Errorf(resourceAForResourceBNotFound(
			common.RESOURCE_TYPE_NETWORK_EN, cloudItem.NetworkLcuuid,
			common.RESOURCE_TYPE_VINTERFACE_EN, cloudItem.Lcuuid,
		))
		return nil, false
	}
	deviceID, exists := i.cache.ToolDataSet.GetDeviceIDByDeviceLcuuid(cloudItem.DeviceType, cloudItem.DeviceLcuuid)
	if !exists {
		log.Errorf(
			"device (type: %d, lcuuid: %s) for %s (lcuuid: %s) not found",
			cloudItem.DeviceType, cloudItem.DeviceLcuuid,
			common.RESOURCE_TYPE_VINTERFACE_EN, cloudItem.Lcuuid,
		)
		return nil, false
	}

	dbItem := &mysql.VInterface{
		Name:       cloudItem.Name,
		Type:       cloudItem.Type,
		State:      1,
		NetworkID:  networkID,
		Mac:        strings.ToLower(cloudItem.Mac),
		TapMac:     strings.ToLower(cloudItem.TapMac),
		DeviceType: cloudItem.DeviceType,
		DeviceID:   deviceID,
		VlanTag:    0,
		SubDomain:  cloudItem.SubDomainLcuuid,
		Domain:     i.cache.DomainLcuuid,
		Region:     cloudItem.RegionLcuuid,
	}
	dbItem.Lcuuid = cloudItem.Lcuuid
	return dbItem, true
}

func (i *VInterface) generateUpdateInfo(diffBase *cache.VInterface, cloudItem *cloudmodel.VInterface) (map[string]interface{}, bool) {
	updateInfo := make(map[string]interface{})
	if diffBase.NetworkLcuuid != cloudItem.NetworkLcuuid {
		networkID, exists := i.cache.ToolDataSet.GetNetworkIDByLcuuid(cloudItem.NetworkLcuuid)
		if !exists {
			log.Errorf(resourceAForResourceBNotFound(
				common.RESOURCE_TYPE_NETWORK_EN, cloudItem.NetworkLcuuid,
				common.RESOURCE_TYPE_VINTERFACE_EN, cloudItem.Lcuuid,
			))
			return nil, false
		}
		updateInfo["subnetid"] = networkID
	}
	if diffBase.Name != cloudItem.Name {
		updateInfo["name"] = cloudItem.Name
	}
	if diffBase.TapMac != cloudItem.TapMac {
		updateInfo["tap_mac"] = cloudItem.TapMac
	}
	if diffBase.RegionLcuuid != cloudItem.RegionLcuuid {
		updateInfo["region"] = cloudItem.RegionLcuuid
	}
	return updateInfo, len(updateInfo) > 0
}

func (i *VInterface) addCache(dbItems []*mysql.VInterface) {
	i.cache.AddVInterfaces(dbItems)
}

func (i *VInterface) updateCache(cloudItem *cloudmodel.VInterface, diffBase *cache.VInterface) {
	diffBase.Update(cloudItem)
}

func (i *VInterface) deleteCache(lcuuids []string) {
	i.cache.DeleteVInterfaces(lcuuids)
}

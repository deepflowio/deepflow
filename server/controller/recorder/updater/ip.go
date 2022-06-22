package updater

import (
	cloudmodel "server/controller/cloud/model"
	"server/controller/common"
	"server/controller/recorder/cache"
	rcommon "server/controller/recorder/common"
)

type IP struct {
	cache        *cache.Cache
	cloudData    []cloudmodel.IP
	wanIPUpdater *WANIP
	lanIPUpdater *LANIP
}

func NewIP(cache *cache.Cache, cloudData []cloudmodel.IP) *IP {
	return &IP{
		cache:     cache,
		cloudData: cloudData,
	}
}

func (i *IP) HandleAddAndUpdate() {
	wanCloudData, lanCloudData := i.splitToWANAndLAN(i.cloudData)
	i.wanIPUpdater = NewWANIP(i.cache, wanCloudData)
	i.lanIPUpdater = NewLANIP(i.cache, lanCloudData)
	i.wanIPUpdater.HandleAddAndUpdate()
	i.lanIPUpdater.HandleAddAndUpdate()
}

func (i *IP) HandleDelete() {
	i.wanIPUpdater.HandleDelete()
	i.lanIPUpdater.HandleDelete()
}

func (i *IP) splitToWANAndLAN(cloudData []cloudmodel.IP) ([]cloudmodel.IP, []cloudmodel.IP) {
	wanCloudData := []cloudmodel.IP{}
	lanCloudData := []cloudmodel.IP{}
	for _, cloudItem := range cloudData {
		vinterface, exists := i.cache.VInterfaces[cloudItem.VInterfaceLcuuid]
		if !exists {
			log.Error(resourceAForResourceBNotFound(
				rcommon.RESOURCE_TYPE_VINTERFACE_EN, cloudItem.VInterfaceLcuuid,
				rcommon.RESOURCE_TYPE_LAN_IP_EN, cloudItem.Lcuuid,
			))
			continue
		}
		if vinterface.Type == common.VIF_TYPE_WAN {
			wanCloudData = append(wanCloudData, cloudItem)
		} else {
			lanCloudData = append(lanCloudData, cloudItem)
		}
	}
	return wanCloudData, lanCloudData
}

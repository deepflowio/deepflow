package updater

import (
	cloudmodel "github.com/metaflowys/metaflow/server/controller/cloud/model"
	"github.com/metaflowys/metaflow/server/controller/common"
	"github.com/metaflowys/metaflow/server/controller/db/mysql"
	"github.com/metaflowys/metaflow/server/controller/recorder/cache"
	"github.com/metaflowys/metaflow/server/controller/recorder/db"
)

type Host struct {
	UpdaterBase[cloudmodel.Host, mysql.Host, *cache.Host]
}

func NewHost(wholeCache *cache.Cache, cloudData []cloudmodel.Host) *Host {
	updater := &Host{
		UpdaterBase[cloudmodel.Host, mysql.Host, *cache.Host]{
			cache:        wholeCache,
			dbOperator:   db.NewHost(),
			diffBaseData: wholeCache.Hosts,
			cloudData:    cloudData,
		},
	}
	updater.dataGenerator = updater
	updater.cacheHandler = updater
	return updater
}

func (h *Host) getDiffBaseByCloudItem(cloudItem *cloudmodel.Host) (diffBase *cache.Host, exists bool) {
	diffBase, exists = h.diffBaseData[cloudItem.Lcuuid]
	return
}

func (h *Host) generateDBItemToAdd(cloudItem *cloudmodel.Host) (*mysql.Host, bool) {
	dbItem := &mysql.Host{
		Name:       cloudItem.Name,
		IP:         cloudItem.IP,
		Type:       cloudItem.Type,
		HType:      cloudItem.HType,
		VCPUNum:    cloudItem.VCPUNum,
		MemTotal:   cloudItem.MemTotal,
		ExtraInfo:  cloudItem.ExtraInfo,
		UserName:   "root",
		UserPasswd: "metaflow",
		State:      common.HOST_STATE_COMPLETE,
		AZ:         cloudItem.AZLcuuid,
		Region:     cloudItem.RegionLcuuid,
		Domain:     h.cache.DomainLcuuid,
	}
	dbItem.Lcuuid = cloudItem.Lcuuid
	return dbItem, true
}

func (h *Host) generateUpdateInfo(diffBase *cache.Host, cloudItem *cloudmodel.Host) (map[string]interface{}, bool) {
	updateInfo := make(map[string]interface{})
	if diffBase.Name != cloudItem.Name {
		updateInfo["name"] = cloudItem.Name
	}
	if diffBase.IP != cloudItem.IP {
		updateInfo["ip"] = cloudItem.IP
	}
	if diffBase.HType != cloudItem.HType {
		updateInfo["htype"] = cloudItem.HType
	}
	if diffBase.VCPUNum != cloudItem.VCPUNum {
		updateInfo["vcpu_num"] = cloudItem.VCPUNum
	}
	if diffBase.MemTotal != cloudItem.MemTotal {
		updateInfo["mem_total"] = cloudItem.MemTotal
	}
	if diffBase.ExtraInfo != cloudItem.ExtraInfo {
		updateInfo["extra_info"] = cloudItem.ExtraInfo
	}
	if diffBase.RegionLcuuid != cloudItem.RegionLcuuid {
		updateInfo["region"] = cloudItem.RegionLcuuid
	}
	if diffBase.AZLcuuid != cloudItem.AZLcuuid {
		updateInfo["az"] = cloudItem.AZLcuuid
	}

	if len(updateInfo) > 0 {
		return updateInfo, true
	}
	return nil, false
}

func (h *Host) addCache(dbItems []*mysql.Host) {
	h.cache.AddHosts(dbItems)
}

func (h *Host) updateCache(cloudItem *cloudmodel.Host, diffBase *cache.Host) {
	diffBase.Update(cloudItem)
}

func (h *Host) deleteCache(lcuuids []string) {
	h.cache.DeleteHosts(lcuuids)
}

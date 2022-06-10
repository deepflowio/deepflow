package updater

import (
	cloudmodel "server/controller/cloud/model"
	"server/controller/db/mysql"
	"server/controller/recorder/cache"
	"server/controller/recorder/common"
	"server/controller/recorder/db"
)

type PodIngressRule struct {
	UpdaterBase[cloudmodel.PodIngressRule, mysql.PodIngressRule, *cache.PodIngressRule]
}

func NewPodIngressRule(wholeCache *cache.Cache, cloudData []cloudmodel.PodIngressRule) *PodIngressRule {
	updater := &PodIngressRule{
		UpdaterBase[cloudmodel.PodIngressRule, mysql.PodIngressRule, *cache.PodIngressRule]{
			cache:        wholeCache,
			dbOperator:   db.NewPodIngressRule(),
			diffBaseData: wholeCache.PodIngressRules,
			cloudData:    cloudData,
		},
	}
	updater.dataGenerator = updater
	updater.cacheHandler = updater
	return updater
}

func (r *PodIngressRule) getDiffBaseByCloudItem(cloudItem *cloudmodel.PodIngressRule) (diffBase *cache.PodIngressRule, exists bool) {
	diffBase, exists = r.diffBaseData[cloudItem.Lcuuid]
	return
}

func (r *PodIngressRule) generateDBItemToAdd(cloudItem *cloudmodel.PodIngressRule) (*mysql.PodIngressRule, bool) {
	podIngressID, exists := r.cache.ToolDataSet.GetPodIngressIDByLcuuid(cloudItem.PodIngressLcuuid)
	if !exists {
		log.Errorf(resourceAForResourceBNotFound(
			common.RESOURCE_TYPE_POD_INGRESS_EN, cloudItem.PodIngressLcuuid,
			common.RESOURCE_TYPE_POD_INGRESS_RULE_EN, cloudItem.Lcuuid,
		))
		return nil, false
	}

	dbItem := &mysql.PodIngressRule{
		Name:         cloudItem.Name,
		Protocol:     cloudItem.Protocol,
		Host:         cloudItem.Host,
		PodIngressID: podIngressID,
		SubDomain:    cloudItem.SubDomainLcuuid,
	}
	dbItem.Lcuuid = cloudItem.Lcuuid
	return dbItem, true
}

// 保留接口
func (r *PodIngressRule) generateUpdateInfo(diffBase *cache.PodIngressRule, cloudItem *cloudmodel.PodIngressRule) (map[string]interface{}, bool) {
	return nil, false
}

func (b *PodIngressRule) addCache(dbItems []*mysql.PodIngressRule) {
	b.cache.AddPodIngressRules(dbItems)
}

// 保留接口
func (b *PodIngressRule) updateCache(cloudItem *cloudmodel.PodIngressRule, diffBase *cache.PodIngressRule) {
}

func (b *PodIngressRule) deleteCache(lcuuids []string) {
	b.cache.DeletePodIngressRules(lcuuids)
}

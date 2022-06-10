package vtap

import (
	"sync"
	"time"

	"gorm.io/gorm"

	models "server/controller/db/mysql"
	"server/controller/trisolaris/dbmgr"
	. "server/controller/trisolaris/utils"
)

type CacheKC struct {
	sync.RWMutex
	kc *models.KubernetesCluster
}

func newCacheKC(kc *models.KubernetesCluster) *CacheKC {
	return &CacheKC{
		kc: kc,
	}
}

func (c *CacheKC) getValue() string {
	c.RLock()
	defer c.RUnlock()
	return c.kc.Value
}

func (c *CacheKC) getSyncedAt() time.Time {
	c.RLock()
	defer c.RUnlock()
	return c.kc.SyncedAt
}

func (c *CacheKC) updateTime(t time.Time) {
	c.Lock()
	c.kc.SyncedAt = t
	c.Unlock()
}

type KubernetesCluster struct {
	sync.RWMutex
	keyToCache map[string]*CacheKC
	db         *gorm.DB
}

func newKubernetesCluster(db *gorm.DB) *KubernetesCluster {
	return &KubernetesCluster{
		keyToCache: make(map[string]*CacheKC),
		db:         db,
	}
}

func (k *KubernetesCluster) add(clusterID string, kc *models.KubernetesCluster) {
	cacheKC := newCacheKC(kc)
	k.Lock()
	k.keyToCache[clusterID] = cacheKC
	k.Unlock()
}

func (k *KubernetesCluster) getValue(clusterID string) string {
	k.RLock()
	kc, ok := k.keyToCache[clusterID]
	k.RUnlock()
	if ok {
		return kc.getValue()
	}

	return ""
}

func (k *KubernetesCluster) getCache(clusterID string) *CacheKC {
	k.RLock()
	kc := k.keyToCache[clusterID]
	k.RUnlock()
	return kc
}

func (k *KubernetesCluster) getCacheSyncedAt(clusterID string) (time.Time, bool) {
	var t time.Time
	b := false
	k.RLock()
	cacheKC, ok := k.keyToCache[clusterID]
	k.RUnlock()
	if ok {
		t = cacheKC.getSyncedAt()
		b = true
	}

	return t, b
}

func (k *KubernetesCluster) updateCacheSyncedAt(clusterID string, t time.Time) {
	k.RLock()
	cacheKC, ok := k.keyToCache[clusterID]
	k.RUnlock()
	if ok {
		cacheKC.updateTime(t)
	}
}

func (k *KubernetesCluster) DeleteCache(clusterID string) {
	k.Lock()
	delete(k.keyToCache, clusterID)
	k.Unlock()
}

func (k *KubernetesCluster) updateCacheSyncTime(clusterID string) {
	k.Lock()
	cacheKC, ok := k.keyToCache[clusterID]
	k.Unlock()
	if ok {
		cacheKC.updateTime(time.Now())
	}
}

// 定时清理数据库中10分钟前未同步的数据(可配置)
// 更新缓存同步时间
func (k *KubernetesCluster) loadAndCheck(clearTime int) {
	log.Info("check kubernetes cluster data")
	mgr := dbmgr.DBMgr[models.KubernetesCluster](k.db)
	kcs, err := mgr.Gets()
	if err != nil {
		log.Error(err)
		return
	}
	now := time.Now()
	deleteIDs := []int{}
	updateData := make([]*models.KubernetesCluster, 0, len(kcs))
	var checkSyncedAt time.Time
	for _, kc := range kcs {
		updatedAt, ok := k.getCacheSyncedAt(kc.ClusterID)
		if ok {
			checkSyncedAt = MaxTime(updatedAt, kc.SyncedAt)
		} else {
			checkSyncedAt = now
		}
		if int(checkSyncedAt.Sub(kc.SyncedAt).Seconds()) > clearTime {
			deleteIDs = append(deleteIDs, kc.ID)
			if ok {
				k.DeleteCache(kc.ClusterID)
			}
			log.Infof(
				"delete kubernetes_cluster(%s, %s) data",
				kc.ClusterID,
				kc.Value)
		} else {
			if ok {
				k.updateCacheSyncedAt(kc.ClusterID, checkSyncedAt)
				kc.SyncedAt = checkSyncedAt
				updateData = append(updateData, kc)
			}
		}
	}
	if len(deleteIDs) > 0 {
		mgr.DeleteBatchFromID(deleteIDs)
	}
	if len(updateData) > 0 {
		mgr.UpdateBulk(updateData)
	}
}

// 查询内存中的kubernetes_cluster_id字典
// - 如果内存中没有查到对应的cluster_id
//   - 往数据库插入一条数据，无相关cluster_id数据则插入,有则不做操作(MySQL INSERT IGNORE)
//     - 根据cluster_id查询最近一条数据，将查到的cluster_id与ctrl_ip + ctrl_mac的对应关系添加到内存中
// - 根据内存查到的对应关系，决定kubernetes_cluster_id的下发值
func (k *KubernetesCluster) getClusterID(clusterID string, value string) string {
	result := k.getValue(clusterID)
	if result == "" {
		mgr := dbmgr.DBMgr[models.KubernetesCluster](k.db)
		data := &models.KubernetesCluster{
			ClusterID: clusterID,
			Value:     value,
			CreatedAt: time.Now(),
			SyncedAt:  time.Now(),
		}
		err := mgr.InsertIgnore(data)
		if err != nil {
			log.Error(err)
		}
		dbKubernetesClusteID, err := mgr.GetFromClusterID(clusterID)
		if err == nil {
			k.add(clusterID, dbKubernetesClusteID)
			result = dbKubernetesClusteID.Value
		}
	} else {
		if result == value {
			k.updateCacheSyncTime(clusterID)
		}
	}

	return result
}

/*
 * Copyright (c) 2024 Yunshan Networks
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package vtap

import (
	"sync"
	"time"

	"gorm.io/gorm"

	models "github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/trisolaris/dbmgr"
	. "github.com/deepflowio/deepflow/server/controller/trisolaris/utils"
	"github.com/deepflowio/deepflow/server/controller/trisolaris/utils/atomicbool"
)

type CacheKC struct {
	sync.RWMutex
	syncFlag atomicbool.Bool
	kc       *models.KubernetesCluster
}

func newCacheKC(kc *models.KubernetesCluster) *CacheKC {
	return &CacheKC{
		kc:       kc,
		syncFlag: atomicbool.NewBool(false),
	}
}

func (c *CacheKC) setSyncFlag() {
	c.syncFlag.Set()
}

func (c *CacheKC) unsetSyncFlag() {
	c.syncFlag.Unset()
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
	ORGID
}

func newKubernetesCluster(db *gorm.DB, orgID ORGID) *KubernetesCluster {
	return &KubernetesCluster{
		keyToCache: make(map[string]*CacheKC),
		db:         db,
		ORGID:      orgID,
	}
}

func (k *KubernetesCluster) updateCache(keyToCache map[string]*CacheKC) {
	k.Lock()
	k.keyToCache = keyToCache
	k.Unlock()
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

func (k *KubernetesCluster) updateSyncTime(clusterID string) {
	k.RLock()
	cacheKC, ok := k.keyToCache[clusterID]
	k.RUnlock()
	if ok {
		cacheKC.updateTime(time.Now())
		cacheKC.setSyncFlag()
	}
}

// 定时清理数据库中10分钟前未同步的数据(可配置)
// 更新缓存同步时间
func (k *KubernetesCluster) loadAndCheck(clearTime int) {
	log.Info(k.Log("check kubernetes cluster data"))
	mgr := dbmgr.DBMgr[models.KubernetesCluster](k.db)
	kcs, err := mgr.Gets()
	if err != nil {
		log.Error(k.Log(err.Error()))
		return
	}
	now := time.Now()
	deleteIDs := []int{}
	updateData := make([]*models.KubernetesCluster, 0, len(kcs))
	keyToCache := make(map[string]*CacheKC)
	var checkSyncedAt time.Time
	for _, dbkc := range kcs {
		cacheKC := k.getCache(dbkc.ClusterID)
		if cacheKC == nil {
			continue
		}
		checkSyncedAt = MaxTime(cacheKC.getSyncedAt(), dbkc.SyncedAt)
		if int(now.Sub(checkSyncedAt).Seconds()) > clearTime {
			deleteIDs = append(deleteIDs, dbkc.ID)
			log.Infof(k.Logf(
				"delete kubernetes_cluster(%s, %s) data",
				dbkc.ClusterID,
				dbkc.Value))
		} else {
			dbkc.SyncedAt = checkSyncedAt
			if cacheKC.syncFlag.IsSet() {
				updateData = append(updateData, dbkc)
			}
			keyToCache[dbkc.ClusterID] = newCacheKC(dbkc)
		}
	}
	if len(deleteIDs) > 0 {
		mgr.DeleteBatchFromID(deleteIDs)
	}
	if len(updateData) > 0 {
		for _, data := range updateData {
			mgr.Updates(&models.KubernetesCluster{ID: data.ID}, map[string]interface{}{
				"synced_at": data.SyncedAt,
			})
		}
	}
	k.updateCache(keyToCache)

}

// 查询内存中的kubernetes_cluster_id字典
// - 如果内存中没有查到对应的cluster_id
//   - 往数据库插入一条数据，无相关cluster_id数据则插入,有则不做操作(MySQL INSERT IGNORE)
//   - 根据cluster_id查询最近一条数据，将查到的cluster_id与ctrl_ip + ctrl_mac的对应关系添加到内存中
//
// - 根据内存查到的对应关系，决定kubernetes_cluster_id的下发值
func (k *KubernetesCluster) getClusterID(clusterID string, value string, force bool) string {
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
			log.Error(k.Log(err.Error()))
		}
		dbKubernetesClusteID, err := mgr.GetFromClusterID(clusterID)
		if err == nil {
			k.add(clusterID, dbKubernetesClusteID)
		} else {
			log.Error(k.Log(err.Error()))
		}
		result = value
	} else {
		if result == value {
			k.updateSyncTime(clusterID)
		} else if force {
			mgr := dbmgr.DBMgr[models.KubernetesCluster](k.db)
			dbKubernetesClusteID, err := mgr.GetFromClusterID(clusterID)
			if err == nil {
				log.Info(k.Logf("ClusteID(%s) sync changed from %s to %s", clusterID, dbKubernetesClusteID.Value, value))
				dbKubernetesClusteID.Value = value
				dbKubernetesClusteID.SyncedAt = time.Now()
				mgr.Save(dbKubernetesClusteID)
				k.add(clusterID, dbKubernetesClusteID)
			} else {
				log.Error(k.Log(err.Error()))
			}
			result = value
		}
	}

	return result
}

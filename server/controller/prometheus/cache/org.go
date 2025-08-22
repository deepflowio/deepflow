/**
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

package cache

import (
	"context"
	"fmt"
	"sync"
	"time"

	cmap "github.com/orcaman/concurrent-map/v2"
	"golang.org/x/exp/slices"

	ctrlrcommon "github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/metadb"
	"github.com/deepflowio/deepflow/server/controller/prometheus/common"
	prometheuscfg "github.com/deepflowio/deepflow/server/controller/prometheus/config"
)

func GetCache(orgID int) (*Cache, error) {
	return GetORGCaches().NewCacheAndInitIfNotExist(orgID)
}

var (
	orgCachesOnce sync.Once
	orgCaches     *ORGCaches
)

type ORGCaches struct {
	ctx    context.Context
	cancel context.CancelFunc

	mux             sync.Mutex
	working         bool
	refreshInterval time.Duration

	orgIDToCache cmap.ConcurrentMap[int, *Cache]
}

func GetORGCaches() *ORGCaches {
	orgCachesOnce.Do(func() {
		orgCaches = &ORGCaches{
			orgIDToCache: cmap.NewWithCustomShardingFunction[int, *Cache](common.ShardingInt),
		}
	})
	return orgCaches
}

func (c *ORGCaches) Init(ctx context.Context, cfg *prometheuscfg.Config) {
	c.ctx = ctx
	c.refreshInterval = time.Duration(cfg.SynchronizerCacheRefreshInterval) * time.Second
}

func (c *ORGCaches) Start(ctx context.Context, cfg *prometheuscfg.Config) error {
	c.Init(ctx, cfg)
	log.Info("prometheus caches started")
	c.mux.Lock()
	if c.working {
		c.mux.Unlock()
		return nil
	}
	c.working = true
	c.mux.Unlock()

	orgIDs, err := metadb.GetORGIDs()
	if err != nil {
		return fmt.Errorf("failed to get org ids: %v", err)
	}

	for _, id := range orgIDs {
		if _, err := c.NewCacheAndInitIfNotExist(id); err != nil {
			return fmt.Errorf("failed to start prometheus cache for org %d: %v", id, err)
		}
	}
	c.refreshRegularly()
	return nil
}

func (c *ORGCaches) Stop() {
	if c.cancel != nil {
		c.cancel()
	}
	c.mux.Lock()
	c.working = false
	c.orgIDToCache.Clear()
	c.mux.Unlock()
	log.Info("prometheus caches stopped")
}

func (c *ORGCaches) NewCacheAndInitIfNotExist(orgID int) (*Cache, error) {
	if orgID == 0 {
		orgID = ctrlrcommon.DEFAULT_ORG_ID
	}
	if cache, ok := c.orgIDToCache.Get(orgID); ok {
		return cache, nil
	}
	cache, err := newCache(orgID)
	if err != nil {
		return nil, err
	}
	err = cache.Refresh()
	if err != nil {
		return nil, err
	}
	c.orgIDToCache.Set(orgID, cache)
	return cache, nil
}

func (c *ORGCaches) refreshRegularly() error {
	go func() {
		ticker := time.NewTicker(c.refreshInterval)
		defer ticker.Stop()
		for {
			select {
			case <-c.ctx.Done():
				return
			case <-ticker.C:
				c.refresh()
			}
		}
	}()
	return nil
}

func (c *ORGCaches) refresh() error {
	if err := c.checkORGs(); err != nil {
		return err
	}
	for iter := range c.orgIDToCache.IterBuffered() {
		iter.Val.Refresh()
	}
	return nil
}

func (c *ORGCaches) checkORGs() error {
	orgIDs, err := metadb.GetORGIDs()
	if err != nil {
		return fmt.Errorf("failed to get org ids: %v", err)
	}

	for iter := range c.orgIDToCache.IterBuffered() {
		if !slices.Contains(orgIDs, iter.Key) {
			c.orgIDToCache.Remove(iter.Key)
		}
	}
	return nil
}

func (c *ORGCaches) GetORGIDToCache() cmap.ConcurrentMap[int, *Cache] {
	return c.orgIDToCache
}

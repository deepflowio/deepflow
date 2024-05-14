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

	"golang.org/x/exp/slices"

	"github.com/deepflowio/deepflow/server/controller/db/mysql"
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

	orgIDToCache map[int]*Cache
}

func GetORGCaches() *ORGCaches {
	orgCachesOnce.Do(func() {
		orgCaches = &ORGCaches{
			orgIDToCache: make(map[int]*Cache),
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

	orgIDs, err := mysql.GetORGIDs()
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
	c.orgIDToCache = make(map[int]*Cache)
	c.mux.Unlock()
	log.Info("prometheus caches stopped")
}

func (c *ORGCaches) NewCacheAndInitIfNotExist(orgID int) (*Cache, error) {
	c.mux.Lock()
	defer c.mux.Unlock()

	if cache, ok := c.orgIDToCache[orgID]; ok {
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
	c.orgIDToCache[orgID] = cache
	return cache, nil
}

func (c *ORGCaches) refreshRegularly() error {
	c.refresh()
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
	for _, en := range c.orgIDToCache {
		en.Refresh()
	}
	return nil
}

func (c *ORGCaches) checkORGs() error {
	orgIDs, err := mysql.GetORGIDs()
	if err != nil {
		return fmt.Errorf("failed to get org ids: %v", err)
	}

	c.mux.Lock()
	defer c.mux.Unlock()
	for orgID := range c.orgIDToCache {
		if !slices.Contains(orgIDs, orgID) {
			delete(c.orgIDToCache, orgID)
		}
	}
	return nil
}

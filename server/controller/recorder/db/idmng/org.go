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

package idmng

import (
	"context"
	"fmt"
	"sync"
	"time"

	"golang.org/x/exp/slices"

	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/metadb"
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	"github.com/deepflowio/deepflow/server/controller/recorder/config"
)

var (
	idMngsOnce sync.Once
	idMngs     *IDManagers
)

func GetIDManager(orgID int) (*IDManager, error) {
	return GetIDManagers().NewIDManagerAndInitIfNotExists(orgID)
}

type IDManagers struct {
	ctx    context.Context
	cancel context.CancelFunc

	inUse        bool
	mux          sync.Mutex
	orgIDToIDMng map[int]*IDManager
	recorderCfg  config.RecorderConfig
}

func GetIDManagers() *IDManagers {
	idMngsOnce.Do(func() {
		idMngs = &IDManagers{}
	})
	return idMngs
}

func (m *IDManagers) Init(ctx context.Context, cfg config.RecorderConfig) {
	m.ctx, m.cancel = context.WithCancel(ctx)
	m.recorderCfg = cfg
	m.orgIDToIDMng = make(map[int]*IDManager)
}

func (m *IDManagers) Start(ctx context.Context) error {
	if m.inUse {
		return nil
	}
	m.inUse = true
	m.ctx, m.cancel = context.WithCancel(ctx)

	orgIDs, err := metadb.GetORGIDs()
	if err != nil {
		return fmt.Errorf("failed to get org ids: %v", err)
	}
	for _, id := range orgIDs {
		if _, err := m.lazyCreate(id); err != nil {
			return fmt.Errorf("failed to start id manager for org %d: %v", id, err)
		}
	}

	m.timedRefresh()
	return nil
}

func (m *IDManagers) Stop() {
	if m.cancel != nil {
		m.cancel()
	}
	// clear before each stop
	m.orgIDToIDMng = make(map[int]*IDManager)
	m.inUse = false
	log.Info("resource id managers stopped")
}

// 定时刷新所有组织的 ID 池，恢复/修复页面删除 domain/sub_domain、定时永久删除无效资源等操作释放的 ID
func (m *IDManagers) timedRefresh() {
	go func() {
		ticker := time.NewTicker(time.Hour)
		defer ticker.Stop()

	LOOP:
		for {
			select {
			case <-ticker.C:
				m.refresh()
			case <-m.ctx.Done():
				break LOOP
			}
		}
	}()
}

func (m *IDManagers) lazyCreate(orgID int) (*IDManager, error) {
	db, err := metadb.GetDB(orgID)
	if err != nil {
		log.Error("failed to get db: %v", err)
		return nil, err
	}

	if orgID != common.DEFAULT_ORG_ID {
		// 仅当组织中存在 domain 时，才创建组织的 IDManager，以避免内存浪费
		var domain *metadbmodel.Domain
		result := db.Limit(1).Find(&domain)
		if result.Error != nil {
			log.Errorf("failed to get domain: %v", err, db.LogPrefixORGID)
			return nil, err
		}
		if result.RowsAffected == 0 {
			log.Infof("no domain in db, skip creating id manager", db.LogPrefixORGID)
			return nil, nil
		}
	}
	return m.NewIDManagerAndInitIfNotExists(orgID)
}

func (m *IDManagers) NewIDManagerAndInitIfNotExists(orgID int) (*IDManager, error) {
	m.mux.Lock()
	defer m.mux.Unlock()

	if mng, ok := m.orgIDToIDMng[orgID]; ok {
		return mng, nil
	}
	mng, err := newIDManager(m.recorderCfg, orgID)
	if err != nil {
		return nil, err
	}
	if err := mng.Refresh(); err != nil {
		return nil, err
	}
	m.orgIDToIDMng[orgID] = mng
	return mng, nil
}

func (m *IDManagers) refresh() error {
	if err := m.checkORGs(); err != nil {
		return err
	}
	for _, mng := range m.orgIDToIDMng {
		mng.Refresh()
	}
	return nil
}

func (m *IDManagers) checkORGs() error {
	orgIDs, err := metadb.GetORGIDs()
	if err != nil {
		return fmt.Errorf("failed to get org ids: %v", err)
	}

	m.mux.Lock()
	defer m.mux.Unlock()
	for orgID := range m.orgIDToIDMng {
		if !slices.Contains(orgIDs, orgID) {
			delete(m.orgIDToIDMng, orgID)
		}
	}
	return nil
}

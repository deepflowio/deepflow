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
	"errors"
	"fmt"
	"sync"

	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/recorder/config"
)

var (
	idMngsOnce sync.Once
	idMngs     *IDManagers
)

func GetIDManager(orgID int) (*IDManager, error) {
	return GetSingleton().NewIDManagerIfNotExists(orgID)
}

type IDManagers struct {
	mux          sync.Mutex
	orgIDToIDMng map[int]*IDManager
	recorderCfg  *config.RecorderConfig
}

func GetSingleton() *IDManagers {
	idMngsOnce.Do(func() {
		idMngs = &IDManagers{
			orgIDToIDMng: make(map[int]*IDManager),
		}
	})
	return idMngs
}

func (m *IDManagers) Init(cfg *config.RecorderConfig) {
	m.recorderCfg = cfg
}

func (m *IDManagers) Start() error {
	orgIDs, err := mysql.GetOrgIDs()
	if err != nil {
		return err
	}
	for _, id := range orgIDs {
		if _, err := m.NewIDManagerIfNotExists(id); err != nil {
			return errors.New(fmt.Sprintf("failed to start id manager for org %d: %v", id, err))
		}
	}
	return nil
}

func (o *IDManagers) Stop() {
	for _, idMng := range o.orgIDToIDMng {
		idMng.Stop()
	}
}

func (m *IDManagers) NewIDManagerIfNotExists(orgID int) (*IDManager, error) {
	if mng, ok := m.get(orgID); ok {
		return mng, nil
	}
	mng, err := newIDManager(m.recorderCfg, orgID)
	if err != nil {
		return nil, err
	}
	if err := mng.Start(); err != nil {
		return nil, err
	}
	m.set(orgID, mng)
	return mng, nil
}

func (m *IDManagers) Delete(orgID int) {
	m.mux.Lock()
	defer m.mux.Unlock()

	delete(m.orgIDToIDMng, orgID)
}

func (m *IDManagers) Create(orgID int) {
	m.NewIDManagerIfNotExists(orgID)
}

func (m *IDManagers) get(orgID int) (*IDManager, bool) {
	m.mux.Lock()
	defer m.mux.Unlock()

	mng, ok := m.orgIDToIDMng[orgID]
	return mng, ok
}

func (m *IDManagers) set(orgID int, idMng *IDManager) {
	m.mux.Lock()
	defer m.mux.Unlock()

	m.orgIDToIDMng[orgID] = idMng
}

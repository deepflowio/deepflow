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

package encoder

import (
	"context"
	"fmt"
	"sync"
	"time"

	"golang.org/x/exp/slices"

	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	prometheuscfg "github.com/deepflowio/deepflow/server/controller/prometheus/config"
)

var (
	orgEncodersOnce sync.Once
	orgEncoders     *ORGEncoders
)

type ORGEncoders struct {
	ctx    context.Context
	cancel context.CancelFunc

	mux     sync.Mutex
	working bool
	cfg     prometheuscfg.Config

	orgIDToEncoder map[int]*Encoder
}

func GetEncoder(orgID int) (*Encoder, error) {
	return GetORGEncoders().NewEncoderAndInitIfNotExist(orgID)
}

func GetORGEncoders() *ORGEncoders {
	orgEncodersOnce.Do(func() {
		orgEncoders = &ORGEncoders{
			orgIDToEncoder: make(map[int]*Encoder),
		}
	})
	return orgEncoders
}

func (e *ORGEncoders) Init(ctx context.Context, cfg prometheuscfg.Config) {
	log.Infof("init prometheus encoder")
	e.ctx, e.cancel = context.WithCancel(ctx)
	e.cfg = cfg
	e.orgIDToEncoder = make(map[int]*Encoder)
	return
}

func (e *ORGEncoders) Start() error {
	log.Info("prometheus encoders started")
	e.mux.Lock()
	if e.working {
		e.mux.Unlock()
		return nil
	}
	e.working = true
	e.mux.Unlock()

	orgIDs, err := mysql.GetORGIDs()
	if err != nil {
		return fmt.Errorf("failed to get org ids: %v", err)
	}

	for _, id := range orgIDs {
		if _, err := e.NewEncoderAndInitIfNotExist(id); err != nil {
			return fmt.Errorf("failed to start prometheus encoder for org %d: %v", id, err)
		}
	}
	e.refreshRegularly()
	return nil
}

func (e *ORGEncoders) Stop() {
	if e.cancel != nil {
		e.cancel()
	}
	e.mux.Lock()
	e.working = false
	e.orgIDToEncoder = make(map[int]*Encoder)
	e.mux.Unlock()
	log.Info("prometheus encoders stopped")
}

func (e *ORGEncoders) NewEncoderAndInitIfNotExist(orgID int) (*Encoder, error) {
	e.mux.Lock()
	defer e.mux.Unlock()

	if encoder, ok := e.orgIDToEncoder[orgID]; ok {
		return encoder, nil
	}
	encoder, err := newEncoder(e.cfg, orgID)
	if err != nil {
		return nil, err
	}
	err = encoder.Refresh()
	if err != nil {
		return nil, err
	}
	e.orgIDToEncoder[orgID] = encoder
	return encoder, nil
}

func (e *ORGEncoders) refreshRegularly() error {
	go func() {
		ticker := time.NewTicker(time.Duration(e.cfg.EncoderCacheRefreshInterval) * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-e.ctx.Done():
				return
			case <-ticker.C:
				e.refresh()
			}
		}
	}()
	return nil
}

func (e *ORGEncoders) refresh() error {
	if err := e.checkORGs(); err != nil {
		return err
	}
	for _, en := range e.orgIDToEncoder {
		en.Refresh()
	}
	return nil
}

func (e *ORGEncoders) checkORGs() error {
	orgIDs, err := mysql.GetORGIDs()
	if err != nil {
		return fmt.Errorf("failed to get org ids: %v", err)
	}

	e.mux.Lock()
	defer e.mux.Unlock()
	for orgID := range e.orgIDToEncoder {
		if !slices.Contains(orgIDs, orgID) {
			delete(e.orgIDToEncoder, orgID)
		}
	}
	return nil
}

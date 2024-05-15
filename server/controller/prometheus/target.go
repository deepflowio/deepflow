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

package prometheus

import (
	"hash/fnv"
	"math/rand"
	"sync/atomic"
	"time"

	"github.com/pkg/errors"

	"github.com/deepflowio/deepflow/message/trident"
)

var (
	targetCacheVersion = uint32(time.Now().Unix()) + uint32(rand.Intn(10000))
	targetCacheHash    uint64
)

type TargetSynchronizer struct {
	Synchronizer
}

func NewTargetSynchronizer() (*TargetSynchronizer, error) {
	synchronizer, err := newSynchronizer(1)
	if err != nil {
		return nil, err
	}
	return &TargetSynchronizer{synchronizer}, nil
}

func (s *TargetSynchronizer) GetTargets(in *trident.PrometheusTargetRequest) (*trident.PrometheusTargetResponse, error) {
	resp := new(trident.PrometheusTargetResponse)
	resp.Version = in.Version
	ts, err := s.refreshVersionIfChanged()
	if err != nil {
		return resp, err
	}

	version := atomic.LoadUint32(&targetCacheVersion)
	// if request version is equal to current cache version, return nothing
	if in.GetVersion() == version {
		return resp, nil
	}
	log.Infof("target version update from %d to %d", in.GetVersion(), version)

	resp.ResponseTargetIds = ts
	resp.Version = &version
	return resp, nil
}

func (s *TargetSynchronizer) refreshVersionIfChanged() ([]*trident.TargetResponse, error) {
	ts, err := s.assembleTargetFully()
	if err != nil {
		return nil, errors.Wrap(err, "assembleTargetFully")
	}

	resp := &trident.PrometheusTargetResponse{ResponseTargetIds: ts}
	respBytes, err := resp.Marshal()
	if err != nil {
		return nil, errors.Wrap(err, "refreshVersionIfChanged")
	}

	h64 := fnv.New64()
	h64.Write(respBytes)
	newHash := h64.Sum64()
	if newHash != atomic.LoadUint64(&targetCacheHash) {
		atomic.AddUint32(&targetCacheVersion, 1)
		atomic.StoreUint64(&targetCacheHash, newHash)
	}
	return ts, nil
}

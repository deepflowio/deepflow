/**
 * Copyright (c) 2023 Yunshan Networks
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

package grpc

import (
	"golang.org/x/net/context"

	"github.com/deepflowio/deepflow/message/controller"
	"github.com/deepflowio/deepflow/server/controller/side/prometheus"
)

type SynchronizerEvent struct{}

func NewSynchronizerEvent() *SynchronizerEvent {
	return &SynchronizerEvent{}
}

func (e *SynchronizerEvent) Sync(ctx context.Context, in *controller.SyncPrometheusRequest) (*controller.SyncPrometheusResponse, error) {
	log.Infof("SyncPrometheusRequest: %+v", in) // TODO debug
	resp, err := prometheus.GetSingleton().Synchronizer.Sync(in)
	if err != nil {
		log.Errorf("sync error: %v", err)
		return &controller.SyncPrometheusResponse{}, nil
	}
	log.Infof("SyncPrometheusResponse: %+v", resp) // TODO debug
	return resp, nil
}

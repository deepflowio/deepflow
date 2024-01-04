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

package controller

import (
	"golang.org/x/net/context"

	api "github.com/deepflowio/deepflow/message/controller"
	"github.com/deepflowio/deepflow/server/controller/recorder/db/idmng"
)

type IDEvent struct{}

func NewIDEvent() *IDEvent {
	return &IDEvent{}
}

func (e *IDEvent) Get(ctx context.Context, in *api.GetResourceIDRequest) (*api.GetResourceIDResponse, error) {
	ids := idmng.GetSingleton().AllocateIDs(*in.Type, int(*in.Count))
	uIDs := make([]uint32, 0, len(ids))
	for _, id := range ids {
		uIDs = append(uIDs, uint32(id))
	}
	return &api.GetResourceIDResponse{Ids: uIDs}, nil
}

func (e *IDEvent) Release(ctx context.Context, in *api.ReleaseResourceIDRequest) (*api.ReleaseResourceIDResponse, error) {
	ids := make([]int, 0, len(in.Ids))
	for _, uID := range in.Ids {
		ids = append(ids, int(uID))
	}
	idmng.GetSingleton().RecycleIDs(*in.Type, ids)
	return &api.ReleaseResourceIDResponse{}, nil
}

/*
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

package controller

import (
	"golang.org/x/net/context"

	"github.com/gogo/protobuf/proto"

	"github.com/deepflowio/deepflow/message/controller"
	"github.com/deepflowio/deepflow/message/trident"
	"github.com/deepflowio/deepflow/server/controller/side/prometheus"
	"github.com/deepflowio/deepflow/server/controller/side/prometheus/allocator"
)

type PrometheusEvent struct{}

func NewPrometheusEvent() *PrometheusEvent {
	return &PrometheusEvent{}
}

func (e *PrometheusEvent) GetStrIDs(ctx context.Context, in *controller.GetPrometheusStrIDsRequest) (*controller.GetPrometheusStrIDsResponse, error) {
	ids, err := allocator.GetSingleton().AllocateIDs(in.GetType(), in.GetStrs())
	strIDs := make([]*controller.PrometheusStrID, 0, len(ids))
	for _, id := range ids {
		strIDs = append(strIDs, &controller.PrometheusStrID{Id: proto.Uint32(uint32(id.ID)), Str: proto.String(id.Str)})
	}
	var errMsg string
	if err != nil {
		errMsg = err.Error()
	}
	return &controller.GetPrometheusStrIDsResponse{ErrorMsg: &errMsg, StrIds: strIDs}, nil
}

func (e *PrometheusEvent) GetAPPLabelIndexes(ctx context.Context, in *controller.GetPrometheusAPPLabelIndexesRequest) (*controller.GetPrometheusAPPLabelIndexesResponse, error) {
	respIdxs, err := allocator.GetSingleton().AllocateLabelIndexes(in.GetRequestIndexes())
	return &controller.GetPrometheusAPPLabelIndexesResponse{ResponseIndexes: respIdxs}, err
}

func (e *PrometheusEvent) GetLabelIDs(ctx context.Context, in *trident.PrometheusLabelIDsRequest) (*trident.PrometheusLabelIDsResponse, error) {
	resp, err := prometheus.NewEncoder().Encode(in.GetRequestLabels())
	return &trident.PrometheusLabelIDsResponse{ResponseLabelIds: resp}, err
}

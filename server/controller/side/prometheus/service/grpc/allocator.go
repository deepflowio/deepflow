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
	"github.com/gogo/protobuf/proto"
	"github.com/op/go-logging"
	"golang.org/x/net/context"

	"github.com/deepflowio/deepflow/message/controller"
	"github.com/deepflowio/deepflow/server/controller/side/prometheus/allocator"
)

var log = logging.MustGetLogger("side.prometheus.service.grpc")

type AllocatorEvent struct{}

func NewAllocatorEvent() *AllocatorEvent {
	return &AllocatorEvent{}
}

func (e *AllocatorEvent) GetStrIDs(ctx context.Context, in *controller.GetPrometheusStrIDsRequest) (*controller.GetPrometheusStrIDsResponse, error) {
	log.Debugf("StrIDsRequest: %s, %v", in.GetType(), in.GetStrs())
	ids, err := allocator.GetSingleton().AllocateIDs(in.GetType(), in.GetStrs())
	strIDs := make([]*controller.PrometheusStrID, 0, len(ids))
	for _, id := range ids {
		strIDs = append(strIDs, &controller.PrometheusStrID{Id: proto.Uint32(uint32(id.ID)), Str: proto.String(id.Str)})
	}
	var errMsg string
	if err != nil {
		errMsg = err.Error()
	}
	log.Debugf("StrIDsResponse: %s, %v", in.GetType(), strIDs)
	return &controller.GetPrometheusStrIDsResponse{ErrorMsg: &errMsg, StrIds: strIDs}, nil
}

func (e *AllocatorEvent) GetAPPLabelIndexes(ctx context.Context, in *controller.GetPrometheusAPPLabelIndexesRequest) (*controller.GetPrometheusAPPLabelIndexesResponse, error) {
	log.Debugf("APPLabelIndexesRequest: %v", in.GetRequestIndexes())
	respIdxs, err := allocator.GetSingleton().AllocateLabelIndexes(in.GetRequestIndexes())
	log.Debugf("APPLabelIndexesResponse: %v", respIdxs)
	return &controller.GetPrometheusAPPLabelIndexesResponse{ResponseIndexes: respIdxs}, err
}

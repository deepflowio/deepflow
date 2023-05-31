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
	"github.com/op/go-logging"
	"golang.org/x/net/context"

	"github.com/deepflowio/deepflow/message/trident"
	"github.com/deepflowio/deepflow/server/controller/side/prometheus"
)

var log = logging.MustGetLogger("side.prometheus.grpc")

type EncoderEvent struct{}

func NewEncoderEvent() *EncoderEvent {
	return &EncoderEvent{}
}

func (e *EncoderEvent) GetLabelIDs(ctx context.Context, in *trident.PrometheusLabelIDsRequest) (*trident.PrometheusLabelIDsResponse, error) {
	log.Debugf("GetLabelIDsRequest: %+v", in)
	resp, err := prometheus.NewEncoder().Encode(in.GetRequestLabels())
	if err != nil {
		log.Errorf("encode str error: %+v", err)
		return &trident.PrometheusLabelIDsResponse{}, nil
	}
	log.Debugf("GetLabelIDsResponse: %v+", resp)
	return &trident.PrometheusLabelIDsResponse{ResponseLabelIds: resp}, err
}

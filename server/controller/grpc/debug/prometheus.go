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

package debug

import (
	"context"

	"github.com/op/go-logging"
	"google.golang.org/grpc"

	"github.com/deepflowio/deepflow/message/controller"
	grpcserver "github.com/deepflowio/deepflow/server/controller/grpc"
	"github.com/deepflowio/deepflow/server/controller/side/prometheus"
)

var log = logging.MustGetLogger("controller/debug")

type prometheusService struct{}

type service struct{}

func init() {
	grpcserver.Add(newPrometheusService())
}

func newPrometheusService() *prometheusService {
	return &prometheusService{}
}

func (p *prometheusService) DebugPrometheusCache(ctx context.Context, in *controller.PrometheusCacheRequest,
	opts ...grpc.CallOption) (*controller.PrometheusCacheResponse, error) {

	return &controller.PrometheusCacheResponse{
		Content: prometheus.GetDebugCache(*in.Type),
	}, nil
}

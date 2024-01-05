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
	"context"

	"google.golang.org/grpc"

	api "github.com/deepflowio/deepflow/message/controller"
	grpcserver "github.com/deepflowio/deepflow/server/controller/grpc"
	"github.com/deepflowio/deepflow/server/controller/prometheus/cache"
)

type prometheusService struct{}

func init() {
	grpcserver.Add(newPrometheusService())
}

func newPrometheusService() *prometheusService {
	return &prometheusService{}
}

func (p *prometheusService) Register(gs *grpc.Server) error {
	log.Info("grpc register controller debug service")
	api.RegisterPrometheusDebugServer(gs, p)
	return nil
}

func (p *prometheusService) DebugPrometheusCache(ctx context.Context,
	in *api.PrometheusCacheRequest) (*api.PrometheusCacheResponse, error) {

	return &api.PrometheusCacheResponse{
		Content: cache.GetDebugCache(*in.Type),
	}, nil
}

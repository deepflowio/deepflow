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
	api "github.com/deepflowio/deepflow/message/controller"
	"github.com/deepflowio/deepflow/message/trident"
	"github.com/deepflowio/deepflow/server/controller/genesis"
	grpcserver "github.com/deepflowio/deepflow/server/controller/grpc"

	"github.com/op/go-logging"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
)

var log = logging.MustGetLogger("grpc.controller")

type service struct {
	encryptKeyEvent *EncryptKeyEvent
	resourceIDEvent *IDEvent
	prometheusEvent *PrometheusEvent
}

func init() {
	grpcserver.Add(newService())
}

func newService() *service {
	return &service{
		encryptKeyEvent: NewEncryptKeyEvent(),
		resourceIDEvent: NewIDEvent(),
		prometheusEvent: NewPrometheusEvent(),
	}
}

func (s *service) Register(gs *grpc.Server) error {
	log.Info("grpc register controller service")
	api.RegisterControllerServer(gs, s)
	return nil
}

func (s *service) GetEncryptKey(ctx context.Context, in *api.EncryptKeyRequest) (*api.EncryptKeyResponse, error) {
	return s.encryptKeyEvent.Get(ctx, in)
}

func (s *service) GenesisSharingK8S(ctx context.Context, in *api.GenesisSharingK8SRequest) (*api.GenesisSharingK8SResponse, error) {
	return genesis.Synchronizer.GenesisSharingK8S(ctx, in)
}

func (s *service) GenesisSharingSync(ctx context.Context, in *api.GenesisSharingSyncRequest) (*api.GenesisSharingSyncResponse, error) {
	return genesis.Synchronizer.GenesisSharingSync(ctx, in)
}

func (s *service) GenesisSharingPrometheus(ctx context.Context, in *api.GenesisSharingPrometheusRequest) (*api.GenesisSharingPrometheusResponse, error) {
	return genesis.Synchronizer.GenesisSharingPrometheus(ctx, in)
}

func (s *service) GetResourceID(ctx context.Context, in *api.GetResourceIDRequest) (*api.GetResourceIDResponse, error) {
	return s.resourceIDEvent.Get(ctx, in)
}

func (s *service) ReleaseResourceID(ctx context.Context, in *api.ReleaseResourceIDRequest) (*api.ReleaseResourceIDResponse, error) {
	return s.resourceIDEvent.Release(ctx, in)
}

func (s *service) GetPrometheusStrIDs(ctx context.Context, in *api.GetPrometheusStrIDsRequest) (*api.GetPrometheusStrIDsResponse, error) {
	return s.prometheusEvent.GetStrIDs(ctx, in)
}

func (s *service) GetPrometheusAPPLabelIndexes(ctx context.Context, in *api.GetPrometheusAPPLabelIndexesRequest) (*api.GetPrometheusAPPLabelIndexesResponse, error) {
	return s.prometheusEvent.GetAPPLabelIndexes(ctx, in)
}

func (s *service) GetPrometheusLabelIDs(ctx context.Context, in *trident.PrometheusLabelIDsRequest) (*trident.PrometheusLabelIDsResponse, error) {
	return s.prometheusEvent.GetLabelIDs(ctx, in)
}

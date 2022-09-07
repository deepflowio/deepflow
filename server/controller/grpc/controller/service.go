/*
 * Copyright (c) 2022 Yunshan Networks
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
	api "github.com/deepflowys/deepflow/message/controller"
	"github.com/deepflowys/deepflow/server/controller/genesis"
	grpcserver "github.com/deepflowys/deepflow/server/controller/grpc"

	"github.com/op/go-logging"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
)

var log = logging.MustGetLogger("grpc.controller")

type service struct {
	encryptKeyEvent *EncryptKeyEvent
	resourceIDEvent *IDEvent
}

func init() {
	log.Info("grpc add controller service")
	grpcserver.Add(newService())
}

func newService() *service {
	return &service{
		encryptKeyEvent: NewEncryptKeyEvent(),
		resourceIDEvent: NewIDEvent(),
	}
}

func (s *service) Register(gs *grpc.Server) error {
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

func (s *service) GetResourceID(ctx context.Context, in *api.GetResourceIDRequest) (*api.GetResourceIDResponse, error) {
	return s.resourceIDEvent.Get(ctx, in)
}

func (s *service) ReleaseResourceID(ctx context.Context, in *api.ReleaseResourceIDRequest) (*api.ReleaseResourceIDResponse, error) {
	return s.resourceIDEvent.Release(ctx, in)
}

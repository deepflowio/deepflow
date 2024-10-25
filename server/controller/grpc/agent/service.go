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

package synchronize

import (
	"time"

	"github.com/op/go-logging"
	"golang.org/x/net/context"
	"google.golang.org/grpc"

	api "github.com/deepflowio/deepflow/message/agent"

	grpcserver "github.com/deepflowio/deepflow/server/controller/grpc"
	"github.com/deepflowio/deepflow/server/controller/grpc/statsd"
)

var log = logging.MustGetLogger("grpc.agent")

type service struct {
	kubernetesClusterIDEvent *KubernetesClusterIDEvent
}

func init() {
	grpcserver.Add(newService())
}

func newService() *service {
	return &service{
		kubernetesClusterIDEvent: NewKubernetesClusterIDEvent(),
	}
}

func (s *service) Register(gs *grpc.Server) error {
	api.RegisterSynchronizerServer(gs, s)
	return nil
}

func (s *service) Sync(ctx context.Context, in *api.SyncRequest) (*api.SyncResponse, error) {
	return &api.SyncResponse{}, nil
}

func (s *service) Push(r *api.SyncRequest, in api.Synchronizer_PushServer) error {
	return nil
}

func (s *service) Upgrade(r *api.UpgradeRequest, in api.Synchronizer_UpgradeServer) error {
	return nil
}

func (s *service) Query(ctx context.Context, in *api.NtpRequest) (*api.NtpResponse, error) {
	return &api.NtpResponse{}, nil
}

func (s *service) GenesisSync(ctx context.Context, in *api.GenesisSyncRequest) (*api.GenesisSyncResponse, error) {
	return &api.GenesisSyncResponse{}, nil
}

func (s *service) KubernetesAPISync(ctx context.Context, in *api.KubernetesAPISyncRequest) (*api.KubernetesAPISyncResponse, error) {
	return &api.KubernetesAPISyncResponse{}, nil
}

func (s *service) GetKubernetesClusterID(ctx context.Context, in *api.KubernetesClusterIDRequest) (*api.KubernetesClusterIDResponse, error) {
	startTime := time.Now()
	defer func() {
		statsd.AddGrpcCostStatsd(statsd.GetKubernetesClusterID, int(time.Now().Sub(startTime).Milliseconds()))
	}()
	return s.kubernetesClusterIDEvent.GetKubernetesClusterID(ctx, in)
}

func (s *service) GPIDSync(ctx context.Context, in *api.GPIDSyncRequest) (*api.GPIDSyncResponse, error) {
	return &api.GPIDSyncResponse{}, nil
}

func (s *service) Plugin(r *api.PluginRequest, in api.Synchronizer_PluginServer) error {
	return nil
}

func (s *service) RemoteExecute(in api.Synchronizer_RemoteExecuteServer) error {
	return nil
}

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

package synchronize

import (
	api "github.com/deepflowys/deepflow/message/trident"
	context "golang.org/x/net/context"
	"google.golang.org/grpc"

	grpcserver "github.com/deepflowys/deepflow/server/controller/grpc"
	"github.com/deepflowys/deepflow/server/controller/trisolaris"
)

type service struct{}

func init() {
	grpcserver.Add(newService())
}

func newService() *service {
	return &service{}
}

func (s *service) Register(gs *grpc.Server) error {
	api.RegisterDebugServer(gs, s)
	return nil
}

func (s *service) DebugGPIDGlobalLocalData(ctx context.Context, in *api.GPIDSyncRequest) (*api.GPIDGlobalLocalData, error) {
	processInfo := trisolaris.GetGVTapInfo().GetProcessInfo()
	return &api.GPIDGlobalLocalData{
		Entries: processInfo.GetGlobalLocalEntries(),
	}, nil
}

func (s *service) DebugGPIDVTapLocalData(ctx context.Context, in *api.GPIDSyncRequest) (*api.GPIDSyncRequest, error) {
	vtapCacheKey := in.GetCtrlIp() + "-" + in.GetCtrlMac()
	vtapCache := trisolaris.GetGVTapInfo().GetVTapCache(vtapCacheKey)
	if vtapCache == nil {
		return &api.GPIDSyncRequest{}, nil
	}
	processInfo := trisolaris.GetGVTapInfo().GetProcessInfo()
	req := processInfo.GetVTapGPIDReq(uint32(vtapCache.GetVTapID()))
	if req == nil {
		req = &api.GPIDSyncRequest{}
	}

	return req, nil
}

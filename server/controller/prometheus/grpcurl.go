/**
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

package prometheus

import (
	"context"
	"fmt"
	"net"

	"google.golang.org/grpc"

	"github.com/deepflowio/deepflow/message/controller"
	"github.com/deepflowio/deepflow/server/controller/common"
)

type GRPCURL struct{}

func GetMasterGRPCConn() (*grpc.ClientConn, error) {
	host, _, grpcPort, err := common.GetMasterControllerHostPort()
	if err != nil {
		log.Error("get master controller host info failed")
		return nil, err
	}
	grpcServer := net.JoinHostPort(host, fmt.Sprintf("%d", grpcPort))
	return grpc.Dial(grpcServer, grpc.WithInsecure())
}

func (s *GRPCURL) Sync(req *controller.SyncPrometheusRequest) (*controller.SyncPrometheusResponse, error) {
	conn, err := GetMasterGRPCConn()
	if err != nil {
		log.Errorf("create grpc connection faild: %s", err.Error())
		return nil, err
	}

	defer conn.Close()
	client := controller.NewControllerClient(conn)

	resp, err := client.SyncPrometheus(context.Background(), req)
	if err != nil {
		log.Error("sync prometheus failed: %s", err.Error())
		return nil, err
	}

	// log.Infof("sync prometheus: %+v ", resp)
	return resp, nil
}

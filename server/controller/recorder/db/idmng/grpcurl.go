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

package idmng

import (
	"context"
	"fmt"
	"net"

	"google.golang.org/grpc"

	api "github.com/deepflowio/deepflow/message/controller"
	"github.com/deepflowio/deepflow/server/controller/common"
)

func GetMasterGRPCConn() (*grpc.ClientConn, error) {
	host, _, grpcPort, err := common.GetMasterControllerHostPort()
	if err != nil {
		log.Error("get master controller host info failed")
		return nil, err
	}
	grpcServer := net.JoinHostPort(host, fmt.Sprintf("%d", grpcPort))
	return grpc.Dial(grpcServer, grpc.WithInsecure())
}

func GetIDs(resourceType string, count int) (ids []int, err error) {
	conn, err := GetMasterGRPCConn()
	if err != nil {
		log.Errorf("create grpc connection failed: %s", err.Error())
		return nil, err
	}
	defer conn.Close()

	client := api.NewControllerClient(conn)
	uCount := uint32(count)
	resp, err := client.GetResourceID(context.Background(), &api.GetResourceIDRequest{Type: &resourceType, Count: &uCount})
	if err != nil {
		log.Error("get %s id failed: %s", resourceType, err.Error())
		return
	}
	for _, uID := range resp.GetIds() {
		ids = append(ids, int(uID))
	}
	log.Infof("get %s ids: %v (expected count: %d, true count: %d)", resourceType, ids, count, len(ids))
	return
}

func ReleaseIDs(resourceType string, ids []int) (err error) {
	conn, err := GetMasterGRPCConn()
	if err != nil {
		log.Errorf("create grpc connection failed: %s", err.Error())
		return err
	}
	defer conn.Close()

	uIDs := make([]uint32, 0, len(ids))
	for _, id := range ids {
		uIDs = append(uIDs, uint32(id))
	}
	client := api.NewControllerClient(conn)
	_, err = client.ReleaseResourceID(context.Background(), &api.ReleaseResourceIDRequest{Ids: uIDs, Type: &resourceType})
	if err != nil {
		log.Errorf("release %s id failed: %s", resourceType, err.Error())
	}
	log.Infof("release %s ids: %v (count: %d)", resourceType, ids, len(ids))
	return
}

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

package common

import (
	"database/sql"
	"fmt"
	"net"
	"sync"

	"github.com/deepflowio/deepflow/message/trident"
	"github.com/deepflowio/deepflow/server/libs/datatype"
	"github.com/deepflowio/deepflow/server/libs/grpc"
	"github.com/deepflowio/deepflow/server/libs/queue"
	"github.com/deepflowio/deepflow/server/libs/stats"
	"github.com/deepflowio/deepflow/server/libs/zerodoc"

	clickhouse "github.com/ClickHouse/clickhouse-go/v2"
	logging "github.com/op/go-logging"
)

var log = logging.MustGetLogger("common")

const (
	MODULE_INGESTER             = "ingester."
	QUEUE_STATS_MODULE_INGESTER = queue.OptionModule(MODULE_INGESTER)
)

type DBs []*sql.DB

func (s DBs) Exec(query string, args ...any) (sql.Result, error) {
	var result sql.Result
	var err error
	for _, conn := range s {
		log.Infof("Begin exec SQL: %s", query)
		result, err = conn.Exec(query, args...)
		log.Infof("End exec SQL: %s, err: %v", query, err)
		if err != nil {
			return result, err
		}
	}
	return result, nil
}

func (s DBs) ExecParallel(query string, args ...any) (sql.Result, error) {
	var result sql.Result
	var err error
	wg := sync.WaitGroup{}
	for _, conn := range s {
		wg.Add(1)
		go func() {
			log.Infof("Begin exec parallel SQL: %s", query)
			r, e := conn.Exec(query, args...)
			log.Infof("End exec parallel SQL: %s, err:%v", query, err)
			if err == nil {
				result = r
				err = e
			}
			wg.Done()
		}()
	}
	wg.Wait()
	return result, err
}

func (s DBs) Query(query string, args ...any) (*sql.Rows, error) {
	var result *sql.Rows
	var err error
	for _, conn := range s {
		result, err = conn.Query(query, args...)
		if err != nil {
			return result, err
		}
	}
	return result, nil
}

func (s DBs) Close() error {
	for _, conn := range s {
		if err := conn.Close(); err != nil {
			return err
		}
	}
	return nil
}

func NewCKConnections(addrs []string, username, password string) (DBs, error) {
	sqlDBs := DBs{}
	for _, addr := range addrs {
		connect, err := NewCKConnection(addr, username, password)
		if err != nil {
			return nil, err
		}
		sqlDBs = append(sqlDBs, connect)
	}
	return sqlDBs, nil
}

func NewCKConnection(addr, username, password string) (*sql.DB, error) {
	connect, err := sql.Open("clickhouse", fmt.Sprintf("//%s:%s@%s", username, password, addr))
	if err != nil {
		return nil, err
	}
	if err := connect.Ping(); err != nil {
		if exception, ok := err.(*clickhouse.Exception); ok {
			log.Warningf("[%d] %s \n%s\n", exception.Code, exception.Message, exception.StackTrace)
		}
		return nil, err
	}
	return connect, nil
}

func RegisterCountableForIngester(name string, countable stats.Countable, opts ...stats.Option) error {
	return stats.RegisterCountableWithModulePrefix(MODULE_INGESTER, name, countable, opts...)
}

// 如果通过MAC匹配平台信息失败，则需要通过IP再获取, 解决工单122/126问题
func RegetInfoFromIP(isIPv6 bool, ip6 net.IP, ip4 uint32, epcID int32, platformData *grpc.PlatformInfoTable) *grpc.Info {
	if isIPv6 {
		return platformData.QueryIPV6Infos(epcID, ip6)
	} else {
		return platformData.QueryIPV4Infos(epcID, ip4)
	}
}

const (
	IpType         = 255
	InternatIpType = 0

	PodType     = 10
	PodNodeType = 14

	ServiceType = 102
)

func GetResourceGl0(podID, podNodeID, l3DeviceID uint32, l3DeviceType uint8, l3EpcID int32) (uint32, uint8) {
	if podID > 0 {
		return podID, PodType
	} else if podNodeID > 0 {
		return podNodeID, PodNodeType
	} else if l3DeviceID > 0 {
		return l3DeviceID, l3DeviceType
	} else if l3EpcID == datatype.EPC_FROM_INTERNET {
		return 0, InternatIpType
	}

	return 0, IpType
}

func GetResourceGl1(podGroupID, podNodeID, l3DeviceID uint32, l3DeviceType, podGroupType uint8, l3EpcID int32) (uint32, uint8) {
	if podGroupID > 0 {
		return podGroupID, podGroupType
	} else if podNodeID > 0 {
		return podNodeID, PodNodeType
	} else if l3DeviceID > 0 {
		return l3DeviceID, l3DeviceType
	} else if l3EpcID == datatype.EPC_FROM_INTERNET {
		return 0, InternatIpType
	}
	return 0, IpType
}

func GetResourceGl2(serviceID, podGroupID, podNodeID, l3DeviceID uint32, l3DeviceType, podGroupType uint8, l3EpcID int32) (uint32, uint8) {
	if serviceID > 0 {
		return serviceID, ServiceType
	}
	return GetResourceGl1(podGroupID, podNodeID, l3DeviceID, l3DeviceType, podGroupType, l3EpcID)
}

func IsPodServiceIP(deviceType zerodoc.DeviceType, podId, podNodeId uint32) bool {
	// 如果是NodeIP,clusterIP或后端podIP需要匹配service_id
	return deviceType == zerodoc.DeviceType(trident.DeviceType_DEVICE_TYPE_POD_SERVICE) || podId != 0 || podNodeId != 0
}

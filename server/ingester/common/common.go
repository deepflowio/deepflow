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

package common

import (
	"database/sql"
	"fmt"
	"net"
	"net/url"
	"sync"

	"github.com/deepflowio/deepflow/message/trident"
	"github.com/deepflowio/deepflow/server/libs/datatype"
	flow_metrics "github.com/deepflowio/deepflow/server/libs/flow-metrics"
	"github.com/deepflowio/deepflow/server/libs/grpc"
	"github.com/deepflowio/deepflow/server/libs/queue"
	"github.com/deepflowio/deepflow/server/libs/stats"

	clickhouse "github.com/ClickHouse/clickhouse-go/v2"
	logging "github.com/op/go-logging"
)

var log = logging.MustGetLogger("common")

const (
	MODULE_INGESTER             = "ingester_"
	QUEUE_STATS_MODULE_INGESTER = queue.OptionModule(MODULE_INGESTER)
)

type DBs []*sql.DB

func (s DBs) Exec(query string, args ...any) (sql.Result, error) {
	var result sql.Result
	var err error
	for _, conn := range s {
		log.Infof("Begin exec SQL: %s", query)
		result, err = conn.Exec(query, args...)
		if err != nil {
			log.Infof("End exec SQL: %s, err: %v", query, err)
			return result, err
		}
		log.Infof("End exec SQL: %s", query)
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

func (s DBs) Query(query string, args ...any) ([]*sql.Rows, error) {
	var results []*sql.Rows
	for _, conn := range s {
		result, err := conn.Query(query, args...)
		results = append(results, result)
		if err != nil {
			return results, err
		}
	}
	return results, nil
}

func (s DBs) Close() error {
	for _, conn := range s {
		if conn == nil {
			continue
		}
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
	connect, err := sql.Open("clickhouse", fmt.Sprintf("//%s@%s?dial_timeout=10s&max_execution_time=120", url.UserPassword(username, password), addr))
	if err != nil {
		return nil, fmt.Errorf("new ck connection to %s failed: %s", addr, err)
	}
	if err := connect.Ping(); err != nil {
		if exception, ok := err.(*clickhouse.Exception); ok {
			log.Warningf("[%d] %s \n%s\n", exception.Code, exception.Message, exception.StackTrace)
		}
		return nil, fmt.Errorf("ck connection ping (%s) failed: %s", addr, err)
	}
	return connect, nil
}

func RegisterCountableForIngester(name string, countable stats.Countable, opts ...stats.Option) error {
	return stats.RegisterCountableWithModulePrefix(MODULE_INGESTER, name, countable, opts...)
}

// 如果通过MAC匹配平台信息失败，则需要通过IP再获取, 解决工单122/126问题
func RegetInfoFromIP(orgId uint16, isIPv6 bool, ip6 net.IP, ip4 uint32, epcID int32, platformData *grpc.PlatformInfoTable) *grpc.Info {
	if isIPv6 {
		return platformData.QueryIPV6Infos(orgId, epcID, ip6)
	} else {
		return platformData.QueryIPV4Infos(orgId, epcID, ip4)
	}
}

const (
	IpType         = 255
	InternetIpType = 0

	PodType     = uint8(trident.AutoServiceType_AUTO_SERVICE_TYPE_POD)      // 10
	PodNodeType = uint8(trident.AutoServiceType_AUTO_SERVICE_TYPE_POD_NODE) // 14

	PodServiceType    = uint8(trident.AutoServiceType_AUTO_SERVICE_TYPE_POD_SERVICE)    // 12
	PodClusterType    = uint8(trident.AutoServiceType_AUTO_SERVICE_TYPE_POD_CLUSTER)    // 103
	CustomServiceType = uint8(trident.AutoServiceType_AUTO_SERVICE_TYPE_CUSTOM_SERVICE) // 104

	ProcessType = uint8(trident.AutoServiceType_AUTO_SERVICE_TYPE_PROCESS) // 120

)

func GetAutoInstance(podID, gpID, podNodeID, l3DeviceID, subnetID uint32, l3DeviceType uint8, l3EpcID int32) (uint32, uint8) {
	if podID > 0 {
		return podID, PodType
	} else if gpID > 0 {
		return gpID, ProcessType
	} else if podNodeID > 0 {
		return podNodeID, PodNodeType
	} else if l3DeviceID > 0 {
		return l3DeviceID, l3DeviceType
	} else if l3EpcID == datatype.EPC_FROM_INTERNET {
		return 0, InternetIpType
	}

	return subnetID, IpType
}

func GetAutoService(customServiceID, podServiceID, podGroupID, gpID, podClusterID, l3DeviceID, subnetID uint32, l3DeviceType, podGroupType uint8, l3EpcID int32) (uint32, uint8) {
	if customServiceID > 0 {
		return customServiceID, CustomServiceType
	} else if podServiceID > 0 {
		return podServiceID, PodServiceType
	} else if podGroupID > 0 {
		return podGroupID, podGroupType
	} else if gpID > 0 {
		return gpID, ProcessType
	} else if podClusterID > 0 {
		return podClusterID, PodClusterType
	} else if l3DeviceID > 0 {
		return l3DeviceID, l3DeviceType
	} else if l3EpcID == datatype.EPC_FROM_INTERNET {
		return 0, InternetIpType
	}
	return subnetID, IpType
}

func IsPodServiceIP(deviceType flow_metrics.DeviceType, podId, podNodeId uint32) bool {
	// 如果是NodeIP,clusterIP或后端podIP需要匹配service_id
	return deviceType == flow_metrics.DeviceType(trident.DeviceType_DEVICE_TYPE_POD_SERVICE) || podId != 0 || podNodeId != 0
}

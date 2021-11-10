package common

import (
	"database/sql"
	"fmt"
	"math"
	"net"

	clickhouse "github.com/ClickHouse/clickhouse-go"
	logging "github.com/op/go-logging"
	"gitlab.yunshan.net/yunshan/droplet-libs/grpc"
	"gitlab.yunshan.net/yunshan/message/trident"
)

var log = logging.MustGetLogger("common")

func NewCKConnection(addr, username, password string) (*sql.DB, error) {
	connect, err := sql.Open("clickhouse", fmt.Sprintf("%s?username=%s&password=%s", addr, username, password))
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

// 如果通过MAC匹配平台信息失败，则需要通过IP再获取, 解决工单122/126问题
// 此时通过IP获取的平台信息中，仅返回subnet_id,az_id,region_id,device_type，且device_type设置为路由器类型
func RegetInfoFromIP(isIPv6 bool, ip6 net.IP, ip4 uint32, epcID int16, platformData *grpc.PlatformInfoTable) *grpc.Info {
	var info *grpc.Info
	if isIPv6 {
		info = platformData.QueryIPV6Infos(epcID, ip6)
	} else {
		info = platformData.QueryIPV4Infos(epcID, ip4)
	}
	if info != nil {
		newInfo := &grpc.Info{}
		newInfo.SubnetID = info.SubnetID
		newInfo.AZID = info.AZID
		newInfo.RegionID = info.RegionID
		newInfo.DeviceType = uint32(trident.DeviceType_DEVICE_TYPE_NSP_VGATEWAY)
		newInfo.DeviceID = math.MaxInt32 // 若为0，WEB会认为无效值，故取Int32最大值，api层会特殊处理
		info = newInfo
	}
	return info
}

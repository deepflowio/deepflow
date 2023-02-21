package dbwriter

import (
	"fmt"
	"net"
	"sync/atomic"
	"time"

	basecommon "github.com/deepflowio/deepflow/server/ingester/common"
	"github.com/deepflowio/deepflow/server/libs/ckdb"
	"github.com/deepflowio/deepflow/server/libs/grpc"
	"github.com/deepflowio/deepflow/server/libs/pool"
	"github.com/google/gopacket/layers"
	"github.com/pyroscope-io/pyroscope/pkg/storage"
)

const (
	DefaultPartition  = ckdb.TimeFuncTwelveHour
	LabelTraceID      = "trace_id"
	LabelSpanName     = "span_name"
	LabelAppService   = "app_service"
	LabelAppInstance  = "app_instance"
	LabelLanguageType = "profile_language_type"
)

var InProcessCounter uint32

type InProcessProfile struct {
	_id  uint64
	Time uint32

	// Profile
	// TODO: ProfileEventType/ProfileValueUnit/ProfileLanguageType/Tags 可以写 flow_tag 优化查询
	// TODO: ProfileEventType/ProfileValueUnit/ProfileLanguageType/Tags can write in flow_tag for query optimize
	AppService         string `json:"app_service"`
	ProfileLocationStr string `json:"profile_location_str"` // package/(class/struct)/function name, e.g.: java/lang/Thread.run
	ProfileValue       int64  `json:"profile_value"`
	// profile_event_type 由 app_service 与 event_type 构成，event_type 的取值与 profile_value_unit 对应关系见下
	// profile_event_type union by app_service and event_type, relations between event_type and profile_value_unit is under the struct definition
	ProfileEventType       string   `json:"profile_event_type"` // app_service.event_type, e.g.: rideshare.java.push.app.cpu
	ProfileValueUnit       string   `json:"profile_value_unit"`
	ProfileCreateTimestamp int64    `json:"profile_create_timestamp"` // 数据上传时间 while data upload to server
	ProfileInTimestamp     int64    `json:"profile_in_timestamp"`     // 数据写入时间 while data write in storage
	ProfileLanguageType    string   `json:"profile_language_type"`    // e.g.: Golang/Java/Python...
	ProfileNodeID          uint64   `json:"profile_node_id"`
	ProfileParentNodeID    uint64   `json:"profile_parent_node_id"`
	ProfileID              string   `json:"profile_id"`
	TraceID                string   `json:"trace_id"`
	SpanName               string   `json:"span_name"`
	AppInstance            string   `json:"app_instance"`
	TagNames               []string `json:"tag_names"`
	TagValues              []string `json:"tag_values"`

	// Universal Tag
	VtapID       uint16
	RegionID     uint16
	AZID         uint16
	L3EpcID      int32
	HostID       uint16
	PodID        uint32
	PodNodeID    uint32
	PodNSID      uint16
	PodClusterID uint16
	PodGroupID   uint32
	IP4          uint32 `json:"ip4"`
	IP6          net.IP `json:"ip6"`
	IsIPv4       bool   `json:"is_ipv4"`

	L3DeviceType uint8
	L3DeviceID   uint32
	ServiceID    uint32
}

// event_type <-> profile_value_unit relation
/*
	| event_type                       | unit    |
	|----------------------------------|---------|
	| cpu                              | samples |
	| inuse_objects                    | objects |
	| alloc_objects                    | objects |
	| inuse_space                      | bytes   |
	| alloc_space                      | bytes   |
	| itimer(java)                     | samples |
	| wall(java)                       | samples |
	| alloc_in_new_tlab_objects(java)  | objects |
	| alloc_in_new_tlab_bytes(java)    | bytes   |
	| alloc_outside_tlab_objects(java) | objects |
	| alloc_in_new_tlab_bytes(java)    | bytes   |
*/

func ProfileColumns() []*ckdb.Column {
	return []*ckdb.Column{
		// profile information
		ckdb.NewColumn("time", ckdb.DateTime),
		ckdb.NewColumn("_id", ckdb.UInt64).SetCodec(ckdb.CodecDoubleDelta),
		ckdb.NewColumn("ip4", ckdb.IPv4).SetComment("IPv4地址"),
		ckdb.NewColumn("ip6", ckdb.IPv6).SetComment("IPV6地址"),

		ckdb.NewColumn("app_service", ckdb.String).SetComment("应用名称, 用户配置上报"),
		ckdb.NewColumn("profile_location_str", ckdb.String).SetComment("profile 位置"),
		ckdb.NewColumn("profile_value", ckdb.Int64).SetComment("profile self value"),
		ckdb.NewColumn("profile_value_unit", ckdb.String).SetComment("profile value 的单位"),
		ckdb.NewColumn("profile_event_type", ckdb.String).SetComment("剖析类型"),
		ckdb.NewColumn("profile_create_timestamp", ckdb.DateTime64us).SetIndex(ckdb.IndexSet).SetComment("client 端聚合时间"),
		ckdb.NewColumn("profile_in_timestamp", ckdb.DateTime64us).SetComment("DeepFlow 的写入时间，同批上报的批次数据具备相同的值"),
		ckdb.NewColumn("profile_language_type", ckdb.String).SetComment("语言类型"),
		ckdb.NewColumn("profile_node_id", ckdb.UInt64).SetComment("叶子节点 ID"),
		ckdb.NewColumn("profile_parent_node_id", ckdb.UInt64).SetComment("父节点 ID"),
		ckdb.NewColumn("profile_id", ckdb.String).SetComment("含义等同 l7_flow_log 的 span_id"),
		ckdb.NewColumn("trace_id", ckdb.String).SetComment("含义等同 l7_flow_log 的 trace_id"),
		ckdb.NewColumn("span_name", ckdb.String).SetComment("含义等同 l7_flow_log 的 endpoint"),
		ckdb.NewColumn("app_instance", ckdb.String).SetComment("应用实例名称, 用户上报"),
		ckdb.NewColumn("tag_names", ckdb.ArrayString).SetComment("profile 上报的 tagnames"),
		ckdb.NewColumn("tag_values", ckdb.ArrayString).SetComment("profile 上报的 tagvalues"),

		// universal tag
		ckdb.NewColumn("vtap_id", ckdb.UInt16).SetIndex(ckdb.IndexSet),
		ckdb.NewColumn("region_id", ckdb.UInt16).SetComment("云平台区域ID"),
		ckdb.NewColumn("az_id", ckdb.UInt16).SetComment("可用区ID"),
		ckdb.NewColumn("l3_epc_id", ckdb.Int32).SetComment("ip对应的EPC ID"),
		ckdb.NewColumn("host_id", ckdb.UInt16).SetComment("宿主机ID"),
		ckdb.NewColumn("pod_id", ckdb.UInt32).SetComment("容器ID"),
		ckdb.NewColumn("pod_node_id", ckdb.UInt32).SetComment("容器节点ID"),
		ckdb.NewColumn("pod_ns_id", ckdb.UInt16).SetComment("容器命名空间ID"),
		ckdb.NewColumn("pod_cluster_id", ckdb.UInt16).SetComment("容器集群ID"),
		ckdb.NewColumn("pod_group_id", ckdb.UInt32).SetComment("容器组ID"),

		ckdb.NewColumn("l3_device_type", ckdb.UInt8).SetComment("资源类型"),
		ckdb.NewColumn("l3_device_id", ckdb.UInt32).SetComment("资源ID"),
		ckdb.NewColumn("service_id", ckdb.UInt32).SetComment("服务ID"),
	}
}

func GenProfileCKTable(cluster, dbName, tableName, storagePolicy string, ttl int, coldStorage *ckdb.ColdStorage) *ckdb.Table {
	timeKey := "time"
	engine := ckdb.MergeTree
	orderKeys := []string{"app_service", "ip4", "ip6", timeKey}

	return &ckdb.Table{
		Version:         basecommon.CK_VERSION,
		Database:        dbName,
		LocalName:       tableName + ckdb.LOCAL_SUBFFIX,
		GlobalName:      tableName,
		Columns:         ProfileColumns(),
		TimeKey:         timeKey,
		TTL:             ttl,
		PartitionFunc:   DefaultPartition,
		Engine:          engine,
		Cluster:         cluster,
		StoragePolicy:   storagePolicy,
		ColdStorage:     *coldStorage,
		OrderKeys:       orderKeys,
		PrimaryKeyCount: len(orderKeys),
	}
}

func (p *InProcessProfile) WriteBlock(block *ckdb.Block) {
	block.WriteDateTime(p.Time)
	block.Write(p._id)
	block.WriteIPv4(p.IP4)
	block.WriteIPv6(p.IP6)

	block.Write(
		p.AppService,
		p.ProfileLocationStr,
		p.ProfileValue,
		p.ProfileValueUnit,
		p.ProfileEventType,
		p.ProfileCreateTimestamp,
		p.ProfileInTimestamp,
		p.ProfileLanguageType,
		p.ProfileNodeID,
		p.ProfileParentNodeID,
		p.ProfileID,
		p.TraceID,
		p.SpanName,
		p.AppInstance,
		p.TagNames,
		p.TagValues,

		p.VtapID,
		p.RegionID,
		p.AZID,
		p.L3EpcID,
		p.HostID,
		p.PodID,
		p.PodNodeID,
		p.PodNSID,
		p.PodClusterID,
		p.PodGroupID,
		p.L3DeviceType,
		p.L3DeviceID,
		p.ServiceID,
	)
}

var poolInProcess = pool.NewLockFreePool(func() interface{} {
	return new(InProcessProfile)
})

func (p *InProcessProfile) Release() {
	ReleaseInProcess(p)
}

func (p *InProcessProfile) String() string {
	return fmt.Sprintf("InProcessProfile:  %+v\n", *p)
}

func AcquireInProcess() *InProcessProfile {
	l := poolInProcess.Get().(*InProcessProfile)
	return l
}

func ReleaseInProcess(p *InProcessProfile) {
	if p == nil {
		return
	}
	tagNames := p.TagNames[:0]
	tagValues := p.TagValues[:0]
	*p = InProcessProfile{}
	p.TagNames = tagNames
	p.TagValues = tagValues
	poolInProcess.Put(p)
}

func (p *InProcessProfile) FillProfile(input *storage.PutInput, platformData *grpc.PlatformInfoTable,
	vtapID uint16, profileName string, location string, self int64,
	inTimeStamp time.Time, languageType string, parentID uint64,
	tagNames []string, tagValues []string) {

	p.Time = uint32(inTimeStamp.Unix())
	p._id = genID(uint32(input.StartTime.UnixNano()/int64(time.Second)), &InProcessCounter, vtapID)
	p.VtapID = vtapID
	p.AppService = profileName
	p.ProfileLocationStr = location
	p.ProfileEventType = input.Key.AppName()
	p.ProfileValue = self
	p.ProfileValueUnit = input.Units.String()
	p.ProfileCreateTimestamp = input.StartTime.UnixMicro()
	p.ProfileInTimestamp = inTimeStamp.UnixMicro()
	p.ProfileLanguageType = languageType
	p.ProfileNodeID = p._id
	p.ProfileParentNodeID = parentID
	p.ProfileID, _ = input.Key.ProfileID()
	if input.Key.Labels() != nil {
		p.SpanName = input.Key.Labels()[LabelSpanName]
	}
	tagNames = append(tagNames, LabelAppService, LabelLanguageType, LabelTraceID, LabelSpanName, LabelAppInstance)
	tagValues = append(tagValues, p.AppService, p.ProfileLanguageType, p.TraceID, p.SpanName, p.AppInstance)
	p.TagNames = tagNames
	p.TagValues = tagValues

	p.fillResource(uint32(vtapID), platformData)
}

func genID(time uint32, counter *uint32, vtapID uint16) uint64 {
	count := atomic.AddUint32(counter, 1)
	return uint64(time)<<32 | ((uint64(vtapID) & 0x3fff) << 18) | (uint64(count) & 0x03ffff)
}

func (p *InProcessProfile) fillResource(vtapID uint32, platformData *grpc.PlatformInfoTable) {
	vtapInfo := platformData.QueryVtapInfo(vtapID)
	p.L3EpcID = vtapInfo.EpcId
	var info *grpc.Info

	if p.IsIPv4 {
		info = platformData.QueryIPV4Infos(p.L3EpcID, p.IP4)
	} else {
		info = platformData.QueryIPV6Infos(p.L3EpcID, p.IP6)
	}

	if info != nil {
		p.RegionID = uint16(info.RegionID)
		p.AZID = uint16(info.AZID)
		p.HostID = uint16(info.AZID)
		p.PodID = info.PodID
		p.PodNodeID = info.PodNodeID
		p.PodNSID = uint16(info.PodNSID)
		p.PodClusterID = uint16(info.PodClusterID)
		p.PodGroupID = info.PodGroupID
		p.L3DeviceType = uint8(info.DeviceType)
		p.L3DeviceID = info.DeviceID
		p.ServiceID = platformData.QueryService(p.PodID, p.PodNodeID, uint32(p.PodClusterID), p.PodGroupID, p.L3EpcID, !p.IsIPv4, p.IP4, p.IP6, layers.IPProtocolTCP, 0)
	}
}

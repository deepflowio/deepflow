package log_data

import (
	"fmt"
	"reflect"
	"unsafe"

	"github.com/deepflowio/deepflow/server/ingester/exporters/common"
	config "github.com/deepflowio/deepflow/server/ingester/exporters/config"
	utag "github.com/deepflowio/deepflow/server/ingester/exporters/universal_tag"
	"github.com/deepflowio/deepflow/server/libs/utils"
)

func (l4 *L4FlowLog) QueryUniversalTags(utags *utag.UniversalTagsManager) (*utag.UniversalTags, *utag.UniversalTags) {
	return utags.QueryUniversalTags(
			l4.RegionID0, l4.AZID0, l4.HostID0, l4.PodNSID0, l4.PodClusterID0, l4.SubnetID0, l4.VtapID,
			l4.L3DeviceType0, l4.AutoServiceType0, l4.AutoInstanceType0,
			l4.L3DeviceID0, l4.AutoServiceID0, l4.AutoInstanceID0, l4.PodNodeID0, l4.PodGroupID0, l4.PodID0, uint32(l4.L3EpcID0), l4.GPID0, l4.ServiceID0,
			l4.IsIPv4, l4.IP40, l4.IP60,
		), utags.QueryUniversalTags(
			l4.RegionID1, l4.AZID1, l4.HostID1, l4.PodNSID1, l4.PodClusterID1, l4.SubnetID1, l4.VtapID,
			l4.L3DeviceType1, l4.AutoServiceType1, l4.AutoInstanceType1,
			l4.L3DeviceID1, l4.AutoServiceID1, l4.AutoInstanceID1, l4.PodNodeID1, l4.PodGroupID1, l4.PodID1, uint32(l4.L3EpcID1), l4.GPID1, l4.ServiceID1,
			l4.IsIPv4, l4.IP41, l4.IP61,
		)
}

func (l4 *L4FlowLog) EncodeTo(protocol config.ExportProtocol, utags *utag.UniversalTagsManager, cfg *config.ExporterCfg) (interface{}, error) {
	switch protocol {
	case config.PROTOCOL_KAFKA:
		tags0, tags1 := l4.QueryUniversalTags(utags)
		k8sLabels0, k8sLabels1 := utags.QueryCustomK8sLabels(l4.PodID0), utags.QueryCustomK8sLabels(l4.PodID1)
		return common.EncodeToJson(l4, int(l4.DataSource()), cfg, tags0, tags1, k8sLabels0, k8sLabels1), nil
	default:
		return nil, fmt.Errorf("l4_flow_log unsupport export to %s", protocol)
	}
}

func (l4 *L4FlowLog) DataSource() uint32 {
	return uint32(config.L4_FLOW_LOG)
}

func (l4 *L4FlowLog) TimestampUs() int64 {
	return int64(l4.FlowInfo.EndTime)
}

func (l7 *L4FlowLog) GetFieldValueByOffsetAndKind(offset uintptr, kind reflect.Kind, dataType utils.DataType) interface{} {
	return utils.GetValueByOffsetAndKind(uintptr(unsafe.Pointer(l7)), offset, kind, dataType)
}

func (l7 *L7FlowLog) EncodeTo(protocol config.ExportProtocol, utags *utag.UniversalTagsManager, cfg *config.ExporterCfg) (interface{}, error) {
	switch protocol {
	case config.PROTOCOL_OTLP:
		return l7.EncodeToOtlp(utags, cfg.ExportFieldCategoryBits), nil
	case config.PROTOCOL_KAFKA:
		tags0, tags1 := l7.QueryUniversalTags(utags)
		k8sLabels0, k8sLabels1 := utags.QueryCustomK8sLabels(l7.PodID0), utags.QueryCustomK8sLabels(l7.PodID1)
		return common.EncodeToJson(l7, int(l7.DataSource()), cfg, tags0, tags1, k8sLabels0, k8sLabels1), nil
	default:
		return nil, fmt.Errorf("l7_flow_log unsupport export to %s", protocol)
	}
}

func (l7 *L7FlowLog) DataSource() uint32 {
	return uint32(config.L7_FLOW_LOG)
}

func (l7 *L7FlowLog) TimestampUs() int64 {
	return int64(l7.L7Base.EndTime)
}

func (l7 *L7FlowLog) GetFieldValueByOffsetAndKind(offset uintptr, kind reflect.Kind, dataType utils.DataType) interface{} {
	return utils.GetValueByOffsetAndKind(uintptr(unsafe.Pointer(l7)), offset, kind, dataType)
}

func (l7 *L7FlowLog) QueryUniversalTags(utags *utag.UniversalTagsManager) (*utag.UniversalTags, *utag.UniversalTags) {
	return utags.QueryUniversalTags(
			l7.RegionID0, l7.AZID0, l7.HostID0, l7.PodNSID0, l7.PodClusterID0, l7.SubnetID0, l7.VtapID,
			l7.L3DeviceType0, l7.AutoServiceType0, l7.AutoInstanceType0,
			l7.L3DeviceID0, l7.AutoServiceID0, l7.AutoInstanceID0, l7.PodNodeID0, l7.PodGroupID0, l7.PodID0, uint32(l7.L3EpcID0), l7.GPID0, l7.ServiceID0,
			l7.IsIPv4, uint32(l7.IP40), l7.IP60,
		), utags.QueryUniversalTags(
			l7.RegionID1, l7.AZID1, l7.HostID1, l7.PodNSID1, l7.PodClusterID1, l7.SubnetID1, l7.VtapID,
			l7.L3DeviceType1, l7.AutoServiceType1, l7.AutoInstanceType1,
			l7.L3DeviceID1, l7.AutoServiceID1, l7.AutoInstanceID1, l7.PodNodeID1, l7.PodGroupID1, l7.PodID1, uint32(l7.L3EpcID1), l7.GPID1, l7.ServiceID1,
			l7.IsIPv4, uint32(l7.IP41), l7.IP61,
		)
}

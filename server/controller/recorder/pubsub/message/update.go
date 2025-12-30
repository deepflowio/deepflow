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

package message

import (
	"time"

	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
)

type Key struct {
	ID     int
	Lcuuid string
}

func (k *Key) SetID(id int) {
	k.ID = id
}

func (k *Key) GetID() int {
	return k.ID
}

func (k *Key) SetLcuuid(lcuuid string) {
	k.Lcuuid = lcuuid
}

func (k *Key) GetLcuuid() string {
	return k.Lcuuid
}

type Fields[T any] struct {
	data *T
}

func (f *Fields[T]) SetFields(data interface{}) {
	f.data = data.(*T)
}

func (f *Fields[T]) GetFields() interface{} {
	return f.data
}

type fieldDetail[T any] struct {
	different bool
	new       T
	old       T
}

func (d *fieldDetail[T]) Set(old, new T) {
	d.SetDifferent()
	d.new = new
	d.old = old
}

func (d *fieldDetail[T]) IsDifferent() bool {
	return d.different
}

// SetDifferent is called when new value or old value is set
func (d *fieldDetail[T]) SetDifferent() {
	d.different = true
}

func (d *fieldDetail[T]) GetNew() T {
	return d.new
}

func (d *fieldDetail[T]) SetNew(new T) {
	d.SetDifferent()
	d.new = new
}

func (d *fieldDetail[T]) GetOld() T {
	return d.old
}

func (d *fieldDetail[T]) SetOld(old T) {
	d.SetDifferent()
	d.old = old
}

// TODO rename to metadb
type MetadbData[MT metadbmodel.AssetResourceConstraint] struct {
	new *MT
	old *MT
}

func (m *MetadbData[MT]) GetNewMetadbItem() interface{} {
	return m.new
}

func (m *MetadbData[MT]) SetNewMetadbItem(new interface{}) {
	m.new = new.(*MT)
}

func (m *MetadbData[MT]) GetOldMetadbItem() interface{} {
	return m.old
}

func (m *MetadbData[MT]) SetOldMetadbItem(old interface{}) {
	m.old = old.(*MT)
}

type UpdatedRegionFields struct {
	Key
	Name  fieldDetail[string]
	Label fieldDetail[string]
}

type UpdatedRegion struct {
	Fields[UpdatedRegionFields]
	MetadbData[metadbmodel.Region]
}

type UpdatedAZFields struct {
	Key
	Name         fieldDetail[string]
	Label        fieldDetail[string]
	RegionLcuuid fieldDetail[string]
}

type UpdatedAZ struct {
	Fields[UpdatedAZFields]
	MetadbData[metadbmodel.AZ]
}

type UpdatedSubDomainFields struct {
	Key
	Name fieldDetail[string]
}
type UpdatedSubDomain struct {
	Fields[UpdatedSubDomainFields]
	MetadbData[metadbmodel.SubDomain]
}

type UpdatedHostFields struct {
	Key
	Name         fieldDetail[string]
	IP           fieldDetail[string]
	UID          fieldDetail[string]
	HType        fieldDetail[int]
	VCPUNum      fieldDetail[int]
	MemTotal     fieldDetail[int]
	ExtraInfo    fieldDetail[string]
	Hostname     fieldDetail[string]
	AZLcuuid     fieldDetail[string]
	RegionLcuuid fieldDetail[string]
}

type UpdatedHost struct {
	Fields[UpdatedHostFields]
	MetadbData[metadbmodel.Host]
}

type UpdatedVMFields struct {
	Key
	Name             fieldDetail[string]
	IP               fieldDetail[string]
	Label            fieldDetail[string]
	State            fieldDetail[int]
	HType            fieldDetail[int]
	LaunchServer     fieldDetail[string]
	LearnedCloudTags fieldDetail[map[string]string]
	CustomCloudTags  fieldDetail[map[string]string]
	HostID           fieldDetail[int]
	UID              fieldDetail[string]
	Hostname         fieldDetail[string]
	VPCID            fieldDetail[int]
	VPCLcuuid        fieldDetail[string]
	AZLcuuid         fieldDetail[string]
	RegionLcuuid     fieldDetail[string]
	NetworkID        fieldDetail[int]
	NetworkLcuuid    fieldDetail[string]
}

type UpdatedVM struct {
	Fields[UpdatedVMFields]
	MetadbData[metadbmodel.VM]
}

type UpdatedVMPodNodeConnectionFields struct {
	Key
}

type UpdatedVMPodNodeConnection struct {
	Fields[UpdatedVMPodNodeConnectionFields]
	MetadbData[metadbmodel.VMPodNodeConnection]
}

type UpdatedVPCFields struct {
	Key
	Name         fieldDetail[string]
	Label        fieldDetail[string]
	Owner        fieldDetail[string]
	CIDR         fieldDetail[string]
	TunnelID     fieldDetail[int]
	RegionLcuuid fieldDetail[string]
	UID          fieldDetail[string]
}

type UpdatedVPC struct {
	Fields[UpdatedVPCFields]
	MetadbData[metadbmodel.VPC]
}

type UpdatedNetworkFields struct {
	Key
	Name           fieldDetail[string]
	Label          fieldDetail[string]
	TunnelID       fieldDetail[int]
	SegmentationID fieldDetail[int]
	NetType        fieldDetail[int]
	VPCID          fieldDetail[int]
	VPCLcuuid      fieldDetail[string]
	AZLcuuid       fieldDetail[string]
	RegionLcuuid   fieldDetail[string]
}

type UpdatedNetwork struct {
	Fields[UpdatedNetworkFields]
	MetadbData[metadbmodel.Network]
}

type UpdatedSubnetFields struct {
	Key
	Name  fieldDetail[string]
	Label fieldDetail[string]
}

type UpdatedSubnet struct {
	Fields[UpdatedSubnetFields]
	MetadbData[metadbmodel.Subnet]
}

type UpdatedVRouterFields struct {
	Key
	Name         fieldDetail[string]
	Label        fieldDetail[string]
	VPCID        fieldDetail[int]
	VPCLcuuid    fieldDetail[string]
	RegionLcuuid fieldDetail[string]
}

type UpdatedVRouter struct {
	Fields[UpdatedVRouterFields]
	MetadbData[metadbmodel.VRouter]
}

type UpdatedRoutingTableFields struct {
	Key
	Destination fieldDetail[string]
	NexthopType fieldDetail[string]
	Nexthop     fieldDetail[string]
}

type UpdatedRoutingTable struct {
	Fields[UpdatedRoutingTableFields]
	MetadbData[metadbmodel.RoutingTable]
}

type UpdatedDHCPPortFields struct {
	Key
	Name         fieldDetail[string]
	VPCID        fieldDetail[int]
	VPCLcuuid    fieldDetail[string]
	AZLcuuid     fieldDetail[string]
	RegionLcuuid fieldDetail[string]
}

type UpdatedDHCPPort struct {
	Fields[UpdatedDHCPPortFields]
	MetadbData[metadbmodel.DHCPPort]
}

type UpdatedVInterfaceFields struct {
	Key
	Name          fieldDetail[string]
	TapMac        fieldDetail[string]
	Type          fieldDetail[int]
	NetnsID       fieldDetail[uint32]
	VTapID        fieldDetail[uint32]
	NetworkID     fieldDetail[int]
	NetworkLcuuid fieldDetail[string]
	RegionLcuuid  fieldDetail[string]
}

type UpdatedVInterface struct {
	Fields[UpdatedVInterfaceFields]
	MetadbData[metadbmodel.VInterface]
}

type UpdatedFloatingIPFields struct {
	Key
	VPCID        fieldDetail[int]
	VPCLcuuid    fieldDetail[string]
	RegionLcuuid fieldDetail[string]
}

type UpdatedFloatingIP struct {
	Fields[UpdatedFloatingIPFields]
	MetadbData[metadbmodel.FloatingIP]
}

type UpdatedLANIPFields struct {
	Key
	SubnetID     fieldDetail[int]
	SubnetLcuuid fieldDetail[string]
}
type UpdatedLANIP struct {
	Fields[UpdatedLANIPFields]
	MetadbData[metadbmodel.LANIP]
}
type UpdatedWANIPFields struct {
	Key
	SubnetID     fieldDetail[int]
	SubnetLcuuid fieldDetail[string]
	RegionLcuuid fieldDetail[string]
}
type UpdatedWANIP struct {
	Fields[UpdatedWANIPFields]
	MetadbData[metadbmodel.WANIP]
}
type UpdatedVIPFields struct {
	Key
	IP     fieldDetail[string]
	VTapID fieldDetail[uint32]
}
type UpdatedVIP struct {
	Fields[UpdatedVIPFields]
	MetadbData[metadbmodel.VIP]
}

type UpdatedNATGatewayFields struct {
	Key
	Name         fieldDetail[string]
	FloatingIPs  fieldDetail[string]
	RegionLcuuid fieldDetail[string]
	UID          fieldDetail[string]
}
type UpdatedNATGateway struct {
	Fields[UpdatedNATGatewayFields]
	MetadbData[metadbmodel.NATGateway]
}

type UpdatedNATRuleFields struct {
	Key
}
type UpdatedNATRule struct {
	Fields[UpdatedNATRuleFields]
	MetadbData[metadbmodel.NATRule]
}

type UpdatedNATVMConnectionFields struct {
	Key
}
type UpdatedNATVMConnection struct {
	Fields[UpdatedNATVMConnectionFields]
	MetadbData[metadbmodel.NATVMConnection]
}

type UpdatedLBFields struct {
	Key
	Name         fieldDetail[string]
	UID          fieldDetail[string]
	Model        fieldDetail[int]
	VIP          fieldDetail[string]
	RegionLcuuid fieldDetail[string]
}
type UpdatedLB struct {
	Fields[UpdatedLBFields]
	MetadbData[metadbmodel.LB]
}

type UpdatedLBListenerFields struct {
	Key
	Name     fieldDetail[string]
	IPs      fieldDetail[string]
	SNATIPs  fieldDetail[string]
	Port     fieldDetail[int]
	Protocol fieldDetail[string]
}
type UpdatedLBListener struct {
	Fields[UpdatedLBListenerFields]
	MetadbData[metadbmodel.LBListener]
}

type UpdatedLBTargetServerFields struct {
	Key
	IP       fieldDetail[string]
	Port     fieldDetail[int]
	Protocol fieldDetail[string]
}
type UpdatedLBTargetServer struct {
	Fields[UpdatedLBTargetServerFields]
	MetadbData[metadbmodel.LBTargetServer]
}

type UpdatedLBVMConnectionFields struct {
	Key
}
type UpdatedLBVMConnection struct {
	Fields[UpdatedLBVMConnectionFields]
	MetadbData[metadbmodel.LBVMConnection]
}

type UpdatedPeerConnectionFields struct {
	Key
	Name fieldDetail[string]
}
type UpdatedPeerConnection struct {
	Fields[UpdatedPeerConnectionFields]
	MetadbData[metadbmodel.PeerConnection]
}

type UpdatedCENFields struct {
	Key
	Name       fieldDetail[string]
	VPCIDs     fieldDetail[[]int]
	VPCLcuuids fieldDetail[[]string]
}
type UpdatedCEN struct {
	Fields[UpdatedCENFields]
	MetadbData[metadbmodel.CEN]
}

type UpdatedRDSInstanceFields struct {
	Key
	Name         fieldDetail[string]
	UID          fieldDetail[string]
	State        fieldDetail[int]
	Series       fieldDetail[int]
	Model        fieldDetail[int]
	AZLcuuid     fieldDetail[string]
	RegionLcuuid fieldDetail[string]
}
type UpdatedRDSInstance struct {
	Fields[UpdatedRDSInstanceFields]
	MetadbData[metadbmodel.RDSInstance]
}

type UpdatedRedisInstanceFields struct {
	Key
	Name         fieldDetail[string]
	UID          fieldDetail[string]
	State        fieldDetail[int]
	PublicHost   fieldDetail[string]
	AZLcuuid     fieldDetail[string]
	RegionLcuuid fieldDetail[string]
}
type UpdatedRedisInstance struct {
	Fields[UpdatedRedisInstanceFields]
	MetadbData[metadbmodel.RedisInstance]
}

type UpdatedPodClusterFields struct {
	Key
	Name         fieldDetail[string]
	ClusterName  fieldDetail[string]
	AZLcuuid     fieldDetail[string]
	RegionLcuuid fieldDetail[string]
}
type UpdatedPodCluster struct {
	Fields[UpdatedPodClusterFields]
	MetadbData[metadbmodel.PodCluster]
}

type UpdatedPodNamespaceFields struct {
	Key
	LearnedCloudTags fieldDetail[map[string]string]
	CustomCloudTags  fieldDetail[map[string]string]
	AZLcuuid         fieldDetail[string]
	RegionLcuuid     fieldDetail[string]
	Name             fieldDetail[string]
	PodClusterID     fieldDetail[int]
}
type UpdatedPodNamespace struct {
	Fields[UpdatedPodNamespaceFields]
	MetadbData[metadbmodel.PodNamespace]
}

type UpdatedPodNodeFields struct {
	Key
	Type         fieldDetail[int]
	State        fieldDetail[int]
	Hostname     fieldDetail[string]
	IP           fieldDetail[string]
	VCPUNum      fieldDetail[int]
	MemTotal     fieldDetail[int]
	AZLcuuid     fieldDetail[string]
	RegionLcuuid fieldDetail[string]
	Name         fieldDetail[string]
}
type UpdatedPodNode struct {
	Fields[UpdatedPodNodeFields]
	MetadbData[metadbmodel.PodNode]
}

type UpdatedPodIngressFields struct {
	Key
	Name         fieldDetail[string]
	AZLcuuid     fieldDetail[string]
	RegionLcuuid fieldDetail[string]
}
type UpdatedPodIngress struct {
	Fields[UpdatedPodIngressFields]
	MetadbData[metadbmodel.PodIngress]
}

type UpdatedPodIngressRuleFields struct {
	Key
}
type UpdatedPodIngressRule struct {
	Fields[UpdatedPodIngressRuleFields]
	MetadbData[metadbmodel.PodIngressRule]
}

type UpdatedPodIngressRuleBackendFields struct {
	Key
}
type UpdatedPodIngressRuleBackend struct {
	Fields[UpdatedPodIngressRuleBackendFields]
	MetadbData[metadbmodel.PodIngressRuleBackend]
}

type UpdatedPodServiceFields struct {
	Key
	Name             fieldDetail[string]
	Label            fieldDetail[string]
	Annotation       fieldDetail[string]
	Selector         fieldDetail[string]
	ExternalIP       fieldDetail[string]
	ServiceClusterIP fieldDetail[string]
	Metadata         fieldDetail[string]
	Spec             fieldDetail[string]
	PodIngressID     fieldDetail[int]
	PodIngressLcuuid fieldDetail[string]
	AZLcuuid         fieldDetail[string]
	RegionLcuuid     fieldDetail[string]
	PodNamespaceID   fieldDetail[int]
	VPCID            fieldDetail[int]
	PodClusterID     fieldDetail[int]
}
type UpdatedPodService struct {
	Fields[UpdatedPodServiceFields]
	MetadbData[metadbmodel.PodService]
}

type UpdatedPodServicePortFields struct {
	Key
	Name fieldDetail[string]
}
type UpdatedPodServicePort struct {
	Fields[UpdatedPodServicePortFields]
	MetadbData[metadbmodel.PodServicePort]
}

type UpdatedPodGroupFields struct {
	Key
	Name           fieldDetail[string]
	Label          fieldDetail[string]
	NetworkMode    fieldDetail[int]
	Type           fieldDetail[int]
	PodNum         fieldDetail[int]
	Metadata       fieldDetail[string]
	Spec           fieldDetail[string]
	AZLcuuid       fieldDetail[string]
	RegionLcuuid   fieldDetail[string]
	PodClusterID   fieldDetail[int]
	PodNamespaceID fieldDetail[int]
}
type UpdatedPodGroup struct {
	Fields[UpdatedPodGroupFields]
	MetadbData[metadbmodel.PodGroup]
}

type UpdatedConfigMapFields struct {
	Key
	Name fieldDetail[string]
	Data fieldDetail[string]
}

type UpdatedConfigMap struct {
	Fields[UpdatedConfigMapFields]
	MetadbData[metadbmodel.ConfigMap]
}

type UpdatedPodGroupConfigMapConnectionFields struct {
	Key
}

type UpdatedPodGroupConfigMapConnection struct {
	Fields[UpdatedPodGroupConfigMapConnectionFields]
	MetadbData[metadbmodel.PodGroupConfigMapConnection]
}

type UpdatedPodGroupPortFields struct {
	Key
	Name fieldDetail[string]
}
type UpdatedPodGroupPort struct {
	Fields[UpdatedPodGroupPortFields]
	MetadbData[metadbmodel.PodGroupPort]
}

type UpdatedPodReplicaSetFields struct {
	Key
	Name         fieldDetail[string]
	Label        fieldDetail[string]
	PodNum       fieldDetail[int]
	AZLcuuid     fieldDetail[string]
	RegionLcuuid fieldDetail[string]
}
type UpdatedPodReplicaSet struct {
	Fields[UpdatedPodReplicaSetFields]
	MetadbData[metadbmodel.PodReplicaSet]
}

type UpdatedPodFields struct {
	Key
	Name                fieldDetail[string]
	Label               fieldDetail[string]
	State               fieldDetail[int]
	Annotation          fieldDetail[string]
	ENV                 fieldDetail[string]
	ContainerIDs        fieldDetail[string]
	CreatedAt           fieldDetail[time.Time]
	PodGroupID          fieldDetail[int]
	PodServiceID        fieldDetail[int]
	PodGroupLcuuid      fieldDetail[string]
	PodServiceLcuuid    fieldDetail[string]
	PodReplicaSetID     fieldDetail[int]
	PodReplicaSetLcuuid fieldDetail[string]
	PodNodeID           fieldDetail[int]
	PodNodeLcuuid       fieldDetail[string]
	VPCID               fieldDetail[int]
	VPCLcuuid           fieldDetail[string]
	AZLcuuid            fieldDetail[string]
	RegionLcuuid        fieldDetail[string]
	PodNamespaceID      fieldDetail[int]
	PodClusterID        fieldDetail[int]
}
type UpdatedPod struct {
	Fields[UpdatedPodFields]
	MetadbData[metadbmodel.Pod]
}

type UpdatedProcessFields struct {
	Key
	Name        fieldDetail[string]
	ProcessName fieldDetail[string]
	ContainerID fieldDetail[string]
	OSAPPTags   fieldDetail[string]
	VMID        fieldDetail[int]
	VPCID       fieldDetail[int]
	GID         fieldDetail[uint32]
}
type UpdatedProcess struct {
	Fields[UpdatedProcessFields]
	MetadbData[metadbmodel.Process]
}

type UpdatedCustomServiceFields struct {
	Key
	Name fieldDetail[string]
}
type UpdatedCustomService struct {
	Fields[UpdatedCustomServiceFields]
	MetadbData[metadbmodel.CustomService]
}

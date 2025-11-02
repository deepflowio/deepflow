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

	cloudmodel "github.com/deepflowio/deepflow/server/controller/cloud/model"
	mysqlmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache/diffbase"
	"github.com/deepflowio/deepflow/server/controller/recorder/constraint"
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

// TODO rename to mysql
type MySQLData[MT mysqlmodel.AssetResourceConstraint] struct {
	new *MT
	old *MT
}

func (m *MySQLData[MT]) GetNewMySQL() interface{} {
	return m.new
}

func (m *MySQLData[MT]) SetNewMySQL(new interface{}) {
	m.new = new.(*MT)
}

func (m *MySQLData[MT]) GetOldMySQL() interface{} {
	return m.old
}

func (m *MySQLData[MT]) SetOldMySQL(old interface{}) {
	m.old = old.(*MT)
}

type DiffBase[DT constraint.DiffBase] struct {
	data DT
}

func (d *DiffBase[DT]) GetDiffBase() interface{} {
	return d.data
}

func (d *DiffBase[DT]) SetDiffBase(data interface{}) {
	d.data = data.(DT)
}

type CloudItem[CT constraint.CloudModel] struct {
	data *CT
}

func (c *CloudItem[CT]) GetCloudItem() interface{} {
	return c.data
}

func (c *CloudItem[CT]) SetCloudItem(data interface{}) {
	c.data = data.(*CT)
}

type UpdatedRegionFields struct {
	Key
	Name  fieldDetail[string]
	Label fieldDetail[string]
}

type UpdatedRegion struct {
	Fields[UpdatedRegionFields]
	CloudItem[cloudmodel.Region]
	DiffBase[*diffbase.Region]
	MySQLData[mysqlmodel.Region]
}

type UpdatedAZFields struct {
	Key
	Name         fieldDetail[string]
	Label        fieldDetail[string]
	RegionLcuuid fieldDetail[string]
}

type UpdatedAZ struct {
	Fields[UpdatedAZFields]
	CloudItem[cloudmodel.AZ]
	DiffBase[*diffbase.AZ]
	MySQLData[mysqlmodel.AZ]
}

type UpdatedSubDomainFields struct {
	Key
	Name fieldDetail[string]
}
type UpdatedSubDomain struct {
	Fields[UpdatedSubDomainFields]
	CloudItem[cloudmodel.SubDomain] // TODO tmp, delete later
	DiffBase[*diffbase.SubDomain]
	MySQLData[mysqlmodel.SubDomain]
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
	CloudItem[cloudmodel.Host]
	DiffBase[*diffbase.Host]
	MySQLData[mysqlmodel.Host]
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
	CloudItem[cloudmodel.VM]
	DiffBase[*diffbase.VM]
	MySQLData[mysqlmodel.VM]
}

type UpdatedVMPodNodeConnectionFields struct {
	Key
}

type UpdatedVMPodNodeConnection struct {
	Fields[UpdatedVMPodNodeConnectionFields]
	CloudItem[cloudmodel.VMPodNodeConnection]
	DiffBase[*diffbase.VMPodNodeConnection]
	MySQLData[mysqlmodel.VMPodNodeConnection]
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
	CloudItem[cloudmodel.VPC]
	DiffBase[*diffbase.VPC]
	MySQLData[mysqlmodel.VPC]
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
	CloudItem[cloudmodel.Network]
	DiffBase[*diffbase.Network]
	MySQLData[mysqlmodel.Network]
}

type UpdatedSubnetFields struct {
	Key
	Name  fieldDetail[string]
	Label fieldDetail[string]
}

type UpdatedSubnet struct {
	Fields[UpdatedSubnetFields]
	CloudItem[cloudmodel.Subnet]
	DiffBase[*diffbase.Subnet]
	MySQLData[mysqlmodel.Subnet]
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
	CloudItem[cloudmodel.VRouter]
	DiffBase[*diffbase.VRouter]
	MySQLData[mysqlmodel.VRouter]
}

type UpdatedRoutingTableFields struct {
	Key
	Destination fieldDetail[string]
	NexthopType fieldDetail[string]
	Nexthop     fieldDetail[string]
}

type UpdatedRoutingTable struct {
	Fields[UpdatedRoutingTableFields]
	CloudItem[cloudmodel.RoutingTable]
	DiffBase[*diffbase.RoutingTable]
	MySQLData[mysqlmodel.RoutingTable]
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
	CloudItem[cloudmodel.DHCPPort]
	DiffBase[*diffbase.DHCPPort]
	MySQLData[mysqlmodel.DHCPPort]
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
	CloudItem[cloudmodel.VInterface]
	DiffBase[*diffbase.VInterface]
	MySQLData[mysqlmodel.VInterface]
}

type UpdatedFloatingIPFields struct {
	Key
	VPCID        fieldDetail[int]
	VPCLcuuid    fieldDetail[string]
	RegionLcuuid fieldDetail[string]
}

type UpdatedFloatingIP struct {
	Fields[UpdatedFloatingIPFields]
	CloudItem[cloudmodel.FloatingIP]
	DiffBase[*diffbase.FloatingIP]
	MySQLData[mysqlmodel.FloatingIP]
}

type UpdatedLANIPFields struct {
	Key
	SubnetID     fieldDetail[int]
	SubnetLcuuid fieldDetail[string]
}
type UpdatedLANIP struct {
	Fields[UpdatedLANIPFields]
	CloudItem[cloudmodel.IP]
	DiffBase[*diffbase.LANIP]
	MySQLData[mysqlmodel.LANIP]
}
type UpdatedWANIPFields struct {
	Key
	SubnetID     fieldDetail[int]
	SubnetLcuuid fieldDetail[string]
	RegionLcuuid fieldDetail[string]
}
type UpdatedWANIP struct {
	Fields[UpdatedWANIPFields]
	CloudItem[cloudmodel.IP]
	DiffBase[*diffbase.WANIP]
	MySQLData[mysqlmodel.WANIP]
}
type UpdatedVIPFields struct {
	Key
	IP     fieldDetail[string]
	VTapID fieldDetail[uint32]
}
type UpdatedVIP struct {
	Fields[UpdatedVIPFields]
	CloudItem[cloudmodel.IP]
	DiffBase[*diffbase.VIP]
	MySQLData[mysqlmodel.VIP]
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
	CloudItem[cloudmodel.NATGateway]
	DiffBase[*diffbase.NATGateway]
	MySQLData[mysqlmodel.NATGateway]
}

type UpdatedNATRuleFields struct {
	Key
}
type UpdatedNATRule struct {
	Fields[UpdatedNATRuleFields]
	CloudItem[cloudmodel.NATRule]
	DiffBase[*diffbase.NATRule]
	MySQLData[mysqlmodel.NATRule]
}

type UpdatedNATVMConnectionFields struct {
	Key
}
type UpdatedNATVMConnection struct {
	Fields[UpdatedNATVMConnectionFields]
	CloudItem[cloudmodel.NATVMConnection]
	DiffBase[*diffbase.NATVMConnection]
	MySQLData[mysqlmodel.NATVMConnection]
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
	CloudItem[cloudmodel.LB]
	DiffBase[*diffbase.LB]
	MySQLData[mysqlmodel.LB]
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
	CloudItem[cloudmodel.LBListener]
	DiffBase[*diffbase.LBListener]
	MySQLData[mysqlmodel.LBListener]
}

type UpdatedLBTargetServerFields struct {
	Key
	IP       fieldDetail[string]
	Port     fieldDetail[int]
	Protocol fieldDetail[string]
}
type UpdatedLBTargetServer struct {
	Fields[UpdatedLBTargetServerFields]
	CloudItem[cloudmodel.LBTargetServer]
	DiffBase[*diffbase.LBTargetServer]
	MySQLData[mysqlmodel.LBTargetServer]
}

type UpdatedLBVMConnectionFields struct {
	Key
}
type UpdatedLBVMConnection struct {
	Fields[UpdatedLBVMConnectionFields]
	CloudItem[cloudmodel.LBVMConnection]
	DiffBase[*diffbase.LBVMConnection]
	MySQLData[mysqlmodel.LBVMConnection]
}

type UpdatedPeerConnectionFields struct {
	Key
	Name               fieldDetail[string]
	RemoteRegionID     fieldDetail[int]
	RemoteRegionLcuuid fieldDetail[string]
	LocalRegionID      fieldDetail[int]
	LocalRegionLcuuid  fieldDetail[string]
}
type UpdatedPeerConnection struct {
	Fields[UpdatedPeerConnectionFields]
	CloudItem[cloudmodel.PeerConnection]
	DiffBase[*diffbase.PeerConnection]
	MySQLData[mysqlmodel.PeerConnection]
}

type UpdatedCENFields struct {
	Key
	Name       fieldDetail[string]
	VPCIDs     fieldDetail[[]int]
	VPCLcuuids fieldDetail[[]string]
}
type UpdatedCEN struct {
	Fields[UpdatedCENFields]
	CloudItem[cloudmodel.CEN]
	DiffBase[*diffbase.CEN]
	MySQLData[mysqlmodel.CEN]
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
	CloudItem[cloudmodel.RDSInstance]
	DiffBase[*diffbase.RDSInstance]
	MySQLData[mysqlmodel.RDSInstance]
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
	CloudItem[cloudmodel.RedisInstance]
	DiffBase[*diffbase.RedisInstance]
	MySQLData[mysqlmodel.RedisInstance]
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
	CloudItem[cloudmodel.PodCluster]
	DiffBase[*diffbase.PodCluster]
	MySQLData[mysqlmodel.PodCluster]
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
	CloudItem[cloudmodel.PodNamespace]
	DiffBase[*diffbase.PodNamespace]
	MySQLData[mysqlmodel.PodNamespace]
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
	CloudItem[cloudmodel.PodNode]
	DiffBase[*diffbase.PodNode]
	MySQLData[mysqlmodel.PodNode]
}

type UpdatedPodIngressFields struct {
	Key
	Name         fieldDetail[string]
	AZLcuuid     fieldDetail[string]
	RegionLcuuid fieldDetail[string]
}
type UpdatedPodIngress struct {
	Fields[UpdatedPodIngressFields]
	CloudItem[cloudmodel.PodIngress]
	DiffBase[*diffbase.PodIngress]
	MySQLData[mysqlmodel.PodIngress]
}

type UpdatedPodIngressRuleFields struct {
	Key
}
type UpdatedPodIngressRule struct {
	Fields[UpdatedPodIngressRuleFields]
	CloudItem[cloudmodel.PodIngressRule]
	DiffBase[*diffbase.PodIngressRule]
	MySQLData[mysqlmodel.PodIngressRule]
}

type UpdatedPodIngressRuleBackendFields struct {
	Key
}
type UpdatedPodIngressRuleBackend struct {
	Fields[UpdatedPodIngressRuleBackendFields]
	CloudItem[cloudmodel.PodIngressRuleBackend]
	DiffBase[*diffbase.PodIngressRuleBackend]
	MySQLData[mysqlmodel.PodIngressRuleBackend]
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
	CloudItem[cloudmodel.PodService]
	DiffBase[*diffbase.PodService]
	MySQLData[mysqlmodel.PodService]
}

type UpdatedPodServicePortFields struct {
	Key
	Name fieldDetail[string]
}
type UpdatedPodServicePort struct {
	Fields[UpdatedPodServicePortFields]
	CloudItem[cloudmodel.PodServicePort]
	DiffBase[*diffbase.PodServicePort]
	MySQLData[mysqlmodel.PodServicePort]
}

type UpdatedPodGroupFields struct {
	Key
	Name           fieldDetail[string]
	Label          fieldDetail[string]
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
	CloudItem[cloudmodel.PodGroup]
	DiffBase[*diffbase.PodGroup]
	MySQLData[mysqlmodel.PodGroup]
}

type UpdatedConfigMapFields struct {
	Key
	Name fieldDetail[string]
	Data fieldDetail[string]
}

type UpdatedConfigMap struct {
	Fields[UpdatedConfigMapFields]
	CloudItem[cloudmodel.ConfigMap]
	DiffBase[*diffbase.ConfigMap]
	MySQLData[mysqlmodel.ConfigMap]
}

type UpdatedPodGroupConfigMapConnectionFields struct {
	Key
}

type UpdatedPodGroupConfigMapConnection struct {
	Fields[UpdatedPodGroupConfigMapConnectionFields]
	CloudItem[cloudmodel.PodGroupConfigMapConnection]
	DiffBase[*diffbase.PodGroupConfigMapConnection]
	MySQLData[mysqlmodel.PodGroupConfigMapConnection]
}

type UpdatedPodGroupPortFields struct {
	Key
	Name fieldDetail[string]
}
type UpdatedPodGroupPort struct {
	Fields[UpdatedPodGroupPortFields]
	CloudItem[cloudmodel.PodGroupPort]
	DiffBase[*diffbase.PodGroupPort]
	MySQLData[mysqlmodel.PodGroupPort]
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
	CloudItem[cloudmodel.PodReplicaSet]
	DiffBase[*diffbase.PodReplicaSet]
	MySQLData[mysqlmodel.PodReplicaSet]
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
	CloudItem[cloudmodel.Pod]
	DiffBase[*diffbase.Pod]
	MySQLData[mysqlmodel.Pod]
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
	CloudItem[cloudmodel.Process]
	DiffBase[*diffbase.Process]
	MySQLData[mysqlmodel.Process]
}

type UpdatedCustomServiceFields struct {
	Key
	Name fieldDetail[string]
}
type UpdatedCustomService struct {
	Fields[UpdatedCustomServiceFields]
	MySQLData[mysqlmodel.CustomService]
}

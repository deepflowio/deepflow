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
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
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

// TODO rename to metadb
type MySQLData[MT constraint.MySQLModel] struct {
	new *MT
	old *MT
}

func (m *MySQLData[MT]) GetNewMySQLItem() interface{} {
	return m.new
}

func (m *MySQLData[MT]) SetNewMySQLItem(new interface{}) {
	m.new = new.(*MT)
}

func (m *MySQLData[MT]) GetOldMySQLItem() interface{} {
	return m.old
}

func (m *MySQLData[MT]) SetOldMySQLItem(old interface{}) {
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

type RegionFieldsUpdate struct {
	Key
	Name  fieldDetail[string]
	Label fieldDetail[string]
}

type RegionUpdate struct {
	Fields[RegionFieldsUpdate]
	CloudItem[cloudmodel.Region]
	DiffBase[*diffbase.Region]
	MySQLData[metadbmodel.Region]
}

type AZFieldsUpdate struct {
	Key
	Name         fieldDetail[string]
	Label        fieldDetail[string]
	RegionLcuuid fieldDetail[string]
}

type AZUpdate struct {
	Fields[AZFieldsUpdate]
	CloudItem[cloudmodel.AZ]
	DiffBase[*diffbase.AZ]
	MySQLData[metadbmodel.AZ]
}

type SubDomainFieldsUpdate struct {
	Key
	Name fieldDetail[string]
}
type SubDomainUpdate struct {
	Fields[SubDomainFieldsUpdate]
	CloudItem[cloudmodel.SubDomain] // TODO tmp, delete later
	DiffBase[*diffbase.SubDomain]
	MySQLData[metadbmodel.SubDomain]
}

type HostFieldsUpdate struct {
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

type HostUpdate struct {
	Fields[HostFieldsUpdate]
	CloudItem[cloudmodel.Host]
	DiffBase[*diffbase.Host]
	MySQLData[metadbmodel.Host]
}

type VMFieldsUpdate struct {
	Key
	Name          fieldDetail[string]
	IP            fieldDetail[string]
	Label         fieldDetail[string]
	State         fieldDetail[int]
	HType         fieldDetail[int]
	LaunchServer  fieldDetail[string]
	CloudTags     fieldDetail[map[string]string]
	HostID        fieldDetail[int]
	UID           fieldDetail[string]
	Hostname      fieldDetail[string]
	VPCID         fieldDetail[int]
	VPCLcuuid     fieldDetail[string]
	AZLcuuid      fieldDetail[string]
	RegionLcuuid  fieldDetail[string]
	NetworkID     fieldDetail[int]
	NetworkLcuuid fieldDetail[string]
}

type VMUpdate struct {
	Fields[VMFieldsUpdate]
	CloudItem[cloudmodel.VM]
	DiffBase[*diffbase.VM]
	MySQLData[metadbmodel.VM]
}

type VMPodNodeConnectionFieldsUpdate struct {
	Key
}

type VMPodNodeConnectionUpdate struct {
	Fields[VMPodNodeConnectionFieldsUpdate]
	CloudItem[cloudmodel.VMPodNodeConnection]
	DiffBase[*diffbase.VMPodNodeConnection]
	MySQLData[metadbmodel.VMPodNodeConnection]
}

type VPCFieldsUpdate struct {
	Key
	Name         fieldDetail[string]
	Label        fieldDetail[string]
	CIDR         fieldDetail[string]
	TunnelID     fieldDetail[int]
	RegionLcuuid fieldDetail[string]
	UID          fieldDetail[string]
}

type VPCUpdate struct {
	Fields[VPCFieldsUpdate]
	CloudItem[cloudmodel.VPC]
	DiffBase[*diffbase.VPC]
	MySQLData[metadbmodel.VPC]
}

type NetworkFieldsUpdate struct {
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

type NetworkUpdate struct {
	Fields[NetworkFieldsUpdate]
	CloudItem[cloudmodel.Network]
	DiffBase[*diffbase.Network]
	MySQLData[metadbmodel.Network]
}

type SubnetFieldsUpdate struct {
	Key
	Name  fieldDetail[string]
	Label fieldDetail[string]
}

type SubnetUpdate struct {
	Fields[SubnetFieldsUpdate]
	CloudItem[cloudmodel.Subnet]
	DiffBase[*diffbase.Subnet]
	MySQLData[metadbmodel.Subnet]
}

type VRouterFieldsUpdate struct {
	Key
	Name         fieldDetail[string]
	Label        fieldDetail[string]
	VPCID        fieldDetail[int]
	VPCLcuuid    fieldDetail[string]
	RegionLcuuid fieldDetail[string]
}

type VRouterUpdate struct {
	Fields[VRouterFieldsUpdate]
	CloudItem[cloudmodel.VRouter]
	DiffBase[*diffbase.VRouter]
	MySQLData[metadbmodel.VRouter]
}

type RoutingTableFieldsUpdate struct {
	Key
	Destination fieldDetail[string]
	NexthopType fieldDetail[string]
	Nexthop     fieldDetail[string]
}

type RoutingTableUpdate struct {
	Fields[RoutingTableFieldsUpdate]
	CloudItem[cloudmodel.RoutingTable]
	DiffBase[*diffbase.RoutingTable]
	MySQLData[metadbmodel.RoutingTable]
}

type DHCPPortFieldsUpdate struct {
	Key
	Name         fieldDetail[string]
	VPCID        fieldDetail[int]
	VPCLcuuid    fieldDetail[string]
	AZLcuuid     fieldDetail[string]
	RegionLcuuid fieldDetail[string]
}

type DHCPPortUpdate struct {
	Fields[DHCPPortFieldsUpdate]
	CloudItem[cloudmodel.DHCPPort]
	DiffBase[*diffbase.DHCPPort]
	MySQLData[metadbmodel.DHCPPort]
}

type VInterfaceFieldsUpdate struct {
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

type VInterfaceUpdate struct {
	Fields[VInterfaceFieldsUpdate]
	CloudItem[cloudmodel.VInterface]
	DiffBase[*diffbase.VInterface]
	MySQLData[metadbmodel.VInterface]
}

type FloatingIPFieldsUpdate struct {
	Key
	VPCID        fieldDetail[int]
	VPCLcuuid    fieldDetail[string]
	RegionLcuuid fieldDetail[string]
}

type FloatingIPUpdate struct {
	Fields[FloatingIPFieldsUpdate]
	CloudItem[cloudmodel.FloatingIP]
	DiffBase[*diffbase.FloatingIP]
	MySQLData[metadbmodel.FloatingIP]
}

type LANIPFieldsUpdate struct {
	Key
	SubnetID     fieldDetail[int]
	SubnetLcuuid fieldDetail[string]
}
type LANIPUpdate struct {
	Fields[LANIPFieldsUpdate]
	CloudItem[cloudmodel.IP]
	DiffBase[*diffbase.LANIP]
	MySQLData[metadbmodel.LANIP]
}
type WANIPFieldsUpdate struct {
	Key
	SubnetID     fieldDetail[int]
	SubnetLcuuid fieldDetail[string]
	RegionLcuuid fieldDetail[string]
}
type WANIPUpdate struct {
	Fields[WANIPFieldsUpdate]
	CloudItem[cloudmodel.IP]
	DiffBase[*diffbase.WANIP]
	MySQLData[metadbmodel.WANIP]
}
type VIPFieldsUpdate struct {
	Key
	IP     fieldDetail[string]
	VTapID fieldDetail[uint32]
}
type VIPUpdate struct {
	Fields[VIPFieldsUpdate]
	CloudItem[cloudmodel.IP]
	DiffBase[*diffbase.VIP]
	MySQLData[metadbmodel.VIP]
}

type NATGatewayFieldsUpdate struct {
	Key
	Name         fieldDetail[string]
	FloatingIPs  fieldDetail[string]
	RegionLcuuid fieldDetail[string]
	UID          fieldDetail[string]
}
type NATGatewayUpdate struct {
	Fields[NATGatewayFieldsUpdate]
	CloudItem[cloudmodel.NATGateway]
	DiffBase[*diffbase.NATGateway]
	MySQLData[metadbmodel.NATGateway]
}

type NATRuleFieldsUpdate struct {
	Key
}
type NATRuleUpdate struct {
	Fields[NATRuleFieldsUpdate]
	CloudItem[cloudmodel.NATRule]
	DiffBase[*diffbase.NATRule]
	MySQLData[metadbmodel.NATRule]
}

type NATVMConnectionFieldsUpdate struct {
	Key
}
type NATVMConnectionUpdate struct {
	Fields[NATVMConnectionFieldsUpdate]
	CloudItem[cloudmodel.NATVMConnection]
	DiffBase[*diffbase.NATVMConnection]
	MySQLData[metadbmodel.NATVMConnection]
}

type LBFieldsUpdate struct {
	Key
	Name         fieldDetail[string]
	UID          fieldDetail[string]
	Model        fieldDetail[int]
	VIP          fieldDetail[string]
	RegionLcuuid fieldDetail[string]
}
type LBUpdate struct {
	Fields[LBFieldsUpdate]
	CloudItem[cloudmodel.LB]
	DiffBase[*diffbase.LB]
	MySQLData[metadbmodel.LB]
}

type LBListenerFieldsUpdate struct {
	Key
	Name     fieldDetail[string]
	IPs      fieldDetail[string]
	SNATIPs  fieldDetail[string]
	Port     fieldDetail[int]
	Protocol fieldDetail[string]
}
type LBListenerUpdate struct {
	Fields[LBListenerFieldsUpdate]
	CloudItem[cloudmodel.LBListener]
	DiffBase[*diffbase.LBListener]
	MySQLData[metadbmodel.LBListener]
}

type LBTargetServerFieldsUpdate struct {
	Key
	IP       fieldDetail[string]
	Port     fieldDetail[int]
	Protocol fieldDetail[string]
}
type LBTargetServerUpdate struct {
	Fields[LBTargetServerFieldsUpdate]
	CloudItem[cloudmodel.LBTargetServer]
	DiffBase[*diffbase.LBTargetServer]
	MySQLData[metadbmodel.LBTargetServer]
}

type LBVMConnectionFieldsUpdate struct {
	Key
}
type LBVMConnectionUpdate struct {
	Fields[LBVMConnectionFieldsUpdate]
	CloudItem[cloudmodel.LBVMConnection]
	DiffBase[*diffbase.LBVMConnection]
	MySQLData[metadbmodel.LBVMConnection]
}

type PeerConnectionFieldsUpdate struct {
	Key
	Name fieldDetail[string]
}
type PeerConnectionUpdate struct {
	Fields[PeerConnectionFieldsUpdate]
	CloudItem[cloudmodel.PeerConnection]
	DiffBase[*diffbase.PeerConnection]
	MySQLData[metadbmodel.PeerConnection]
}

type CENFieldsUpdate struct {
	Key
	Name       fieldDetail[string]
	VPCIDs     fieldDetail[[]int]
	VPCLcuuids fieldDetail[[]string]
}
type CENUpdate struct {
	Fields[CENFieldsUpdate]
	CloudItem[cloudmodel.CEN]
	DiffBase[*diffbase.CEN]
	MySQLData[metadbmodel.CEN]
}

type RDSInstanceFieldsUpdate struct {
	Key
	Name         fieldDetail[string]
	UID          fieldDetail[string]
	State        fieldDetail[int]
	Series       fieldDetail[int]
	Model        fieldDetail[int]
	AZLcuuid     fieldDetail[string]
	RegionLcuuid fieldDetail[string]
}
type RDSInstanceUpdate struct {
	Fields[RDSInstanceFieldsUpdate]
	CloudItem[cloudmodel.RDSInstance]
	DiffBase[*diffbase.RDSInstance]
	MySQLData[metadbmodel.RDSInstance]
}

type RedisInstanceFieldsUpdate struct {
	Key
	Name         fieldDetail[string]
	UID          fieldDetail[string]
	State        fieldDetail[int]
	PublicHost   fieldDetail[string]
	AZLcuuid     fieldDetail[string]
	RegionLcuuid fieldDetail[string]
}
type RedisInstanceUpdate struct {
	Fields[RedisInstanceFieldsUpdate]
	CloudItem[cloudmodel.RedisInstance]
	DiffBase[*diffbase.RedisInstance]
	MySQLData[metadbmodel.RedisInstance]
}

type PodClusterFieldsUpdate struct {
	Key
	Name         fieldDetail[string]
	ClusterName  fieldDetail[string]
	AZLcuuid     fieldDetail[string]
	RegionLcuuid fieldDetail[string]
}
type PodClusterUpdate struct {
	Fields[PodClusterFieldsUpdate]
	CloudItem[cloudmodel.PodCluster]
	DiffBase[*diffbase.PodCluster]
	MySQLData[metadbmodel.PodCluster]
}

type PodNamespaceFieldsUpdate struct {
	Key
	CloudTags    fieldDetail[map[string]string]
	AZLcuuid     fieldDetail[string]
	RegionLcuuid fieldDetail[string]
	Name         fieldDetail[string]
	PodClusterID fieldDetail[int]
}
type PodNamespaceUpdate struct {
	Fields[PodNamespaceFieldsUpdate]
	CloudItem[cloudmodel.PodNamespace]
	DiffBase[*diffbase.PodNamespace]
	MySQLData[metadbmodel.PodNamespace]
}

type PodNodeFieldsUpdate struct {
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
type PodNodeUpdate struct {
	Fields[PodNodeFieldsUpdate]
	CloudItem[cloudmodel.PodNode]
	DiffBase[*diffbase.PodNode]
	MySQLData[metadbmodel.PodNode]
}

type PodIngressFieldsUpdate struct {
	Key
	Name         fieldDetail[string]
	AZLcuuid     fieldDetail[string]
	RegionLcuuid fieldDetail[string]
}
type PodIngressUpdate struct {
	Fields[PodIngressFieldsUpdate]
	CloudItem[cloudmodel.PodIngress]
	DiffBase[*diffbase.PodIngress]
	MySQLData[metadbmodel.PodIngress]
}

type PodIngressRuleFieldsUpdate struct {
	Key
}
type PodIngressRuleUpdate struct {
	Fields[PodIngressRuleFieldsUpdate]
	CloudItem[cloudmodel.PodIngressRule]
	DiffBase[*diffbase.PodIngressRule]
	MySQLData[metadbmodel.PodIngressRule]
}

type PodIngressRuleBackendFieldsUpdate struct {
	Key
}
type PodIngressRuleBackendUpdate struct {
	Fields[PodIngressRuleBackendFieldsUpdate]
	CloudItem[cloudmodel.PodIngressRuleBackend]
	DiffBase[*diffbase.PodIngressRuleBackend]
	MySQLData[metadbmodel.PodIngressRuleBackend]
}

type PodServiceFieldsUpdate struct {
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
type PodServiceUpdate struct {
	Fields[PodServiceFieldsUpdate]
	CloudItem[cloudmodel.PodService]
	DiffBase[*diffbase.PodService]
	MySQLData[metadbmodel.PodService]
}

type PodServicePortFieldsUpdate struct {
	Key
	Name fieldDetail[string]
}
type PodServicePortUpdate struct {
	Fields[PodServicePortFieldsUpdate]
	CloudItem[cloudmodel.PodServicePort]
	DiffBase[*diffbase.PodServicePort]
	MySQLData[metadbmodel.PodServicePort]
}

type PodGroupFieldsUpdate struct {
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
type PodGroupUpdate struct {
	Fields[PodGroupFieldsUpdate]
	CloudItem[cloudmodel.PodGroup]
	DiffBase[*diffbase.PodGroup]
	MySQLData[metadbmodel.PodGroup]
}

type ConfigMapFieldsUpdate struct {
	Key
	Name fieldDetail[string]
	Data fieldDetail[string]
}

type ConfigMapUpdate struct {
	Fields[ConfigMapFieldsUpdate]
	CloudItem[cloudmodel.ConfigMap]
	DiffBase[*diffbase.ConfigMap]
	MySQLData[metadbmodel.ConfigMap]
}

type PodGroupConfigMapConnectionFieldsUpdate struct {
	Key
}

type PodGroupConfigMapConnectionUpdate struct {
	Fields[PodGroupConfigMapConnectionFieldsUpdate]
	CloudItem[cloudmodel.PodGroupConfigMapConnection]
	DiffBase[*diffbase.PodGroupConfigMapConnection]
	MySQLData[metadbmodel.PodGroupConfigMapConnection]
}

type PodGroupPortFieldsUpdate struct {
	Key
	Name fieldDetail[string]
}
type PodGroupPortUpdate struct {
	Fields[PodGroupPortFieldsUpdate]
	CloudItem[cloudmodel.PodGroupPort]
	DiffBase[*diffbase.PodGroupPort]
	MySQLData[metadbmodel.PodGroupPort]
}

type PodReplicaSetFieldsUpdate struct {
	Key
	Name         fieldDetail[string]
	Label        fieldDetail[string]
	PodNum       fieldDetail[int]
	AZLcuuid     fieldDetail[string]
	RegionLcuuid fieldDetail[string]
}
type PodReplicaSetUpdate struct {
	Fields[PodReplicaSetFieldsUpdate]
	CloudItem[cloudmodel.PodReplicaSet]
	DiffBase[*diffbase.PodReplicaSet]
	MySQLData[metadbmodel.PodReplicaSet]
}

type PodFieldsUpdate struct {
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
type PodUpdate struct {
	Fields[PodFieldsUpdate]
	CloudItem[cloudmodel.Pod]
	DiffBase[*diffbase.Pod]
	MySQLData[metadbmodel.Pod]
}

type ProcessFieldsUpdate struct {
	Key
	Name        fieldDetail[string]
	ProcessName fieldDetail[string]
	ContainerID fieldDetail[string]
	OSAPPTags   fieldDetail[string]
	VMID        fieldDetail[int]
	VPCID       fieldDetail[int]
	GID         fieldDetail[uint32]
}
type ProcessUpdate struct {
	Fields[ProcessFieldsUpdate]
	CloudItem[cloudmodel.Process]
	DiffBase[*diffbase.Process]
	MySQLData[metadbmodel.Process]
}

type CustomServiceFieldsUpdate struct {
	Key
	Name fieldDetail[string]
}
type CustomServiceUpdate struct {
	Fields[CustomServiceFieldsUpdate]
	MySQLData[metadbmodel.CustomService]
}

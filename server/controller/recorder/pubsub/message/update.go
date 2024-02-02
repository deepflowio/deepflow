/**
 * Copyright (c) 2023 Yunshan Networks
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
	cloudmodel "github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
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

type MySQLData[MT constraint.MySQLModel] struct {
	new *MT
	old *MT
}

func (m *MySQLData[MT]) GetNewMySQL() *MT {
	return m.new
}

func (m *MySQLData[MT]) SetNewMySQL(new *MT) {
	m.new = new
}

func (m *MySQLData[MT]) GetOldMySQL() *MT {
	return m.old
}

func (m *MySQLData[MT]) SetOldMySQL(old *MT) {
	m.old = old
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
	MySQLData[mysql.Region]
}

func (r RegionUpdate) GetFields() interface{} {
	return r.Fields.data
}

func (r RegionUpdate) SetFields(fields interface{}) {
	r.Fields.SetFields(fields.(*RegionFieldsUpdate))
}

func (r RegionUpdate) GetMySQLItems() interface{} {
	return r.MySQLData.GetNewMySQL()
}

func (r RegionUpdate) SetMySQLItems(items interface{}) {
	r.MySQLData.SetNewMySQL(items.(*mysql.Region))
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
	MySQLData[mysql.AZ]
}

type SubDomainFieldsUpdate struct {
	Key
	Name fieldDetail[string]
}
type SubDomainUpdate struct {
	Fields[SubDomainFieldsUpdate]
	CloudItem[cloudmodel.SubDomain] // TODO tmp, delete later
	DiffBase[*diffbase.SubDomain]
	MySQLData[mysql.SubDomain]
}

type HostFieldsUpdate struct {
	Key
	Name         fieldDetail[string]
	IP           fieldDetail[string]
	HType        fieldDetail[int]
	VCPUNum      fieldDetail[int]
	MemTotal     fieldDetail[int]
	ExtraInfo    fieldDetail[string]
	AZLcuuid     fieldDetail[string]
	RegionLcuuid fieldDetail[string]
}

type HostUpdate struct {
	Fields[HostFieldsUpdate]
	CloudItem[cloudmodel.Host]
	DiffBase[*diffbase.Host]
	MySQLData[mysql.Host]
}

type VMFieldsUpdate struct {
	Key
	Name         fieldDetail[string]
	Label        fieldDetail[string]
	State        fieldDetail[int]
	HType        fieldDetail[int]
	LaunchServer fieldDetail[string]
	CloudTags    fieldDetail[map[string]string]
	VPCID        fieldDetail[int]
	VPCLcuuid    fieldDetail[string]
	AZLcuuid     fieldDetail[string]
	RegionLcuuid fieldDetail[string]
}

type VMUpdate struct {
	Fields[VMFieldsUpdate]
	CloudItem[cloudmodel.VM]
	DiffBase[*diffbase.VM]
	MySQLData[mysql.VM]
}

type VMPodNodeConnectionFieldsUpdate struct {
	Key
}

type VMPodNodeConnectionUpdate struct {
	Fields[VMPodNodeConnectionFieldsUpdate]
	CloudItem[cloudmodel.VMPodNodeConnection]
	DiffBase[*diffbase.VMPodNodeConnection]
	MySQLData[mysql.VMPodNodeConnection]
}

type VPCFieldsUpdate struct {
	Key
	Name         fieldDetail[string]
	Label        fieldDetail[string]
	CIDR         fieldDetail[string]
	TunnelID     fieldDetail[int]
	RegionLcuuid fieldDetail[string]
}

type VPCUpdate struct {
	Fields[VPCFieldsUpdate]
	CloudItem[cloudmodel.VPC]
	DiffBase[*diffbase.VPC]
	MySQLData[mysql.VPC]
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
	MySQLData[mysql.Network]
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
	MySQLData[mysql.Subnet]
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
	MySQLData[mysql.VRouter]
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
	MySQLData[mysql.RoutingTable]
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
	MySQLData[mysql.DHCPPort]
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
	MySQLData[mysql.VInterface]
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
	MySQLData[mysql.FloatingIP]
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
	MySQLData[mysql.LANIP]
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
	MySQLData[mysql.WANIP]
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
	MySQLData[mysql.VIP]
}
type SecurityGroupFieldsUpdate struct {
	Key
	Name         fieldDetail[string]
	Label        fieldDetail[string]
	RegionLcuuid fieldDetail[string]
}
type SecurityGroupUpdate struct {
	Fields[SecurityGroupFieldsUpdate]
	CloudItem[cloudmodel.SecurityGroup]
	DiffBase[*diffbase.SecurityGroup]
	MySQLData[mysql.SecurityGroup]
}

type SecurityGroupRuleFieldsUpdate struct {
	Key
	Priority        fieldDetail[int]
	EtherType       fieldDetail[int]
	RemotePortRange fieldDetail[string]
	Local           fieldDetail[string]
	Remote          fieldDetail[string]
}
type SecurityGroupRuleUpdate struct {
	Fields[SecurityGroupRuleFieldsUpdate]
	CloudItem[cloudmodel.SecurityGroupRule]
	DiffBase[*diffbase.SecurityGroupRule]
	MySQLData[mysql.SecurityGroupRule]
}

type VMSecurityGroupFieldsUpdate struct {
	Key
	Priority fieldDetail[int]
}
type VMSecurityGroupUpdate struct {
	Fields[VMSecurityGroupFieldsUpdate]
	CloudItem[cloudmodel.VMSecurityGroup]
	DiffBase[*diffbase.VMSecurityGroup]
	MySQLData[mysql.VMSecurityGroup]
}

type NATGatewayFieldsUpdate struct {
	Key
	Name         fieldDetail[string]
	FloatingIPs  fieldDetail[string]
	RegionLcuuid fieldDetail[string]
}
type NATGatewayUpdate struct {
	Fields[NATGatewayFieldsUpdate]
	CloudItem[cloudmodel.NATGateway]
	DiffBase[*diffbase.NATGateway]
	MySQLData[mysql.NATGateway]
}

type NATRuleFieldsUpdate struct {
	Key
}
type NATRuleUpdate struct {
	Fields[NATRuleFieldsUpdate]
	CloudItem[cloudmodel.NATRule]
	DiffBase[*diffbase.NATRule]
	MySQLData[mysql.NATRule]
}

type NATVMConnectionFieldsUpdate struct {
	Key
}
type NATVMConnectionUpdate struct {
	Fields[NATVMConnectionFieldsUpdate]
	CloudItem[cloudmodel.NATVMConnection]
	DiffBase[*diffbase.NATVMConnection]
	MySQLData[mysql.NATVMConnection]
}

type LBFieldsUpdate struct {
	Key
	Name         fieldDetail[string]
	Model        fieldDetail[int]
	VIP          fieldDetail[string]
	RegionLcuuid fieldDetail[string]
}
type LBUpdate struct {
	Fields[LBFieldsUpdate]
	CloudItem[cloudmodel.LB]
	DiffBase[*diffbase.LB]
	MySQLData[mysql.LB]
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
	MySQLData[mysql.LBListener]
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
	MySQLData[mysql.LBTargetServer]
}

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

package baidubce

import (
	"encoding/json"

	"github.com/baidubce/bce-sdk-go/services/appblb"
	"github.com/baidubce/bce-sdk-go/services/bcc/api"
	"github.com/baidubce/bce-sdk-go/services/blb"
	"github.com/baidubce/bce-sdk-go/services/cce"
	"github.com/baidubce/bce-sdk-go/services/csn"
	"github.com/baidubce/bce-sdk-go/services/eni"
	"github.com/baidubce/bce-sdk-go/services/rds"
	"github.com/baidubce/bce-sdk-go/services/scs"
	"github.com/baidubce/bce-sdk-go/services/vpc"
	simplejson "github.com/bitly/go-simplejson"
	logging "github.com/op/go-logging"

	cloudcommon "github.com/deepflowio/deepflow/server/controller/cloud/common"
	cloudconfig "github.com/deepflowio/deepflow/server/controller/cloud/config"
	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/statsd"
)

var log = logging.MustGetLogger("cloud.baidu")

type BaiduBce struct {
	name         string
	uuid         string
	uuidGenerate string
	regionUuid   string
	secretID     string
	secretKey    string
	endpoint     string
	httpTimeout  int

	// 以下两个字段的作用：消除公有云的无资源的区域和可用区
	regionLcuuidToResourceNum map[string]int
	azLcuuidToResourceNum     map[string]int

	cloudStatsd statsd.CloudStatsd
	debugger    *cloudcommon.Debugger
}

func NewBaiduBce(domain mysql.Domain, cfg cloudconfig.CloudConfig) (*BaiduBce, error) {
	config, err := simplejson.NewJson([]byte(domain.Config))
	if err != nil {
		log.Error(err)
		return nil, err
	}

	secretID, err := config.Get("secret_id").String()
	if err != nil {
		log.Error("secret_id must be specified")
		return nil, err
	}

	secretKey, err := config.Get("secret_key").String()
	if err != nil {
		log.Error("secret_key must be specified")
		return nil, err
	}
	decryptSecretKey, err := common.DecryptSecretKey(secretKey)
	if err != nil {
		log.Error("decrypt secret_key failed (%s)", err.Error())
		return nil, err
	}

	endpoint, err := config.Get("endpoint").String()
	if err != nil {
		log.Error("endpoint must be specified")
		return nil, err
	}

	return &BaiduBce{
		uuid: domain.Lcuuid,
		name: domain.Name,
		// TODO: display_name后期需要修改为uuid_generate
		uuidGenerate: domain.DisplayName,
		regionUuid:   config.Get("region_uuid").MustString(),
		secretID:     secretID,
		secretKey:    decryptSecretKey,
		endpoint:     endpoint,
		httpTimeout:  cfg.HTTPTimeout,

		regionLcuuidToResourceNum: make(map[string]int),
		azLcuuidToResourceNum:     make(map[string]int),

		cloudStatsd: statsd.NewCloudStatsd(),
		debugger:    cloudcommon.NewDebugger(domain.Name),
	}, nil
}

func (b *BaiduBce) ClearDebugLog() {
	b.debugger.Clear()
}

func (b *BaiduBce) CheckAuth() error {
	return nil
}

func (b *BaiduBce) GetStatter() statsd.StatsdStatter {
	globalTags := map[string]string{
		"domain_name": b.name,
		"domain":      b.uuid,
		"platform":    common.BAIDU_BCE_EN,
	}

	return statsd.StatsdStatter{
		GlobalTags: globalTags,
		Element:    statsd.GetCloudStatsd(b.cloudStatsd),
	}
}

func (b *BaiduBce) GetCloudData() (model.Resource, error) {
	var resource model.Resource
	var vinterfaces []model.VInterface
	var ips []model.IP
	b.cloudStatsd = statsd.NewCloudStatsd()

	// 区域和可用区
	regions, azs, zoneNameToAZLcuuid, err := b.getRegionAndAZs()
	if err != nil {
		log.Error("get region and az data failed")
		return resource, err
	}
	// 页面指定区域时，优先使用页面指定区域
	region := model.Region{}
	if b.regionUuid != "" {
		region.Lcuuid = b.regionUuid
	} else {
		region = regions[0]
	}

	// VPC
	vpcs, vpcIdToLcuuid, vpcIdToName, err := b.getVPCs(region)
	if err != nil {
		log.Error("get vpc data failed")
		return resource, err
	}

	// 子网及网段信息
	networks, subnets, networkIdToLcuuid, err := b.getNetworks(region, zoneNameToAZLcuuid, vpcIdToLcuuid)
	if err != nil {
		log.Error("get network and subnet data failed")
		return resource, err
	}

	// 虚拟机
	vms, tmpVInterfaces, tmpIPs, err := b.getVMs(region, zoneNameToAZLcuuid, vpcIdToLcuuid, networkIdToLcuuid)
	if err != nil {
		log.Error("get vm data failed")
		return resource, err
	}
	vinterfaces = append(vinterfaces, tmpVInterfaces...)
	ips = append(ips, tmpIPs...)

	// 路由器及路由表
	vrouters, routingTables, err := b.getRouterAndTables(region, vpcIdToLcuuid, vpcIdToName)
	if err != nil {
		log.Error("get vrouter data failed")
		return resource, err
	}

	// 安全组及规则（暂不支持对接虚拟机与安全组的关联关系）
	securityGroups, securityGroupRules, err := b.getSecurityGroups(region, vpcIdToLcuuid)
	if err != nil {
		log.Error("get security_group data failed")
		return resource, err
	}

	// NAT网关及IP
	natGateways, tmpVInterfaces, tmpIPs, err := b.getNatGateways(region, vpcIdToLcuuid)
	if err != nil {
		log.Error("get nat_gateway data failed")
		return resource, err
	}
	vinterfaces = append(vinterfaces, tmpVInterfaces...)
	ips = append(ips, tmpIPs...)

	// 负载均衡器
	lbs, tmpVInterfaces, tmpIPs, err := b.getLoadBalances(region, vpcIdToLcuuid, networkIdToLcuuid)
	if err != nil {
		log.Error("get load_balance data failed")
		return resource, err
	}
	vinterfaces = append(vinterfaces, tmpVInterfaces...)
	ips = append(ips, tmpIPs...)

	// 对等连接
	peerConnections, err := b.getPeerConnections(region, vpcIdToLcuuid)
	if err != nil {
		log.Error("get peer_connection data failed")
		return resource, err
	}

	// CSN
	cens, err := b.getCENs()
	if err != nil {
		resource.ErrorState = common.RESOURCE_STATE_CODE_WARNING
		resource.ErrorMessage = err.Error()
		log.Warning(err)
	}

	// RDS
	rdsInstances, tmpVInterfaces, tmpIPs, err := b.getRDSInstances(
		region, vpcIdToLcuuid, networkIdToLcuuid, zoneNameToAZLcuuid,
	)
	if err != nil {
		log.Error("get rds_instance data failed")
		return resource, err
	}
	vinterfaces = append(vinterfaces, tmpVInterfaces...)
	ips = append(ips, tmpIPs...)

	// Redis
	redisInstances, redisVInterfaces, redisIPs, err := b.getRedisInstances(
		region, vpcIdToLcuuid, networkIdToLcuuid, zoneNameToAZLcuuid,
	)
	if err != nil {
		log.Error("get redis_instance data failed")
		return resource, err
	}
	vinterfaces = append(vinterfaces, redisVInterfaces...)
	ips = append(ips, redisIPs...)

	// 附属容器集群
	subDomains, err := b.getSubDomains(region, vpcIdToLcuuid)
	if err != nil {
		log.Error("get sub_domain data failed")
		return resource, err
	}

	resource.Regions = cloudcommon.EliminateEmptyRegions(regions, b.regionLcuuidToResourceNum)
	resource.AZs = cloudcommon.EliminateEmptyAZs(azs, b.azLcuuidToResourceNum)
	resource.VPCs = vpcs
	resource.Networks = networks
	resource.Subnets = subnets
	resource.VMs = vms
	resource.VInterfaces = vinterfaces
	resource.IPs = ips
	resource.SecurityGroups = securityGroups
	resource.SecurityGroupRules = securityGroupRules
	resource.VRouters = vrouters
	resource.RoutingTables = routingTables
	resource.NATGateways = natGateways
	resource.LBs = lbs
	resource.PeerConnections = peerConnections
	resource.CENs = cens
	resource.RDSInstances = rdsInstances
	resource.RedisInstances = redisInstances
	resource.SubDomains = subDomains
	b.cloudStatsd.ResCount = statsd.GetResCount(resource)
	statsd.MetaStatsd.RegisterStatsdTable(b)
	b.debugger.Refresh()
	return resource, nil
}

type BCEResultStruct interface {
	api.ZoneModel | *blb.DescribeLoadBalancersResult | *vpc.ListNatGatewayResult | *vpc.ListSubnetResult |
		*vpc.ListPeerConnsResult | *rds.ListRdsResult | *vpc.GetRouteTableResult | *api.ListSecurityGroupResult |
		*cce.ListClusterResult | *api.ListInstanceResult | *eni.ListEniResult | *vpc.ListVPCResult | csn.Csn | csn.Instance |
		*appblb.DescribeLoadBalancersResult | *scs.ListInstancesResult
}

func structToJson[T BCEResultStruct](structs []T) (jsonList []*simplejson.Json) {
	for _, s := range structs {
		byteData, _ := json.Marshal(s)
		jsonData, err := simplejson.NewJson(byteData)
		if err != nil {
			log.Errorf("convert to json data failed: %s", err.Error())
			continue
		}
		jsonList = append(jsonList, jsonData)
	}
	return
}

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

package aliyun

import (
	"errors"
	"fmt"

	"github.com/aliyun/alibaba-cloud-sdk-go/sdk"
	ecs "github.com/aliyun/alibaba-cloud-sdk-go/services/ecs"
	resmanager "github.com/aliyun/alibaba-cloud-sdk-go/services/resourcemanager"
	simplejson "github.com/bitly/go-simplejson"

	cloudcommon "github.com/deepflowio/deepflow/server/controller/cloud/common"
	cloudconfig "github.com/deepflowio/deepflow/server/controller/cloud/config"
	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	"github.com/deepflowio/deepflow/server/libs/logger"
)

var log = logger.MustGetLogger("cloud.aliyun")

const (
	REGION_NAME = "cn-beijing"
)

type Aliyun struct {
	orgID          int
	teamID         int
	uuid           string
	uuidGenerate   string
	regionLcuuid   string
	secretID       string
	secretKey      string
	regionName     string
	httpTimeout    int
	includeRegions map[string]bool
	vpcIDToLcuuids map[string]string

	// 消除公有云的无资源可用区使用
	azLcuuidToResourceNum map[string]int

	debugger *cloudcommon.Debugger
}

func NewAliyun(orgID int, domain metadbmodel.Domain, cfg cloudconfig.CloudConfig) (*Aliyun, error) {
	config, err := simplejson.NewJson([]byte(domain.Config))
	if err != nil {
		log.Error(err, logger.NewORGPrefix(orgID))
		return nil, err
	}

	secretID, err := config.Get("secret_id").String()
	if err != nil {
		log.Error("secret_id must be specified", logger.NewORGPrefix(orgID))
		return nil, err
	}

	secretKey, err := config.Get("secret_key").String()
	if err != nil {
		log.Error("secret_key must be specified", logger.NewORGPrefix(orgID))
		return nil, err
	}
	decryptSecretKey, err := common.DecryptSecretKey(secretKey)
	if err != nil {
		log.Errorf("decrypt secret_key failed (%s)", err.Error(), logger.NewORGPrefix(orgID))
		return nil, err
	}

	regionName := config.Get("region_name").MustString()
	if regionName == "" {
		regionName = REGION_NAME
	}

	regionLcuuid := config.Get("region_uuid").MustString()
	if regionLcuuid == "" {
		regionLcuuid = common.DEFAULT_REGION
	}

	return &Aliyun{
		orgID:  orgID,
		teamID: domain.TeamID,
		uuid:   domain.Lcuuid,
		// TODO: display_name后期需要修改为uuid_generate
		uuidGenerate:   domain.DisplayName,
		regionLcuuid:   regionLcuuid,
		secretID:       secretID,
		secretKey:      decryptSecretKey,
		regionName:     regionName,
		includeRegions: cloudcommon.UniqRegions(config.Get("include_regions").MustString()),
		httpTimeout:    cfg.HTTPTimeout,

		azLcuuidToResourceNum: make(map[string]int),

		vpcIDToLcuuids: map[string]string{},

		debugger: cloudcommon.NewDebugger(domain.Name),
	}, nil
}

func (a *Aliyun) ClearDebugLog() {
	a.debugger.Clear()
}

func (a *Aliyun) CheckAuth() error {
	_, err := sdk.NewClientWithAccessKey(a.regionName, a.secretID, a.secretKey)
	return err
}

func (a *Aliyun) checkRequiredAttributes(json *simplejson.Json, attributes []string) error {
	for _, attribute := range attributes {
		if _, ok := json.CheckGet(attribute); !ok {
			log.Infof("get attribute (%s) failed", attribute, logger.NewORGPrefix(a.orgID))
			return errors.New(fmt.Sprintf("get attribute (%s) failed", attribute))
		}
	}
	return nil
}

func (a *Aliyun) GetCloudData() (model.Resource, error) {
	var resource model.Resource
	var azs []model.AZ
	var vpcs []model.VPC
	var networks []model.Network
	var subnets []model.Subnet
	var vms []model.VM
	var vinterfaces []model.VInterface
	var ips []model.IP
	var floatingIPs []model.FloatingIP
	var vrouters []model.VRouter
	var routingTables []model.RoutingTable
	var natGateways []model.NATGateway
	var natRules []model.NATRule
	var lbs []model.LB
	var lbListeners []model.LBListener
	var lbTargetServers []model.LBTargetServer
	var redisInstances []model.RedisInstance
	var rdsInstances []model.RDSInstance
	var cens []model.CEN
	var subDomains []model.SubDomain

	regions, err := a.getRegions()
	if err != nil {
		log.Error("get region data failed", logger.NewORGPrefix(a.orgID))
		return resource, err
	}

	var hasVM bool
	regionToRGIDs := map[string][]string{}
	for _, region := range regions {
		vmResponses, err := a.getVMResponse(region.Label, ecs.CreateDescribeInstancesRequest())
		if err != nil {
			log.Errorf("check instance count error: %s", err.Error(), logger.NewORGPrefix(a.orgID))
			return resource, err
		}
		for _, vmResponse := range vmResponses {
			if len(vmResponse.Get("Instance").MustArray()) != 0 {
				hasVM = true
				break
			}
		}
		if hasVM {
			break
		}
	}
	if !hasVM {
		log.Debug("get instance resource", logger.NewORGPrefix(a.orgID))
		resRequest := resmanager.CreateListResourcesRequest()
		resRequest.SetScheme("https")
		resRequest.ResourceType = "instance"
		resResponses, err := a.getResourceResponse(a.regionName, resRequest)
		if err != nil {
			log.Errorf("get resource group info error: %s", err.Error(), logger.NewORGPrefix(a.orgID))
			return resource, err
		}
		for _, responses := range resResponses {
			resources := responses.Get("Resource")
			for r := range resources.MustArray() {
				res := resources.GetIndex(r)
				regionID := res.Get("RegionId").MustString()
				rgID := res.Get("ResourceGroupId").MustString()
				if regionID == "" || rgID == "" {
					log.Warningf("list resources instance RegionId (%s) or ResourceGroupId (%s) is null", regionID, rgID, logger.NewORGPrefix(a.orgID))
					continue
				}
				regionToRGIDs[regionID] = append(regionToRGIDs[regionID], rgID)
			}
		}
	}

	for _, region := range regions {
		log.Infof("get region (%s) data starting", region.Name, logger.NewORGPrefix(a.orgID))
		a.vpcIDToLcuuids = map[string]string{}

		// 可用区
		tmpAZs, err := a.getAZs(region)
		if err != nil {
			log.Errorf("get region (%s) az data failed", region.Name, logger.NewORGPrefix(a.orgID))
			return resource, err
		}
		azs = append(azs, tmpAZs...)

		// VPC
		tmpVPCs, err := a.getVPCs(region)
		if err != nil {
			log.Errorf("get region (%s) vpc data failed", region.Name, logger.NewORGPrefix(a.orgID))
			return resource, err
		}
		vpcs = append(vpcs, tmpVPCs...)

		// 子网及网段
		tmpNetworks, tmpSubnets, err := a.getNetworks(region)
		if err != nil {
			log.Errorf("get region (%s) vpc data failed", region.Name, logger.NewORGPrefix(a.orgID))
			return resource, err
		}
		networks = append(networks, tmpNetworks...)
		subnets = append(subnets, tmpSubnets...)

		// VM及相关资源
		tmpVMs, tmpVInterfaces, tmpIPs, tmpFloatingIPs, vmLcuuidToVPCLcuuid, err := a.getVMs(region, regionToRGIDs[region.Label])
		if err != nil {
			log.Errorf("get region (%s) vm data failed", region.Name, logger.NewORGPrefix(a.orgID))
			return resource, err
		}
		vms = append(vms, tmpVMs...)
		vinterfaces = append(vinterfaces, tmpVInterfaces...)
		ips = append(ips, tmpIPs...)
		floatingIPs = append(floatingIPs, tmpFloatingIPs...)

		// VM接口信息
		tmpVInterfaces, tmpIPs, tmpFloatingIPs, tmpNATRules, err := a.getVMPorts(region)
		if err != nil {
			log.Errorf("get region (%s) port data failed", region.Name, logger.NewORGPrefix(a.orgID))
			return resource, err
		}
		vinterfaces = append(vinterfaces, tmpVInterfaces...)
		ips = append(ips, tmpIPs...)
		floatingIPs = append(floatingIPs, tmpFloatingIPs...)
		natRules = append(natRules, tmpNATRules...)

		// 路由表及规则
		tmpVRouters, tmpRoutingTables := a.getRouterAndTables(region)
		vrouters = append(vrouters, tmpVRouters...)
		routingTables = append(routingTables, tmpRoutingTables...)

		// NAT网关及规则
		tmpNATGateways, tmpNATRules, tmpVInterfaces, tmpIPs := a.getNatGateways(region)
		natGateways = append(natGateways, tmpNATGateways...)
		natRules = append(natRules, tmpNATRules...)
		vinterfaces = append(vinterfaces, tmpVInterfaces...)
		ips = append(ips, tmpIPs...)

		// 负载均衡器及规则
		tmpLBs, tmpLBListeners, tmpLBTargetServers, tmpVInterfaces, tmpIPs := a.getLoadBalances(region, vmLcuuidToVPCLcuuid)
		lbs = append(lbs, tmpLBs...)
		lbListeners = append(lbListeners, tmpLBListeners...)
		lbTargetServers = append(lbTargetServers, tmpLBTargetServers...)
		vinterfaces = append(vinterfaces, tmpVInterfaces...)
		ips = append(ips, tmpIPs...)

		// 云企业网
		cens = append(cens, a.getCens(region)...)

		// Redis
		tmpRedisInstances, tmpVInterfaces, tmpIPs := a.getRedisInstances(region)
		redisInstances = append(redisInstances, tmpRedisInstances...)
		vinterfaces = append(vinterfaces, tmpVInterfaces...)
		ips = append(ips, tmpIPs...)

		// RDS
		tmpRDSInstances, tmpVInterfaces, tmpIPs := a.getRDSInstances(region)
		rdsInstances = append(rdsInstances, tmpRDSInstances...)
		vinterfaces = append(vinterfaces, tmpVInterfaces...)
		ips = append(ips, tmpIPs...)

		// 附属容器集群
		subDomains = append(subDomains, a.getSubDomains(region)...)

		log.Infof("get region (%s) data completed", region.Name, logger.NewORGPrefix(a.orgID))
	}

	resource.AZs = cloudcommon.EliminateEmptyAZs(azs, a.azLcuuidToResourceNum)
	resource.VPCs = vpcs
	resource.Networks = networks
	resource.Subnets = subnets
	resource.VMs = vms
	resource.VInterfaces = vinterfaces
	resource.IPs = ips
	resource.FloatingIPs = floatingIPs
	resource.VRouters = vrouters
	resource.RoutingTables = routingTables
	resource.NATGateways = natGateways
	resource.NATRules = natRules
	resource.LBs = lbs
	resource.LBListeners = lbListeners
	resource.LBTargetServers = lbTargetServers
	resource.RedisInstances = redisInstances
	resource.RDSInstances = rdsInstances
	resource.CENs = cens
	resource.SubDomains = subDomains
	a.debugger.Refresh()
	return resource, err
}

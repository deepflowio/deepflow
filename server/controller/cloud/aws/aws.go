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

package aws

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws/transport/http"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/bitly/go-simplejson"

	cloudcommon "github.com/deepflowio/deepflow/server/controller/cloud/common"
	cloudconfig "github.com/deepflowio/deepflow/server/controller/cloud/config"
	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	"github.com/deepflowio/deepflow/server/libs/logger"
)

var log = logger.MustGetLogger("cloud.aws")

const (
	REGION_NAME                  = "cn-north-1"
	EKS_NODE_DESCRIPTION_PREFIX  = "aws-K8S-"
	EKS_NODE_TAG_INSTANCE_ID_KEY = "node.k8s.amazonaws.com/instance_id"
)

type Aws struct {
	orgID                 int
	teamID                int
	name                  string
	lcuuid                string
	regionLcuuid          string
	uuidGenerate          string
	apiDefaultRegion      string
	httpClient            *http.BuildableClient
	azLcuuidMap           map[string]int
	includeRegions        map[string]bool
	vpcOrSubnetToRouter   map[string]string
	vmIDToPrivateIP       map[string]string
	vpcIDToLcuuid         map[string]string
	instanceIDToPrimaryIP map[string]string
	subnetIDToVPCAZLcuuid map[string][2]string
	publicIPToVinterface  map[string]model.VInterface
	credential            awsconfig.LoadOptionsFunc
}

type awsGressRule struct {
	direction int
	priority  int
	rule      types.IpPermission
}

func NewAws(orgID int, domain metadbmodel.Domain, cfg cloudconfig.CloudConfig) (*Aws, error) {
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

	httpClient := http.NewBuildableClient().WithTimeout(time.Second * time.Duration(cfg.HTTPTimeout))

	return &Aws{
		// TODO: display_name后期需要修改为uuid_generate
		orgID:            orgID,
		teamID:           domain.TeamID,
		name:             domain.Name,
		lcuuid:           domain.Lcuuid,
		uuidGenerate:     domain.DisplayName,
		httpClient:       httpClient,
		apiDefaultRegion: regionName,
		regionLcuuid:     regionLcuuid,
		includeRegions:   cloudcommon.UniqRegions(config.Get("include_regions").MustString()),
		credential:       awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(secretID, decryptSecretKey, "")),

		// 以下属性为获取资源所用的关联关系
		azLcuuidMap:           map[string]int{},
		vpcOrSubnetToRouter:   map[string]string{},
		vmIDToPrivateIP:       map[string]string{},
		vpcIDToLcuuid:         map[string]string{},
		instanceIDToPrimaryIP: map[string]string{},
		subnetIDToVPCAZLcuuid: map[string][2]string{},
		publicIPToVinterface:  map[string]model.VInterface{},
	}, nil
}

func (a *Aws) CheckAuth() error {
	awsClientConfig, err := awsconfig.LoadDefaultConfig(context.TODO(), a.credential, awsconfig.WithRegion(a.apiDefaultRegion), awsconfig.WithHTTPClient(a.httpClient))
	if err != nil {
		log.Error("client config failed (%s)", err.Error(), logger.NewORGPrefix(a.orgID))
		return err
	}
	_, err = ec2.NewFromConfig(awsClientConfig).DescribeRegions(context.TODO(), &ec2.DescribeRegionsInput{})
	return err
}

func (a *Aws) getResultTagName(tags []types.Tag) string {
	var name string
	for _, t := range tags {
		if a.getStringPointerValue(t.Key) == "Name" {
			name = a.getStringPointerValue(t.Value)
		}
	}
	return name
}

func (a *Aws) getStringPointerValue(pString *string) string {
	if pString == nil {
		return ""
	}
	return *pString
}

func (a *Aws) getInt32PointerValue(pInt32 *int32) int32 {
	if pInt32 == nil {
		return 0
	}
	return *pInt32
}

func (a *Aws) getBoolPointerValue(pBool *bool) bool {
	if pBool == nil {
		return false
	}
	return *pBool
}

func (a *Aws) getTimePointerValue(pTime *time.Time) time.Time {
	if pTime == nil {
		return time.Time{}
	}
	return *pTime
}

func (a *Aws) ClearDebugLog() {}

func (a *Aws) GetCloudData() (model.Resource, error) {
	var resource model.Resource

	regions, err := a.getRegions()
	if err != nil {
		return model.Resource{}, err
	}

	for _, region := range regions {
		log.Infof("region (%s) collect starting", region, logger.NewORGPrefix(a.orgID))

		clientConfig, err := awsconfig.LoadDefaultConfig(context.TODO(), a.credential, awsconfig.WithRegion(region), awsconfig.WithHTTPClient(a.httpClient))
		if err != nil {
			log.Error("client config failed (%s)", err.Error(), logger.NewORGPrefix(a.orgID))
			return model.Resource{}, err
		}
		ec2Client := ec2.NewFromConfig(clientConfig)

		a.azLcuuidMap = map[string]int{}
		a.vpcIDToLcuuid = map[string]string{}
		a.instanceIDToPrimaryIP = map[string]string{}
		a.subnetIDToVPCAZLcuuid = map[string][2]string{}

		vpcs, err := a.getVPCs(ec2Client)
		if err != nil {
			return model.Resource{}, err
		}
		resource.VPCs = append(resource.VPCs, vpcs...)

		peerConnections, err := a.getPeerConnections(ec2Client)
		if err != nil {
			return model.Resource{}, err
		}
		resource.PeerConnections = append(resource.PeerConnections, peerConnections...)

		natGateways, natVinterfaces, natIPs, err := a.getNatGateways(ec2Client)
		if err != nil {
			return model.Resource{}, err
		}
		resource.NATGateways = append(resource.NATGateways, natGateways...)
		resource.VInterfaces = append(resource.VInterfaces, natVinterfaces...)
		resource.IPs = append(resource.IPs, natIPs...)

		routers, routerTables, err := a.getRouterAndTables(ec2Client)
		if err != nil {
			return model.Resource{}, err
		}
		resource.VRouters = append(resource.VRouters, routers...)
		resource.RoutingTables = append(resource.RoutingTables, routerTables...)

		networks, subnets, netVinterfaces, err := a.getNetworks(ec2Client)
		if err != nil {
			return model.Resource{}, err
		}
		resource.Networks = append(resource.Networks, networks...)
		resource.Subnets = append(resource.Subnets, subnets...)
		resource.VInterfaces = append(resource.VInterfaces, netVinterfaces...)

		vinterfaces, ips, vNatRules, err := a.getVInterfacesAndIPs(ec2Client)
		if err != nil {
			return model.Resource{}, err
		}
		resource.VInterfaces = append(resource.VInterfaces, vinterfaces...)
		resource.IPs = append(resource.IPs, ips...)
		resource.NATRules = append(resource.NATRules, vNatRules...)

		vms, err := a.getVMs(ec2Client)
		if err != nil {
			return model.Resource{}, err
		}
		resource.VMs = append(resource.VMs, vms...)

		rdsInstances, err := a.getRDSInstances(region)
		if err != nil {
			return model.Resource{}, err
		}
		resource.RDSInstances = append(resource.RDSInstances, rdsInstances...)

		redisInstances, err := a.getRedisInstances(region)
		if err != nil {
			return model.Resource{}, err
		}
		resource.RedisInstances = append(resource.RedisInstances, redisInstances...)

		lbs, lbListeners, lbTargetServers, err := a.getLoadBalances(region)
		if err != nil {
			return model.Resource{}, err
		}
		resource.LBs = append(resource.LBs, lbs...)
		resource.LBListeners = append(resource.LBListeners, lbListeners...)
		resource.LBTargetServers = append(resource.LBTargetServers, lbTargetServers...)

		fIPs, err := a.getFloatingIPs()
		if err != nil {
			return model.Resource{}, err
		}
		resource.FloatingIPs = append(resource.FloatingIPs, fIPs...)

		// 附属容器集群
		sDomains, err := a.getSubDomains(region)
		if err != nil {
			return resource, err
		}
		resource.SubDomains = append(resource.SubDomains, sDomains...)

		azs, err := a.getAZs(ec2Client)
		if err != nil {
			return model.Resource{}, err
		}
		resource.AZs = append(resource.AZs, azs...)

		log.Infof("region (%s) collect complete", region, logger.NewORGPrefix(a.orgID))
	}

	return resource, nil
}

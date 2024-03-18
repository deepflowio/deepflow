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
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws/transport/http"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/bitly/go-simplejson"
	cloudconfig "github.com/deepflowio/deepflow/server/controller/cloud/config"
	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/op/go-logging"
)

var log = logging.MustGetLogger("cloud.aws")

const (
	REGION_NAME                 = "cn-north-1"
	EKS_NODE_DESCRIPTION_PREFIX = "aws-K8S-"
)

type Aws struct {
	name                  string
	lcuuid                string
	regionUUID            string
	uuidGenerate          string
	apiDefaultRegion      string
	includeRegions        []string
	excludeRegions        []string
	httpClient            *http.BuildableClient
	azLcuuidMap           map[string]int
	vpcOrSubnetToRouter   map[string]string
	vmIDToPrivateIP       map[string]string
	vpcIDToLcuuid         map[string]string
	instanceIDToPrimaryIP map[string]string
	publicIPToVinterface  map[string]model.VInterface
	credential            awsconfig.LoadOptionsFunc
	ec2Client             *ec2.Client
}

type awsRegion struct {
	name   string
	lcuuid string
}

type awsGressRule struct {
	direction int
	priority  int
	rule      types.IpPermission
}

func NewAws(domain mysql.Domain, cfg cloudconfig.CloudConfig) (*Aws, error) {
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

	excludeRegionsStr := config.Get("exclude_regions").MustString()
	excludeRegions := []string{}
	if excludeRegionsStr != "" {
		excludeRegions = strings.Split(excludeRegionsStr, ",")
	}

	sort.Strings(excludeRegions)
	includeRegionsStr := config.Get("include_regions").MustString()
	includeRegions := []string{}
	if includeRegionsStr != "" {
		includeRegions = strings.Split(includeRegionsStr, ",")
	}
	sort.Strings(includeRegions)

	httpClient := http.NewBuildableClient().WithTimeout(time.Second * time.Duration(cfg.HTTPTimeout))

	return &Aws{
		// TODO: display_name后期需要修改为uuid_generate
		name:             domain.Name,
		lcuuid:           domain.Lcuuid,
		uuidGenerate:     domain.DisplayName,
		excludeRegions:   excludeRegions,
		includeRegions:   includeRegions,
		httpClient:       httpClient,
		apiDefaultRegion: cfg.AWSRegionName,
		regionUUID:       config.Get("region_uuid").MustString(),
		credential:       awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(secretID, decryptSecretKey, "")),

		// 以下属性为获取资源所用的关联关系
		azLcuuidMap:           map[string]int{},
		vpcOrSubnetToRouter:   map[string]string{},
		vmIDToPrivateIP:       map[string]string{},
		vpcIDToLcuuid:         map[string]string{},
		instanceIDToPrimaryIP: map[string]string{},
		publicIPToVinterface:  map[string]model.VInterface{},
	}, nil
}

func (a *Aws) CheckAuth() error {
	awsClientConfig, err := awsconfig.LoadDefaultConfig(context.TODO(), a.credential, awsconfig.WithRegion(a.apiDefaultRegion), awsconfig.WithHTTPClient(a.httpClient))
	if err != nil {
		log.Error("client config failed (%s)", err.Error())
		return err
	}
	_, err = ec2.NewFromConfig(awsClientConfig).DescribeRegions(context.TODO(), &ec2.DescribeRegionsInput{})
	return err
}

func (a *Aws) getRegionLcuuid(lcuuid string) string {
	if a.regionUUID != "" {
		return a.regionUUID
	}
	return lcuuid
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

	regionList, err := a.getRegions()
	if err != nil {
		return model.Resource{}, err
	}

	for _, region := range regionList {
		log.Infof("region (%s) collect starting", region.name)

		clientConfig, err := awsconfig.LoadDefaultConfig(context.TODO(), a.credential, awsconfig.WithRegion(region.name), awsconfig.WithHTTPClient(a.httpClient))
		if err != nil {
			log.Error("client config failed (%s)", err.Error())
			return model.Resource{}, err
		}
		a.ec2Client = ec2.NewFromConfig(clientConfig)

		regionFlag := false
		a.azLcuuidMap = map[string]int{}
		a.vpcIDToLcuuid = map[string]string{}
		a.instanceIDToPrimaryIP = map[string]string{}

		vpcs, err := a.getVPCs(region)
		if err != nil {
			return model.Resource{}, err
		}
		if len(vpcs) > 0 {
			regionFlag = true
			resource.VPCs = append(resource.VPCs, vpcs...)
		}

		peerConnections, err := a.getPeerConnections(region)
		if err != nil {
			return model.Resource{}, err
		}
		if len(peerConnections) > 0 {
			regionFlag = true
			resource.PeerConnections = append(resource.PeerConnections, peerConnections...)
		}

		natGateways, natVinterfaces, natIPs, err := a.getNatGateways(region)
		if err != nil {
			return model.Resource{}, err
		}
		if len(natGateways) > 0 || len(natVinterfaces) > 0 || len(natIPs) > 0 {
			regionFlag = true
			resource.NATGateways = append(resource.NATGateways, natGateways...)
			resource.VInterfaces = append(resource.VInterfaces, natVinterfaces...)
			resource.IPs = append(resource.IPs, natIPs...)
		}

		routers, routerTables, err := a.getRouterAndTables(region)
		if err != nil {
			return model.Resource{}, err
		}
		if len(routers) > 0 || len(routerTables) > 0 {
			regionFlag = true
			resource.VRouters = append(resource.VRouters, routers...)
			resource.RoutingTables = append(resource.RoutingTables, routerTables...)
		}

		networks, subnets, netVinterfaces, err := a.getNetworks(region)
		if err != nil {
			return model.Resource{}, err
		}
		if len(networks) > 0 || len(netVinterfaces) > 0 {
			regionFlag = true
			resource.Networks = append(resource.Networks, networks...)
			resource.Subnets = append(resource.Subnets, subnets...)
			resource.VInterfaces = append(resource.VInterfaces, netVinterfaces...)
		}

		sgs, sgRules, err := a.getSecurityGroups(region)
		if err != nil {
			return model.Resource{}, err
		}
		if len(sgs) > 0 || len(sgRules) > 0 {
			regionFlag = true
			resource.SecurityGroups = append(resource.SecurityGroups, sgs...)
			resource.SecurityGroupRules = append(resource.SecurityGroupRules, sgRules...)
		}

		vinterfaces, ips, vNatRules, err := a.getVInterfacesAndIPs(region)
		if err != nil {
			return model.Resource{}, err
		}
		if len(vinterfaces) > 0 || len(ips) > 0 || len(vNatRules) > 0 {
			regionFlag = true
			resource.VInterfaces = append(resource.VInterfaces, vinterfaces...)
			resource.IPs = append(resource.IPs, ips...)
			resource.NATRules = append(resource.NATRules, vNatRules...)
		}

		vms, vmSGs, err := a.getVMs(region)
		if err != nil {
			return model.Resource{}, err
		}
		if len(vms) > 0 || len(vmSGs) > 0 {
			regionFlag = true
			resource.VMs = append(resource.VMs, vms...)
			resource.VMSecurityGroups = append(resource.VMSecurityGroups, vmSGs...)
		}

		lbs, lbListeners, lbTargetServers, err := a.getLoadBalances(region)
		if err != nil {
			return model.Resource{}, err
		}
		if len(lbs) > 0 || len(lbListeners) > 0 || len(lbTargetServers) > 0 {
			regionFlag = true
			resource.LBs = append(resource.LBs, lbs...)
			resource.LBListeners = append(resource.LBListeners, lbListeners...)
			resource.LBTargetServers = append(resource.LBTargetServers, lbTargetServers...)
		}

		fIPs, err := a.getFloatingIPs()
		if err != nil {
			return model.Resource{}, err
		}
		if len(fIPs) > 0 {
			regionFlag = true
			resource.FloatingIPs = append(resource.FloatingIPs, fIPs...)
		}

		// 附属容器集群
		sDomains, err := a.getSubDomains(region)
		if err != nil {
			return resource, err
		}
		if len(sDomains) > 0 {
			regionFlag = true
			resource.SubDomains = append(resource.SubDomains, sDomains...)
		}

		if regionFlag && a.regionUUID == "" {
			resource.Regions = append(resource.Regions, model.Region{
				Name:   region.name,
				Lcuuid: region.lcuuid,
			})
		}

		azs, err := a.getAZs(region)
		if err != nil {
			return model.Resource{}, err
		}
		if len(azs) > 0 {
			resource.AZs = append(resource.AZs, azs...)
		}

		log.Infof("region (%s) collect complete", region.name)
	}

	return resource, nil
}

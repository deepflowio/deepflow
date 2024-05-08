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

package tencent

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/bitly/go-simplejson"
	cloudcommon "github.com/deepflowio/deepflow/server/controller/cloud/common"
	cloudconfig "github.com/deepflowio/deepflow/server/controller/cloud/config"
	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/statsd"
	"github.com/op/go-logging"
	tcommon "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	thttp "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/http"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/profile"
)

var log = logging.MustGetLogger("cloud.tencent")

const (
	FINANCE_REGION_PROFILE = "金融"
	TENCENT_ENDPOINT       = ".tencentcloudapi.com"
)

var pagesIntControl = map[string]int{
	"DescribeInstances":                                      0,
	"DescribeNatGateways":                                    0,
	"DescribeLoadBalancers":                                  0,
	"DescribeNetworkInterfaces":                              0,
	"DescribeVpcPeerConnections":                             0,
	"DescribeNatGatewayDestinationIpPortTranslationNatRules": 0,
}

type Tencent struct {
	orgID                int
	name                 string
	lcuuid               string
	regionUUID           string
	uuidGenerate         string
	httpTimeout          int
	includeRegions       []string
	excludeRegions       []string
	credential           *tcommon.Credential
	natIDs               []string
	azLcuuidMap          map[string]int
	vpcIDToRegionLcuuid  map[string]string
	publicIPToVinterface map[string]model.VInterface
	cloudStatsd          statsd.CloudStatsd

	debugger *cloudcommon.Debugger
}

type tencentRegion struct {
	finance    bool
	name       string
	lcuuid     string
	regionName string
}

type tencentGressRule struct {
	direction int
	rule      *simplejson.Json
}

type tencentTargetServer struct {
	lcuuid string
	server *simplejson.Json
}

type tencentProtocolPort struct {
	port     string
	protocol string
}

func NewTencent(orgID int, domain mysql.Domain, cfg cloudconfig.CloudConfig) (*Tencent, error) {
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

	return &Tencent{
		// TODO: display_name后期需要修改为uuid_generate
		orgID:          orgID,
		name:           domain.Name,
		lcuuid:         domain.Lcuuid,
		uuidGenerate:   domain.DisplayName,
		excludeRegions: excludeRegions,
		includeRegions: includeRegions,
		httpTimeout:    cfg.HTTPTimeout,
		regionUUID:     config.Get("region_uuid").MustString(),
		credential:     tcommon.NewCredential(secretID, decryptSecretKey),

		// 以下属性为获取资源所用的关联关系
		natIDs:               []string{},
		azLcuuidMap:          map[string]int{},
		vpcIDToRegionLcuuid:  map[string]string{},
		publicIPToVinterface: map[string]model.VInterface{},
		cloudStatsd:          statsd.NewCloudStatsd(),
		debugger:             cloudcommon.NewDebugger(domain.Name),
	}, nil
}

func (t *Tencent) ClearDebugLog() {
	t.debugger.Clear()
}

func (t *Tencent) CheckAuth() error {
	// TODO: 更新验证
	return nil
}

func (t *Tencent) getResponse(service, version, action, regionName, resultKey string, pages bool, params map[string]interface{}, filters ...map[string]interface{}) ([]*simplejson.Json, error) {
	var responses []*simplejson.Json
	var err error
	var totalCount int

	startTime := time.Now()
	// tencent api 3.0 limit max 100
	offset, limit := 0, 100
	// simple config
	cpf := profile.NewClientProfile()
	// sdk debug
	// cpf.Debug = true
	cpf.HttpProfile.Endpoint = service + ".tencentcloudapi.com"
	cpf.HttpProfile.ReqMethod = "POST"
	cpf.HttpProfile.ReqTimeout = t.httpTimeout
	cpf.NetworkFailureMaxRetries = 1
	cpf.NetworkFailureRetryDuration = profile.ExponentialBackoff
	cpf.RateLimitExceededMaxRetries = 1
	cpf.RateLimitExceededRetryDuration = profile.ExponentialBackoff
	// create common client
	client := tcommon.NewCommonClient(t.credential, regionName, cpf)

	// create common request
	request := thttp.NewCommonRequest(service, version, action)

	// SetActionParameters
	body := map[string]interface{}{}
	for pKey, pValue := range params {
		body[pKey] = pValue
	}
	if len(filters) > 0 {
		// filters example:
		// body["Filters"] = []map[string]interface{}{
		// 	{
		// 		"Name":   "service-template-group-id",
		// 		"Values": []string{"ppmg-e6dy460g"},
		// 	},
		// }
		body["Filters"] = filters
	}

	for {
		if pages {
			if _, ok := pagesIntControl[action]; ok {
				body["Limit"] = limit
				body["Offset"] = offset
			} else {
				body["Limit"] = strconv.Itoa(limit)
				body["Offset"] = strconv.Itoa(offset)
			}
		}

		// set action request params
		err = request.SetActionParameters(body)
		if err != nil {
			return []*simplejson.Json{}, err
		}

		// create common response
		response := thttp.NewCommonResponse()

		// do request
		err = client.Send(request, response)
		if err != nil {
			return []*simplejson.Json{}, err
		}

		respJson, err := simplejson.NewJson(response.GetBody())
		if err != nil {
			return []*simplejson.Json{}, err
		}

		resultSet, ok := respJson.Get("Response").CheckGet(resultKey)
		if !ok {
			errMsg := fmt.Sprintf("request tencent action (%s) exception: not found result key (%s)", action, resultKey)
			return []*simplejson.Json{}, errors.New(errMsg)
		}

		if len(resultSet.MustMap()) > 0 {
			responses = append(responses, resultSet)
			totalCount = 1
		} else {
			for r := range resultSet.MustArray() {
				responses = append(responses, resultSet.GetIndex(r))
			}
			totalCount = len(resultSet.MustArray())
		}

		if !pages {
			break
		}

		totalCount = respJson.Get("Response").Get("TotalCount").MustInt()
		offset += limit
		if totalCount <= offset {
			break
		}
	}

	log.Debugf("request tencent action (%s): total count is (%v)", action, totalCount)

	if !strings.Contains(common.CloudMonitorExceptionAPI[common.TENCENT_EN], action) {
		t.cloudStatsd.RefreshAPIMoniter(action, totalCount, startTime)
	}
	t.debugger.WriteJson(resultKey, regionName, responses)
	return responses, nil
}

func (t *Tencent) checkRequiredAttributes(json *simplejson.Json, attributes []string) bool {
	for _, attribute := range attributes {
		if _, ok := json.CheckGet(attribute); !ok {
			log.Warningf("get attribute (%s) failed", attribute)
			return false
		}
	}
	return true
}

func (t *Tencent) getRegionLcuuid(lcuuid string) string {
	if t.regionUUID != "" {
		return t.regionUUID
	}
	return lcuuid
}

func (t *Tencent) GetStatter() statsd.StatsdStatter {
	globalTags := map[string]string{
		"domain_name": t.name,
		"domain":      t.lcuuid,
		"platform":    common.TENCENT_EN,
	}

	return statsd.StatsdStatter{
		GlobalTags: globalTags,
		Element:    statsd.GetCloudStatsd(t.cloudStatsd),
	}
}

func (t *Tencent) GetCloudData() (model.Resource, error) {
	var resource model.Resource
	// 任务循环执行的是同一个实例，所以这里要对关联关系进行初始化
	t.natIDs = []string{}
	t.cloudStatsd = statsd.NewCloudStatsd()
	t.vpcIDToRegionLcuuid = map[string]string{}
	t.publicIPToVinterface = map[string]model.VInterface{}

	regionList, err := t.getRegions()
	if err != nil {
		return model.Resource{}, err
	}
	for _, region := range regionList {
		log.Infof("region (%s) collect starting", region.regionName)

		regionFlag := false
		t.azLcuuidMap = map[string]int{}

		vpcs, err := t.getVPCs(region)
		if err != nil {
			return model.Resource{}, err
		}
		if len(vpcs) > 0 {
			regionFlag = true
			resource.VPCs = append(resource.VPCs, vpcs...)
		}

		natGateways, natVinterfaces, natIPs, err := t.getNatGateways(region)
		if err != nil {
			return model.Resource{}, err
		}
		if len(natGateways) > 0 || len(natVinterfaces) > 0 || len(natIPs) > 0 {
			regionFlag = true
			resource.NATGateways = append(resource.NATGateways, natGateways...)
			resource.VInterfaces = append(resource.VInterfaces, natVinterfaces...)
			resource.IPs = append(resource.IPs, natIPs...)
		}

		natRules, err := t.getNatRules(region)
		if err != nil {
			return model.Resource{}, err
		}
		if len(natRules) > 0 {
			regionFlag = true
			resource.NATRules = append(resource.NATRules, natRules...)

		}

		sgs, sgRules, err := t.getSecurityGroups(region)
		if err != nil {
			return model.Resource{}, err
		}
		if len(sgs) > 0 || len(sgRules) > 0 {
			regionFlag = true
			resource.SecurityGroups = append(resource.SecurityGroups, sgs...)
			resource.SecurityGroupRules = append(resource.SecurityGroupRules, sgRules...)
		}

		routers, routerTables, err := t.getRouterAndTables(region)
		if err != nil {
			return model.Resource{}, err
		}
		if len(routers) > 0 || len(routerTables) > 0 {
			regionFlag = true
			resource.VRouters = append(resource.VRouters, routers...)
			resource.RoutingTables = append(resource.RoutingTables, routerTables...)
		}

		networks, subnets, netVinterfaces, err := t.getNetworks(region)
		if err != nil {
			return model.Resource{}, err
		}
		if len(networks) > 0 || len(subnets) > 0 || len(netVinterfaces) > 0 {
			regionFlag = true
			resource.Networks = append(resource.Networks, networks...)
			resource.Subnets = append(resource.Subnets, subnets...)
			resource.VInterfaces = append(resource.VInterfaces, netVinterfaces...)
		}

		vms, vmSGs, err := t.getVMs(region)
		if err != nil {
			return model.Resource{}, err
		}
		if len(vms) > 0 || len(vmSGs) > 0 {
			regionFlag = true
			resource.VMs = append(resource.VMs, vms...)
			resource.VMSecurityGroups = append(resource.VMSecurityGroups, vmSGs...)
		}

		vinterfaces, ips, vNatRules, err := t.getVInterfacesAndIPs(region)
		if err != nil {
			return model.Resource{}, err
		}
		if len(vinterfaces) > 0 || len(ips) > 0 || len(vNatRules) > 0 {
			regionFlag = true
			resource.VInterfaces = append(resource.VInterfaces, vinterfaces...)
			resource.IPs = append(resource.IPs, ips...)
			resource.NATRules = append(resource.NATRules, vNatRules...)
		}

		fIPs, err := t.getFloatingIPs()
		if err != nil {
			return model.Resource{}, err
		}
		if len(fIPs) > 0 {
			regionFlag = true
			resource.FloatingIPs = append(resource.FloatingIPs, fIPs...)
		}

		lbs, lbListeners, lbTargetServers, lbVinterfaces, lbIPs, err := t.getLoadBalances(region)
		if err != nil {
			return model.Resource{}, err
		}
		if len(lbs) > 0 || len(lbListeners) > 0 || len(lbTargetServers) > 0 {
			regionFlag = true
			resource.LBs = append(resource.LBs, lbs...)
			resource.LBListeners = append(resource.LBListeners, lbListeners...)
			resource.LBTargetServers = append(resource.LBTargetServers, lbTargetServers...)
			resource.VInterfaces = append(resource.VInterfaces, lbVinterfaces...)
			resource.IPs = append(resource.IPs, lbIPs...)
		}

		if regionFlag && t.regionUUID == "" {
			resource.Regions = append(resource.Regions, model.Region{
				Name:   region.regionName,
				Lcuuid: region.lcuuid,
			})
		}

		azs, err := t.getAZs(region)
		if err != nil {
			return model.Resource{}, err
		}
		if len(azs) > 0 {
			resource.AZs = append(resource.AZs, azs...)
		}

		log.Infof("region (%s) collect complete", region.regionName)
	}

	// TODO: 因为腾讯云服务器 API 3.0 版本暂未支持对等连接的获取，这里等待后续支持
	// peerConnections := []model.PeerConnection{}
	// for _, r := range regionList {
	// 	pConnections, err := t.getPeerConnections(r, peerConnections)
	// 	if err != nil {
	// 		return model.Resource{}, err
	// 	}
	// 	peerConnections = append(peerConnections, pConnections...)
	// }
	// resource.PeerConnections = peerConnections

	t.cloudStatsd.ResCount = statsd.GetResCount(resource)
	statsd.MetaStatsd.RegisterStatsdTable(t)
	t.debugger.Refresh()
	return resource, nil
}

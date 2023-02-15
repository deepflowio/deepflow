/*
 * Copyright (c) 2022 Yunshan Networks
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

package qingcloud

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	b64 "encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	simplejson "github.com/bitly/go-simplejson"
	logging "github.com/op/go-logging"

	cloudcommon "github.com/deepflowio/deepflow/server/controller/cloud/common"
	cloudconfig "github.com/deepflowio/deepflow/server/controller/cloud/config"
	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/statsd"
)

var log = logging.MustGetLogger("cloud.qingcloud")

type QingCloud struct {
	Uuid          string
	UuidGenerate  string
	Name          string
	RegionUuid    string
	url           string
	secretID      string
	secretKey     string
	isPublicCloud bool
	httpTimeout   int

	defaultVPCName   string
	defaultVxnetName string

	RegionIdToLcuuid           map[string]string
	regionIdToDefaultVPCLcuuid map[string]string
	regionIdToVxnetIds         map[string][]string
	ZoneNames                  []string
	vpcIdToCidr                map[string]string
	vxnetIdToVPCLcuuid         map[string]string
	vxnetIdToSubnetLcuuid      map[string]string
	defaultVxnetIDs            []string
	HostNameToIP               map[string]string
	vmIdToVPCLcuuid            map[string]string
	// 以下两个字段的作用：消除公有云的无资源的区域和可用区
	regionLcuuidToResourceNum map[string]int
	azLcuuidToResourceNum     map[string]int

	// statsd monitor
	cloudStatsd statsd.CloudStatsd

	debugger *cloudcommon.Debugger
}

func NewQingCloud(domain mysql.Domain, cfg cloudconfig.CloudConfig) (*QingCloud, error) {
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
	log.Debugf(
		"domain (%s) secret_key: %s, decrypt secret_key: %s",
		domain.Name, secretKey, decryptSecretKey,
	)

	url := config.Get("url").MustString()
	if url == "" {
		url = "https://api.qingcloud.com"
	}

	return &QingCloud{
		Uuid: domain.Lcuuid,
		// TODO: display_name后期需要修改为uuid_generate
		UuidGenerate:  domain.DisplayName,
		Name:          domain.Name,
		RegionUuid:    config.Get("region_uuid").MustString(),
		url:           url,
		secretID:      secretID,
		secretKey:     decryptSecretKey,
		isPublicCloud: domain.Type == common.QINGCLOUD,
		httpTimeout:   cfg.HTTPTimeout,

		defaultVPCName:            domain.Name + "_default_vpc",
		defaultVxnetName:          "vxnet-0",
		regionLcuuidToResourceNum: make(map[string]int),
		azLcuuidToResourceNum:     make(map[string]int),
		cloudStatsd: statsd.CloudStatsd{
			APICount: make(map[string][]int),
			APICost:  make(map[string][]int),
			ResCount: make(map[string][]int),
		},

		debugger: cloudcommon.NewDebugger(domain.Name),
	}, nil
}

func (q *QingCloud) ClearDebugLog() {
	q.debugger.Clear()
}

func (q *QingCloud) GenSignature(signURL, secret string) string {
	key := []byte(secret)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(signURL))
	sEnc := b64.StdEncoding.EncodeToString(mac.Sum(nil))
	strings.Replace(sEnc, " ", "+", -1)
	return url.QueryEscape(sEnc)
}

func (q *QingCloud) getURL(action string, kwargs []*Param, offset, limit int) string {
	params := Params{
		{"access_key_id", q.secretID},
		{"action", action},
		{"limit", limit},
		{"offset", offset},
		{"signature_method", "HmacSHA256"},
		{"signature_version", 1},
		{"time_stamp", time.Now().UTC().Format("2006-01-02T15:04:05Z")},
		{"version", 1},
	}

	if action != "DescribeClusters" && action != "DescribeLoadBalancerListeners" &&
		action != "DescribeRouters" {
		params = append(params, &Param{"verbose", 2})
	}

	for _, args := range kwargs {
		params = append(params, args)
	}

	// 参数排序
	sort.Sort(params)
	// 对特定的 + 进行转义
	// 生成url中的参数
	urlParams := []string{}
	for _, v := range params {
		if str, ok := v.Value.(string); ok {
			v.Value = strings.Replace(url.QueryEscape(str), "+", "%20", -1)
		}
		urlParams = append(urlParams, fmt.Sprintf("%v=%v", v.Name, v.Value))
	}
	url := strings.Join(urlParams, "&")

	// 生成签名
	signURL := "GET\n/iaas/\n" + url
	signature := q.GenSignature(signURL, q.secretKey)
	return fmt.Sprintf("%s/iaas/?%v&signature=%v", q.url, url, signature)
}

func (q *QingCloud) GetResponse(action string, resultKey string, kwargs []*Param) ([]*simplejson.Json, error) {
	var response []*simplejson.Json
	startTime := time.Now()
	count := 0

	offset, limit := 0, 100
	for {
		url := q.getURL(action, kwargs, offset, limit)
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			log.Errorf("new (%s) request failed, (%v)", action, err)
			return nil, err
		}

		client := &http.Client{
			Timeout: time.Second * time.Duration(q.httpTimeout),
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		}
		resp, err := client.Do(req)
		if err != nil {
			log.Errorf("curl (%s) failed, (%v)", url, err)
			return nil, err
		} else if resp.StatusCode != http.StatusOK {
			log.Errorf("curl (%s) failed, (%v)", url, resp)
			defer resp.Body.Close()
			return nil, errors.New(fmt.Sprintf("curl (%s) failed, (%v)", url, resp))
		}
		defer resp.Body.Close()

		respBytes, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Errorf("read (%s) response failed, (%v)", action, err)
			return nil, err
		}
		respJson, err := simplejson.NewJson(respBytes)
		if err != nil {
			log.Errorf("parse (%s) response failed, (%v)", action, err)
			return nil, err
		}
		if curResp, ok := respJson.CheckGet(resultKey); ok {
			response = append(response, curResp)
			curRespLens := len(curResp.MustArray())
			count += curRespLens
			if curRespLens < limit {
				break
			}
			offset += limit
		} else {
			err := errors.New(fmt.Sprintf("get (%s) response (%s) failed, (%v)", action, resultKey, respJson))
			log.Error(respJson)
			return nil, err
		}
	}

	// qingcloud has a unified call API，so this could be very convenient
	if !strings.Contains(common.CloudMonitorExceptionAPI[common.QINGCLOUD_EN], action) {
		cost := time.Now().Sub(startTime).Milliseconds()
		if _, ok := q.cloudStatsd.APICost[action]; !ok {
			q.cloudStatsd.APICost[action] = []int{int(cost)}
		} else {
			q.cloudStatsd.APICost[action] = append(q.cloudStatsd.APICost[action], int(cost))
		}
		if _, ok := q.cloudStatsd.APICount[action]; !ok {
			q.cloudStatsd.APICount[action] = []int{count}
		} else {
			q.cloudStatsd.APICount[action] = append(q.cloudStatsd.APICount[action], count)
		}
	}
	q.debugger.WriteJson(resultKey, " ", response)
	return response, nil
}

func (q *QingCloud) GetRegionLcuuid(lcuuid string) string {
	if q.RegionUuid != "" {
		return q.RegionUuid
	} else {
		return lcuuid
	}
}

func (q *QingCloud) CheckRequiredAttributes(json *simplejson.Json, attributes []string) error {
	for _, attribute := range attributes {
		if _, ok := json.CheckGet(attribute); !ok {
			log.Debugf("get attribute (%s) failed", attribute)
			return errors.New(fmt.Sprintf("get attribute (%s) failed", attribute))
		}
	}
	return nil
}

func (q *QingCloud) CheckAuth() error {
	_, _, err := q.getRegionAndAZs()
	return err
}

func (q *QingCloud) GetStatter() statsd.StatsdStatter {
	globalTags := map[string]string{
		"domain_name": q.Name,
		"domain":      q.Uuid,
		"platform":    common.QINGCLOUD_EN,
	}

	return statsd.StatsdStatter{
		GlobalTags: globalTags,
		Element:    statsd.GetCloudStatsd(q.cloudStatsd),
	}
}

func (q *QingCloud) GetCloudData() (model.Resource, error) {
	var resource model.Resource
	// every tasks must init
	q.cloudStatsd.APICount = map[string][]int{}
	q.cloudStatsd.APICost = map[string][]int{}
	q.cloudStatsd.ResCount = map[string][]int{}

	// 区域和可用区
	regions, azs, err := q.getRegionAndAZs()
	if err != nil {
		log.Error("get region and az data failed")
		return resource, err
	}

	// VPC
	vpcs, err := q.GetVPCs()
	if err != nil {
		log.Error("get vpc data failed")
		return resource, err
	}

	// 子网及网段
	networks, subnets, err := q.GetNetworks()
	if err != nil {
		log.Error("get network and subnet data failed")
		return resource, err
	}

	// 虚拟机及关联安全组信息
	vms, vmSecurityGroups, tmpSubnets, err := q.GetVMs()
	if err != nil {
		log.Error("get vm data failed")
		return resource, err
	}
	subnets = append(subnets, tmpSubnets...)

	// 虚拟机网卡及IP信息
	vinterfaces, ips, err := q.GetVMNics()
	if err != nil {
		log.Error("get vm nic data failed")
		return resource, err
	}

	// 安全组及规则
	securityGroups, securityGroupRules, err := q.GetSecurityGroups()
	if err != nil {
		log.Error("get security_group and rule data failed")
		return resource, err
	}

	// 路由表及规则
	vrouters, routingTables, tmpVInterfaces, tmpIPs, err := q.GetRouterAndTables()
	if err != nil {
		log.Error("get router and rule data failed")
		return resource, err
	}
	vinterfaces = append(vinterfaces, tmpVInterfaces...)
	ips = append(ips, tmpIPs...)

	// NAT网关
	natGateways, tmpVInterfaces, tmpIPs, natVMConnections, err := q.GetNATGateways()
	if err != nil {
		log.Error("get nat_gateway data failed")
		return resource, err
	}
	vinterfaces = append(vinterfaces, tmpVInterfaces...)
	ips = append(ips, tmpIPs...)

	// 负载均衡器及规则
	lbs, lbListeners, lbTargetServers, tmpVInterfaces, tmpIPs, lbVMConnections, err := q.GetLoadBalances()
	if err != nil {
		log.Error("get load_balance data failed")
		return resource, err
	}
	vinterfaces = append(vinterfaces, tmpVInterfaces...)
	ips = append(ips, tmpIPs...)

	// FloatingIP
	tmpVInterfaces, tmpIPs, floatingIPs, err := q.GetFloatingIPs()
	if err != nil {
		log.Error("get floating_ip data failed")
		return resource, err
	}
	vinterfaces = append(vinterfaces, tmpVInterfaces...)
	ips = append(ips, tmpIPs...)

	// 附属容器集群
	subDomains, err := q.GetSubDomains()
	if err != nil {
		log.Error("get sub_domain data failed")
		return resource, err
	}

	resource.Regions = cloudcommon.EliminateEmptyRegions(regions, q.regionLcuuidToResourceNum)
	resource.AZs = cloudcommon.EliminateEmptyAZs(azs, q.azLcuuidToResourceNum)
	resource.VPCs = vpcs
	resource.Networks = networks
	resource.Subnets = subnets
	resource.VMs = vms
	resource.VMSecurityGroups = vmSecurityGroups
	resource.VInterfaces = vinterfaces
	resource.IPs = ips
	resource.SecurityGroups = securityGroups
	resource.SecurityGroupRules = securityGroupRules
	resource.VRouters = vrouters
	resource.RoutingTables = routingTables
	resource.NATGateways = natGateways
	resource.NATVMConnections = natVMConnections
	resource.LBs = lbs
	resource.LBVMConnections = lbVMConnections
	resource.LBListeners = lbListeners
	resource.LBTargetServers = lbTargetServers
	resource.LBVMConnections = lbVMConnections
	resource.FloatingIPs = floatingIPs
	resource.SubDomains = subDomains

	// write monitor
	q.cloudStatsd.ResCount = statsd.GetResCount(resource)
	// register statsd
	statsd.MetaStatsd.RegisterStatsdTable(q)
	q.debugger.Refresh()
	return resource, nil
}

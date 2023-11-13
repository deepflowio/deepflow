/*
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

package huawei

import (
	"fmt"
	"time"

	"github.com/bitly/go-simplejson"
	"github.com/op/go-logging"

	cloudcommon "github.com/deepflowio/deepflow/server/controller/cloud/common"
	"github.com/deepflowio/deepflow/server/controller/cloud/config"
	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/statsd"
)

var log = logging.MustGetLogger("cloud.huawei")

type HuaWei struct {
	lcuuid          string
	lcuuidGenerate  string
	name            string
	httpTimeout     int
	config          *Config
	projectTokenMap map[Project]*Token // 缓存各项目的token
	toolDataSet     *ToolDataSet       // 处理资源数据时，构建的需要提供给其他资源使用的工具数据
	cloudStatsd     statsd.CloudStatsd // 性能监控
	debugger        *cloudcommon.Debugger
}

func NewHuaWei(domain mysql.Domain, globalCloudCfg config.CloudConfig) (*HuaWei, error) {
	conf := &Config{}
	err := conf.LoadFromString(domain.Config)
	if err != nil {
		return nil, err
	}
	return &HuaWei{
		lcuuid: domain.Lcuuid,
		// TODO: display_name后期需要修改为uuid_generate
		lcuuidGenerate:  domain.DisplayName,
		name:            domain.Name,
		httpTimeout:     globalCloudCfg.HTTPTimeout,
		config:          conf,
		projectTokenMap: make(map[Project]*Token),
		debugger:        cloudcommon.NewDebugger(domain.Name),
	}, nil
}

func (h *HuaWei) ClearDebugLog() {
	h.debugger.Clear()
}

func (h *HuaWei) CheckAuth() error {
	_, err := h.createToken(h.config.ProjectName, h.config.ProjectID)
	return err
}

func (h *HuaWei) GetCloudData() (model.Resource, error) {
	h.cloudStatsd = statsd.NewCloudStatsd()
	h.toolDataSet = NewToolDataSet()
	var resource model.Resource
	err := h.refreshTokenMap()
	if err != nil {
		return resource, err
	}

	regions, err := h.getRegions()
	if err != nil {
		return resource, err
	}

	azs, err := h.getAZs()
	if err != nil {
		return resource, err
	}

	peers, err := h.getPeerConnections()
	if err != nil {
		return resource, err
	}
	resource.PeerConnections = append(resource.PeerConnections, peers...)

	networks, subnets, vifs, err := h.getNetworks()
	if err != nil {
		return resource, err
	}
	resource.Networks = append(resource.Networks, networks...)
	resource.Subnets = append(resource.Subnets, subnets...)
	resource.VInterfaces = append(resource.VInterfaces, vifs...)

	dhcps, vifs, ips, fIPs, natRules, err := h.getVInterfaces()
	if err != nil {
		return resource, err
	}
	resource.DHCPPorts = append(resource.DHCPPorts, dhcps...)
	resource.VInterfaces = append(resource.VInterfaces, vifs...)
	resource.IPs = append(resource.IPs, ips...)
	resource.FloatingIPs = append(resource.FloatingIPs, fIPs...)
	resource.NATRules = append(resource.NATRules, natRules...)

	vpcs, vrouters, routingTables, err := h.getVPCs()
	if err != nil {
		return resource, err
	}
	resource.VPCs = append(resource.VPCs, vpcs...)
	resource.VRouters = append(resource.VRouters, vrouters...)
	resource.RoutingTables = append(resource.RoutingTables, routingTables...)

	sgs, sgRules, err := h.getSecurityGroups()
	if err != nil {
		return resource, err
	}
	resource.SecurityGroups = append(resource.SecurityGroups, sgs...)
	resource.SecurityGroupRules = append(resource.SecurityGroupRules, sgRules...)

	vms, vmSGs, vifs, ips, err := h.getVMs()
	if err != nil {
		return resource, err
	}
	resource.VMs = append(resource.VMs, vms...)
	resource.VMSecurityGroups = append(resource.VMSecurityGroups, vmSGs...)
	resource.VInterfaces = append(resource.VInterfaces, vifs...)
	resource.IPs = append(resource.IPs, ips...)

	ngws, natRules, vifs, ips, err := h.getNATGateways()
	if err != nil {
		return resource, err
	}
	resource.NATGateways = append(resource.NATGateways, ngws...)
	resource.NATRules = append(resource.NATRules, natRules...)
	resource.VInterfaces = append(resource.VInterfaces, vifs...)
	resource.IPs = append(resource.IPs, ips...)

	lbs, listeners, targetServers, vifs, ips, err := h.getLBs()
	if err != nil {
		return resource, err
	}
	resource.LBs = append(resource.LBs, lbs...)
	resource.LBListeners = append(resource.LBListeners, listeners...)
	resource.LBTargetServers = append(resource.LBTargetServers, targetServers...)
	resource.VInterfaces = append(resource.VInterfaces, vifs...)
	resource.IPs = append(resource.IPs, ips...)

	log.Debugf("region resource num info: %v", h.toolDataSet.regionLcuuidToResourceNum)
	log.Debugf("az resource num info: %v", h.toolDataSet.azLcuuidToResourceNum)
	resource.Regions = cloudcommon.EliminateEmptyRegions(regions, h.toolDataSet.regionLcuuidToResourceNum)
	resource.AZs = cloudcommon.EliminateEmptyAZs(azs, h.toolDataSet.azLcuuidToResourceNum)

	h.cloudStatsd.ResCount = statsd.GetResCount(resource)
	statsd.MetaStatsd.RegisterStatsdTable(h)

	h.debugger.Refresh()
	return resource, nil
}

func (h *HuaWei) GetStatter() statsd.StatsdStatter {
	globalTags := map[string]string{
		"domain_name": h.name,
		"domain":      h.lcuuid,
		"platform":    common.HUAWEI_EN,
	}

	return statsd.StatsdStatter{
		GlobalTags: globalTags,
		Element:    statsd.GetCloudStatsd(h.cloudStatsd),
	}
}

func (h *HuaWei) getRawData(ctx rawDataGetContext) (jsonList []*simplejson.Json, err error) {
	statsdAPIStartTime := time.Now()
	statsdAPIDataCount := 0

	if ctx.pageQuery {
		var marker string
		limit := 50
		baseURL := ctx.url
		for {
			if marker == "" {
				ctx.url = fmt.Sprintf("%s?limit=%d", baseURL, limit)
			} else {
				ctx.url = fmt.Sprintf("%s?limit=%d&marker=%s", baseURL, limit, marker)
			}
			resp, err := RequestGet(ctx.url, ctx.token, time.Duration(h.httpTimeout), ctx.additionalHeaders)
			if err != nil {
				return []*simplejson.Json{}, err
			}

			jData := resp.Get(ctx.resultKey)
			curCount := len(jData.MustArray())
			for i := range jData.MustArray() {
				jsonList = append(jsonList, jData.GetIndex(i))
				if i == curCount-1 {
					marker = jData.GetIndex(i).Get("id").MustString()
				}
			}
			statsdAPIDataCount += curCount
			// response data is not incomplete when getting ports by page,
			// for example: ports total count is 128, set limit to 50 may get only 38 items.
			// so checking response count is 0 is used as break sign.
			if curCount == 0 {
				break
			}
		}
	} else {
		resp, err := RequestGet(ctx.url, ctx.token, time.Duration(h.httpTimeout), ctx.additionalHeaders)
		if err != nil {
			return []*simplejson.Json{}, err
		}
		jData := resp.Get(ctx.resultKey)
		for i := range jData.MustArray() {
			jsonList = append(jsonList, jData.GetIndex(i))
		}
	}

	h.cloudStatsd.RefreshAPIMoniter(ctx.resultKey, statsdAPIDataCount, statsdAPIStartTime)

	h.debugger.WriteJson(ctx.resultKey, ctx.url, jsonList)
	return
}

type rawDataGetContext struct {
	url               string
	token             string
	pageQuery         bool
	resultKey         string
	additionalHeaders map[string]string
}

func newRawDataGetContext(url, token, resultKey string, pageQuery bool) rawDataGetContext {
	return rawDataGetContext{
		url:               url,
		token:             token,
		resultKey:         resultKey,
		pageQuery:         pageQuery,
		additionalHeaders: make(map[string]string),
	}
}

func (c rawDataGetContext) addHeader(key, value string) rawDataGetContext {
	c.additionalHeaders[key] = value
	return c
}

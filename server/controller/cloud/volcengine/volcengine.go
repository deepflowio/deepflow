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

package volcengine

import (
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/bitly/go-simplejson"
	cloudconfig "github.com/deepflowio/deepflow/server/controller/cloud/config"
	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/op/go-logging"
	"github.com/volcengine/volcengine-go-sdk/volcengine"
	"github.com/volcengine/volcengine-go-sdk/volcengine/credentials"
	"github.com/volcengine/volcengine-go-sdk/volcengine/session"
)

var log = logging.MustGetLogger("cloud.volcengine")

var vmStates = map[string]int{
	"RUNNING": common.VM_STATE_RUNNING,
	"STOPPED": common.VM_STATE_STOPPED,
}

var rdsStates = map[string]int{
	"Running":   common.RDS_STATE_RUNNING,
	"Restoring": common.RDS_STATE_RESTORING,
}

var rdsSeries = map[string]int{
	"HA":      common.RDS_SERIES_HA,
	"Cluster": common.RDS_SERIES_HA,
	"Basic":   common.RDS_SERIES_BASIC,
}

var rdsMSSQLModel = map[string]int{
	"Primary":  common.RDS_MODEL_PRIMARY,
	"ReadOnly": common.RDS_MODEL_READONLY,
}

const (
	DEFAULT_REGION = "cn-beijing"
)

type VolcEngine struct {
	orgID          int
	teamID         int
	name           string
	lcuuid         string
	regionUUID     string
	uuidGenerate   string
	secretID       string
	secretKey      string
	includeRegions []string
	excludeRegions []string
	azLcuuids      map[string]bool
	httpClient     *http.Client
}

func NewVolcEngine(orgID int, domain mysql.Domain, cfg cloudconfig.CloudConfig) (*VolcEngine, error) {
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

	includeRegionsStr := config.Get("include_regions").MustString()
	includeRegions := []string{}
	if includeRegionsStr != "" {
		includeRegions = strings.Split(includeRegionsStr, ",")
	}
	sort.Strings(includeRegions)

	excludeRegionsStr := config.Get("exclude_regions").MustString()
	excludeRegions := []string{}
	if excludeRegionsStr != "" {
		excludeRegions = strings.Split(excludeRegionsStr, ",")
	}
	sort.Strings(excludeRegions)

	regionUUID := config.Get("region_uuid").MustString()
	if regionUUID == "" {
		regionUUID = common.DEFAULT_REGION
	}

	return &VolcEngine{
		orgID:          orgID,
		teamID:         domain.TeamID,
		name:           domain.Name,
		lcuuid:         domain.Lcuuid,
		uuidGenerate:   domain.DisplayName,
		regionUUID:     regionUUID,
		secretID:       secretID,
		secretKey:      decryptSecretKey,
		excludeRegions: excludeRegions,
		includeRegions: includeRegions,
		azLcuuids:      map[string]bool{},
		httpClient: &http.Client{
			Timeout: time.Duration(cfg.HTTPTimeout) * time.Second,
		},
	}, nil
}

func (v *VolcEngine) CheckAuth() error {
	return nil
}

func (v *VolcEngine) ClearDebugLog() {}

func (v *VolcEngine) getStringPointerValue(pString *string) string {
	if pString == nil {
		return ""
	}
	return *pString
}

func (v *VolcEngine) GetCloudData() (model.Resource, error) {
	var resource model.Resource

	regionIDs, err := v.getRegions()
	if err != nil {
		return model.Resource{}, err
	}

	for _, regionID := range regionIDs {
		log.Infof("region (%s) collect starting", regionID)

		v.azLcuuids = map[string]bool{}

		config := volcengine.NewConfig().
			WithCredentials(credentials.NewStaticCredentials(v.secretID, v.secretKey, "")).
			WithRegion(regionID).
			WithHTTPClient(v.httpClient)

		sess, err := session.NewSession(config)
		if err != nil {
			log.Errorf("get volcengine session error: (%s)", err.Error())
			return model.Resource{}, err
		}

		vpcs, err := v.getVPCs(sess)
		if err != nil {
			return model.Resource{}, err
		}
		resource.VPCs = append(resource.VPCs, vpcs...)

		networks, subnets, err := v.getNetworks(sess)
		if err != nil {
			return model.Resource{}, err
		}
		resource.Networks = append(resource.Networks, networks...)
		resource.Subnets = append(resource.Subnets, subnets...)

		vms, vmVInterfaces, vmIPs, err := v.getVMs(sess)
		if err != nil {
			return model.Resource{}, err
		}
		resource.VMs = append(resource.VMs, vms...)
		resource.VInterfaces = append(resource.VInterfaces, vmVInterfaces...)
		resource.IPs = append(resource.IPs, vmIPs...)

		cens, err := v.getCens(sess)
		if err != nil {
			return model.Resource{}, err
		}
		resource.CENs = append(resource.CENs, cens...)

		rdsInstances, rdsVInterfaces, rdsIPs, err := v.getRDSInstances(sess)
		if err != nil {
			return model.Resource{}, err
		}
		resource.RDSInstances = append(resource.RDSInstances, rdsInstances...)
		resource.VInterfaces = append(resource.VInterfaces, rdsVInterfaces...)
		resource.IPs = append(resource.IPs, rdsIPs...)

		redisInstances, redisVInterfaces, redisIPs, err := v.getRedisInstances(regionID, sess)
		if err != nil {
			return model.Resource{}, err
		}
		resource.RedisInstances = append(resource.RedisInstances, redisInstances...)
		resource.VInterfaces = append(resource.VInterfaces, redisVInterfaces...)
		resource.IPs = append(resource.IPs, redisIPs...)

		resource.SubDomains = append(resource.SubDomains, v.getSubDomains(sess)...)

		azs, err := v.getAZs(sess)
		if err != nil {
			return model.Resource{}, err
		}
		resource.AZs = append(resource.AZs, azs...)

		log.Infof("region (%s) collect complete", regionID)
	}
	return resource, nil
}

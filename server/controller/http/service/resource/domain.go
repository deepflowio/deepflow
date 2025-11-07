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

package resource

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/bitly/go-simplejson"
	uuid "github.com/satori/go.uuid"
	"gorm.io/gorm/clause"

	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/config"
	mysql "github.com/deepflowio/deepflow/server/controller/db/metadb"
	mysqlcommon "github.com/deepflowio/deepflow/server/controller/db/metadb/common"
	mysqlmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	httpcommon "github.com/deepflowio/deepflow/server/controller/http/common"
	"github.com/deepflowio/deepflow/server/controller/http/common/response"
	svc "github.com/deepflowio/deepflow/server/controller/http/service"
	"github.com/deepflowio/deepflow/server/controller/model"
	"github.com/deepflowio/deepflow/server/controller/recorder/constraint"
	"github.com/deepflowio/deepflow/server/controller/recorder/pubsub/message"
	"github.com/deepflowio/deepflow/server/controller/tagrecorder"
	"github.com/deepflowio/deepflow/server/libs/logger"
)

var log = logger.MustGetLogger("service.resource")

var DOMAIN_PASSWORD_KEYS = map[string]bool{
	"admin_password":      false,
	"secret_key":          false,
	"client_secret":       false,
	"password":            false,
	"boss_secret_key":     false,
	"manage_one_password": false,
	"token":               false,
	"app_secret":          false,
}

type ResourceCount struct {
	Domain string
	Count  int
}

func getGrpcServerAndPort(db *mysql.DB, controllerIP string, cfg *config.ControllerConfig) (string, string) {
	// get local controller ip
	localControllerIP := os.Getenv(common.NODE_IP_KEY)
	if localControllerIP == "" {
		log.Errorf("get env(%s) data failed", common.NODE_IP_KEY)
		return controllerIP, cfg.GrpcNodePort
	}

	// get controller region
	var localAZConn mysqlmodel.AZControllerConnection
	var localRegion string
	if ret := db.Where("controller_ip = ?", localControllerIP).First(&localAZConn); ret.Error == nil {
		localRegion = localAZConn.Region
	}

	var azConn mysqlmodel.AZControllerConnection
	var region string
	if ret := db.Where("controller_ip = ?", controllerIP).First(&azConn); ret.Error == nil {
		region = azConn.Region
	}

	// return ip and grpc_node_port if local_region != regionToAZLcuuids
	// return pod_ip and grpc_port if local_region == region
	if region != localRegion {
		return controllerIP, cfg.GrpcNodePort
	} else {
		localPodIP := os.Getenv(common.POD_IP_KEY)
		if localPodIP == "" {
			log.Errorf("get env(%s) data failed", common.POD_IP_KEY)
			return controllerIP, cfg.GrpcNodePort
		}
		return localPodIP, cfg.GrpcPort
	}
}

func UnscopedSelectGroupByFind[T any, R any](db *mysql.DB, columns []string, groupBy string) ([]R, error) {
	var results []R

	// 构建查询
	query := db.Model(new(T)).Select(columns).Unscoped()

	// 如果需要分组
	if groupBy != "" {
		query = query.Group(groupBy)
	}

	// 执行查询
	err := query.Find(&results).Error
	return results, err
}

func GetDomains(orgDB *mysql.DB, excludeTeamIDs []int, filter map[string]interface{}) (resp []model.Domain, err error) {
	var response []model.Domain
	var domains []mysqlmodel.Domain
	var azs []mysqlmodel.AZ
	var subDomains []mysqlmodel.SubDomain
	var controllers []mysqlmodel.Controller
	var domainLcuuids []string
	var domainToAZLcuuids map[string][]string
	var domainToRegionLcuuidsToAZLcuuids map[string](map[string][]string)
	var controllerIPToName map[string]string
	var domainToVMCount map[string]int
	var domainToPodCount map[string]int

	db := orgDB.DB
	if fLcuuid, ok := filter["lcuuid"]; ok {
		db = db.Where("lcuuid = ?", fLcuuid)
	}
	if fName, ok := filter["name"]; ok {
		db = db.Where("binary name = ?", fName)
	}
	if fTeamID, ok := filter["team_id"]; ok {
		db = db.Where("team_id = ?", fTeamID)
	}
	if fUserID, ok := filter["user_id"]; ok {
		db = db.Where("user_id = ?", fUserID)
	}
	err = db.Not(map[string]interface{}{"team_id": excludeTeamIDs}).Order("created_at DESC").Find(&domains).Error
	if err != nil {
		return response, err
	}

	for _, domain := range domains {
		domainLcuuids = append(domainLcuuids, domain.Lcuuid)
	}
	err = orgDB.Where("\"domain\" IN (?)", domainLcuuids).Find(&azs).Error // TODO extract common method
	if err != nil {
		return response, err
	}

	domainToAZLcuuids = make(map[string][]string)
	domainToRegionLcuuidsToAZLcuuids = make(map[string]map[string][]string)
	for _, az := range azs {
		domainToAZLcuuids[az.Domain] = append(domainToAZLcuuids[az.Domain], az.Lcuuid)
		if _, ok := domainToRegionLcuuidsToAZLcuuids[az.Domain]; ok {
			regionToAZLcuuids := domainToRegionLcuuidsToAZLcuuids[az.Domain]
			regionToAZLcuuids[az.Region] = append(regionToAZLcuuids[az.Region], az.Lcuuid)
		} else {
			regionToAZLcuuids := map[string][]string{az.Region: {az.Lcuuid}}
			domainToRegionLcuuidsToAZLcuuids[az.Domain] = regionToAZLcuuids
		}
	}

	err = orgDB.Find(&controllers).Error
	if err != nil {
		return response, err
	}
	controllerIPToName = make(map[string]string)
	for _, controller := range controllers {
		controllerIPToName[controller.IP] = controller.Name
	}

	err = orgDB.Find(&subDomains).Error
	if err != nil {
		return response, err
	}
	domainToSubDomainNames := make(map[string][]string)
	for _, subDomain := range subDomains {
		domainToSubDomainNames[subDomain.Domain] = append(
			domainToSubDomainNames[subDomain.Domain], subDomain.Name,
		)
	}

	clusterIDToValue := map[string]string{}
	var k8sClusters []mysqlmodel.KubernetesCluster
	if err = orgDB.Find(&k8sClusters).Error; err != nil {
		return response, err
	}
	for _, k8sCluster := range k8sClusters {
		clusterIDToValue[k8sCluster.ClusterID] = k8sCluster.Value
	}

	var vtaps []mysqlmodel.VTap
	if err = orgDB.Select("id", "ctrl_ip", "ctrl_mac", "name").Find(&vtaps).Error; err != nil {
		return response, err
	}
	valueToVtap := map[string]mysqlmodel.VTap{}
	for _, vtap := range vtaps {
		valueToVtap[fmt.Sprintf("%s-%s", vtap.CtrlIP, vtap.CtrlMac)] = vtap
	}

	domainToVMCount = make(map[string]int)
	vmCounts, _ := UnscopedSelectGroupByFind[mysqlmodel.VM, ResourceCount](
		orgDB, []string{"domain", "count(id) as count"}, "domain",
	)
	for _, item := range vmCounts {
		domainToVMCount[item.Domain] = item.Count
	}

	domainToPodCount = make(map[string]int)
	podCounts, _ := UnscopedSelectGroupByFind[mysqlmodel.Pod, ResourceCount](
		orgDB, []string{"domain", "count(id) as count"}, "domain",
	)
	for _, item := range podCounts {
		domainToPodCount[item.Domain] = item.Count
	}

	for _, domain := range domains {
		syncedAt := ""
		if domain.SyncedAt != nil {
			syncedAt = domain.SyncedAt.Format(common.GO_BIRTHDAY)
		}
		domainResp := model.Domain{
			ID:           domain.ClusterID,
			Name:         domain.Name,
			DisplayName:  domain.DisplayName,
			ClusterID:    domain.ClusterID,
			Type:         domain.Type,
			Enabled:      domain.Enabled,
			State:        domain.State,
			ErrorMsg:     domain.ErrorMsg,
			ControllerIP: domain.ControllerIP,
			IconID:       domain.IconID, // 后续与前端沟通icon作为默认配置
			TeamID:       domain.TeamID,
			UserID:       domain.UserID,
			CreatedAt:    domain.CreatedAt.Format(common.GO_BIRTHDAY),
			SyncedAt:     syncedAt,
			Lcuuid:       domain.Lcuuid,
			DomainID:     domain.ID,
		}

		if _, ok := domainToRegionLcuuidsToAZLcuuids[domain.Lcuuid]; ok {
			domainResp.RegionCount = len(domainToRegionLcuuidsToAZLcuuids[domain.Lcuuid])
		}
		if _, ok := domainToAZLcuuids[domain.Lcuuid]; ok {
			domainResp.AZCount = len(domainToAZLcuuids[domain.Lcuuid])
		}
		if _, ok := controllerIPToName[domain.ControllerIP]; ok {
			domainResp.ControllerName = controllerIPToName[domain.ControllerIP]
		}

		if _, ok := domainToVMCount[domain.Lcuuid]; ok {
			domainResp.VMCount = domainToVMCount[domain.Lcuuid]
		}
		if _, ok := domainToPodCount[domain.Lcuuid]; ok {
			domainResp.PodCount = domainToPodCount[domain.Lcuuid]
		}

		domainResp.Config = make(map[string]interface{})
		json.Unmarshal([]byte(domain.Config), &domainResp.Config)
		for key := range DOMAIN_PASSWORD_KEYS {
			if _, ok := domainResp.Config[key]; ok {
				domainResp.Config[key] = common.DEFAULT_ENCRYPTION_PASSWORD
			}
		}

		if domain.Type != common.KUBERNETES {
			domainResp.K8sEnabled = 1
			if subDomains, ok := domainToSubDomainNames[domain.Lcuuid]; ok {
				domainResp.PodClusters = subDomains
			}
		} else {
			if clusterValue, ok := clusterIDToValue[domain.ClusterID]; ok {
				if vtap, ok := valueToVtap[clusterValue]; ok {
					domainResp.VTapName = vtap.Name
					domainResp.VTapCtrlIP = vtap.CtrlIP
					domainResp.VTapCtrlMAC = vtap.CtrlMac
					domainResp.Config["vtap_id"] = vtap.Name
				} else {
					domainResp.VTapName = clusterValue
				}
			}
		}

		response = append(response, domainResp)
	}
	return response, nil
}

func maskDomainInfo(domainCreate model.DomainCreate) model.DomainCreate {
	log.Debugf("domain request raw data: %v", domainCreate)
	info := domainCreate
	info.Config = map[string]interface{}{}
	for k, v := range domainCreate.Config {
		if _, ok := DOMAIN_PASSWORD_KEYS[k]; ok {
			info.Config[k] = "******"
		} else {
			info.Config[k] = v
		}
	}
	return info
}

var ClusterIDRegex = regexp.MustCompile("^[0-9a-zA-Z][-0-9a-zA-Z]{0,31}$")

func CheckClusterID(clusterID string) bool {
	return ClusterIDRegex.MatchString(clusterID)
}

func CreateDomain(domainCreate model.DomainCreate, userInfo *httpcommon.UserInfo, db *mysql.DB, cfg *config.ControllerConfig) (*model.Domain, error) {
	var count int64

	db.Model(&mysqlmodel.Domain{}).Where("binary name = ?", domainCreate.Name).Count(&count)
	if count > 0 {
		return nil, response.ServiceError(httpcommon.RESOURCE_ALREADY_EXIST, fmt.Sprintf("domain (%s) already exist", domainCreate.Name))
	}

	db.Model(&mysqlmodel.SubDomain{}).Where("binary name = ?", domainCreate.Name).Count(&count)
	if count > 0 {
		return nil, response.ServiceError(httpcommon.RESOURCE_ALREADY_EXIST, fmt.Sprintf("sub_domain (%s) already exist", domainCreate.Name))
	}

	k8sClusterIDCreate := domainCreate.KubernetesClusterID
	if domainCreate.KubernetesClusterID != "" {
		if !CheckClusterID(domainCreate.KubernetesClusterID) {
			return nil, response.ServiceError(httpcommon.INVALID_PARAMETERS, fmt.Sprintf("domain cluster_id (%s) invalid", domainCreate.KubernetesClusterID))
		}

		var domainCheck mysqlmodel.Domain
		count = db.Where("binary cluster_id = ?", domainCreate.KubernetesClusterID).First(&domainCheck).RowsAffected
		if count > 0 {
			return nil, response.ServiceError(httpcommon.RESOURCE_ALREADY_EXIST, fmt.Sprintf("domain cluster_id (%s) already exist in domain (%s)", domainCreate.KubernetesClusterID, domainCheck.Name))
		}

		var subDomainCheck mysqlmodel.SubDomain
		count = db.Where("binary cluster_id = ?", domainCreate.KubernetesClusterID).First(&subDomainCheck).RowsAffected
		if count > 0 {
			return nil, response.ServiceError(httpcommon.RESOURCE_ALREADY_EXIST, fmt.Sprintf("domain cluster_id (%s) already exist in sub_domain (%s)", domainCreate.KubernetesClusterID, subDomainCheck.Name))
		}

		if db.ORGID != mysqlcommon.DEFAULT_ORG_ID {
			k8sClusterIDCreate += strconv.Itoa(db.ORGID)
		}
	}

	displayName := common.GetUUID(k8sClusterIDCreate, uuid.Nil)
	lcuuid := common.GetUUID(displayName, uuid.Nil)
	domain := mysqlmodel.Domain{}
	domain.Lcuuid = lcuuid
	domain.Name = domainCreate.Name
	domain.TeamID = domainCreate.TeamID
	domain.UserID = userInfo.ID
	domain.DisplayName = displayName
	domain.Type = domainCreate.Type
	domain.IconID = domainCreate.IconID
	domain.State = common.DOMAIN_STATE_NORMAL

	// set region and controller ip if not specified
	if domainCreate.Config == nil {
		domainCreate.Config = map[string]interface{}{
			"region_uuid":   "",
			"controller_ip": "",
		}
	}

	var regionLcuuid string
	confRegion, ok := domainCreate.Config["region_uuid"]
	if !ok || confRegion.(string) == "" {
		var region mysqlmodel.Region
		res := db.Find(&region)
		if res.RowsAffected != int64(1) {
			return nil, response.ServiceError(httpcommon.INVALID_PARAMETERS, fmt.Sprintf("can not find region, please specify or create one"))
		}
		domainCreate.Config["region_uuid"] = region.Lcuuid
		regionLcuuid = region.Lcuuid
	} else {
		regionLcuuid = confRegion.(string)
	}

	// only one type (agent_sync) can exist in the same region
	// 同一区域只允许存在一个(采集器同步)类型
	if domainCreate.Type == common.AGENT_SYNC {
		var agentSyncDomains []mysqlmodel.Domain
		err := db.Where("type = ?", common.AGENT_SYNC).Find(&agentSyncDomains).Error
		if err != nil {
			return nil, response.ServiceError(httpcommon.SERVER_ERROR, err.Error())
		}
		for _, asDomain := range agentSyncDomains {
			configJson, err := simplejson.NewJson([]byte(asDomain.Config))
			if err != nil {
				return nil, response.ServiceError(httpcommon.SERVER_ERROR, err.Error())
			}
			if regionLcuuid == configJson.Get("region_uuid").MustString() {
				return nil, response.ServiceError(httpcommon.RESOURCE_ALREADY_EXIST, fmt.Sprintf("only one agent_sync can exist in the region (%s)", regionLcuuid))
			}
		}
	}

	// TODO: controller_ip拿到config外面，直接作为domain的一级参数
	var controllerIP string
	confControllerIP, ok := domainCreate.Config["controller_ip"]
	if !ok || confControllerIP.(string) == "" {
		var azConn mysqlmodel.AZControllerConnection
		res := db.Where("region = ?", regionLcuuid).First(&azConn)
		if res.RowsAffected != int64(1) {
			return nil, response.ServiceError(httpcommon.INVALID_PARAMETERS, fmt.Sprintf("can not find controller ip, please specify or create one"))
		}
		domainCreate.Config["controller_ip"] = azConn.ControllerIP
		controllerIP = azConn.ControllerIP
	} else {
		controllerIP = confControllerIP.(string)
	}
	domain.ControllerIP = controllerIP

	// encrypt password/access_key
	for key := range DOMAIN_PASSWORD_KEYS {
		if _, ok := domainCreate.Config[key]; ok && cfg != nil {

			// running in standalone mode, not support password encryptKey
			if common.IsStandaloneRunningMode() {
				return nil, response.ServiceError(
					httpcommon.SERVER_ERROR, "not support current type domain in standalone mode",
				)
			}

			serverIP, grpcServerPort := getGrpcServerAndPort(db, domain.ControllerIP, cfg)
			encryptKey, err := common.GetEncryptKey(
				serverIP, grpcServerPort, domainCreate.Config[key].(string),
			)
			if err != nil {
				log.Error("get encrypt key failed (%s)", err.Error())
				return nil, response.ServiceError(httpcommon.SERVER_ERROR, err.Error())
			}

			domainCreate.Config[key] = encryptKey
			log.Debugf(
				"domain (%s) %s: %s, encrypt %s: %s",
				domainCreate.Name, key, domainCreate.Config[key].(string), key, encryptKey,
			)
		}
	}
	configStr, _ := json.Marshal(domainCreate.Config)
	domain.Config = string(configStr)

	if domainCreate.Type == common.KUBERNETES {
		// support specify cluster_id
		if domainCreate.KubernetesClusterID != "" {
			domain.ClusterID = domainCreate.KubernetesClusterID
		} else {
			domain.ClusterID = "d-" + common.GenerateShortUUID()
		}
	}

	err := svc.NewResourceAccess(cfg.FPermit, userInfo).CanAddResource(domainCreate.TeamID, common.SET_RESOURCE_TYPE_DOMAIN, lcuuid)
	if err != nil {
		return nil, err
	}

	log.Infof("create domain (%v)", maskDomainInfo(domainCreate), db.LogPrefixORGID)

	err = db.Clauses(clause.Insert{Modifier: "IGNORE"}).Create(&domain).Error
	if err != nil {
		return nil, response.ServiceError(httpcommon.SERVER_ERROR, fmt.Sprintf("create domain (%s) failed", domainCreate.Name))
	}
	response, _ := GetDomains(db, []int{}, map[string]interface{}{"lcuuid": lcuuid})
	return &response[0], nil
}

func UpdateDomain(lcuuid string, domainUpdate map[string]interface{}, userInfo *httpcommon.UserInfo, cfg *config.ControllerConfig, db *mysql.DB) (*model.Domain, error) {
	var domain mysqlmodel.Domain
	var dbUpdateMap = make(map[string]interface{})

	if ret := db.Where("lcuuid = ?", lcuuid).First(&domain); ret.Error != nil {
		return nil, response.ServiceError(
			httpcommon.RESOURCE_NOT_FOUND, fmt.Sprintf("domain (%s) not found", lcuuid),
		)
	}

	resourceUp := map[string]interface{}{}
	// user id
	if uUserID, ok := domainUpdate["USER_ID"]; ok {
		dbUpdateMap["user_id"] = uUserID
		resourceUp["owner_user_id"] = uUserID
	}

	// 修改名称
	if uName, ok := domainUpdate["NAME"]; ok {
		dbUpdateMap["name"] = uName
	}

	// 禁用/启用
	if uEnabled, ok := domainUpdate["ENABLED"]; ok {
		dbUpdateMap["enabled"] = uEnabled
	}

	// 图标
	if uIconID, ok := domainUpdate["ICON_ID"]; ok {
		dbUpdateMap["icon_id"] = uIconID
	}

	// 控制器IP
	if uControllerIP, ok := domainUpdate["CONTROLLER_IP"]; ok {
		dbUpdateMap["controller_ip"] = uControllerIP
		domain.ControllerIP = uControllerIP.(string)
	}

	err := svc.NewResourceAccess(cfg.FPermit, userInfo).CanUpdateResource(domain.TeamID, common.SET_RESOURCE_TYPE_DOMAIN, lcuuid, resourceUp)
	if err != nil {
		return nil, err
	}

	// config
	// 注意：密码相关字段因为返回是****，所以不能直接把页面更新入库
	if fConfig, ok := domainUpdate["CONFIG"]; ok && fConfig != nil {
		config := make(map[string]interface{})
		json.Unmarshal([]byte(domain.Config), &config)

		configUpdate := fConfig.(map[string]interface{})

		// 如果存在资源同步控制器IP的修改，则需要更新controller_ip字段
		if controllerIP, ok := configUpdate["controller_ip"]; ok {
			if controllerIP != domain.ControllerIP {
				dbUpdateMap["controller_ip"] = controllerIP
				domain.ControllerIP = controllerIP.(string)
			}
		}
		// 如果修改region，则清理掉云平台下所有软删除的数据
		if region, ok := configUpdate["region_uuid"]; ok {
			regionLcuuid, ok := region.(string)
			if !ok {
				return nil, response.ServiceError(httpcommon.INVALID_PARAMETERS, "region lcuuid must be string")
			}
			if domain.Type == common.AGENT_SYNC {
				var agentSyncDomains []mysqlmodel.Domain
				err := db.Where("type = ? AND lcuuid != ?", common.AGENT_SYNC, domain.Lcuuid).Find(&agentSyncDomains).Error
				if err != nil {
					return nil, response.ServiceError(httpcommon.SERVER_ERROR, err.Error())
				}
				for _, asDomain := range agentSyncDomains {
					configJson, err := simplejson.NewJson([]byte(asDomain.Config))
					if err != nil {
						return nil, response.ServiceError(httpcommon.SERVER_ERROR, err.Error())
					}
					if regionLcuuid == configJson.Get("region_uuid").MustString() {
						return nil, response.ServiceError(httpcommon.RESOURCE_ALREADY_EXIST, fmt.Sprintf("region (%s) already exist agent sync doamin (%s)", regionLcuuid, asDomain.Name))
					}
				}
			}
			if region != config["region_uuid"] {
				log.Infof("delete domain (%s) soft deleted resource", domain.Name, db.LogPrefixORGID)
				cleanSoftDeletedResource(db, lcuuid)
			}
		}

		// transfer password/access_key
		for key := range DOMAIN_PASSWORD_KEYS {
			if _, ok := configUpdate[key]; ok && cfg != nil {
				if configUpdate[key] == common.DEFAULT_ENCRYPTION_PASSWORD {
					configUpdate[key] = config[key]
				} else {
					serverIP, grpcServerPort := getGrpcServerAndPort(db, domain.ControllerIP, cfg)
					// encrypt password/access_key
					encryptKey, err := common.GetEncryptKey(
						serverIP, grpcServerPort, configUpdate[key].(string),
					)
					if err != nil {
						log.Error(err)
						return nil, response.ServiceError(httpcommon.SERVER_ERROR, err.Error())
					}
					configUpdate[key] = encryptKey
					log.Debugf(
						"domain (%s) %s: %s, encrypt %s: %s",
						domain.Name, key, configUpdate[key].(string), key, encryptKey,
					)
				}
			}
		}
		configStr, _ := json.Marshal(configUpdate)
		dbUpdateMap["config"] = string(configStr)
	}

	log.Infof("update domain (%s) config (%v)", domain.Name, domainUpdate, db.LogPrefixORGID)

	// 更新domain DB
	err = db.Model(&domain).Updates(dbUpdateMap).Error
	if err != nil {
		return nil, err
	}

	response, _ := GetDomains(db, []int{}, map[string]interface{}{"lcuuid": domain.Lcuuid})
	return &response[0], nil
}

func cleanSoftDeletedResource(db *mysql.DB, lcuuid string) {
	condition := "\"domain\" = ? AND deleted_at IS NOT NULL"
	log.Infof("clean soft deleted resources (domain = %s AND deleted_at IS NOT NULL) started", lcuuid, db.LogPrefixORGID)
	forceDelete[mysqlmodel.CEN](db, condition, lcuuid)
	forceDelete[mysqlmodel.PeerConnection](db, condition, lcuuid)
	forceDelete[mysqlmodel.RedisInstance](db, condition, lcuuid)
	forceDelete[mysqlmodel.RDSInstance](db, condition, lcuuid)
	forceDelete[mysqlmodel.LBListener](db, condition, lcuuid)
	forceDelete[mysqlmodel.LB](db, condition, lcuuid)
	forceDelete[mysqlmodel.NATGateway](db, condition, lcuuid)
	forceDelete[mysqlmodel.DHCPPort](db, condition, lcuuid)
	forceDelete[mysqlmodel.VRouter](db, condition, lcuuid)
	forceDelete[mysqlmodel.ConfigMap](db, condition, lcuuid)
	forceDelete[mysqlmodel.Pod](db, condition, lcuuid)
	forceDelete[mysqlmodel.PodReplicaSet](db, condition, lcuuid)
	forceDelete[mysqlmodel.PodGroup](db, condition, lcuuid)
	forceDelete[mysqlmodel.PodService](db, condition, lcuuid)
	forceDelete[mysqlmodel.PodIngress](db, condition, lcuuid)
	forceDelete[mysqlmodel.PodNamespace](db, condition, lcuuid)
	forceDelete[mysqlmodel.PodNode](db, condition, lcuuid)
	forceDelete[mysqlmodel.PodCluster](db, condition, lcuuid)
	forceDelete[mysqlmodel.VM](db, condition, lcuuid)
	forceDelete[mysqlmodel.Host](db, condition, lcuuid)
	forceDelete[mysqlmodel.Network](db, condition, lcuuid)
	forceDelete[mysqlmodel.VPC](db, condition, lcuuid)
	forceDelete[mysqlmodel.AZ](db, condition, lcuuid)
	log.Info("clean soft deleted resources completed", db.LogPrefixORGID)
}

func DeleteDomainByNameOrUUID(nameOrUUID string, db *mysql.DB, userInfo *httpcommon.UserInfo, cfg *config.ControllerConfig) (map[string]string, error) {
	var domain mysqlmodel.Domain
	err1 := db.Where("lcuuid = ?", nameOrUUID).First(&domain).Error
	var domains []mysqlmodel.Domain
	err2 := db.Where("name = ?", nameOrUUID).Find(&domains).Error
	if err1 == nil && err2 == nil && len(domains) > 0 {
		return nil, response.ServiceError(
			httpcommon.PARAMETER_ILLEGAL, fmt.Sprintf("remove domain (name: %s, uuid: %s) conflict", nameOrUUID, nameOrUUID),
		)
	}
	// delete domain by lcuuid
	if err1 == nil {
		return deleteDomain(&domain, db, userInfo, cfg)
	}

	if len(domains) > 1 {
		return nil, response.ServiceError(
			httpcommon.PARAMETER_ILLEGAL, fmt.Sprintf("duplicate domain (name: %s)", nameOrUUID),
		)
	}
	// delete domain by name
	if err2 == nil && len(domains) > 0 {
		return deleteDomain(&domains[0], db, userInfo, cfg)
	}

	return nil, response.ServiceError(
		httpcommon.RESOURCE_NOT_FOUND, fmt.Sprintf("domain (uuid or name: %s) not found", nameOrUUID),
	)
}

func deleteDomain(domain *mysqlmodel.Domain, db *mysql.DB, userInfo *httpcommon.UserInfo, cfg *config.ControllerConfig) (map[string]string, error) { // TODO whether release resource ids
	log.Infof("delete domain (%s) resources started", domain.Name, db.LogPrefixORGID)

	err := svc.NewResourceAccess(cfg.FPermit, userInfo).CanDeleteResource(domain.TeamID, common.SET_RESOURCE_TYPE_DOMAIN, domain.Lcuuid)
	if err != nil {
		return nil, err
	}

	lcuuid := domain.Lcuuid
	db.Unscoped().Where("\"domain\" = ?", lcuuid).Delete(&mysqlmodel.WANIP{}) // TODO use forceDelete func
	db.Unscoped().Where("\"domain\" = ?", lcuuid).Delete(&mysqlmodel.LANIP{})
	db.Unscoped().Where("\"domain\" = ?", lcuuid).Delete(&mysqlmodel.FloatingIP{})
	db.Unscoped().Where("\"domain\" = ?", lcuuid).Delete(&mysqlmodel.VInterface{})
	db.Unscoped().Where("\"domain\" = ?", lcuuid).Delete(&mysqlmodel.CEN{})
	db.Unscoped().Where("\"domain\" = ?", lcuuid).Delete(&mysqlmodel.PeerConnection{})
	db.Unscoped().Where("\"domain\" = ?", lcuuid).Delete(&mysqlmodel.RedisInstance{})
	db.Unscoped().Where("\"domain\" = ?", lcuuid).Delete(&mysqlmodel.RDSInstance{})
	db.Unscoped().Where("\"domain\" = ?", lcuuid).Delete(&mysqlmodel.LBVMConnection{})
	db.Unscoped().Where("\"domain\" = ?", lcuuid).Delete(&mysqlmodel.LBTargetServer{})
	db.Unscoped().Where("\"domain\" = ?", lcuuid).Delete(&mysqlmodel.LBListener{})
	db.Unscoped().Where("\"domain\" = ?", lcuuid).Delete(&mysqlmodel.LB{})
	db.Unscoped().Where("\"domain\" = ?", lcuuid).Delete(&mysqlmodel.NATVMConnection{})
	db.Unscoped().Where("\"domain\" = ?", lcuuid).Delete(&mysqlmodel.NATRule{})
	db.Unscoped().Where("\"domain\" = ?", lcuuid).Delete(&mysqlmodel.NATGateway{})
	db.Unscoped().Where("\"domain\" = ?", lcuuid).Delete(&mysqlmodel.Process{})
	// db.Unscoped().Where("\"domain\" = ?", lcuuid).Delete(&mysqlmodel.PrometheusTarget{})
	db.Unscoped().Where("\"domain\" = ?", lcuuid).Delete(&mysqlmodel.VIP{})
	db.Unscoped().Where("\"domain\" = ?", lcuuid).Delete(&mysqlmodel.DHCPPort{})
	var vRouters []mysqlmodel.VRouter
	db.Unscoped().Where("\"domain\" = ?", lcuuid).Find(&vRouters)
	vRouterIDs := make([]int, len(vRouters))
	for _, vRouter := range vRouters {
		vRouterIDs = append(vRouterIDs, vRouter.ID)
	}
	db.Unscoped().Where("vnet_id IN ?", vRouterIDs).Delete(&mysqlmodel.RoutingTable{})
	db.Unscoped().Where("\"domain\" = ?", lcuuid).Delete(&mysqlmodel.VRouter{})
	db.Unscoped().Where("\"domain\" = ?", lcuuid).Delete(&mysqlmodel.VMPodNodeConnection{})
	db.Unscoped().Where("\"domain\" = ?", lcuuid).Delete(&mysqlmodel.PodGroupConfigMapConnection{})
	db.Unscoped().Where("\"domain\" = ?", lcuuid).Delete(&mysqlmodel.ConfigMap{})
	db.Unscoped().Where("\"domain\" = ?", lcuuid).Delete(&mysqlmodel.Pod{})
	db.Unscoped().Where("\"domain\" = ?", lcuuid).Delete(&mysqlmodel.PodReplicaSet{})
	db.Unscoped().Where("\"domain\" = ?", lcuuid).Delete(&mysqlmodel.PodGroup{})
	var podServices []mysqlmodel.PodService
	db.Unscoped().Where("\"domain\" = ?", lcuuid).Find(&podServices)
	podServiceIDs := make([]int, len(podServices))
	for _, podService := range podServices {
		podServiceIDs = append(podServiceIDs, podService.ID)
	}
	db.Unscoped().Where("pod_service_id IN ?", podServiceIDs).Delete(&mysqlmodel.PodServicePort{})
	db.Unscoped().Where("pod_service_id IN ?", podServiceIDs).Delete(&mysqlmodel.PodGroupPort{})
	db.Unscoped().Where("\"domain\" = ?", lcuuid).Delete(&mysqlmodel.PodService{})
	var podIngresses []mysqlmodel.PodIngress
	db.Unscoped().Where("\"domain\" = ?", lcuuid).Find(&podIngresses)
	podIngressIDs := make([]int, len(podIngresses))
	for _, podIngress := range podIngresses {
		podIngressIDs = append(podIngressIDs, podIngress.ID)
	}
	db.Unscoped().Where("pod_ingress_id IN ?", podIngressIDs).Delete(&mysqlmodel.PodIngressRule{})
	db.Unscoped().Where("pod_ingress_id IN ?", podIngressIDs).Delete(&mysqlmodel.PodIngressRuleBackend{})
	db.Unscoped().Where("\"domain\" = ?", lcuuid).Delete(&mysqlmodel.PodIngress{})
	db.Unscoped().Where("\"domain\" = ?", lcuuid).Delete(&mysqlmodel.PodNamespace{})
	db.Unscoped().Where("\"domain\" = ?", lcuuid).Delete(&mysqlmodel.PodNode{})
	db.Unscoped().Where("\"domain\" = ?", lcuuid).Delete(&mysqlmodel.PodCluster{})
	db.Unscoped().Where("\"domain\" = ?", lcuuid).Delete(&mysqlmodel.VM{})
	db.Unscoped().Where("\"domain\" = ?", lcuuid).Delete(&mysqlmodel.Host{})
	var networks []mysqlmodel.Network
	db.Unscoped().Where("\"domain\" = ?", lcuuid).Find(&networks)
	networkIDs := make([]int, len(networks))
	for _, network := range networks {
		networkIDs = append(networkIDs, network.ID)
	}
	db.Unscoped().Where("vl2id IN ?", networkIDs).Delete(&mysqlmodel.Subnet{})
	db.Unscoped().Where("\"domain\" = ?", lcuuid).Delete(&mysqlmodel.Network{})
	db.Unscoped().Where("\"domain\" = ?", lcuuid).Delete(&mysqlmodel.VPC{})
	db.Unscoped().Where("\"domain\" = ?", lcuuid).Delete(&mysqlmodel.SubDomain{})
	db.Unscoped().Where("\"domain\" = ?", lcuuid).Delete(&mysqlmodel.AZ{})

	db.Delete(&domain)

	// pub to tagrecorder
	metadata := message.NewMetadata(message.MetadataDB(db), message.MetadataDomain(*domain))
	for _, s := range tagrecorder.GetSubscriberManager().GetSubscribers("domain") {
		s.OnDomainDeleted(metadata)
	}

	log.Infof("delete domain (%s) resources completed", domain.Name, db.LogPrefixORGID)
	return map[string]string{"LCUUID": lcuuid}, nil
}

func GetSubDomains(orgDB *mysql.DB, excludeTeamIDs []int, filter map[string]interface{}) ([]*model.SubDomain, error) {
	var response []*model.SubDomain
	var subDomains []mysqlmodel.SubDomain
	var vpcs []mysqlmodel.VPC

	db := orgDB.DB
	if fLcuuid, ok := filter["lcuuid"]; ok {
		db = db.Where("lcuuid = ?", fLcuuid)
	}
	if fDomain, ok := filter["domain"]; ok {
		db = db.Where("\"domain\" = ?", fDomain)
	}
	if fClusterID, ok := filter["cluster_id"]; ok {
		db = db.Where("binary cluster_id = ?", fClusterID)
	}
	if fTeamID, ok := filter["team_id"]; ok {
		db = db.Where("team_id = ?", fTeamID)
	}
	if fUserID, ok := filter["user_id"]; ok {
		db = db.Where("user_id = ?", fUserID)
	}
	err := db.Not(map[string]interface{}{"team_id": excludeTeamIDs}).Order("created_at DESC").Find(&subDomains).Error
	if err != nil {
		return response, err
	}

	orgDB.Select("name", "lcuuid").Find(&vpcs)
	lcuuidToVPCName := make(map[string]string)
	for _, vpc := range vpcs {
		lcuuidToVPCName[vpc.Lcuuid] = vpc.Name
	}

	for _, subDomain := range subDomains {
		syncedAt := ""
		if subDomain.SyncedAt != nil {
			syncedAt = subDomain.SyncedAt.Format(common.GO_BIRTHDAY)
		}
		subDomainResp := model.SubDomain{
			ID:           subDomain.ID,
			TeamID:       subDomain.TeamID,
			UserID:       subDomain.UserID,
			Name:         subDomain.Name,
			DisplayName:  subDomain.DisplayName,
			ClusterID:    subDomain.ClusterID,
			State:        subDomain.State,
			ErrorMsg:     subDomain.ErrorMsg,
			CreateMethod: subDomain.CreateMethod,
			CreatedAt:    subDomain.CreatedAt.Format(common.GO_BIRTHDAY),
			SyncedAt:     syncedAt,
			Domain:       subDomain.Domain,
			Lcuuid:       subDomain.Lcuuid,
			SubDomainID:  subDomain.ID,
		}

		subDomainResp.Config = make(map[string]interface{})
		json.Unmarshal([]byte(subDomain.Config), &subDomainResp.Config)

		if _, ok := subDomainResp.Config["vpc_uuid"]; ok {
			vpcLcuuid := subDomainResp.Config["vpc_uuid"].(string)
			if _, ok := lcuuidToVPCName[vpcLcuuid]; ok {
				subDomainResp.VPCName = lcuuidToVPCName[vpcLcuuid]
			}
		}

		var k8sCluster mysqlmodel.KubernetesCluster
		if err := orgDB.Where("cluster_id = ?", subDomain.ClusterID).First(&k8sCluster).Error; err == nil {
			v := strings.Split(k8sCluster.Value, "-")
			if len(v) == 2 {
				var vtap mysqlmodel.VTap
				if err = orgDB.Where("ctrl_ip = ? AND ctrl_mac = ?", v[0], v[1]).First(&vtap).Error; err == nil {
					subDomainResp.Config["vtap_id"] = vtap.Name
				}
			}
		}

		// get domain name
		var domain mysqlmodel.Domain
		if err := orgDB.Where("lcuuid = ?", subDomain.Domain).First(&domain).Error; err != nil {
			log.Error(err)
		}
		subDomainResp.DomainName = domain.Name

		response = append(response, &subDomainResp)
	}
	return response, nil
}

func CreateSubDomain(subDomainCreate model.SubDomainCreate, db *mysql.DB, userInfo *httpcommon.UserInfo, cfg *config.ControllerConfig) (*model.SubDomain, error) {
	var domain mysqlmodel.Domain
	if err := db.Model(&mysqlmodel.Domain{}).Where("lcuuid = ?", subDomainCreate.Domain).First(&domain).Error; err != nil {
		return nil, err
	}

	var count int64
	db.Model(&mysqlmodel.SubDomain{}).Where("binary name = ?", subDomainCreate.Name).Count(&count)
	if count > 0 {
		return nil, response.ServiceError(httpcommon.RESOURCE_ALREADY_EXIST, fmt.Sprintf("sub_domain (%s) already exist", subDomainCreate.Name))
	}
	if subDomainCreate.ClusterID != "" {
		if !CheckClusterID(subDomainCreate.ClusterID) {
			return nil, response.ServiceError(httpcommon.INVALID_PARAMETERS, fmt.Sprintf("sub_domain cluster_id (%s) invalid", subDomainCreate.ClusterID))
		}

		var domainCheck mysqlmodel.Domain
		count = db.Where("binary cluster_id = ?", subDomainCreate.ClusterID).First(&domainCheck).RowsAffected
		if count > 0 {
			return nil, response.ServiceError(httpcommon.RESOURCE_ALREADY_EXIST, fmt.Sprintf("sub_domain cluster_id (%s) already exist in domain (%s)", subDomainCreate.ClusterID, domainCheck.Name))
		}

		var subDomainCheck mysqlmodel.SubDomain
		count = db.Where("binary cluster_id = ?", subDomainCreate.ClusterID).First(&subDomainCheck).RowsAffected
		if count > 0 {
			return nil, response.ServiceError(httpcommon.RESOURCE_ALREADY_EXIST, fmt.Sprintf("sub_domain cluster_id (%s) already exist in sub_domain (%s)", subDomainCreate.ClusterID, subDomainCheck.Name))
		}
	} else {
		subDomainCreate.ClusterID = "d-" + common.GenerateShortUUID()
	}

	displayName := common.GetUUID("", uuid.Nil)
	lcuuid := common.GetUUID(displayName, uuid.Nil)
	if subDomainCreate.TeamID == 0 {
		subDomainCreate.TeamID = domain.TeamID
	}
	err := svc.NewResourceAccess(cfg.FPermit, userInfo).CanAddSubDomainResource(domain.TeamID, subDomainCreate.TeamID, lcuuid)
	if err != nil {
		return nil, err
	}

	log.Infof("create sub_domain (%v)", subDomainCreate, db.LogPrefixORGID)

	subDomain := mysqlmodel.SubDomain{}
	subDomain.Lcuuid = lcuuid
	subDomain.TeamID = subDomainCreate.TeamID
	subDomain.UserID = domain.UserID
	subDomain.Name = subDomainCreate.Name
	subDomain.DisplayName = displayName
	subDomain.CreateMethod = common.CREATE_METHOD_USER_DEFINE
	subDomain.ClusterID = subDomainCreate.ClusterID
	subDomain.Domain = subDomainCreate.Domain
	configStr, _ := json.Marshal(subDomainCreate.Config)
	subDomain.Config = string(configStr)
	err = db.Create(&subDomain).Error
	if err != nil {
		return nil, err
	}

	response, _ := GetSubDomains(db, []int{}, map[string]interface{}{"lcuuid": lcuuid})
	return response[0], nil
}

func UpdateSubDomain(lcuuid string, db *mysql.DB, userInfo *httpcommon.UserInfo, cfg *config.ControllerConfig, subDomainUpdate map[string]interface{}) (*model.SubDomain, error) {
	if _, ok := subDomainUpdate["NAME"]; ok {
		return nil, errors.New("name field cannot be modified")
	}
	if _, ok := subDomainUpdate["DOMAIN_NAME"]; ok {
		return nil, errors.New("domain_name field cannot be modified")
	}

	var domain mysqlmodel.Domain
	var subDomain mysqlmodel.SubDomain
	var dbUpdateMap = make(map[string]interface{})
	var resourceUp = make(map[string]interface{})
	// if userID, ok := subDomainUpdate["USER_ID"]; ok {
	// 	dbUpdateMap["user_id"] = userID
	// 	resourceUp["owner_user_id"] = userID
	// }
	teamID, teamIDChanged := subDomainUpdate["TEAM_ID"]
	if teamIDChanged {
		dbUpdateMap["team_id"] = teamID
		resourceUp["team_id"] = teamID
	}

	if ret := db.Where("lcuuid = ?", lcuuid).First(&subDomain); ret.Error != nil {
		return nil, response.ServiceError(
			httpcommon.RESOURCE_NOT_FOUND, fmt.Sprintf("sub_domain (%s) not found", lcuuid),
		)
	}
	if ret := db.Where("lcuuid = ?", subDomain.Domain).First(&domain); ret.Error != nil {
		return nil, response.ServiceError(
			httpcommon.RESOURCE_NOT_FOUND, fmt.Sprintf("sub_domain (%s) not found domain", lcuuid),
		)
	}

	err := svc.NewResourceAccess(cfg.FPermit, userInfo).CanUpdateSubDomainResource(domain.TeamID, subDomain.TeamID, lcuuid, resourceUp)
	if err != nil {
		return nil, err
	}

	log.Infof("update sub_domain (%s) config (%v)", subDomain.Name, subDomainUpdate, db.LogPrefixORGID)

	// config
	fConfig, ok := subDomainUpdate["CONFIG"]
	if ok {
		configStr, _ := json.Marshal(fConfig)
		dbUpdateMap["config"] = string(configStr)
	}

	err = db.Model(&subDomain).Updates(dbUpdateMap).Error
	if err != nil {
		return nil, err
	}

	if teamIDChanged {
		metadata := message.NewMetadata(message.MetadataDB(db), message.MetadataSubDomain(subDomain))
		for _, s := range tagrecorder.GetSubscriberManager().GetSubscribers("sub_domain") {
			s.OnSubDomainTeamIDUpdated(metadata)
		}
	}

	response, _ := GetSubDomains(db, []int{}, map[string]interface{}{"lcuuid": lcuuid})
	return response[0], nil
}

func DeleteSubDomain(lcuuid string, db *mysql.DB, userInfo *httpcommon.UserInfo, cfg *config.ControllerConfig) (map[string]string, error) {
	var domain mysqlmodel.Domain
	var subDomain mysqlmodel.SubDomain
	if ret := db.Where("lcuuid = ?", lcuuid).First(&subDomain); ret.Error != nil {
		return nil, response.ServiceError(
			httpcommon.RESOURCE_NOT_FOUND, fmt.Sprintf("sub_domain (%s) not found", lcuuid),
		)
	}
	if ret := db.Where("lcuuid = ?", subDomain.Domain).First(&domain); ret.Error != nil {
		return nil, response.ServiceError(
			httpcommon.RESOURCE_NOT_FOUND, fmt.Sprintf("sub_domain (%s) not found domain", lcuuid),
		)
	}

	err := svc.NewResourceAccess(cfg.FPermit, userInfo).CanDeleteSubDomainResource(domain.TeamID, subDomain.TeamID, lcuuid)
	if err != nil {
		return nil, err
	}

	log.Infof("delete sub_domain (%s) resources started", subDomain.Name, db.LogPrefixORGID)

	var podCluster mysqlmodel.PodCluster
	db.Unscoped().Where("sub_domain = ?", lcuuid).Find(&podCluster)
	if podCluster.ID != 0 {
		log.Infof("delete pod_cluster (%+v) resources", podCluster, db.LogPrefixORGID)
		db.Unscoped().Where("sub_domain = ?", lcuuid).Delete(&mysqlmodel.WANIP{}) // TODO use forceDelete func
		db.Unscoped().Where("sub_domain = ?", lcuuid).Delete(&mysqlmodel.LANIP{})
		db.Unscoped().Where("sub_domain = ?", lcuuid).Delete(&mysqlmodel.VInterface{})
		db.Unscoped().Where("sub_domain = ?", lcuuid).Delete(&mysqlmodel.Subnet{})
		db.Unscoped().Where("sub_domain = ?", lcuuid).Delete(&mysqlmodel.Network{})
		db.Unscoped().Where("sub_domain = ?", lcuuid).Delete(&mysqlmodel.VMPodNodeConnection{})
		db.Unscoped().Where("sub_domain = ?", lcuuid).Delete(&mysqlmodel.PodGroupConfigMapConnection{})
		db.Unscoped().Where("sub_domain = ?", lcuuid).Delete(&mysqlmodel.ConfigMap{})
		db.Unscoped().Where("sub_domain = ?", lcuuid).Delete(&mysqlmodel.Pod{})
		db.Unscoped().Where("sub_domain = ?", lcuuid).Delete(&mysqlmodel.PodReplicaSet{})
		db.Unscoped().Where("sub_domain = ?", lcuuid).Delete(&mysqlmodel.PodGroupPort{})
		db.Unscoped().Where("sub_domain = ?", lcuuid).Delete(&mysqlmodel.PodGroup{})
		db.Unscoped().Where("sub_domain = ?", lcuuid).Delete(&mysqlmodel.PodServicePort{})
		db.Unscoped().Where("sub_domain = ?", lcuuid).Delete(&mysqlmodel.PodService{})
		db.Unscoped().Where("sub_domain = ?", lcuuid).Delete(&mysqlmodel.PodIngressRuleBackend{})
		db.Unscoped().Where("sub_domain = ?", lcuuid).Delete(&mysqlmodel.PodIngressRule{})
		db.Unscoped().Where("sub_domain = ?", lcuuid).Delete(&mysqlmodel.PodIngress{})
		db.Unscoped().Where("sub_domain = ?", lcuuid).Delete(&mysqlmodel.PodNamespace{})
		db.Unscoped().Where("sub_domain = ?", lcuuid).Delete(&mysqlmodel.PodNode{})
		db.Unscoped().Where("sub_domain = ?", lcuuid).Delete(&mysqlmodel.PodCluster{})
		db.Unscoped().Where("sub_domain = ?", lcuuid).Delete(&mysqlmodel.Process{})
		// db.Unscoped().Where("sub_domain = ?", lcuuid).Delete(&mysqlmodel.PrometheusTarget{})
	}

	err = db.Delete(&subDomain).Error
	if err != nil {
		return nil, err
	}

	// pub to tagrecorder
	metadata := message.NewMetadata(message.MetadataDB(db), message.MetadataSubDomain(subDomain))
	for _, s := range tagrecorder.GetSubscriberManager().GetSubscribers("sub_domain") {
		s.OnSubDomainDeleted(metadata)
	}

	log.Infof("delete sub_domain (%s) resources completed", subDomain.Name, db.LogPrefixORGID)
	return map[string]string{"LCUUID": lcuuid}, nil
}

func forceDelete[MT constraint.MySQLSoftDeleteModel](db *mysql.DB, query interface{}, args ...interface{}) { // TODO common func
	err := db.Unscoped().Where(query, args...).Delete(new(MT)).Error
	if err != nil {
		log.Errorf("mysql delete resource: %v %v failed: %s", query, args, err, db.LogPrefixORGID)
	}
}

type DomainChecker struct {
	ctx    context.Context
	cancel context.CancelFunc
}

func NewDomainCheck(ctx context.Context) *DomainChecker {
	cCtx, cCancel := context.WithCancel(ctx)
	return &DomainChecker{ctx: cCtx, cancel: cCancel}
}

func (c *DomainChecker) Start(sCtx context.Context) {
	log.Info("domain check started")
	c.CheckRegularly(sCtx)
}

func (c *DomainChecker) Stop() {
	if c.cancel != nil {
		c.cancel()
	}
	log.Info("domain check stopped")
}

func (c *DomainChecker) CheckRegularly(sCtx context.Context) {
	go func() {
		ticker := time.NewTicker(time.Duration(5) * time.Minute)
		defer ticker.Stop()
	LOOP:
		for {
			select {
			case <-ticker.C:
				for _, db := range mysql.GetDBs().All() {
					c.checkAndAllocateController(db)
				}
			case <-sCtx.Done():
				break LOOP
			case <-c.ctx.Done():
				break LOOP
			}
		}
	}()
}

func (c *DomainChecker) checkAndAllocateController(db *mysql.DB) {
	log.Info("check domain controller health started", db.LogPrefixORGID)
	controllerIPToRegionLcuuid := make(map[string]string)
	var azCConns []*mysqlmodel.AZControllerConnection
	db.Find(&azCConns)
	for _, c := range azCConns {
		controllerIPToRegionLcuuid[c.ControllerIP] = c.Region
	}
	var controllers []*mysqlmodel.Controller
	db.Find(&controllers)
	regionLcuuidToHealthyControllerIPs := make(map[string][]string)
	for _, c := range controllers {
		if c.State == common.CONTROLLER_STATE_NORMAL {
			regionLcuuidToHealthyControllerIPs[controllerIPToRegionLcuuid[c.IP]] = append(
				regionLcuuidToHealthyControllerIPs[controllerIPToRegionLcuuid[c.IP]], c.IP,
			)
		}
	}
	log.Debug(regionLcuuidToHealthyControllerIPs, db.LogPrefixORGID)

	var domains []*mysqlmodel.Domain
	db.Find(&domains)
	for _, domain := range domains {
		config := make(map[string]interface{})
		json.Unmarshal([]byte(domain.Config), &config)
		regionLcuuid := config["region_uuid"].(string)
		healthyControllerIPs := regionLcuuidToHealthyControllerIPs[regionLcuuid]
		if !common.Contains(healthyControllerIPs, domain.ControllerIP) {
			length := len(healthyControllerIPs)
			if length > 0 {
				ip := healthyControllerIPs[rand.Intn(length)]
				domain.ControllerIP = ip
				config := make(map[string]interface{})
				json.Unmarshal([]byte(domain.Config), &config)
				config["controller_ip"] = ip
				configStr, _ := json.Marshal(config)
				domain.Config = string(configStr)
				db.Save(&domain)
				log.Infof("change domain (name: %s) controller ip to %s", domain.Name, domain.ControllerIP, db.LogPrefixORGID)
			}
		}
	}
	log.Info("check domain controller health ended", db.LogPrefixORGID)
}

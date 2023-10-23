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

package resource

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"strings"
	"time"

	uuid "github.com/satori/go.uuid"
	"gorm.io/gorm/clause"

	cloudcommon "github.com/deepflowio/deepflow/server/controller/cloud/common"
	k8s "github.com/deepflowio/deepflow/server/controller/cloud/kubernetes_gather"
	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/config"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	servicecommon "github.com/deepflowio/deepflow/server/controller/http/service/common"
	"github.com/deepflowio/deepflow/server/controller/model"
	"github.com/deepflowio/deepflow/server/controller/recorder/constraint"
)

var DOMAIN_PASSWORD_KEYS = []string{
	"admin_password", "secret_key", "password", "boss_secret_key", "manage_one_password", "token",
}

func getGrpcServerAndPort(controllerIP string, cfg *config.ControllerConfig) (string, string) {
	// get local controller ip
	localControllerIP := os.Getenv(common.NODE_IP_KEY)
	if localControllerIP == "" {
		log.Errorf("get env(%s) data failed", common.NODE_IP_KEY)
		return controllerIP, cfg.GrpcNodePort
	}

	// get controller region
	var localAZConn mysql.AZControllerConnection
	var localRegion string
	if ret := mysql.Db.Where("controller_ip = ?", localControllerIP).First(&localAZConn); ret.Error == nil {
		localRegion = localAZConn.Region
	}

	var azConn mysql.AZControllerConnection
	var region string
	if ret := mysql.Db.Where("controller_ip = ?", controllerIP).First(&azConn); ret.Error == nil {
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

func GetDomains(filter map[string]interface{}) (resp []model.Domain, err error) {
	var response []model.Domain
	var domains []mysql.Domain
	var azs []mysql.AZ
	var subDomains []mysql.SubDomain
	var controllers []mysql.Controller
	var domainLcuuids []string
	var domainToAZLcuuids map[string][]string
	var domainToRegionLcuuidsToAZLcuuids map[string](map[string][]string)
	var controllerIPToName map[string]string

	Db := mysql.Db
	if _, ok := filter["lcuuid"]; ok {
		Db = Db.Where("lcuuid = ?", filter["lcuuid"])
	}
	if _, ok := filter["name"]; ok {
		Db = Db.Where("name = ?", filter["name"])
	}
	Db.Order("created_at DESC").Find(&domains)

	for _, domain := range domains {
		domainLcuuids = append(domainLcuuids, domain.Lcuuid)
	}
	mysql.Db.Where("domain IN (?)", domainLcuuids).Find(&azs)

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

	mysql.Db.Find(&controllers)
	controllerIPToName = make(map[string]string)
	for _, controller := range controllers {
		controllerIPToName[controller.IP] = controller.Name
	}

	mysql.Db.Find(&subDomains)
	domainToSubDomainNames := make(map[string][]string)
	for _, subDomain := range subDomains {
		domainToSubDomainNames[subDomain.Domain] = append(
			domainToSubDomainNames[subDomain.Domain], subDomain.Name,
		)
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
			CreatedAt:    domain.CreatedAt.Format(common.GO_BIRTHDAY),
			SyncedAt:     syncedAt,
			Lcuuid:       domain.Lcuuid,
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

		domainResp.Config = make(map[string]interface{})
		json.Unmarshal([]byte(domain.Config), &domainResp.Config)
		for _, key := range DOMAIN_PASSWORD_KEYS {
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
			var k8sCluster mysql.KubernetesCluster
			if err = mysql.Db.Where("cluster_id = ?", domain.ClusterID).First(&k8sCluster).Error; err == nil {
				v := strings.Split(k8sCluster.Value, "-")
				if len(v) == 2 {
					var vtap mysql.VTap
					if err = mysql.Db.Where("ctrl_ip = ? AND ctrl_mac = ?", v[0], v[1]).First(&vtap).Error; err == nil {
						domainResp.VTapName = vtap.Name
						domainResp.VTapCtrlIP = vtap.CtrlIP
						domainResp.VTapCtrlMAC = vtap.CtrlMac
						domainResp.Config["vtap_id"] = vtap.Name
					}
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
		if common.Contains(DOMAIN_PASSWORD_KEYS, k) {
			info.Config[k] = "******"
		} else {
			info.Config[k] = v
		}
	}
	return info
}

func CreateDomain(domainCreate model.DomainCreate, cfg *config.ControllerConfig) (*model.Domain, error) {
	var count int64

	mysql.Db.Model(&mysql.Domain{}).Where("name = ?", domainCreate.Name).Count(&count)
	if count > 0 {
		return nil, servicecommon.NewError(common.RESOURCE_ALREADY_EXIST, fmt.Sprintf("domain (%s) already exist", domainCreate.Name))
	}

	mysql.Db.Model(&mysql.SubDomain{}).Where("name = ?", domainCreate.Name).Count(&count)
	if count > 0 {
		return nil, servicecommon.NewError(common.RESOURCE_ALREADY_EXIST, fmt.Sprintf("sub_domain (%s) already exist", domainCreate.Name))
	}

	if domainCreate.KubernetesClusterID != "" {
		mysql.Db.Model(&mysql.Domain{}).Where("cluster_id = ?", domainCreate.KubernetesClusterID).Count(&count)
		if count > 0 {
			return nil, servicecommon.NewError(common.RESOURCE_ALREADY_EXIST, fmt.Sprintf("domain cluster_id (%s) already exist", domainCreate.KubernetesClusterID))
		}

		mysql.Db.Model(&mysql.SubDomain{}).Where("cluster_id = ?", domainCreate.KubernetesClusterID).Count(&count)
		if count > 0 {
			return nil, servicecommon.NewError(common.RESOURCE_ALREADY_EXIST, fmt.Sprintf("sub_domain cluster_id (%s) already exist", domainCreate.KubernetesClusterID))
		}
	}

	log.Infof("create domain (%v)", maskDomainInfo(domainCreate))

	domain := mysql.Domain{}
	displayName := common.GetUUID(domainCreate.KubernetesClusterID, uuid.Nil)
	lcuuid := common.GetUUID(displayName, uuid.Nil)
	domain.Lcuuid = lcuuid
	domain.Name = domainCreate.Name
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
		var region mysql.Region
		res := mysql.Db.Find(&region)
		if res.RowsAffected != int64(1) {
			return nil, servicecommon.NewError(common.INVALID_PARAMETERS, fmt.Sprintf("can not find region, please specify or create one"))
		}
		domainCreate.Config["region_uuid"] = region.Lcuuid
		regionLcuuid = region.Lcuuid
	} else {
		regionLcuuid = confRegion.(string)
	}
	// TODO: controller_ip拿到config外面，直接作为domain的一级参数
	var controllerIP string
	confControllerIP, ok := domainCreate.Config["controller_ip"]
	if !ok || confControllerIP.(string) == "" {
		var azConn mysql.AZControllerConnection
		res := mysql.Db.Where("region = ?", regionLcuuid).First(&azConn)
		if res.RowsAffected != int64(1) {
			return nil, servicecommon.NewError(common.INVALID_PARAMETERS, fmt.Sprintf("can not find controller ip, please specify or create one"))
		}
		domainCreate.Config["controller_ip"] = azConn.ControllerIP
		controllerIP = azConn.ControllerIP
	} else {
		controllerIP = confControllerIP.(string)
	}
	domain.ControllerIP = controllerIP

	// encrypt password/access_key
	for _, key := range DOMAIN_PASSWORD_KEYS {
		if _, ok := domainCreate.Config[key]; ok && cfg != nil {
			serverIP, grpcServerPort := getGrpcServerAndPort(domain.ControllerIP, cfg)
			encryptKey, err := common.GetEncryptKey(
				serverIP, grpcServerPort, domainCreate.Config[key].(string),
			)
			if err != nil {
				log.Error("get encrypt key failed (%s)", err.Error())
				return nil, servicecommon.NewError(common.SERVER_ERROR, err.Error())
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
		createKubernetesRelatedResources(domain, regionLcuuid)
	}
	mysql.Db.Clauses(clause.Insert{Modifier: "IGNORE"}).Create(&domain)

	response, _ := GetDomains(map[string]interface{}{"lcuuid": lcuuid})
	return &response[0], nil
}

func createKubernetesRelatedResources(domain mysql.Domain, regionLcuuid string) {
	if regionLcuuid == "" {
		regionLcuuid = common.DEFAULT_REGION
	}
	az := mysql.AZ{}
	az.Lcuuid = cloudcommon.GetAZLcuuidFromUUIDGenerate(domain.DisplayName)
	az.Name = domain.Name
	az.Domain = domain.Lcuuid
	az.Region = regionLcuuid
	az.CreateMethod = common.CREATE_METHOD_LEARN
	err := mysql.Db.Clauses(clause.Insert{Modifier: "IGNORE"}).Create(&az).Error
	if err != nil {
		log.Errorf("create az failed: %s", err)
	}
	vpc := mysql.VPC{}
	vpc.Lcuuid = k8s.GetVPCLcuuidFromUUIDGenerate(domain.DisplayName)
	vpc.Name = domain.Name
	vpc.Domain = domain.Lcuuid
	vpc.Region = regionLcuuid
	vpc.CreateMethod = common.CREATE_METHOD_LEARN
	err = mysql.Db.Clauses(clause.Insert{Modifier: "IGNORE"}).Create(&vpc).Error
	if err != nil {
		log.Errorf("create vpc failed: %s", err)
	}
	return
}

func UpdateDomain(
	lcuuid string, domainUpdate map[string]interface{}, cfg *config.ControllerConfig,
) (*model.Domain, error) {
	var domain mysql.Domain
	var dbUpdateMap = make(map[string]interface{})

	if ret := mysql.Db.Where("lcuuid = ?", lcuuid).First(&domain); ret.Error != nil {
		return nil, servicecommon.NewError(
			common.RESOURCE_NOT_FOUND, fmt.Sprintf("domain (%s) not found", lcuuid),
		)
	}

	log.Infof("update domain (%s) config (%v)", domain.Name, domainUpdate)

	// 修改名称
	if _, ok := domainUpdate["NAME"]; ok {
		dbUpdateMap["name"] = domainUpdate["NAME"]
	}

	// 禁用/启用
	if _, ok := domainUpdate["ENABLED"]; ok {
		dbUpdateMap["enabled"] = domainUpdate["ENABLED"]
	}

	// 图标
	if _, ok := domainUpdate["ICON_ID"]; ok {
		dbUpdateMap["icon_id"] = domainUpdate["ICON_ID"]
	}

	// 控制器IP
	if _, ok := domainUpdate["CONTROLLER_IP"]; ok {
		dbUpdateMap["controller_ip"] = domainUpdate["CONTROLLER_IP"]
		domain.ControllerIP = domainUpdate["CONTROLLER_IP"].(string)
	}

	// config
	// 注意：密码相关字段因为返回是****，所以不能直接把页面更新入库
	if _, ok := domainUpdate["CONFIG"]; ok && domainUpdate["CONFIG"] != nil {
		config := make(map[string]interface{})
		json.Unmarshal([]byte(domain.Config), &config)

		configUpdate := domainUpdate["CONFIG"].(map[string]interface{})

		// 如果存在资源同步控制器IP的修改，则需要更新controller_ip字段
		if controllerIP, ok := configUpdate["controller_ip"]; ok {
			if controllerIP != domain.ControllerIP {
				dbUpdateMap["controller_ip"] = controllerIP
				domain.ControllerIP = controllerIP.(string)
			}
		}
		// 如果修改region，则清理掉云平台下所有软删除的数据
		if region, ok := configUpdate["region_uuid"]; ok {
			if region != config["region_uuid"] {
				log.Infof("delete domain (%s) soft deleted resource", domain.Name)
				cleanSoftDeletedResource(lcuuid)
			}
		}

		// transfer password/access_key
		for _, key := range DOMAIN_PASSWORD_KEYS {
			if _, ok := configUpdate[key]; ok && cfg != nil {
				if configUpdate[key] == common.DEFAULT_ENCRYPTION_PASSWORD {
					configUpdate[key] = config[key]
				} else {
					serverIP, grpcServerPort := getGrpcServerAndPort(domain.ControllerIP, cfg)
					// encrypt password/access_key
					encryptKey, err := common.GetEncryptKey(
						serverIP, grpcServerPort, configUpdate[key].(string),
					)
					if err != nil {
						log.Error(err)
						return nil, servicecommon.NewError(common.SERVER_ERROR, err.Error())
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

	// 更新domain DB
	mysql.Db.Model(&domain).Updates(dbUpdateMap)

	response, _ := GetDomains(map[string]interface{}{"lcuuid": domain.Lcuuid})
	return &response[0], nil
}

func cleanSoftDeletedResource(lcuuid string) {
	condition := "domain = ? AND deleted_at IS NOT NULL"
	log.Infof("clean soft deleted resources (domain = %s AND deleted_at IS NOT NULL) started", lcuuid)
	forceDelete[mysql.CEN](condition, lcuuid)
	forceDelete[mysql.PeerConnection](condition, lcuuid)
	forceDelete[mysql.RedisInstance](condition, lcuuid)
	forceDelete[mysql.RDSInstance](condition, lcuuid)
	forceDelete[mysql.LBListener](condition, lcuuid)
	forceDelete[mysql.LB](condition, lcuuid)
	forceDelete[mysql.NATGateway](condition, lcuuid)
	forceDelete[mysql.SecurityGroup](condition, lcuuid)
	forceDelete[mysql.DHCPPort](condition, lcuuid)
	forceDelete[mysql.VRouter](condition, lcuuid)
	forceDelete[mysql.Pod](condition, lcuuid)
	forceDelete[mysql.PodReplicaSet](condition, lcuuid)
	forceDelete[mysql.PodGroup](condition, lcuuid)
	forceDelete[mysql.PodService](condition, lcuuid)
	forceDelete[mysql.PodIngress](condition, lcuuid)
	forceDelete[mysql.PodNamespace](condition, lcuuid)
	forceDelete[mysql.PodNode](condition, lcuuid)
	forceDelete[mysql.PodCluster](condition, lcuuid)
	forceDelete[mysql.VM](condition, lcuuid)
	forceDelete[mysql.Host](condition, lcuuid)
	forceDelete[mysql.Network](condition, lcuuid)
	forceDelete[mysql.VPC](condition, lcuuid)
	forceDelete[mysql.AZ](condition, lcuuid)
	log.Info("clean soft deleted resources completed")
}

func DeleteDomainByNameOrUUID(nameOrUUID string) (map[string]string, error) {
	var domain mysql.Domain
	err1 := mysql.Db.Where("lcuuid = ?", nameOrUUID).First(&domain).Error
	var domains []mysql.Domain
	err2 := mysql.Db.Where("name = ?", nameOrUUID).Find(&domains).Error
	if err1 == nil && err2 == nil && len(domains) > 0 {
		return nil, servicecommon.NewError(
			common.PARAMETER_ILLEGAL, fmt.Sprintf("remove domain (name: %s, uuid: %s) conflict", nameOrUUID, nameOrUUID),
		)
	}
	// delete domain by lcuuid
	if err1 == nil {
		return deleteDomain(&domain)
	}

	if len(domains) > 1 {
		return nil, servicecommon.NewError(
			common.PARAMETER_ILLEGAL, fmt.Sprintf("duplicate domain (name: %s)", nameOrUUID),
		)
	}
	// delete domain by name
	if err2 == nil && len(domains) > 0 {
		return deleteDomain(&domains[0])
	}

	return nil, servicecommon.NewError(
		common.RESOURCE_NOT_FOUND, fmt.Sprintf("domain (uuid or name: %s) not found", nameOrUUID),
	)
}

func deleteDomain(domain *mysql.Domain) (map[string]string, error) { // TODO whether release resource ids
	log.Infof("delete domain (%s) resources started", domain.Name)

	lcuuid := domain.Lcuuid
	mysql.Db.Unscoped().Where("domain = ?", lcuuid).Delete(&mysql.WANIP{}) // TODO use forceDelete func
	mysql.Db.Unscoped().Where("domain = ?", lcuuid).Delete(&mysql.LANIP{})
	mysql.Db.Unscoped().Where("domain = ?", lcuuid).Delete(&mysql.FloatingIP{})
	mysql.Db.Unscoped().Where("domain = ?", lcuuid).Delete(&mysql.VInterface{})
	mysql.Db.Unscoped().Where("domain = ?", lcuuid).Delete(&mysql.CEN{})
	mysql.Db.Unscoped().Where("domain = ?", lcuuid).Delete(&mysql.PeerConnection{})
	mysql.Db.Unscoped().Where("domain = ?", lcuuid).Delete(&mysql.RedisInstance{})
	mysql.Db.Unscoped().Where("domain = ?", lcuuid).Delete(&mysql.RDSInstance{})
	mysql.Db.Unscoped().Where("domain = ?", lcuuid).Delete(&mysql.LBVMConnection{})
	mysql.Db.Unscoped().Where("domain = ?", lcuuid).Delete(&mysql.LBTargetServer{})
	mysql.Db.Unscoped().Where("domain = ?", lcuuid).Delete(&mysql.LBListener{})
	mysql.Db.Unscoped().Where("domain = ?", lcuuid).Delete(&mysql.LB{})
	mysql.Db.Unscoped().Where("domain = ?", lcuuid).Delete(&mysql.NATVMConnection{})
	mysql.Db.Unscoped().Where("domain = ?", lcuuid).Delete(&mysql.NATRule{})
	mysql.Db.Unscoped().Where("domain = ?", lcuuid).Delete(&mysql.NATGateway{})
	mysql.Db.Unscoped().Where("domain = ?", lcuuid).Delete(&mysql.Process{})
	var sgs []mysql.SecurityGroup
	// mysql.Db.Unscoped().Clauses(clause.Returning{Columns: []clause.Column{{Name: "id"}}}).Where("domain = ?", lcuuid).Delete(&sgs)
	mysql.Db.Unscoped().Where("domain = ?", lcuuid).Find(&sgs)
	sgIDs := make([]int, len(sgs))
	for _, sg := range sgs {
		sgIDs = append(sgIDs, sg.ID)
	}
	mysql.Db.Unscoped().Where("sg_id IN ?", sgIDs).Delete(&mysql.VMSecurityGroup{})
	mysql.Db.Unscoped().Where("sg_id IN ?", sgIDs).Delete(&mysql.SecurityGroupRule{})
	mysql.Db.Unscoped().Where("domain = ?", lcuuid).Delete(&mysql.SecurityGroup{})
	mysql.Db.Unscoped().Where("domain = ?", lcuuid).Delete(&mysql.DHCPPort{})
	var vRouters []mysql.VRouter
	// mysql.Db.Unscoped().Clauses(clause.Returning{Columns: []clause.Column{{Name: "id"}}}).Where("domain = ?", lcuuid).Delete(&vRouters)
	mysql.Db.Unscoped().Where("domain = ?", lcuuid).Find(&vRouters)
	vRouterIDs := make([]int, len(vRouters))
	for _, vRouter := range vRouters {
		vRouterIDs = append(vRouterIDs, vRouter.ID)
	}
	mysql.Db.Unscoped().Where("vnet_id IN ?", vRouterIDs).Delete(&mysql.RoutingTable{})
	mysql.Db.Unscoped().Where("domain = ?", lcuuid).Delete(&mysql.VRouter{})
	mysql.Db.Unscoped().Where("domain = ?", lcuuid).Delete(&mysql.VMPodNodeConnection{})
	mysql.Db.Unscoped().Where("domain = ?", lcuuid).Delete(&mysql.Pod{})
	mysql.Db.Unscoped().Where("domain = ?", lcuuid).Delete(&mysql.PodReplicaSet{})
	mysql.Db.Unscoped().Where("domain = ?", lcuuid).Delete(&mysql.PodGroup{})
	var podServices []mysql.PodService
	// mysql.Db.Unscoped().Clauses(clause.Returning{Columns: []clause.Column{{Name: "id"}}}).Where("domain = ?", lcuuid).Delete(&podServices)
	mysql.Db.Unscoped().Where("domain = ?", lcuuid).Find(&podServices)
	podServiceIDs := make([]int, len(podServices))
	for _, podService := range podServices {
		podServiceIDs = append(podServiceIDs, podService.ID)
	}
	mysql.Db.Unscoped().Where("pod_service_id IN ?", podServiceIDs).Delete(&mysql.PodServicePort{})
	mysql.Db.Unscoped().Where("pod_service_id IN ?", podServiceIDs).Delete(&mysql.PodGroupPort{})
	mysql.Db.Unscoped().Where("domain = ?", lcuuid).Delete(&mysql.PodService{})
	var podIngresses []mysql.PodIngress
	// mysql.Db.Unscoped().Clauses(clause.Returning{Columns: []clause.Column{{Name: "id"}}}).Where("domain = ?", lcuuid).Delete(&podIngresses)
	mysql.Db.Unscoped().Where("domain = ?", lcuuid).Find(&podIngresses)
	podIngressIDs := make([]int, len(podIngresses))
	for _, podIngress := range podIngresses {
		podIngressIDs = append(podIngressIDs, podIngress.ID)
	}
	mysql.Db.Unscoped().Where("pod_ingress_id IN ?", podIngressIDs).Delete(&mysql.PodIngressRule{})
	mysql.Db.Unscoped().Where("pod_ingress_id IN ?", podIngressIDs).Delete(&mysql.PodIngressRuleBackend{})
	mysql.Db.Unscoped().Where("domain = ?", lcuuid).Delete(&mysql.PodIngress{})
	mysql.Db.Unscoped().Where("domain = ?", lcuuid).Delete(&mysql.PodNamespace{})
	mysql.Db.Unscoped().Where("domain = ?", lcuuid).Delete(&mysql.PodNode{})
	mysql.Db.Unscoped().Where("domain = ?", lcuuid).Delete(&mysql.PodCluster{})
	mysql.Db.Unscoped().Where("domain = ?", lcuuid).Delete(&mysql.VM{})
	mysql.Db.Unscoped().Where("domain = ?", lcuuid).Delete(&mysql.Host{})
	var networks []mysql.Network
	// mysql.Db.Unscoped().Clauses(clause.Returning{Columns: []clause.Column{{Name: "id"}}}).Where("domain = ?", lcuuid).Delete(&networks)
	mysql.Db.Unscoped().Where("domain = ?", lcuuid).Find(&networks)
	networkIDs := make([]int, len(networks))
	for _, network := range networks {
		networkIDs = append(networkIDs, network.ID)
	}
	mysql.Db.Unscoped().Where("vl2id IN ?", networkIDs).Delete(&mysql.Subnet{})
	mysql.Db.Unscoped().Where("domain = ?", lcuuid).Delete(&mysql.Network{})
	mysql.Db.Unscoped().Where("domain = ?", lcuuid).Delete(&mysql.VPC{})
	mysql.Db.Unscoped().Where("domain = ?", lcuuid).Delete(&mysql.SubDomain{})
	mysql.Db.Unscoped().Where("domain = ?", lcuuid).Delete(&mysql.AZ{})

	mysql.Db.Delete(&domain)
	log.Infof("delete domain (%s) resources completed", domain.Name)
	return map[string]string{"LCUUID": lcuuid}, nil
}

func GetSubDomains(filter map[string]interface{}) ([]*model.SubDomain, error) {
	var response []*model.SubDomain
	var subDomains []mysql.SubDomain
	var vpcs []mysql.VPC

	Db := mysql.Db
	if _, ok := filter["lcuuid"]; ok {
		Db = Db.Where("lcuuid = ?", filter["lcuuid"])
	}
	if _, ok := filter["domain"]; ok {
		Db = Db.Where("domain = ?", filter["domain"])
	}
	if _, ok := filter["cluster_id"]; ok {
		Db = Db.Where("cluster_id = ?", filter["cluster_id"])
	}
	Db.Order("created_at DESC").Find(&subDomains)

	mysql.Db.Select("name", "lcuuid").Find(&vpcs)
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
		}

		subDomainResp.Config = make(map[string]interface{})
		json.Unmarshal([]byte(subDomain.Config), &subDomainResp.Config)

		if _, ok := subDomainResp.Config["vpc_uuid"]; ok {
			vpcLcuuid := subDomainResp.Config["vpc_uuid"].(string)
			if _, ok := lcuuidToVPCName[vpcLcuuid]; ok {
				subDomainResp.VPCName = lcuuidToVPCName[vpcLcuuid]
			}
		}

		var k8sCluster mysql.KubernetesCluster
		if err := mysql.Db.Where("cluster_id = ?", subDomain.ClusterID).First(&k8sCluster).Error; err == nil {
			v := strings.Split(k8sCluster.Value, "-")
			if len(v) == 2 {
				var vtap mysql.VTap
				if err = mysql.Db.Where("ctrl_ip = ? AND ctrl_mac = ?", v[0], v[1]).First(&vtap).Error; err == nil {
					subDomainResp.Config["vtap_id"] = vtap.Name
				}
			}
		}

		// get domain name
		var domain mysql.Domain
		if err := mysql.Db.Where("lcuuid = ?", subDomain.Domain).First(&domain).Error; err != nil {
			log.Error(err)
		}
		subDomainResp.DomainName = domain.Name

		response = append(response, &subDomainResp)
	}
	return response, nil
}

func CreateSubDomain(subDomainCreate model.SubDomainCreate) (*model.SubDomain, error) {
	var domainCount int64
	if err := mysql.Db.Model(&mysql.Domain{}).Where("lcuuid = ?", subDomainCreate.Domain).Count(&domainCount).Error; err != nil {
		return nil, err
	}
	if domainCount == 0 {
		return nil, servicecommon.NewError(common.RESOURCE_NOT_FOUND, fmt.Sprintf("domain lcuuid (%s) does not exit", subDomainCreate.Domain))
	}

	var count int64
	mysql.Db.Model(&mysql.SubDomain{}).Where("name = ?", subDomainCreate.Name).Count(&count)
	if count > 0 {
		return nil, servicecommon.NewError(common.RESOURCE_ALREADY_EXIST, fmt.Sprintf("sub_domain (%s) already exist", subDomainCreate.Name))
	}

	log.Infof("create sub_domain (%v)", subDomainCreate)

	subDomain := mysql.SubDomain{}
	displayName := common.GetUUID("", uuid.Nil)
	lcuuid := common.GetUUID(displayName, uuid.Nil)
	subDomain.Lcuuid = lcuuid
	subDomain.Name = subDomainCreate.Name
	subDomain.DisplayName = displayName
	subDomain.CreateMethod = common.CREATE_METHOD_USER_DEFINE
	subDomain.ClusterID = "d-" + common.GenerateShortUUID()
	subDomain.Domain = subDomainCreate.Domain
	configStr, _ := json.Marshal(subDomainCreate.Config)
	subDomain.Config = string(configStr)
	mysql.Db.Create(&subDomain)

	response, _ := GetSubDomains(map[string]interface{}{"lcuuid": lcuuid})
	return response[0], nil
}

func UpdateSubDomain(lcuuid string, subDomainUpdate map[string]interface{}) (*model.SubDomain, error) {
	if _, ok := subDomainUpdate["NAME"]; ok {
		return nil, errors.New("name field cannot be modified")
	}
	if _, ok := subDomainUpdate["DOMAIN_NAME"]; ok {
		return nil, errors.New("domain_name field cannot be modified")
	}
	var subDomain mysql.SubDomain
	var dbUpdateMap = make(map[string]interface{})

	if ret := mysql.Db.Where("lcuuid = ?", lcuuid).First(&subDomain); ret.Error != nil {
		return nil, servicecommon.NewError(
			common.RESOURCE_NOT_FOUND, fmt.Sprintf("sub_domain (%s) not found", lcuuid),
		)
	}

	log.Infof("update sub_domain (%s) config (%v)", subDomain.Name, subDomainUpdate)

	// config
	if _, ok := subDomainUpdate["CONFIG"]; ok {
		configStr, _ := json.Marshal(subDomainUpdate["CONFIG"])
		dbUpdateMap["config"] = string(configStr)
	}

	// 更新domain DB
	mysql.Db.Model(&subDomain).Updates(dbUpdateMap)

	response, _ := GetSubDomains(map[string]interface{}{"lcuuid": lcuuid})
	return response[0], nil
}

func DeleteSubDomain(lcuuid string) (map[string]string, error) {
	var subDomain mysql.SubDomain
	if ret := mysql.Db.Where("lcuuid = ?", lcuuid).First(&subDomain); ret.Error != nil {
		return nil, servicecommon.NewError(
			common.RESOURCE_NOT_FOUND, fmt.Sprintf("sub_domain (%s) not found", lcuuid),
		)
	}
	log.Infof("delete sub_domain (%s) resources started", subDomain.Name)

	var podCluster mysql.PodCluster
	mysql.Db.Unscoped().Where("lcuuid = ?", lcuuid).Find(&podCluster)
	// TODO debug为什么此处赋值在mysql中没生效
	// mysql.Db.Unscoped().Clauses(clause.Returning{Columns: []clause.Column{{Name: "id"}}}).Where("lcuuid = ?", lcuuid).Delete(&podCluster)
	log.Info(podCluster)
	if podCluster.ID != 0 {
		log.Infof("delete pod_cluster (%+v) resources", podCluster)
		mysql.Db.Unscoped().Where("sub_domain = ?", lcuuid).Delete(&mysql.WANIP{}) // TODO use forceDelete func
		mysql.Db.Unscoped().Where("sub_domain = ?", lcuuid).Delete(&mysql.LANIP{})
		mysql.Db.Unscoped().Where("sub_domain = ?", lcuuid).Delete(&mysql.VInterface{})
		mysql.Db.Unscoped().Where("sub_domain = ?", lcuuid).Delete(&mysql.Subnet{})
		mysql.Db.Unscoped().Where("sub_domain = ?", lcuuid).Delete(&mysql.Network{})
		mysql.Db.Unscoped().Where("sub_domain = ?", lcuuid).Delete(&mysql.VMPodNodeConnection{})
		mysql.Db.Unscoped().Where("sub_domain = ?", lcuuid).Delete(&mysql.Pod{})
		mysql.Db.Unscoped().Where("sub_domain = ?", lcuuid).Delete(&mysql.PodReplicaSet{})
		mysql.Db.Unscoped().Where("sub_domain = ?", lcuuid).Delete(&mysql.PodGroupPort{})
		mysql.Db.Unscoped().Where("sub_domain = ?", lcuuid).Delete(&mysql.PodGroup{})
		mysql.Db.Unscoped().Where("sub_domain = ?", lcuuid).Delete(&mysql.PodServicePort{})
		mysql.Db.Unscoped().Where("sub_domain = ?", lcuuid).Delete(&mysql.PodService{})
		mysql.Db.Unscoped().Where("sub_domain = ?", lcuuid).Delete(&mysql.PodIngressRuleBackend{})
		mysql.Db.Unscoped().Where("sub_domain = ?", lcuuid).Delete(&mysql.PodIngressRule{})
		mysql.Db.Unscoped().Where("sub_domain = ?", lcuuid).Delete(&mysql.PodIngress{})
		mysql.Db.Unscoped().Where("sub_domain = ?", lcuuid).Delete(&mysql.PodNamespace{})
		mysql.Db.Unscoped().Where("sub_domain = ?", lcuuid).Delete(&mysql.PodNode{})
		mysql.Db.Unscoped().Where("sub_domain = ?", lcuuid).Delete(&mysql.PodCluster{})
		mysql.Db.Unscoped().Where("sub_domain = ?", lcuuid).Delete(&mysql.Process{})
	}

	mysql.Db.Delete(&subDomain)
	log.Infof("delete sub_domain (%s) resources completed", subDomain.Name)
	return map[string]string{"LCUUID": lcuuid}, nil
}

func forceDelete[MT constraint.MySQLSoftDeleteModel](query interface{}, args ...interface{}) { // TODO common func
	err := mysql.Db.Unscoped().Where(query, args...).Delete(new(MT)).Error
	if err != nil {
		log.Errorf("mysql delete resource: %v %v failed: %s", query, args, err)
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

func (c *DomainChecker) Start() {
	log.Info("domain check startted")
	c.TimedCheck()
}

func (c *DomainChecker) Stop() {
	if c.cancel != nil {
		c.cancel()
	}
	log.Info("domain check stopped")
}

func (c *DomainChecker) TimedCheck() {
	c.checkAndAllocateController()
	go func() {
		for range time.Tick(time.Duration(5) * time.Minute) {
			c.checkAndAllocateController()
		}
	}()
}

func (c *DomainChecker) checkAndAllocateController() {
	log.Infof("check domain controller health started")
	controllerIPToRegionLcuuid := make(map[string]string)
	var azCConns []*mysql.AZControllerConnection
	mysql.Db.Find(&azCConns)
	for _, c := range azCConns {
		controllerIPToRegionLcuuid[c.ControllerIP] = c.Region
	}
	var controllers []*mysql.Controller
	mysql.Db.Find(&controllers)
	regionLcuuidToHealthyControllerIPs := make(map[string][]string)
	for _, c := range controllers {
		if c.State == common.CONTROLLER_STATE_NORMAL {
			regionLcuuidToHealthyControllerIPs[controllerIPToRegionLcuuid[c.IP]] = append(
				regionLcuuidToHealthyControllerIPs[controllerIPToRegionLcuuid[c.IP]], c.IP,
			)
		}
	}
	log.Debug(regionLcuuidToHealthyControllerIPs)

	var domains []*mysql.Domain
	mysql.Db.Find(&domains)
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
				mysql.Db.Save(&domain)
				log.Infof("change domain (name: %s) controller ip to %s", domain.Name, domain.ControllerIP)
			}
		}
	}
}

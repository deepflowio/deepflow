package service

import (
	"encoding/json"
	"fmt"
	"server/controller/common"
	"server/controller/db/mysql"
	"server/controller/model"

	"github.com/google/uuid"
	"gorm.io/gorm/clause"
)

func GetDomains(filter map[string]interface{}) (resp []model.Domain, err error) {
	var response []model.Domain
	var domains []mysql.Domain
	var azs []mysql.AZ
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
			regionToAZLcuuids := map[string][]string{az.Region: []string{az.Lcuuid}}
			domainToRegionLcuuidsToAZLcuuids[az.Domain] = regionToAZLcuuids
		}
	}

	mysql.Db.Find(&controllers)
	controllerIPToName = make(map[string]string)
	for _, controller := range controllers {
		controllerIPToName[controller.IP] = controller.Name
	}

	for _, domain := range domains {
		syncedAt := ""
		if domain.SyncedAt != nil {
			syncedAt = domain.SyncedAt.Format(common.GO_BIRTHDAY)
		}
		domainResp := model.Domain{
			ID:           domain.ID,
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
		if domain.Type != common.KUBERNETES {
			domainResp.K8sEnabled = 1
		}
		// TODO: 后续与前端沟通，更换字段为PodClusterCount
		domainResp.PodClusters = []interface{}{}

		domainResp.Config = make(map[string]interface{})
		json.Unmarshal([]byte(domain.Config), &domainResp.Config)

		response = append(response, domainResp)
	}
	return response, nil
}

func CreateDomain(domainCreate model.DomainCreate) (*model.Domain, error) {
	var count int64

	mysql.Db.Model(&mysql.Domain{}).Where("name = ?", domainCreate.Name).Count(&count)
	if count > 0 {
		return nil, NewError(common.RESOURCE_ALREADY_EXIST, fmt.Sprintf("domain (%s) already exist", domainCreate.Name))
	}

	mysql.Db.Model(&mysql.SubDomain{}).Where("name = ?", domainCreate.Name).Count(&count)
	if count > 0 {
		return nil, NewError(common.RESOURCE_ALREADY_EXIST, fmt.Sprintf("sub_domain (%s) already exist", domainCreate.Name))
	}

	log.Infof("create domain (%v)", domainCreate)

	domain := mysql.Domain{}
	lcuuid := uuid.New().String()
	domain.Lcuuid = lcuuid
	domain.Name = domainCreate.Name
	domain.DisplayName = lcuuid
	domain.Type = domainCreate.Type
	domain.IconID = domainCreate.IconID
	// TODO: controller_ip拿到config外面，直接作为domain的一级参数
	domain.ControllerIP = domainCreate.Config["controller_ip"].(string)
	if domainCreate.Type == common.KUBERNETES {
		domain.ClusterID = "d-" + common.GenerateShortUUID()
	}
	configStr, _ := json.Marshal(domainCreate.Config)
	domain.Config = string(configStr)
	mysql.Db.Create(&domain)

	// TODO: K8s云平台额外优先添加region和az数据库表，后续考虑放到exchange中

	response, _ := GetDomains(map[string]interface{}{"lcuuid": lcuuid})
	return &response[0], nil
}

func UpdateDomain(lcuuid string, domainUpdate map[string]interface{}) (*model.Domain, error) {
	var domain mysql.Domain
	var dbUpdateMap = make(map[string]interface{})

	if ret := mysql.Db.Where("lcuuid = ?", lcuuid).First(&domain); ret.Error != nil {
		return nil, NewError(
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
	}

	// config
	// 注意：密码相关字段因为返回是****，所以不能直接把页面更新入库
	if _, ok := domainUpdate["CONFIG"]; ok {
		config := make(map[string]interface{})
		json.Unmarshal([]byte(domain.Config), &config)

		configUpdate := domainUpdate["CONFIG"].(map[string]interface{})
		for _, key := range []string{
			"admin_password", "secret_key", "password", "boss_secret_key",
		} {
			if _, ok := configUpdate[key]; ok {
				if configUpdate[key] == common.DEFAULT_ENCRYPTION_PASSWORD {
					configUpdate[key] = config[key]
				}
			}
		}
		// 如果存在资源同步控制器IP的修改，则需要更新controller_ip字段
		if controllerIP, ok := configUpdate["controller_ip"]; ok {
			if controllerIP != domain.ControllerIP {
				dbUpdateMap["controller_ip"] = controllerIP
			}
		}
		configStr, _ := json.Marshal(domainUpdate["CONFIG"])
		dbUpdateMap["config"] = string(configStr)
	}

	// 更新domain DB
	mysql.Db.Model(&domain).Updates(dbUpdateMap)

	response, _ := GetDomains(map[string]interface{}{"lcuuid": domain.Lcuuid})
	return &response[0], nil
}

func DeleteDomain(lcuuid string) (map[string]string, error) {
	var domain mysql.Domain

	if ret := mysql.Db.Where("lcuuid = ?", lcuuid).First(&domain); ret.Error != nil {
		return nil, NewError(
			common.RESOURCE_NOT_FOUND, fmt.Sprintf("domain (%s) not found", lcuuid),
		)
	}

	log.Infof("delete domain (%s)", domain.Name)

	mysql.Db.Unscoped().Where("domain = ?", lcuuid).Delete(&mysql.WANIP{})
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
	var sgs []mysql.SecurityGroup
	mysql.Db.Unscoped().Clauses(clause.Returning{Columns: []clause.Column{{Name: "id"}}}).Where("domain = ?", lcuuid).Delete(&sgs)
	sgIDs := make([]int, len(sgs))
	for _, sg := range sgs {
		sgIDs = append(sgIDs, sg.ID)
	}
	mysql.Db.Unscoped().Where("sg_id IN ?", sgIDs).Delete(&mysql.VMSecurityGroup{})
	mysql.Db.Unscoped().Where("sg_id IN ?", sgIDs).Delete(&mysql.SecurityGroupRule{})
	mysql.Db.Unscoped().Where("domain = ?", lcuuid).Delete(&mysql.SecurityGroup{})
	mysql.Db.Unscoped().Where("domain = ?", lcuuid).Delete(&mysql.DHCPPort{})
	var vRouters []mysql.VRouter
	mysql.Db.Unscoped().Clauses(clause.Returning{Columns: []clause.Column{{Name: "id"}}}).Where("domain = ?", lcuuid).Delete(&vRouters)
	vRouterIDs := make([]int, len(vRouters))
	for _, vRouter := range vRouters {
		vRouterIDs = append(vRouterIDs, vRouter.ID)
	}
	mysql.Db.Unscoped().Where("vnet_id IN ?", vRouterIDs).Delete(&mysql.RoutingTable{})
	mysql.Db.Unscoped().Where("domain = ?", lcuuid).Delete(&mysql.VMPodNodeConnection{})
	mysql.Db.Unscoped().Where("domain = ?", lcuuid).Delete(&mysql.Pod{})
	mysql.Db.Unscoped().Where("domain = ?", lcuuid).Delete(&mysql.PodReplicaSet{})
	mysql.Db.Unscoped().Where("domain = ?", lcuuid).Delete(&mysql.PodGroup{})
	var podServices []mysql.PodService
	mysql.Db.Unscoped().Clauses(clause.Returning{Columns: []clause.Column{{Name: "id"}}}).Where("domain = ?", lcuuid).Delete(&podServices)
	podServiceIDs := make([]int, len(podServices))
	for _, podService := range podServices {
		podServiceIDs = append(podServiceIDs, podService.ID)
	}
	mysql.Db.Unscoped().Where("pod_service_id IN ?", podServiceIDs).Delete(&mysql.PodServicePort{})
	mysql.Db.Unscoped().Where("pod_service_id IN ?", podServiceIDs).Delete(&mysql.PodGroupPort{})
	var podIngresses []mysql.PodIngress
	mysql.Db.Unscoped().Clauses(clause.Returning{Columns: []clause.Column{{Name: "id"}}}).Where("domain = ?", lcuuid).Delete(&podIngresses)
	podIngressIDs := make([]int, len(podIngresses))
	for _, podIngress := range podIngresses {
		podIngressIDs = append(podIngressIDs, podIngress.ID)
	}
	mysql.Db.Unscoped().Where("pod_ingress_id IN ?", podIngressIDs).Delete(&mysql.PodIngressRule{})
	mysql.Db.Unscoped().Where("pod_ingress_id IN ?", podIngressIDs).Delete(&mysql.PodIngressRuleBackend{})
	mysql.Db.Unscoped().Where("domain = ?", lcuuid).Delete(&mysql.PodNamespace{})
	mysql.Db.Unscoped().Where("domain = ?", lcuuid).Delete(&mysql.PodNode{})
	mysql.Db.Unscoped().Where("domain = ?", lcuuid).Delete(&mysql.PodCluster{})
	mysql.Db.Unscoped().Where("domain = ?", lcuuid).Delete(&mysql.VM{})
	mysql.Db.Unscoped().Where("domain = ?", lcuuid).Delete(&mysql.Host{})
	var networks []mysql.Network
	mysql.Db.Unscoped().Clauses(clause.Returning{Columns: []clause.Column{{Name: "id"}}}).Where("domain = ?", lcuuid).Delete(&networks)
	networkIDs := make([]int, len(networks))
	for _, network := range networks {
		networkIDs = append(networkIDs, network.ID)
	}
	mysql.Db.Unscoped().Where("vl2id IN ?", networkIDs).Delete(&mysql.Subnet{})
	mysql.Db.Unscoped().Where("domain = ?", lcuuid).Delete(&mysql.VPC{})
	mysql.Db.Unscoped().Where("domain = ?", lcuuid).Delete(&mysql.SubDomain{})
	mysql.Db.Unscoped().Where("domain = ?", lcuuid).Delete(&mysql.AZ{})

	mysql.Db.Delete(&domain)
	return map[string]string{"LCUUID": lcuuid}, nil
}

func GetSubDomains(filter map[string]interface{}) ([]model.SubDomain, error) {
	var response []model.SubDomain
	var subDomains []mysql.SubDomain
	var vpcs []mysql.VPC

	Db := mysql.Db
	if _, ok := filter["lcuuid"]; ok {
		Db = Db.Where("lcuuid = ?", filter["lcuuid"])
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
		response = append(response, subDomainResp)
	}
	return response, nil
}

func CreateSubDomain(subDomainCreate model.SubDomainCreate) (*model.SubDomain, error) {
	var count int64

	mysql.Db.Model(&mysql.SubDomain{}).Where("name = ?", subDomainCreate.Name).Count(&count)
	if count > 0 {
		return nil, NewError(common.RESOURCE_ALREADY_EXIST, fmt.Sprintf("sub_domain (%s) already exist", subDomainCreate.Name))
	}

	log.Infof("create sub_domain (%v)", subDomainCreate)

	subDomain := mysql.SubDomain{}
	lcuuid := uuid.New().String()
	subDomain.Lcuuid = lcuuid
	subDomain.Name = subDomainCreate.Name
	subDomain.DisplayName = lcuuid
	subDomain.CreateMethod = common.CREATE_METHOD_USER_DEFINE
	subDomain.ClusterID = "d-" + common.GenerateShortUUID()
	configStr, _ := json.Marshal(subDomainCreate.Config)
	subDomain.Config = string(configStr)
	mysql.Db.Create(&subDomain)

	response, _ := GetSubDomains(map[string]interface{}{"lcuuid": lcuuid})
	return &response[0], nil
}

func UpdateSubDomain(lcuuid string, subDomainUpdate map[string]interface{}) (*model.SubDomain, error) {
	var subDomain mysql.SubDomain
	var dbUpdateMap = make(map[string]interface{})

	if ret := mysql.Db.Where("lcuuid = ?", lcuuid).First(&subDomain); ret.Error != nil {
		return nil, NewError(
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
	return &response[0], nil
}

func DeleteSubDomain(lcuuid string) (map[string]string, error) {
	var subDomain mysql.SubDomain

	if ret := mysql.Db.Where("lcuuid = ?", lcuuid).First(&subDomain); ret.Error != nil {
		return nil, NewError(
			common.RESOURCE_NOT_FOUND, fmt.Sprintf("sub_domain (%s) not found", lcuuid),
		)
	}

	log.Infof("delete sub_domain (%s)", subDomain.Name)

	var podCluster mysql.PodCluster
	mysql.Db.Unscoped().Clauses(clause.Returning{Columns: []clause.Column{{Name: "id"}}}).Where("lcuuid = ?", lcuuid).Delete(&podCluster)
	if podCluster.ID != 0 {
		mysql.Db.Unscoped().Where("sub_domain = ?", lcuuid).Delete(&mysql.WANIP{})
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
	}

	mysql.Db.Delete(&subDomain)
	return map[string]string{"LCUUID": lcuuid}, nil
}

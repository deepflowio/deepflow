package cloud

import (
	"context"
	"sync"
	"time"

	mapset "github.com/deckarep/golang-set"
	logging "github.com/op/go-logging"

	"server/controller/cloud/config"
	"server/controller/cloud/model"
	"server/controller/common"
	"server/controller/db/mysql"
)

var log = logging.MustGetLogger("cloud")

type Platform interface {
	CheckAuth() error
	GetCloudData() (model.Resource, error)
}

type Cloud struct {
	cfg                     config.CloudConfig
	cCtx                    context.Context
	cCancel                 context.CancelFunc
	mutex                   sync.RWMutex
	basicInfo               model.BasicInfo
	resource                model.Resource
	platform                Platform
	kubernetesGatherTaskMap map[string]*KubernetesGatherTask
}

// TODO 添加参数
func NewCloud(domain mysql.Domain, interval int, platform Platform, cfg config.CloudConfig, ctx context.Context) *Cloud {
	cCtx, cCancel := context.WithCancel(ctx)
	return &Cloud{
		basicInfo: model.BasicInfo{
			Lcuuid:   domain.Lcuuid,
			Name:     domain.Name,
			Type:     domain.Type,
			Interval: time.Duration(interval),
		},
		platform:                platform,
		kubernetesGatherTaskMap: make(map[string]*KubernetesGatherTask),
		cfg:                     cfg,
		cCtx:                    cCtx,
		cCancel:                 cCancel,
	}
}

func (c *Cloud) Start() {
	go c.run()
	go c.runKubernetesGatherTask()
}

func (c *Cloud) Stop() {
	if c.cCancel != nil {
		c.cCancel()
	}
}

func (c *Cloud) UpdateBasicInfoName(name string) {
	c.basicInfo.Name = name
}

func (c *Cloud) GetBasicInfo() model.BasicInfo {
	return c.basicInfo
}

func (c *Cloud) GetResource() model.Resource {
	return c.resource
}

func (c *Cloud) GetKubernetesGatherTaskMap() map[string]*KubernetesGatherTask {
	return c.kubernetesGatherTaskMap
}

func (c *Cloud) getCloudData() {
	if c.basicInfo.Type != common.KUBERNETES {
		var err error
		c.resource, err = c.platform.GetCloudData()
		// 这里因为任务内部没有对成功的状态赋值状态码，在这里统一处理了
		if err != nil {
			c.resource.ErrorMessage = err.Error()
			if c.resource.ErrorState == 0 {
				c.resource.ErrorState = common.RESOURCE_STATE_CODE_EXCEPTION
			}
		} else {
			c.resource.ErrorState = common.RESOURCE_STATE_CODE_SUCCESS
		}
		c.getSubDomainData()
	} else {
		c.getKubernetesData()
	}
}

func (c *Cloud) run() {
	log.Infof("cloud (%s) started", c.basicInfo.Name)

	if err := c.platform.CheckAuth(); err != nil {
		log.Error("cloud (%s) check auth failed", c.basicInfo)
	}

	ticker := time.NewTicker(time.Second * c.basicInfo.Interval)
LOOP:
	for {
		select {
		case <-ticker.C:
			log.Infof("cloud (%s) assemble data starting", c.basicInfo.Name)
			c.getCloudData()
			log.Infof("cloud (%s) assemble data complete", c.basicInfo.Name)
		case <-c.cCtx.Done():
			break LOOP
		}
	}
	log.Infof("cloud (%s) stopped", c.basicInfo.Name)
	ticker.Stop()
}

func (c *Cloud) runKubernetesGatherTask() {
	go func() {
		for range time.Tick(time.Duration(c.cfg.KubernetesGatherInterval) * time.Second) {
			if c.basicInfo.Type == common.KUBERNETES {
				// Kubernetes平台，只会有一个KubernetesGatherTask
				// - 如果已存在KubernetesGatherTask，则无需启动新的Task
				// Kubernetes平台，无需考虑KubernetesGatherTask的更新/删除，会在Cloud层面统一处理
				if len(c.kubernetesGatherTaskMap) != 0 {
					continue
				}
				var domains []mysql.Domain
				mysql.Db.Where("lcuuid = ?", c.basicInfo.Lcuuid).Find(&domains)
				if len(domains) == 0 {
					continue
				}
				domain := domains[0]
				kubernetesGatherTask := NewKubernetesGatherTask(&domain, nil, c.cCtx, false)
				if kubernetesGatherTask == nil {
					continue
				}
				c.mutex.Lock()
				c.kubernetesGatherTaskMap[domain.Lcuuid] = kubernetesGatherTask
				c.kubernetesGatherTaskMap[domain.Lcuuid].Start()
				c.mutex.Unlock()

			} else {
				// 附属容器集群的处理
				var subDomains []mysql.SubDomain
				var oldSubDomains = mapset.NewSet()
				var newSubDomains = mapset.NewSet()
				var delSubDomains = mapset.NewSet()
				var addSubDomains = mapset.NewSet()
				var intersectSubDomains = mapset.NewSet()

				for lcuuid := range c.kubernetesGatherTaskMap {
					oldSubDomains.Add(lcuuid)
				}

				mysql.Db.Where("domain = ?", c.basicInfo.Lcuuid).Find(&subDomains)
				lcuuidToSubDomain := make(map[string]*mysql.SubDomain)
				for index, subDomain := range subDomains {
					lcuuidToSubDomain[subDomain.Lcuuid] = &subDomains[index]
					newSubDomains.Add(subDomain.Lcuuid)
				}

				// 对于删除的subDomain，停止Task，并移除管理
				delSubDomains = oldSubDomains.Difference(newSubDomains)
				for _, subDomain := range delSubDomains.ToSlice() {
					lcuuid := subDomain.(string)
					c.kubernetesGatherTaskMap[lcuuid].Stop()
					c.mutex.Lock()
					delete(c.kubernetesGatherTaskMap, lcuuid)
					c.mutex.Unlock()
				}

				// 对于新增的subDomain，启动Task，并纳入Manger管理
				addSubDomains = newSubDomains.Difference(oldSubDomains)
				for _, subDomain := range addSubDomains.ToSlice() {
					lcuuid := subDomain.(string)
					kubernetesGatherTask := NewKubernetesGatherTask(
						nil, lcuuidToSubDomain[lcuuid], c.cCtx, true)
					if kubernetesGatherTask == nil {
						continue
					}
					c.mutex.Lock()
					c.kubernetesGatherTaskMap[lcuuid] = kubernetesGatherTask
					c.kubernetesGatherTaskMap[lcuuid].Start()
					c.mutex.Unlock()
				}

				// 检查已有subDomain是否存在配置修改
				// 如果存在配置修改，则停止已有Task，并移除管理；同时启动新的Task，并纳入Cloud管理
				intersectSubDomains = newSubDomains.Intersect(oldSubDomains)
				for _, subDomain := range intersectSubDomains.ToSlice() {
					lcuuid := subDomain.(string)
					oldSubDomainConfig := c.kubernetesGatherTaskMap[lcuuid].SubDomainConfig
					newSubDomainConfig := lcuuidToSubDomain[lcuuid].Config
					if oldSubDomainConfig != newSubDomainConfig {
						log.Infof("oldSubDomainConfig: %s", oldSubDomainConfig)
						log.Infof("newSubDomainConfig: %s", newSubDomainConfig)
						c.kubernetesGatherTaskMap[lcuuid].Stop()
						kubernetesGatherTask := NewKubernetesGatherTask(
							nil, lcuuidToSubDomain[lcuuid], c.cCtx, true)
						if kubernetesGatherTask == nil {
							continue
						}

						c.mutex.Lock()
						delete(c.kubernetesGatherTaskMap, lcuuid)
						c.kubernetesGatherTaskMap[lcuuid] = kubernetesGatherTask
						c.kubernetesGatherTaskMap[lcuuid].Start()
						c.mutex.Unlock()
					}
				}
			}
		}
	}()
}

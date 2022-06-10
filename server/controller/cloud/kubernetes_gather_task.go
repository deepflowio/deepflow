package cloud

import (
	"context"
	"time"

	"server/controller/cloud/kubernetes_gather"
	kubernetes_gather_model "server/controller/cloud/kubernetes_gather/model"
	"server/controller/db/mysql"
)

type KubernetesGatherTask struct {
	kCtx             context.Context
	kCancel          context.CancelFunc
	kubernetesGather *kubernetes_gather.KubernetesGather
	resource         kubernetes_gather_model.KubernetesGatherResource
	basicInfo        kubernetes_gather_model.KubernetesGatherBasicInfo
	SubDomainConfig  string // 附属容器集群配置字段config
}

func NewKubernetesGatherTask(
	domain *mysql.Domain, subDomain *mysql.SubDomain, ctx context.Context,
) *KubernetesGatherTask {
	kubernetesGather := kubernetes_gather.NewKubernetesGather(domain, subDomain)
	if kubernetesGather == nil {
		log.Errorf("kubernetes_gather (%s) task init faild", subDomain.Name)
		return nil
	}
	subDomainConfig := ""
	if subDomain != nil {
		subDomainConfig = subDomain.Config
	}

	kCtx, kCancel := context.WithCancel(ctx)
	return &KubernetesGatherTask{
		basicInfo: kubernetes_gather_model.KubernetesGatherBasicInfo{
			Name:                  kubernetesGather.Name,
			ClusterID:             kubernetesGather.ClusterID,
			PortNameRegex:         kubernetesGather.PortNameRegex,
			PodNetIPv4CIDRMaxMask: kubernetesGather.PodNetIPv4CIDRMaxMask,
			PodNetIPv6CIDRMaxMask: kubernetesGather.PodNetIPv6CIDRMaxMask,
		},
		kCtx:             kCtx,
		kCancel:          kCancel,
		kubernetesGather: kubernetesGather,
		SubDomainConfig:  subDomainConfig,
	}
}

func (k *KubernetesGatherTask) GetBasicInfo() kubernetes_gather_model.KubernetesGatherBasicInfo {
	return k.basicInfo
}

func (k *KubernetesGatherTask) GetResource() kubernetes_gather_model.KubernetesGatherResource {
	return k.resource
}

func (k *KubernetesGatherTask) Start() {
	go func() {
		// TODO 配置时间间隔
		ticker := time.NewTicker(time.Minute)
	LOOP:
		for {
			select {
			case <-ticker.C:
				log.Infof("kubernetes gather (%s) assemble data starting", k.kubernetesGather.Name)
				k.resource, _ = k.kubernetesGather.GetKubernetesGatherData()
				log.Infof("kubernetes gather (%s) assemble data complete", k.kubernetesGather.Name)
			case <-k.kCtx.Done():
				break LOOP
			}
		}
	}()
}

func (k *KubernetesGatherTask) Stop() {
	if k.kCancel != nil {
		k.kCancel()
	}
}

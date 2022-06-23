package manager

import (
	"context"
	"time"

	"server/controller/cloud"
	"server/controller/cloud/aliyun"
	"server/controller/cloud/baidubce"
	"server/controller/cloud/genesis"
	"server/controller/cloud/kubernetes"
	"server/controller/cloud/qingcloud"
	"server/controller/common"
	"server/controller/db/mysql"
	"server/controller/manager/config"
	"server/controller/recorder"
)

type Task struct {
	tCtx         context.Context
	tCancel      context.CancelFunc
	cfg          config.TaskConfig
	Cloud        *cloud.Cloud
	Recorder     *recorder.Recorder
	DomainName   string // 云平台名称
	DomainConfig string // 云平台配置字段config
}

func NewTask(domain mysql.Domain, cfg config.TaskConfig, ctx context.Context) *Task {
	var platform cloud.Platform
	var err error

	// FIXME task本身不关心platform，生成后仅供NewCloud使用，可将此逻辑移入NewCloud中
	switch domain.Type {
	case common.ALIYUN:
		platform, err = aliyun.NewAliyun(domain)
	case common.GENESIS:
		platform, err = genesis.NewGenesis(domain, cfg.CloudCfg)
	case common.QINGCLOUD:
		platform, err = qingcloud.NewQingCloud(domain)
	case common.BAIDU_BCE:
		platform, err = baidubce.NewBaiduBce(domain)
	case common.KUBERNETES:
		platform, err = kubernetes.NewKubernetes(domain)
	// TODO: 其他云平台
	default:
		return nil
	}
	if err != nil {
		return nil
	}

	log.Infof("task (%s) init success", domain.Name)

	tCtx, tCancel := context.WithCancel(ctx)
	return &Task{
		tCtx:         tCtx,
		tCancel:      tCancel,
		cfg:          cfg,
		Cloud:        cloud.NewCloud(domain, 60, platform, cfg.CloudCfg, tCtx),
		Recorder:     recorder.NewRecorder(domain.Lcuuid, cfg.RecorderCfg, tCtx),
		DomainName:   domain.Name,
		DomainConfig: domain.Config,
	}
}

func (t *Task) Start() {
	t.Recorder.Start()
	t.Cloud.Start()

	go func() {
		ticker := time.NewTicker(time.Duration(t.cfg.ResourceRecorderInterval) * time.Second)
	LOOP:
		for {
			select {
			case <-ticker.C:
				t.Recorder.Refresh(t.Cloud.GetResource())
			case <-t.tCtx.Done():
				break LOOP
			}
		}
	}()
}

func (t *Task) Stop() {
	if t.tCancel != nil {
		t.tCancel()
	}
	log.Infof("task (%s) stopped", t.DomainName)
}

func (t *Task) UpdateDomainName(name string) {
	t.DomainName = name
	t.Cloud.UpdateBasicInfoName(name)
}

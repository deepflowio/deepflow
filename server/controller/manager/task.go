package manager

import (
	"context"
	"time"

	"github.com/metaflowys/metaflow/server/controller/cloud"
	"github.com/metaflowys/metaflow/server/controller/db/mysql"
	"github.com/metaflowys/metaflow/server/controller/manager/config"
	"github.com/metaflowys/metaflow/server/controller/recorder"
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

	tCtx, tCancel := context.WithCancel(ctx)
	cloud := cloud.NewCloud(domain, 60, cfg.CloudCfg, tCtx)
	if cloud == nil {
		return nil
	}

	log.Infof("task (%s) init success", domain.Name)

	return &Task{
		tCtx:         tCtx,
		tCancel:      tCancel,
		cfg:          cfg,
		Cloud:        cloud,
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

package tagrecorder

import (
	"time"

	// "server/controller/tagrecorder/config"
	"server/controller/config"
	logging "github.com/op/go-logging"
)

var log = logging.MustGetLogger("tagrecorder")

type TagRecorder struct {
	cfg config.Config
}

func NewTagRecorder(cfg config.Config) *TagRecorder {
	return &TagRecorder{cfg: cfg}
}

// 每次执行需要做的事情
func (c *TagRecorder) run() {
	log.Info("tagrecorder run")

	// 连接数据节点刷新ClickHouse中的字典定义
	c.UpdateChDictionary()
	// 调用API获取资源对应的icon_id
	domainToIconID, resourceToIconID, err := c.UpdateIconInfo()
	if err != nil {
		return
	}
	c.refresh(domainToIconID, resourceToIconID)
	// c.UpdateChServerPort()
}

func (c *TagRecorder) Start() {
	go func() {
		for range time.Tick(time.Duration(c.cfg.TagRecorderCfg.Interval) * time.Second) {
			c.run()
		}
	}()
}

func (c *TagRecorder) refresh(domainLcuuidToIconID map[string]int, resourceTypeToIconID map[IconKey]int) {
	// 生成各资源更新器，刷新ch数据
	updaters := []ChResourceUpdater{
		NewChRegion(domainLcuuidToIconID, resourceTypeToIconID),
		NewChAZ(domainLcuuidToIconID, resourceTypeToIconID),
		NewChVPC(resourceTypeToIconID),
		NewChDevice(resourceTypeToIconID),
		NewChIPRelation(),
		NewChIPResource(),
		NewChDevicePort(),
		NewChPodPort(),
		NewChPodNodePort(),
		NewChPodGroupPort(),
		NewChIPPort(),
		NewChK8sLabel(),
		NewChVTapPort(),
		NewChNetwork(resourceTypeToIconID),
		NewChTapType(resourceTypeToIconID),
		NewChVTap(resourceTypeToIconID),
		NewChPod(resourceTypeToIconID),
		NewChPodCluster(resourceTypeToIconID),
		NewChPodGroup(resourceTypeToIconID),
		NewChPodNamespace(resourceTypeToIconID),
		NewChPodNode(resourceTypeToIconID),
		NewChLbListener(resourceTypeToIconID),
	}
	for _, updater := range updaters {
		updater.Refresh()
	}
}

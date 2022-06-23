package node

import (
	"os"

	"github.com/google/uuid"
	"github.yunshan.net/metaflowys/metaflow/server/libs/utils"

	. "server/controller/common"
	models "server/controller/db/mysql"
	. "server/controller/trisolaris/common"
)

type ControllerDiscovery struct {
	ctrlIP             string
	nodeType           int
	regionDomainPrefix string
}

func newControllerDiscovery(masterIP string, nodeType string, regionDomainPrefix string) *ControllerDiscovery {
	log.Info("node info: ", masterIP, nodeType, regionDomainPrefix)
	nodeTypeInt := CONTROLLER_NODE_TYPE_MASTER
	if nodeType == "slave" {
		nodeTypeInt = CONTROLLER_NODE_TYPE_SLAVE
	}
	return &ControllerDiscovery{
		ctrlIP:             masterIP,
		nodeType:           nodeTypeInt,
		regionDomainPrefix: regionDomainPrefix,
	}
}

func (c *ControllerDiscovery) GetControllerData() *models.Controller {
	envData := utils.GetRuntimeEnv()
	hostName, err := os.Hostname()
	if err != nil {
		log.Error(err)
	}
	return &models.Controller{
		Name:               hostName,
		CPUNum:             int(envData.CpuNum),
		MemorySize:         int64(envData.MemorySize),
		Arch:               envData.Arch,
		Os:                 envData.OS,
		KernelVersion:      envData.KernelVersion,
		IP:                 c.ctrlIP,
		NodeType:           c.nodeType,
		State:              HOST_STATE_COMPLETE,
		VTapMax:            CONTROLLER_VTAP_MAX,
		Lcuuid:             uuid.NewString(),
		RegionDomainPrefix: c.regionDomainPrefix,
	}
}

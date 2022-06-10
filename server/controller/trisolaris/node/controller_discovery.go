package node

import (
	"net"
	"os"

	"github.com/google/uuid"
	"gitlab.yunshan.net/yunshan/metaflow/libs/utils"

	. "server/controller/common"
	models "server/controller/db/mysql"
	. "server/controller/trisolaris/common"
	. "server/controller/trisolaris/utils"
)

type ControllerDiscovery struct {
	ctrlIP             string
	masterIP           net.IP
	nodeType           int
	regionDomainPrefix string
}

func newControllerDiscovery(masterIP net.IP, nodeType string, regionDomainPrefix string) *ControllerDiscovery {
	log.Info(masterIP, nodeType, regionDomainPrefix)
	ctrlIP := ""
	if ip, err := Lookup(masterIP); err == nil {
		ctrlIP = ip.String()
	} else {
		log.Error(err, "lookup controller ip failed", masterIP)
	}
	nodeTypeInt := CONTROLLER_NODE_TYPE_MASTER
	if nodeType == "slave" {
		nodeTypeInt = CONTROLLER_NODE_TYPE_SLAVE
	}
	return &ControllerDiscovery{
		ctrlIP:             ctrlIP,
		masterIP:           masterIP,
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
	if c.ctrlIP == "" {
		if ip, err := Lookup(c.masterIP); err == nil {
			c.ctrlIP = ip.String()
		} else {
			log.Error(err, "lookup controller ip failed", c.masterIP)
			return nil
		}
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

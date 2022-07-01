// tagrecorder包中使用到的泛型约束
package tagrecorder

import (
	"github.com/metaflowys/metaflow/server/controller/db/mysql"
)

// 资源的MySQL orm对象
type MySQLChModel interface {
	mysql.ChPodGroupPort | mysql.ChPodPort | mysql.ChVTapPort | mysql.ChAZ | mysql.ChIPResource | mysql.ChK8sLabel | mysql.ChLBListener | mysql.ChPodNodePort | mysql.ChIPPort | mysql.ChDevicePort | mysql.ChRegion | mysql.ChVPC | mysql.ChDevice | mysql.ChIPRelation | mysql.ChPodGroup | mysql.ChNetwork | mysql.ChPod | mysql.ChPodCluster | mysql.ChPodNode | mysql.ChPodNamespace | mysql.ChTapType | mysql.ChVTap
}

// ch资源的组合key
type ChModelKey interface {
	VtapPortKey | IPResourceKey | K8sLabelKey | PortIDKey | PortIPKey | PortDeviceKey | IDKey | DeviceKey | IPRelationKey | TapTypeKey
}

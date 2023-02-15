/*
 * Copyright (c) 2022 Yunshan Networks
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

// tagrecorder包中使用到的泛型约束
package tagrecorder

import (
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
)

// 资源的MySQL orm对象
type MySQLChModel interface {
	mysql.ChOSAppTags | mysql.ChOSAppTag | mysql.ChPodNSCloudTags | mysql.ChChostCloudTags | mysql.ChPodNSCloudTag | mysql.ChChostCloudTag | mysql.ChIntEnum | mysql.ChStringEnum | mysql.ChPodIngress | mysql.ChPodGroupPort | mysql.ChPodPort | mysql.ChVTapPort | mysql.ChAZ | mysql.ChIPResource | mysql.ChK8sLabel |
		mysql.ChLBListener | mysql.ChPodNodePort | mysql.ChIPPort | mysql.ChDevicePort | mysql.ChRegion | mysql.ChVPC |
		mysql.ChDevice | mysql.ChIPRelation | mysql.ChPodGroup | mysql.ChNetwork | mysql.ChPod | mysql.ChPodCluster |
		mysql.ChPodNode | mysql.ChPodNamespace | mysql.ChTapType | mysql.ChVTap | mysql.ChK8sLabels | mysql.ChNodeType | mysql.ChGProcess
}

// ch资源的组合key
type ChModelKey interface {
	OSAPPTagKey | OSAPPTagsKey | CloudTagsKey | CloudTagKey | IntEnumTagKey | StringEnumTagKey | VtapPortKey | IPResourceKey | K8sLabelKey | PortIDKey | PortIPKey | PortDeviceKey | IDKey | DeviceKey |
		IPRelationKey | TapTypeKey | K8sLabelsKey | NodeTypeKey
}

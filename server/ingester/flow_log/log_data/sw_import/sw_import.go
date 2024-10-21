/*
 * Copyright (c) 2024 Yunshan Networks
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

package sw_import

import (
	flowlogCfg "github.com/deepflowio/deepflow/server/ingester/flow_log/config"
	"github.com/deepflowio/deepflow/server/ingester/flow_log/log_data"
	"github.com/deepflowio/deepflow/server/libs/grpc"
)

func SkyWalkingDataToL7FlowLogs(vtapID, orgId, teamId uint16, segmentData, peerIP []byte, uri string, platformData *grpc.PlatformInfoTable, cfg *flowlogCfg.Config) []*log_data.L7FlowLog {
	return []*log_data.L7FlowLog{}
}

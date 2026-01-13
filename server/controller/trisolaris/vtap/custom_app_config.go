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

package vtap

import (
	"github.com/deepflowio/deepflow/server/controller/trisolaris/metadata"
)

type CustomAppConfigData struct {
	metaData *metadata.MetaData
}

func newCustomAppConfigData(metaData *metadata.MetaData) *CustomAppConfigData {
	return &CustomAppConfigData{
		metaData: metaData,
	}
}

func (c *CustomAppConfigData) getCustomAppConfigByte(teamID, agentGroupID int) []byte {
	return c.metaData.GetCustomAppConfigByte(teamID, agentGroupID)
}

func (c *CustomAppConfigData) getCustomAppConfigVersion() uint64 {
	return c.metaData.GetCustomAppConfigVersion()
}

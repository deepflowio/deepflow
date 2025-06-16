/**
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

package common

import (
	"github.com/deepflowio/deepflow/server/controller/common/metadata"
	"github.com/deepflowio/deepflow/server/controller/recorder/config"
)

type Metadata struct {
	Config config.RecorderConfig
	metadata.Platform
}

func NewMetadata(cfg config.RecorderConfig, orgID int) (*Metadata, error) {
	platformRscMd, err := metadata.NewPlatform(orgID)
	if err != nil {
		return nil, err
	}
	return &Metadata{
		Config:   cfg,
		Platform: platformRscMd,
	}, err
}

func (m Metadata) Copy() *Metadata {
	return &Metadata{
		Config:   m.Config,
		Platform: m.Platform.Copy(),
	}
}

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

package recorder

import (
	"context"
	"sync"

	"github.com/deepflowio/deepflow/server/controller/recorder/config"
	"github.com/deepflowio/deepflow/server/controller/recorder/db/idmng"
)

var (
	resourceOnce sync.Once
	resource     *Resource
)

type Resource struct {
	Cleaners   *Cleaners
	IDManagers *idmng.IDManagers
}

func GetResource() *Resource {
	resourceOnce.Do(func() {
		resource = &Resource{
			Cleaners:   GetCleaners(),
			IDManagers: idmng.GetSingleton(),
		}
	})
	return resource
}

func (r *Resource) Init(ctx context.Context, cfg config.RecorderConfig) *Resource {
	r.Cleaners.Init(ctx, cfg)
	r.IDManagers.Init(&cfg) // TODO add ctx
	return r
}

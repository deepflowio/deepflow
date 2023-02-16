/*
 * Copyright (c) 2023 Yunshan Networks
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

package scheduler

import (
	"github.com/deepflowio/deepflow/server/controller/http/service/resource/data/provider"
)

type Task struct {
	ID           int
	ResourceType string
	Done         bool
	Refresher    provider.DataRefresher
	DataContext  *provider.DataContext
}

func NewTask(id int, rt string, re provider.DataRefresher, dc *provider.DataContext) *Task {
	return &Task{
		ID:           id,
		ResourceType: rt,
		Refresher:    re,
	}
}

func (t *Task) Run() {
	t.Refresher.Refresh(t.DataContext)
	t.Done = true
}

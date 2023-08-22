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

package service

import (
	"sync"

	"github.com/deepflowio/deepflow/server/querier/app/tracing-adapter/config"
	"github.com/deepflowio/deepflow/server/querier/app/tracing-adapter/model"
	"github.com/op/go-logging"
)

var (
	Adapters map[string]TraceAdapter
	once     sync.Once
	log_base = logging.MustGetLogger("tracing-adapter.base")
)

type TraceAdapter interface {
	GetTrace(traceID string, c *config.ExternalAPM) (*model.ExTrace, error)
}

func MustRegister(name string, ad TraceAdapter) error {
	once.Do(func() {
		if Adapters == nil {
			Adapters = make(map[string]TraceAdapter, 0)
		}
	})
	Adapters[name] = ad
	log_base.Debugf("external apm %s register success", name)
	return nil
}

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

package bill

import (
	"context"

	"github.com/deepflowio/deepflow/server/controller/monitor/config"
)

type BillCheck struct {
	vCtx    context.Context
	vCancel context.CancelFunc
	config  config.MonitorConfig
}

func NewBillCheck(method string, cfg config.MonitorConfig, ctx context.Context) *BillCheck {
	vCtx, vCancel := context.WithCancel(ctx)
	return &BillCheck{
		vCtx:    vCtx,
		vCancel: vCancel,
		config:  cfg,
	}
}

func (b *BillCheck) Start(sCtx context.Context) {}

func (b *BillCheck) Stop() {
	if b.vCancel != nil {
		b.vCancel()
	}
}

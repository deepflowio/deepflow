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

package mysql

import (
	"context"
	"fmt"
	"time"

	"gorm.io/gorm"
)

type _BaseMgr struct {
	*gorm.DB
	ctx       context.Context
	cancel    context.CancelFunc
	timeout   time.Duration
	isRelated bool
}

type _DBMgr[M any] struct {
	*_BaseMgr
	m M
}

// TODO any -> constraint
func DBMgr[M any](db *gorm.DB) *_DBMgr[M] {
	if db == nil {
		fmt.Println("DBMgr need init by db")
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &_DBMgr[M]{_BaseMgr: &_BaseMgr{DB: db, ctx: ctx, cancel: cancel, timeout: -1}}
}

func (obj *_DBMgr[M]) GetAll() (results []*M, err error) {
	err = obj.DB.WithContext(obj.ctx).Model(obj.m).Find(&results).Error
	return
}

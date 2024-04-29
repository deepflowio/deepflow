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

package common

import (
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
)

type ORG struct {
	ID     int       // org id
	DB     *mysql.DB // org database connection
	Logger *Logger   // log controller
}

func NewORG(id int) (*ORG, error) {
	db, err := mysql.GetDB(id)
	return &ORG{
		ID:     id,
		DB:     db,
		Logger: NewLogger(id),
	}, err
}

// LogPre adds org id, domain info, sub_domain info to logs
func (o *ORG) LogPre(format string, a ...any) string {
	return o.Logger.AddPre(format, a...)
}

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
	"fmt"

	"github.com/deepflowio/deepflow/server/controller/db/mysql"
)

type ORG struct {
	ID int       // org id
	DB *mysql.DB // org database connection
}

func NewORG(id int) (*ORG, error) {
	db, err := mysql.GetDB(id)
	return &ORG{
		ID: id,
		DB: db,
	}, err
}

func (o *ORG) Logf(format string, a ...any) string {
	return o.addLogPre(fmt.Sprintf(format, a...))
}

func (o *ORG) Log(format string) string {
	return o.addLogPre(format)
}

func (o *ORG) addLogPre(msg string) string {
	return fmt.Sprintf("[OID-%d] ", o.ID) + msg
}

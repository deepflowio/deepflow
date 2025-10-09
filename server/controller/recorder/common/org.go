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
	// "fmt"

	"github.com/deepflowio/deepflow/server/controller/db/metadb"
	"github.com/deepflowio/deepflow/server/libs/logger"
)

type ORG struct {
	ID        int        // org id
	DB        *metadb.DB // org database connection
	LogPrefix logger.Prefix
}

func NewORG(id int) (*ORG, error) {
	db, err := metadb.GetDB(id)
	return &ORG{
		ID:        id,
		DB:        db,
		LogPrefix: logger.NewORGPrefix(id),
	}, err
}

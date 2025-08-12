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

package message

import (
	"github.com/deepflowio/deepflow/server/controller/common/metadata"
	"github.com/deepflowio/deepflow/server/controller/db/metadb"
	metadbModel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache/tool"
)

type Metadata struct {
	metadata.Platform // Base metadata containing platform resource common fields
	Addition          // Additional metadata for specific message types
}

func NewMetadata(options ...func(*Metadata)) *Metadata {
	md := &Metadata{
		metadata.Platform{},
		Addition{},
	}
	for _, option := range options {
		option(md)
	}
	return md
}

func MetadataPlatform(base metadata.Platform) func(*Metadata) {
	return func(m *Metadata) {
		m.Platform = base
	}
}

func MetadataDB(db *metadb.DB) func(*Metadata) {
	return func(m *Metadata) {
		m.SetDB(db)
	}
}

func MetadataDomain(domain metadbModel.Domain) func(*Metadata) {
	return func(m *Metadata) {
		m.SetDomain(domain)
	}
}

func MetadataSubDomain(subDomain metadbModel.SubDomain) func(*Metadata) {
	return func(m *Metadata) {
		m.SetSubDomain(subDomain)
	}
}

func MetadataSoftDelete(flag bool) func(*Metadata) {
	return func(m *Metadata) {
		m.Addition.SoftDelete = flag
	}
}

func MetadataToolDataSet(ds *tool.DataSet) func(*Metadata) {
	return func(m *Metadata) {
		m.Addition.ToolDataSet = ds
	}
}

type Addition struct { // TODO better
	SoftDelete  bool          // for message type of delete action
	ToolDataSet *tool.DataSet // for message type of resource event
}

func (m Addition) GetSoftDelete() bool {
	return m.SoftDelete
}

func (m Addition) GetToolDataSet() *tool.DataSet {
	return m.ToolDataSet
}

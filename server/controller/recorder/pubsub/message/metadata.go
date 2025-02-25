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
	"github.com/deepflowio/deepflow/server/controller/db/metadb"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache/tool"
	"github.com/deepflowio/deepflow/server/libs/logger"
)

type Metadata struct {
	ORGID           int
	TeamID          int
	DomainID        int
	DomainLcuuid    string
	SubDomainID     int
	SubDomainLcuuid string

	LogPrefixes
	AdditionalMetadata // Additional metadata for specific message types
}

func (m *Metadata) GetORGID() int {
	return m.ORGID
}

func (m *Metadata) GetTeamID() int {
	return m.TeamID
}

func (m *Metadata) GetDomainID() int {
	return m.DomainID
}

func (m *Metadata) GetSubDomainID() int {
	return m.SubDomainID
}

func (m *Metadata) GetDomainLcuuid() string {
	return m.DomainLcuuid
}

func (m *Metadata) GetSubDomainLcuuid() string {
	return m.SubDomainLcuuid
}

func NewMetadata(orgID int, options ...func(*Metadata)) *Metadata {
	md := &Metadata{
		ORGID: orgID,
	}
	for _, option := range options {
		option(md)
	}
	md.SetLogORGIDPrefix(orgID)
	return md
}

func MetadataSubDomainID(id int) func(*Metadata) {
	return func(m *Metadata) {
		m.SubDomainID = id
	}
}

func MetadataTeamID(id int) func(*Metadata) {
	return func(m *Metadata) {
		m.TeamID = id
	}
}

func MetadataDomainID(id int) func(*Metadata) {
	return func(m *Metadata) {
		m.DomainID = id
	}
}

func MetadataDomainLcuuid(lcuuid string) func(*Metadata) {
	return func(m *Metadata) {
		m.DomainLcuuid = lcuuid
	}
}

func MetadataSubDomainLcuuid(lcuuid string) func(*Metadata) {
	return func(m *Metadata) {
		m.SubDomainLcuuid = lcuuid
	}
}

func MetadataSoftDelete(flag bool) func(*Metadata) {
	return func(m *Metadata) {
		m.AdditionalMetadata.SoftDelete = flag
	}
}

func MetadataToolDataSet(ds *tool.DataSet) func(*Metadata) {
	return func(m *Metadata) {
		m.AdditionalMetadata.ToolDataSet = ds
	}
}

func MetadataDB(db *metadb.DB) func(*Metadata) {
	return func(m *Metadata) {
		m.AdditionalMetadata.DB = db
	}
}

type AdditionalMetadata struct { // TODO better
	SoftDelete  bool          // for message type of delete action
	ToolDataSet *tool.DataSet // for message type of resource event
	DB          *metadb.DB    // for message type of resource event
}

func (m *AdditionalMetadata) GetSoftDelete() bool {
	return m.SoftDelete
}

func (m *AdditionalMetadata) GetToolDataSet() *tool.DataSet {
	return m.ToolDataSet
}

func (m *AdditionalMetadata) GetDB() *metadb.DB {
	return m.DB
}

type LogPrefixes struct {
	LogPrefixORGID  logger.Prefix
	LogPrefixTeamID logger.Prefix
}

func (l *LogPrefixes) SetLogORGIDPrefix(id int) {
	l.LogPrefixORGID = logger.NewORGPrefix(id)
}

func (l *LogPrefixes) SetLogPrefixTeamID(id int) {
	l.LogPrefixTeamID = logger.NewTeamPrefix(id)
}

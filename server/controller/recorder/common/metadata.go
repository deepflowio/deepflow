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

package common

import (
	"github.com/deepflowio/deepflow/server/controller/db/metadb"
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	"github.com/deepflowio/deepflow/server/controller/recorder/config"
	"github.com/deepflowio/deepflow/server/libs/logger"
)

func NewMetadataBase(orgID int, options ...func(*MetadataBase)) (MetadataBase, error) {
	db, err := metadb.GetDB(orgID)
	md := &MetadataBase{
		ORGID:       orgID,
		DB:          db,
		Domain:      new(DomainInfo),
		SubDomain:   new(SubDomainInfo),
		LogPrefixes: []logger.Prefix{logger.NewORGPrefix(orgID)},
	}
	for _, option := range options {
		option(md)
	}
	return *md, err
}

type MetadataBase struct { // TODO better name
	ORGID       int        // org id
	DB          *metadb.DB // org database connection
	teamID      int
	Domain      *DomainInfo
	SubDomain   *SubDomainInfo
	LogPrefixes []logger.Prefix
}

func (m *MetadataBase) GetDB() *metadb.DB {
	return m.DB
}

func (m *MetadataBase) GetORGID() int {
	return m.ORGID
}

func (m *MetadataBase) GetTeamID() int { // TODO return m.teamID
	if m.SubDomain.TeamID != 0 {
		return m.SubDomain.TeamID
	} else {
		return m.Domain.TeamID
	}
}

func (m *MetadataBase) GetDomainLcuuid() string {
	return m.Domain.Lcuuid
}

func (m *MetadataBase) GetSubDomainLcuuid() string {
	return m.SubDomain.Lcuuid
}

func (m *MetadataBase) GetDomainID() int {
	return m.Domain.ID
}

func (m *MetadataBase) GetSubDomainID() int {
	return m.SubDomain.ID
}

func (m *MetadataBase) GetDomainInfo() *DomainInfo {
	return m.Domain
}

func (m *MetadataBase) GetSubDomainInfo() *SubDomainInfo {
	return m.SubDomain
}

func (m *MetadataBase) SetORGID(orgID int) {
	m.ORGID = orgID
	m.LogPrefixes = append(m.LogPrefixes, logger.NewORGPrefix(orgID))
}

func (m *MetadataBase) SetDB(db *metadb.DB) {
	m.DB = db
	m.SetORGID(db.GetORGID())
}

func (m *MetadataBase) SetDomain(domain metadbmodel.Domain) {
	m.Domain = &DomainInfo{domain}
	if m.teamID == 0 {
		m.teamID = domain.TeamID
		m.LogPrefixes = append(m.LogPrefixes, logger.NewTeamPrefix(domain.TeamID))
	}
	m.LogPrefixes = append(m.LogPrefixes, NewDomainPrefix(domain.Name))
}

func (m *MetadataBase) SetSubDomain(subDomain metadbmodel.SubDomain) {
	m.SubDomain = &SubDomainInfo{subDomain}
	if subDomain.TeamID != 0 {
		m.teamID = subDomain.TeamID
		m.LogPrefixes = append(m.LogPrefixes, logger.NewTeamPrefix(subDomain.TeamID))
	}
	m.LogPrefixes = append(m.LogPrefixes, NewSubDomainPrefix(subDomain.Name))
}

func MetadataDomain(domain metadbmodel.Domain) func(*MetadataBase) {
	return func(m *MetadataBase) {
		m.SetDomain(domain)
	}
}

func MetadataSubDomain(subDomain metadbmodel.SubDomain) func(*MetadataBase) {
	return func(m *MetadataBase) {
		m.SetSubDomain(subDomain)
	}
}

type DomainInfo struct {
	metadbmodel.Domain
}
type SubDomainInfo struct {
	metadbmodel.SubDomain
}

type Metadata struct {
	Config config.RecorderConfig
	MetadataBase
}

func NewMetadata(cfg config.RecorderConfig, orgID int) (*Metadata, error) {
	db, err := metadb.GetDB(orgID)
	return &Metadata{
		Config: cfg,
		MetadataBase: MetadataBase{
			ORGID:       orgID,
			DB:          db,
			Domain:      new(DomainInfo),
			SubDomain:   new(SubDomainInfo),
			LogPrefixes: []logger.Prefix{logger.NewORGPrefix(orgID)},
		},
	}, err
}

func (m *Metadata) Copy() *Metadata {
	return &Metadata{
		Config: m.Config,
		MetadataBase: MetadataBase{
			ORGID:       m.ORGID,
			DB:          m.DB,
			Domain:      m.Domain,
			SubDomain:   m.SubDomain,
			LogPrefixes: m.LogPrefixes[:],
		},
	}
}

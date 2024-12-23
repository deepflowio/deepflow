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

type Metadata struct {
	Config      config.RecorderConfig
	ORGID       int        // org id
	DB          *metadb.DB // org database connection
	Domain      *DomainInfo
	SubDomain   *SubDomainInfo
	LogPrefixes []logger.Prefix
}

func NewMetadata(cfg config.RecorderConfig, orgID int) (*Metadata, error) {
	db, err := metadb.GetDB(orgID)
	return &Metadata{
		Config:      cfg,
		ORGID:       orgID,
		DB:          db,
		Domain:      new(DomainInfo),
		SubDomain:   new(SubDomainInfo),
		LogPrefixes: []logger.Prefix{logger.NewORGPrefix(orgID)},
	}, err
}

func (m *Metadata) Copy() *Metadata {
	return &Metadata{
		Config:      m.Config,
		ORGID:       m.ORGID,
		DB:          m.DB,
		Domain:      m.Domain,
		SubDomain:   m.SubDomain,
		LogPrefixes: m.LogPrefixes[:],
	}
}

func (m *Metadata) GetORGID() int {
	return m.ORGID
}

func (m *Metadata) GetTeamID() int {
	if m.SubDomain.TeamID != 0 {
		return m.SubDomain.TeamID
	} else {
		return m.Domain.TeamID
	}
}

func (m *Metadata) SetDomain(domain metadbmodel.Domain) {
	m.Domain = &DomainInfo{domain}
	m.LogPrefixes = append(m.LogPrefixes, logger.NewTeamPrefix(domain.TeamID))
	m.LogPrefixes = append(m.LogPrefixes, NewDomainPrefix(domain.Name))
}

func (m *Metadata) SetSubDomain(subDomain metadbmodel.SubDomain) {
	m.SubDomain = &SubDomainInfo{subDomain}
	if subDomain.TeamID != 0 {
		m.LogPrefixes = append(m.LogPrefixes, logger.NewTeamPrefix(subDomain.TeamID))
	}
	m.LogPrefixes = append(m.LogPrefixes, NewSubDomainPrefix(subDomain.Name))
}

type DomainInfo struct {
	metadbmodel.Domain
}

type SubDomainInfo struct {
	metadbmodel.SubDomain
}

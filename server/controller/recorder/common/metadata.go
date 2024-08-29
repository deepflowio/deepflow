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
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	mysqlmodel "github.com/deepflowio/deepflow/server/controller/db/mysql/model"
	"github.com/deepflowio/deepflow/server/libs/logger"
)

type Metadata struct {
	ORGID       int       // org id
	DB          *mysql.DB // org database connection
	Domain      *DomainInfo
	SubDomain   *SubDomainInfo
	LogPrefixes []logger.Prefix
}

func NewMetadata(orgID int) (*Metadata, error) {
	db, err := mysql.GetDB(orgID)
	return &Metadata{
		ORGID:       orgID,
		DB:          db,
		Domain:      new(DomainInfo),
		SubDomain:   new(SubDomainInfo),
		LogPrefixes: []logger.Prefix{logger.NewORGPrefix(orgID)},
	}, err
}

func (m *Metadata) Copy() *Metadata {
	return &Metadata{
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

func (m *Metadata) SetDomain(domain mysqlmodel.Domain) {
	m.Domain = &DomainInfo{domain}
	m.LogPrefixes = append(m.LogPrefixes, logger.NewTeamPrefix(domain.TeamID))
	m.LogPrefixes = append(m.LogPrefixes, NewDomainPrefix(domain.Name))
}

func (m *Metadata) SetSubDomain(subDomain mysqlmodel.SubDomain) {
	m.SubDomain = &SubDomainInfo{subDomain}
	if subDomain.TeamID != 0 {
		m.LogPrefixes = append(m.LogPrefixes, logger.NewTeamPrefix(subDomain.TeamID))
	}
	m.LogPrefixes = append(m.LogPrefixes, NewSubDomainPrefix(subDomain.Name))
}

type DomainInfo struct {
	mysqlmodel.Domain
}

type SubDomainInfo struct {
	mysqlmodel.SubDomain
}

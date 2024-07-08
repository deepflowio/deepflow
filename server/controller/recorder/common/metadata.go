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
	"github.com/deepflowio/deepflow/server/controller/logger"
)

type Metadata struct {
	ORGID       int       // org id
	DB          *mysql.DB // org database connection
	Logger      *Logger   // log controller // TODO delete
	Domain      *DomainInfo
	SubDomain   *SubDomainInfo
	LogPrefixes []logger.Prefix
}

func NewMetadata(orgID int) (*Metadata, error) {
	db, err := mysql.GetDB(orgID)
	return &Metadata{
		ORGID:       orgID,
		DB:          db,
		Logger:      NewLogger(orgID),
		Domain:      new(DomainInfo),
		SubDomain:   new(SubDomainInfo),
		LogPrefixes: []logger.Prefix{logger.NewORGPrefix(orgID)},
	}, err
}

func (m *Metadata) Copy() *Metadata {
	return &Metadata{
		ORGID:       m.ORGID,
		DB:          m.DB,
		Logger:      m.Logger.Copy(),
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

func (m *Metadata) SetDomain(domain mysql.Domain) {
	m.Domain = &DomainInfo{domain}
	m.Logger.SetTeamID(domain.TeamID)
	m.Logger.SetDomainName(domain.Name)
	m.LogPrefixes = append(m.LogPrefixes, NewDomainPrefix(domain.Name))
}

func (m *Metadata) SetSubDomain(subDomain mysql.SubDomain) {
	m.SubDomain = &SubDomainInfo{subDomain}
	m.Logger.SetTeamID(subDomain.TeamID)
	m.Logger.SetSubDomainName(subDomain.Name)
	m.LogPrefixes = append(m.LogPrefixes, NewSubDomainPrefix(subDomain.Name))
}

// Logf adds org id, domain info, sub_domain info to logs
func (m *Metadata) Logf(format string, a ...any) string {
	return m.Logger.AddPre(format, a...)
}

func (m *Metadata) Log(format string) string {
	return m.Logger.AddPre(format)
}

type DomainInfo struct {
	mysql.Domain
}

type SubDomainInfo struct {
	mysql.SubDomain
}

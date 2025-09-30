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

package metadata

import (
	"fmt"

	"github.com/deepflowio/deepflow/server/controller/db/metadb"
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	"github.com/deepflowio/deepflow/server/libs/logger"
)

func NewPlatform(orgID int, options ...func(*Platform)) (Platform, error) {
	db, err := metadb.GetDB(orgID)
	md := &Platform{
		orgID:       orgID,
		DB:          db,
		domain:      DomainInfo{},
		subDomain:   SubDomainInfo{},
		LogPrefixes: []logger.Prefix{logger.NewORGPrefix(orgID)},
	}
	for _, option := range options {
		option(md)
	}
	return *md, err
}

// Platform is the metadata of the platform resource.
// It contains organization ID, team ID, db connection, domain and sub domain information.
type Platform struct {
	DB          *metadb.DB
	orgID       int
	teamID      int
	domain      DomainInfo
	subDomain   SubDomainInfo
	LogPrefixes []logger.Prefix
}

func (m Platform) Copy() Platform {
	return Platform{
		DB:          m.DB,
		orgID:       m.orgID,
		teamID:      m.teamID,
		domain:      m.domain,
		subDomain:   m.subDomain,
		LogPrefixes: m.LogPrefixes[:],
	}
}

func (m Platform) IsSubDomainValid() bool {
	return m.subDomain.ID != 0
}

func (m Platform) GetDB() *metadb.DB {
	return m.DB
}

func (m Platform) GetORGID() int {
	return m.orgID
}

func (m Platform) GetTeamID() int {
	return m.teamID
}

func (m Platform) GetDomainInfo() DomainInfo {
	return m.domain
}

func (m Platform) GetSubDomainInfo() SubDomainInfo {
	return m.subDomain
}

func (m Platform) GetDomainLcuuid() string {
	return m.domain.Lcuuid
}

func (m Platform) GetSubDomainLcuuid() string {
	return m.subDomain.Lcuuid
}

func (m Platform) GetDomainID() int {
	return m.domain.ID
}

func (m Platform) GetSubDomainID() int {
	return m.subDomain.ID
}

func (m *Platform) SetORGID(orgID int) {
	m.orgID = orgID
	m.LogPrefixes = append(m.LogPrefixes, logger.NewORGPrefix(orgID))
}

func (m *Platform) SetDB(db *metadb.DB) {
	m.DB = db
	m.SetORGID(db.GetORGID())
}

func (m *Platform) SetDomain(domain metadbmodel.Domain) {
	m.domain = DomainInfo{domain}
	if m.teamID == 0 {
		m.teamID = domain.TeamID
		m.LogPrefixes = append(m.LogPrefixes, logger.NewTeamPrefix(domain.TeamID))
	}
	m.LogPrefixes = append(m.LogPrefixes, NewDomainPrefix(domain.Name))
}

func (m *Platform) SetSubDomain(subDomain metadbmodel.SubDomain) {
	m.subDomain = SubDomainInfo{subDomain}
	if subDomain.TeamID != 0 {
		m.teamID = subDomain.TeamID
		m.LogPrefixes = append(m.LogPrefixes, logger.NewTeamPrefix(subDomain.TeamID))
	}
	m.LogPrefixes = append(m.LogPrefixes, NewSubDomainPrefix(subDomain.Name))
}

func MetadataDomain(domain metadbmodel.Domain) func(*Platform) {
	return func(m *Platform) {
		m.SetDomain(domain)
	}
}

func MetadataSubDomain(subDomain metadbmodel.SubDomain) func(*Platform) {
	return func(m *Platform) {
		m.SetSubDomain(subDomain)
	}
}

type DomainInfo struct {
	metadbmodel.Domain
}

type SubDomainInfo struct {
	metadbmodel.SubDomain
}

func NewDomainPrefix(name string) logger.Prefix {
	if name == "" {
		return &DomainIDPrefix{0}
	}
	return &DomainNameLogPrefix{name}
}

type DomainIDPrefix struct {
	ID int
}

func (p *DomainIDPrefix) Prefix() string {
	return fmt.Sprintf("[DomainID-%d]", p.ID)
}

type DomainNameLogPrefix struct {
	Name string
}

func (p *DomainNameLogPrefix) Prefix() string {
	return fmt.Sprintf("[DomainName-%s]", p.Name)
}

func NewSubDomainPrefix(name string) logger.Prefix {
	return &SubDomainNameLogPrefix{name}
}

type SubDomainNameLogPrefix struct {
	Name string
}

func (p *SubDomainNameLogPrefix) Prefix() string {
	return fmt.Sprintf("[SubDomainName-%s]", p.Name)
}

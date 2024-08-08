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

type Metadata struct {
	ORGID       int
	TeamID      int
	DomainID    int
	SubDomainID int

	AdditionalMetadata // Additional metadata for specific message types
}

func NewMetadata(orgID int, options ...func(*Metadata)) *Metadata {
	md := &Metadata{
		ORGID: orgID,
	}
	for _, option := range options {
		option(md)
	}
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

func MetadataSoftDelete(flag bool) func(*Metadata) {
	return func(m *Metadata) {
		m.AdditionalMetadata.SoftDelete = flag
	}
}

type AdditionalMetadata struct {
	SoftDelete bool // for message type of delete action
}

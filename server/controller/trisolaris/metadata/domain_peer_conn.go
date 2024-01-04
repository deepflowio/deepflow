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

package metadata

import (
	"github.com/deepflowio/deepflow/message/trident"
)

type TPeerConnections []*trident.PeerConnection

type DomainPeerConnsData map[string]TPeerConnections

type DomainPeerConnProto struct {
	domainToPeerConns DomainPeerConnsData
	peerConns         TPeerConnections
	noDomainPeerConns TPeerConnections
}

const noDomain = "ffffffff-ffff-ffff-ffff-ffffffffffff"

func NewDomainPeerConnProto(length int) *DomainPeerConnProto {
	return &DomainPeerConnProto{
		domainToPeerConns: make(DomainPeerConnsData),
		peerConns:         make(TPeerConnections, 0, length),
		noDomainPeerConns: make(TPeerConnections, 0, length),
	}
}

func (d *DomainPeerConnProto) addData(domain string, data *trident.PeerConnection) {
	d.peerConns = append(d.peerConns, data)
	if domain == "" || domain == noDomain {
		d.noDomainPeerConns = append(d.noDomainPeerConns, data)
		return
	}
	if _, ok := d.domainToPeerConns[domain]; ok {
		d.domainToPeerConns[domain] = append(d.domainToPeerConns[domain], data)
	} else {
		d.domainToPeerConns[domain] = []*trident.PeerConnection{data}
	}
}

func (d *DomainPeerConnProto) getNoDomainPeerConns() TPeerConnections {
	return d.noDomainPeerConns
}

package metadata

import (
	"gitlab.yunshan.net/yunshan/metaflow/message/trident"
)

type TPeerConnections []*trident.PeerConnection

type DomainPeerConnsData map[string]TPeerConnections

type DomainPeerConnProto struct {
	domainToPeerConns DomainPeerConnsData
	peerConns         TPeerConnections
}

func NewDomainPeerConnProto(length int) *DomainPeerConnProto {
	return &DomainPeerConnProto{
		domainToPeerConns: make(DomainPeerConnsData),
		peerConns:         make(TPeerConnections, 0, length),
	}
}

func (d *DomainPeerConnProto) addData(domain string, data *trident.PeerConnection) {
	d.peerConns = append(d.peerConns, data)
	if _, ok := d.domainToPeerConns[domain]; ok {
		d.domainToPeerConns[domain] = append(d.domainToPeerConns[domain], data)
	} else {
		d.domainToPeerConns[domain] = []*trident.PeerConnection{data}
	}
}

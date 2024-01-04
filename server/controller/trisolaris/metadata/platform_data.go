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
	"fmt"
	"hash/fnv"
	"math/rand"
	"time"

	"github.com/deepflowio/deepflow/message/trident"
)

var offsetInterval uint64 = 1000000
var offsetVersion uint64 = 1000000

type PlatformData struct {
	domain             string
	lcuuid             string
	platformDataStr    []byte
	platformDataHash   uint64
	platformDataProtos *trident.PlatformData
	interfaceProtos    []*trident.Interface
	peerConnProtos     []*trident.PeerConnection
	cidrProtos         []*trident.Cidr
	gprocessInfoProtos []*trident.GProcessInfo
	version            uint64
	mergeDomains       []string
	dataType           uint32
}

func NewPlatformData(domain string, lcuuid string, version uint64, dataType uint32) *PlatformData {
	return &PlatformData{
		domain:             domain,
		lcuuid:             lcuuid,
		platformDataStr:    []byte{},
		platformDataHash:   0,
		platformDataProtos: &trident.PlatformData{},
		interfaceProtos:    []*trident.Interface{},
		peerConnProtos:     []*trident.PeerConnection{},
		cidrProtos:         []*trident.Cidr{},
		gprocessInfoProtos: []*trident.GProcessInfo{},
		version:            version,
		mergeDomains:       []string{},
		dataType:           dataType,
	}
}

func (f *PlatformData) setPlatformData(ifs []*trident.Interface, pcs []*trident.PeerConnection, cidrs []*trident.Cidr,
	gpis []*trident.GProcessInfo) {
	f.initPlatformData(ifs, pcs, cidrs, gpis)
	f.GeneratePlatformDataResult()
}

func (f *PlatformData) GetPlatformDataResult() ([]byte, uint64) {
	return f.platformDataStr, f.version
}

func (f *PlatformData) GetPlatformDataStr() []byte {
	return f.platformDataStr
}

func (f *PlatformData) GetPlatformDataVersion() uint64 {
	return f.version
}

func (f *PlatformData) setVersion(version uint64) {
	f.version = version
}

func (f *PlatformData) GetVersion() uint64 {
	return f.version
}

func (f *PlatformData) initVersion() {
	rand.Seed(time.Now().Unix())
	f.version = offsetVersion + uint64(time.Now().Unix()) + uint64(rand.Intn(10000))
	offsetVersion += offsetInterval
}

func (f *PlatformData) initPlatformData(ifs []*trident.Interface, pcs []*trident.PeerConnection, cidrs []*trident.Cidr,
	gpi []*trident.GProcessInfo) {
	f.interfaceProtos = ifs
	f.peerConnProtos = pcs
	f.cidrProtos = cidrs
	f.gprocessInfoProtos = gpi
}

func (f *PlatformData) GeneratePlatformDataResult() {
	f.platformDataProtos = &trident.PlatformData{
		Interfaces:      f.interfaceProtos,
		PeerConnections: f.peerConnProtos,
		Cidrs:           f.cidrProtos,
		GprocessInfos:   f.gprocessInfoProtos,
	}
	var err error
	f.platformDataStr, err = f.platformDataProtos.Marshal()
	if err != nil {
		log.Error(err)
		return
	}
	h64 := fnv.New64()
	h64.Write(f.platformDataStr)
	f.platformDataHash = h64.Sum64()
}
func (f *PlatformData) Merge(other *PlatformData) {
	if other == nil {
		return
	}
	f.interfaceProtos = append(f.interfaceProtos, other.interfaceProtos...)
	f.peerConnProtos = append(f.peerConnProtos, other.peerConnProtos...)
	f.cidrProtos = append(f.cidrProtos, other.cidrProtos...)
	f.gprocessInfoProtos = append(f.gprocessInfoProtos, other.gprocessInfoProtos...)
	f.version += other.version
	if len(other.domain) != 0 {
		f.mergeDomains = append(f.mergeDomains, other.domain)
	}
}

func (f *PlatformData) MergeInterfaces(other *PlatformData) {
	if other == nil {
		return
	}
	f.interfaceProtos = append(f.interfaceProtos, other.interfaceProtos...)
	f.version += other.version
	if len(other.domain) != 0 {
		f.mergeDomains = append(f.mergeDomains, other.domain)
	}
}

func (f *PlatformData) MergePeerConnProtos(other *PlatformData) {
	if other == nil {
		return
	}
	f.peerConnProtos = append(f.peerConnProtos, other.peerConnProtos...)
	f.version += other.version
	if len(other.domain) != 0 {
		f.mergeDomains = append(f.mergeDomains, other.domain)
	}
}

func (f *PlatformData) equal(other *PlatformData) bool {
	if other == nil {
		return false
	}

	if f.platformDataHash != other.platformDataHash {
		return false
	}

	return true
}

func (f *PlatformData) String() string {
	return fmt.Sprintf("name: %s, lcuuid: %s, data_type: %d, version: %d, platform_data_hash: %d, interfaces: %d, peer_connections: %d, cidrs: %d, gprocess_info: %d, merge_domains: %s",
		f.domain, f.lcuuid, f.dataType, f.version, f.platformDataHash, len(f.interfaceProtos), len(f.peerConnProtos), len(f.cidrProtos), len(f.gprocessInfoProtos), f.mergeDomains)
}

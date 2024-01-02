/*
 * Copyright (c) 2023 Yunshan Networks
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
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	mapset "github.com/deckarep/golang-set"
	"github.com/deepflowio/deepflow/message/trident"
	models "github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/golang/protobuf/proto"

	. "github.com/deepflowio/deepflow/server/controller/common"
	. "github.com/deepflowio/deepflow/server/controller/trisolaris/common"
)

type PolicyRawData struct {
	idToNpbTunnel      map[int]*models.NpbTunnel
	idToACL            map[int]*models.ACL
	aclIDToNpbPolices  map[int][]*models.NpbPolicy
	aclIDToPcapPolices map[int][]*models.PcapPolicy
	idToNpbPolicy      map[int]*models.NpbPolicy
	idToPcapPolicy     map[int]*models.PcapPolicy
}

func newPolicyRawData() *PolicyRawData {
	return &PolicyRawData{
		idToNpbTunnel:      make(map[int]*models.NpbTunnel),
		idToACL:            make(map[int]*models.ACL),
		aclIDToNpbPolices:  make(map[int][]*models.NpbPolicy),
		aclIDToPcapPolices: make(map[int][]*models.PcapPolicy),
		idToNpbPolicy:      make(map[int]*models.NpbPolicy),
		idToPcapPolicy:     make(map[int]*models.PcapPolicy),
	}
}

type Policy struct {
	vtapID              int
	version             uint64
	npbVersion          uint64
	pcapVersion         uint64
	serializeString     []byte
	allDataHash         uint64
	npbSerializeString  []byte
	npbDataHash         uint64
	pcapSerializeString []byte
	pcapDataHash        uint64
	flowACLs            []*trident.FlowAcl
	npbFlowACLs         []*trident.FlowAcl
	pcapFlowACLs        []*trident.FlowAcl
	billingMethod       string
}

func newPolicy(vtapID int, billingMethod string) *Policy {
	return &Policy{
		vtapID:        vtapID,
		billingMethod: billingMethod,
	}
}

func (p *Policy) toSerializeString() {
	var err error
	if len(p.flowACLs) > 0 {
		flowACLsProto := trident.FlowAcls{
			FlowAcl: p.flowACLs,
		}
		p.serializeString, err = flowACLsProto.Marshal()
		if err != nil {
			log.Error(err)
		} else {
			h64 := fnv.New64()
			h64.Write(p.serializeString)
			p.allDataHash = h64.Sum64()
		}
	}
	if p.billingMethod == BILLING_METHOD_LICENSE {
		if len(p.npbFlowACLs) > 0 {
			npbFlowACLsProto := trident.FlowAcls{
				FlowAcl: p.npbFlowACLs,
			}
			p.npbSerializeString, err = npbFlowACLsProto.Marshal()
			if err != nil {
				log.Error(err)
			} else {
				h64 := fnv.New64()
				h64.Write(p.npbSerializeString)
				p.npbDataHash = h64.Sum64()
			}
		}

		if len(p.pcapFlowACLs) > 0 {
			pcapFlowACLsProto := trident.FlowAcls{
				FlowAcl: p.pcapFlowACLs,
			}
			p.pcapSerializeString, err = pcapFlowACLsProto.Marshal()
			if err != nil {
				log.Error(err)
			} else {
				h64 := fnv.New64()
				h64.Write(p.pcapSerializeString)
				p.pcapDataHash = h64.Sum64()
			}
		}
	}
}

func (p *Policy) addFlowACL(flowACL *trident.FlowAcl, aclType int) {
	p.flowACLs = append(p.flowACLs, flowACL)
	if p.billingMethod == BILLING_METHOD_LICENSE {
		if aclType == APPLICATION_NPB {
			p.npbFlowACLs = append(p.npbFlowACLs, flowACL)
		} else if aclType == APPLICATION_PCAP {
			p.pcapFlowACLs = append(p.pcapFlowACLs, flowACL)
		}
	}
}

var tnFunction mapset.Set = mapset.NewSet(VTAP_LICENSE_FUNCTION_TRAFFIC_DISTRIBUTION,
	VTAP_LICENSE_FUNCTION_NETWORK_MONITORING)
var tFunction mapset.Set = mapset.NewSet(VTAP_LICENSE_FUNCTION_TRAFFIC_DISTRIBUTION)
var nFunction mapset.Set = mapset.NewSet(VTAP_LICENSE_FUNCTION_NETWORK_MONITORING)

func (p *Policy) getPolicyString(functions mapset.Set) []byte {
	if p.billingMethod == BILLING_METHOD_LICENSE {
		if functions.Cardinality() == 0 {
			return nil
		}
		if tnFunction.IsSubset(functions) {
			return p.serializeString
		} else if tFunction.IsSubset(functions) {
			return p.npbSerializeString
		} else if nFunction.IsSubset(functions) {
			return p.pcapSerializeString
		}
	} else {
		return p.serializeString
	}

	return nil
}

func (p *Policy) getPolicyVersion(functions mapset.Set) uint64 {
	if p.billingMethod == BILLING_METHOD_LICENSE {
		if functions.Cardinality() == 0 {
			return 0xFFFFFFFF
		}
		if tnFunction.IsSubset(functions) {
			return p.version
		} else if tFunction.IsSubset(functions) {
			return p.npbVersion
		} else if nFunction.IsSubset(functions) {
			return p.pcapVersion
		}
	} else {
		return p.version
	}

	return 0xFFFFFFFF
}

func (p *Policy) getAllSerializeString() []byte {
	return p.serializeString
}

func (p *Policy) getAllVersion() uint64 {
	return p.version
}

func (p *Policy) initVersion(version uint64) {
	p.version = version
	p.npbVersion = version + 100
	p.pcapVersion = version + 200
}

func (p *Policy) setVersion(other *Policy) {
	if p.allDataHash != other.allDataHash {
		log.Infof("vtap(vtapID = %d) Flow acl version changed to %d", p.vtapID, other.version+1)
		p.version = other.version + 1
	} else {
		p.version = other.version
	}
	if p.npbDataHash != other.npbDataHash {
		log.Infof("vtap(vtapID = %d) Flow acl npb version changed to %d", p.vtapID, other.npbVersion+1)
		p.npbVersion = other.npbVersion + 1
	} else {
		p.npbVersion = other.npbVersion
	}
	if p.pcapDataHash != other.pcapDataHash {
		log.Infof("vtap(vtapID = %d) Flow acl pcap version changed to %d", p.vtapID, other.pcapVersion+1)
		p.pcapVersion = other.pcapVersion + 1
	} else {
		p.pcapVersion = other.pcapVersion
	}
}

func (p *Policy) merger(other *Policy) {
	if len(other.flowACLs) != 0 {
		p.flowACLs = append(p.flowACLs, other.flowACLs...)
	}
	if len(other.npbFlowACLs) != 0 {
		p.npbFlowACLs = append(p.npbFlowACLs, other.npbFlowACLs...)
	}
	if len(other.pcapFlowACLs) != 0 {
		p.pcapFlowACLs = append(p.pcapFlowACLs, other.pcapFlowACLs...)
	}
}

func (p *Policy) String() string {
	return fmt.Sprintf("vtap_id: %d, version: %d, flow_acls: %d, allDataHash: %d, "+
		"pcapVersion: %d, pcap_flow_acls: %d, pcapDataHash: %d "+
		"npbVersion: %d, npb_flow_acls: %d, npbDataHash: %d",
		p.vtapID, p.version, len(p.flowACLs), p.allDataHash,
		p.pcapVersion, len(p.pcapFlowACLs), p.pcapDataHash,
		p.npbVersion, len(p.npbFlowACLs), p.npbDataHash)
}

type PolicyDataOP struct {
	metaData *MetaData
	rawData  *atomic.Value // *FlowAclRawData
	// single vtap policy
	vtapIDToPolicy *atomic.Value // map[int]*Policy
	// all vtap share policy
	allVTapSharePolicy *atomic.Value // *Policy
	// droplet policy
	dropletPolicy *atomic.Value //*Policy
	//whether the policy initializes the identity
	init          bool
	billingMethod string
}

func newPolicyDaTaOP(metaData *MetaData, billingMethod string) *PolicyDataOP {
	rawData := &atomic.Value{}
	rawData.Store(newPolicyRawData())
	vtapIDToPolicy := &atomic.Value{}
	vtapIDToPolicy.Store(make(map[int]*Policy))
	allVTapSharePolicy := &atomic.Value{}
	allVTapSharePolicy.Store(newPolicy(0, billingMethod))
	dropletPolicy := &atomic.Value{}
	dropletPolicy.Store(newPolicy(-1, billingMethod))
	return &PolicyDataOP{
		rawData:            rawData,
		metaData:           metaData,
		vtapIDToPolicy:     vtapIDToPolicy,
		allVTapSharePolicy: allVTapSharePolicy,
		dropletPolicy:      dropletPolicy,
		init:               false,
		billingMethod:      billingMethod,
	}
}

func (op *PolicyDataOP) String() string {
	vtapIDToPolicy := op.getVTapIDToPolicy()
	allVTapSharePolicy := op.getAllVTapSharePolicy()
	dropletPolicy := op.getDropletPolicy()
	result := "\n"
	for _, vtapPolicy := range vtapIDToPolicy {
		result += fmt.Sprintf("%s\n", vtapPolicy)
	}
	result += fmt.Sprintf("%s\n", allVTapSharePolicy)
	result += fmt.Sprintf("%s\n", dropletPolicy)
	return result
}

func (op *PolicyDataOP) GetRawData() *PolicyRawData {
	return op.rawData.Load().(*PolicyRawData)
}

func (op *PolicyDataOP) updateRawData(r *PolicyRawData) {
	op.rawData.Store(r)
}

func (op *PolicyDataOP) getVTapIDToPolicy() map[int]*Policy {
	return op.vtapIDToPolicy.Load().(map[int]*Policy)
}

func (op *PolicyDataOP) updateVTapIDToPolicy(data map[int]*Policy) {
	op.vtapIDToPolicy.Store(data)
}

func (op *PolicyDataOP) getAllVTapSharePolicy() *Policy {
	return op.allVTapSharePolicy.Load().(*Policy)
}

func (op *PolicyDataOP) updateAllVTapSharePolicy(data *Policy) {
	op.allVTapSharePolicy.Store(data)
}

func (op *PolicyDataOP) getDropletPolicy() *Policy {
	return op.dropletPolicy.Load().(*Policy)
}

func (op *PolicyDataOP) updateDropletPolicy(data *Policy) {
	op.dropletPolicy.Store(data)
}

func (op *PolicyDataOP) getDropletPolicyVersion() uint64 {
	return op.getDropletPolicy().getAllVersion()
}

func (op *PolicyDataOP) getDropletPolicyStr() []byte {
	return op.getDropletPolicy().getAllSerializeString()
}

func (op *PolicyDataOP) getVTapPolicyVersion(vtapID int, functions mapset.Set) uint64 {
	var version uint64
	vtapIDToPolicy := op.getVTapIDToPolicy()
	if policy, ok := vtapIDToPolicy[vtapID]; ok {
		version = policy.getPolicyVersion(functions)
	} else {
		allVTapSharePolicy := op.getAllVTapSharePolicy()
		version = allVTapSharePolicy.getPolicyVersion(functions)
	}
	return version
}

func (op *PolicyDataOP) getVTapPolicyString(vtapID int, functions mapset.Set) []byte {
	var policyStr []byte
	vtapIDToPolicy := op.getVTapIDToPolicy()
	if policy, ok := vtapIDToPolicy[vtapID]; ok {
		policyStr = policy.getPolicyString(functions)
	} else {
		allVTapSharePolicy := op.getAllVTapSharePolicy()
		policyStr = allVTapSharePolicy.getPolicyString(functions)
	}
	return policyStr
}

func (op *PolicyDataOP) generatePolicyData() {
	op.generateRawData()
	op.generatePolicies()
}

func (op *PolicyDataOP) generateRawData() {
	dbDataCache := op.metaData.GetDBDataCache()

	npbTunnels := dbDataCache.GetNpbTunnels()
	acls := dbDataCache.GetACLs()
	npbPolicies := dbDataCache.GetNpbPolicies()
	pcapPolicies := dbDataCache.GetPcapPolicies()

	rawData := newPolicyRawData()
	for _, npbTunnel := range npbTunnels {
		rawData.idToNpbTunnel[npbTunnel.ID] = npbTunnel
	}

	for _, acl := range acls {
		rawData.idToACL[acl.ID] = acl
	}

	for _, npbPolicy := range npbPolicies {
		rawData.idToNpbPolicy[npbPolicy.ID] = npbPolicy
		if _, ok := rawData.aclIDToNpbPolices[npbPolicy.ACLID]; ok {
			rawData.aclIDToNpbPolices[npbPolicy.ACLID] = append(
				rawData.aclIDToNpbPolices[npbPolicy.ACLID], npbPolicy)
		} else {
			rawData.aclIDToNpbPolices[npbPolicy.ACLID] = []*models.NpbPolicy{npbPolicy}
		}
	}

	for _, pcapPolicy := range pcapPolicies {
		rawData.idToPcapPolicy[pcapPolicy.ID] = pcapPolicy
		if _, ok := rawData.aclIDToPcapPolices[pcapPolicy.ACLID]; ok {
			rawData.aclIDToPcapPolices[pcapPolicy.ACLID] = append(
				rawData.aclIDToPcapPolices[pcapPolicy.ACLID], pcapPolicy)
		} else {
			rawData.aclIDToPcapPolices[pcapPolicy.ACLID] = []*models.PcapPolicy{pcapPolicy}
		}
	}

	op.updateRawData(rawData)
}

type GroupIDs struct {
	srcGroupIDs []int32
	dstGroupIDs []int32
}

func convertGroupIDs(acl *models.ACL) *GroupIDs {
	var srcGroupIDs, dstGroupIDs []int32
	if len(acl.SrcGroupIDs) > 0 {
		groups := strings.Split(acl.SrcGroupIDs, ",")
		srcGroupIDs = make([]int32, 0, len(groups))
		for _, group := range groups {
			groupInt, err := strconv.Atoi(group)
			if err != nil {
				log.Error(err, acl.SrcGroupIDs)
				continue
			}
			srcGroupIDs = append(srcGroupIDs, int32(groupInt))
		}
	}
	if len(acl.DstGroupIDs) > 0 {
		groups := strings.Split(acl.DstGroupIDs, ",")
		dstGroupIDs = make([]int32, 0, len(groups))
		for _, group := range groups {
			groupInt, err := strconv.Atoi(group)
			if err != nil {
				log.Error(err, acl.DstGroupIDs)
				continue
			}
			dstGroupIDs = append(dstGroupIDs, int32(groupInt))
		}
	}

	return &GroupIDs{
		srcGroupIDs: srcGroupIDs,
		dstGroupIDs: dstGroupIDs,
	}
}

func (op *PolicyDataOP) generateProtoPorts(acl *models.ACL, flowACL *trident.FlowAcl, groupIDs *GroupIDs) int {
	srcGroupIDs := groupIDs.srcGroupIDs
	dstGroupIDs := groupIDs.dstGroupIDs
	dstPorts := acl.DstPorts
	srcPorts := acl.SrcPorts
	srcProtocol := PROTOCOL_ALL
	dstProtocol := PROTOCOL_ALL
	protocol := PROTOCOL_ALL
	if acl.Protocol != nil {
		srcProtocol = *acl.Protocol
		dstProtocol = *acl.Protocol
		protocol = *acl.Protocol
	}
	dstGroupType := -1
	srcGroupType := -1
	groupDataOP := op.metaData.GetGroupDataOP()
	idToGroup := groupDataOP.GetIDToGroup()
	groupIDToPodServiceIDs := groupDataOP.GetGroupIDToPodServiceIDs()
	pRawData := op.metaData.GetPlatformDataOP().GetRawData()
	dstPortsStr := make(map[string]struct{})
	srcPortsStr := make(map[string]struct{})
	if len(dstGroupIDs) > 0 {
		dstGroup, ok := idToGroup[int(dstGroupIDs[0])]
		if ok && dstGroup.Type == RESOURCE_GROUP_TYPE_ANONYMOUS_POD_SERVICE &&
			len(dstGroup.ExtraInfoIDs) > 0 {
			dstGroupType = RESOURCE_GROUP_TYPE_ANONYMOUS_POD_SERVICE
			for _, podServiceID := range groupIDToPodServiceIDs[dstGroup.ID] {
				podService, ok := pRawData.idToPodService[podServiceID]
				if ok == false {
					log.Errorf("pod service (id = %d) not found.", podServiceID)
					continue
				}
				protocols := make(map[string]struct{})
				if podService.ServiceClusterIP != "" {
					for _, podServicePort := range pRawData.podServiceIDToPorts[podServiceID] {
						dstPortsStr[strconv.Itoa(podServicePort.Port)] = struct{}{}
						if podService.Type == POD_SERVICE_TYPE_NODE_PORT {
							dstPortsStr[strconv.Itoa(podServicePort.NodePort)] = struct{}{}
						}
						protocols[podServicePort.Protocol] = struct{}{}
					}
				} else {
					for _, podGroupPort := range pRawData.podServiceIDToPodGroupPorts[podServiceID] {
						dstPortsStr[strconv.Itoa(podGroupPort.Port)] = struct{}{}
						protocols[podGroupPort.Protocol] = struct{}{}
					}
				}
				if len(protocols) == 1 {
					for key, _ := range protocols {
						dstProtocol = ProtocolMap[key]
					}
					if dstProtocol == 0 {
						dstProtocol = PROTOCOL_ALL
					}
				} else {
					dstProtocol = PROTOCOL_ALL
				}
			}
		}
	}

	if len(srcGroupIDs) > 0 {
		srcGroup, ok := idToGroup[int(srcGroupIDs[0])]
		if ok && srcGroup.Type == RESOURCE_GROUP_TYPE_ANONYMOUS_POD_GROUP_AS_POD_SERVICE &&
			len(srcGroup.ExtraInfoIDs) > 0 {
			srcGroupType = RESOURCE_GROUP_TYPE_ANONYMOUS_POD_GROUP_AS_POD_SERVICE
			for _, podServiceID := range groupIDToPodServiceIDs[srcGroup.ID] {
				protocols := make(map[string]struct{})
				for _, podGroupPort := range pRawData.podServiceIDToPodGroupPorts[podServiceID] {
					srcPortsStr[strconv.Itoa(podGroupPort.Port)] = struct{}{}
					protocols[podGroupPort.Protocol] = struct{}{}
				}
				if len(protocols) == 1 {
					for key, _ := range protocols {
						srcProtocol = ProtocolMap[key]
					}
					if srcProtocol == 0 {
						srcProtocol = PROTOCOL_ALL
					}
				} else {
					srcProtocol = PROTOCOL_ALL
				}
			}
		}
	}

	// The collection point acts as a client, ignoring the port/protocol information;
	// the peer acts as a server and needs to carry the port/protocol
	if srcGroupType == RESOURCE_GROUP_TYPE_ANONYMOUS_POD_GROUP_AS_POD_SERVICE &&
		dstGroupType == RESOURCE_GROUP_TYPE_ANONYMOUS_POD_SERVICE {
		protocol = dstProtocol
		dstPortsStrList := make([]string, 0, len(dstPortsStr))
		for key, _ := range dstPortsStr {
			dstPortsStrList = append(dstPortsStrList, key)
		}
		if len(dstPortsStrList) > 0 {
			sort.Strings(dstPortsStrList)
			dstPorts = strings.Join(dstPortsStrList, ",")
		}
		srcPorts = ""
	} else if dstGroupType == RESOURCE_GROUP_TYPE_ANONYMOUS_POD_SERVICE {
		protocol = dstProtocol
		dstPortsStrList := make([]string, 0, len(dstPortsStr))
		for key, _ := range dstPortsStr {
			dstPortsStrList = append(dstPortsStrList, key)
		}
		if len(dstPortsStrList) > 0 {
			sort.Strings(dstPortsStrList)
			dstPorts = strings.Join(dstPortsStrList, ",")
		}
	} else if srcGroupType == RESOURCE_GROUP_TYPE_ANONYMOUS_POD_GROUP_AS_POD_SERVICE {
		protocol = srcProtocol
		srcPortsStrList := make([]string, 0, len(srcPortsStr))
		for key, _ := range srcPortsStr {
			srcPortsStrList = append(srcPortsStrList, key)
		}
		if len(srcPortsStrList) > 0 {
			sort.Strings(srcPortsStrList)
			srcPorts = strings.Join(srcPortsStrList, ",")
		}
	}

	flowACL.SrcPorts = proto.String(srcPorts)
	flowACL.DstPorts = proto.String(dstPorts)
	return protocol
}

var (
	tapSideSRC  = trident.TapSide_SRC
	tapSideDST  = trident.TapSide_DST
	tapSideBOTH = trident.TapSide_BOTH

	tunnelTypePCAP = trident.TunnelType_PCAP
)

func (op *PolicyDataOP) generateProtoActions(acl *models.ACL) (map[int][]*trident.NpbAction, []*trident.NpbAction) {
	vtapIDToNpbActions := make(map[int][]*trident.NpbAction)
	allVTapNpbActions := []*trident.NpbAction{}
	rawData := op.GetRawData()
	appInt, err := strconv.Atoi(acl.Applications)
	if err != nil {
		log.Errorf("err: %s, applications: %s", err, acl.Applications)
		return vtapIDToNpbActions, allVTapNpbActions
	}
	switch appInt {
	case APPLICATION_NPB:
		var payloadSlice int
		for _, npbPolicy := range rawData.aclIDToNpbPolices[acl.ID] {
			npbTunnel, ok := rawData.idToNpbTunnel[npbPolicy.NpbTunnelID]
			if ok == false {
				log.Errorf("npb tunnel id (%d) not found", npbPolicy.NpbTunnelID)
				continue
			}

			tunnelType := trident.TunnelType(npbTunnel.Type)
			if npbPolicy.Distribute == NPB_POLICY_FLOW_DROP {
				tunnelType = trident.TunnelType_NPB_DROP
			}
			if npbPolicy.PayloadSlice == nil {
				payloadSlice = MAX_PAYLOAD_SLICE
			} else {
				payloadSlice = *npbPolicy.PayloadSlice
			}
			direction := trident.Direction(npbPolicy.Direction)
			npbAction := &trident.NpbAction{
				TunnelId:      proto.Uint32(uint32(npbPolicy.Vni)),
				TunnelIp:      proto.String(npbTunnel.IP),
				TapSide:       &tapSideSRC,
				TunnelType:    &tunnelType,
				PayloadSlice:  proto.Uint32(uint32(payloadSlice)),
				TunnelIpId:    proto.Uint32(uint32(npbTunnel.ID)),
				NpbAclGroupId: proto.Uint32(uint32(npbPolicy.PolicyACLGroupID)),
				Direction:     &direction,
			}
			if len(npbPolicy.VtapIDs) == 0 {
				allVTapNpbActions = append(allVTapNpbActions, npbAction)
			} else {
				for _, vtapIDStr := range strings.Split(npbPolicy.VtapIDs, ",") {
					vtapIDInt, err := strconv.Atoi(vtapIDStr)
					if err != nil {
						log.Errorf("err: %s, vtapIDs: %s", err, npbPolicy.VtapIDs)
						continue
					}
					vtapIDToNpbActions[vtapIDInt] = append(vtapIDToNpbActions[vtapIDInt], npbAction)
				}
			}
		}
	case APPLICATION_PCAP:
		var payloadSlice int
		for _, pcapPolicy := range rawData.aclIDToPcapPolices[acl.ID] {
			if pcapPolicy.PayloadSlice == nil {
				payloadSlice = MAX_PAYLOAD_SLICE
			} else {
				payloadSlice = *pcapPolicy.PayloadSlice
			}
			npbAction := &trident.NpbAction{
				TapSide:       &tapSideSRC,
				TunnelType:    &tunnelTypePCAP,
				PayloadSlice:  proto.Uint32(uint32(payloadSlice)),
				NpbAclGroupId: proto.Uint32(uint32(pcapPolicy.PolicyACLGroupID)),
			}
			if len(pcapPolicy.VtapIDs) == 0 {
				allVTapNpbActions = append(allVTapNpbActions, npbAction)
			} else {
				for _, vtapIDStr := range strings.Split(pcapPolicy.VtapIDs, ",") {
					vtapIDInt, err := strconv.Atoi(vtapIDStr)
					if err != nil {
						log.Errorf("err: %s, vtapIDs: %s", err, pcapPolicy.VtapIDs)
						continue
					}
					vtapIDToNpbActions[vtapIDInt] = append(vtapIDToNpbActions[vtapIDInt], npbAction)
				}
			}
		}
	}

	return vtapIDToNpbActions, allVTapNpbActions
}

func (op *PolicyDataOP) generatePolicies() {
	vtapIDToPolicy := make(map[int]*Policy)
	allVTapSharePolicy := newPolicy(0, op.billingMethod)
	dropletPolicy := newPolicy(-1, op.billingMethod)
	rawData := op.GetRawData()

	dbDataCache := op.metaData.GetDBDataCache()
	for _, acl := range dbDataCache.GetACLs() {
		appInt, err := strconv.Atoi(acl.Applications)
		if err != nil {
			log.Error(err, acl.Applications)
			continue
		}
		if appInt != APPLICATION_NPB && appInt != APPLICATION_PCAP {
			continue
		}
		groupIDs := convertGroupIDs(acl)
		// generat droplet policy
		if appInt == APPLICATION_PCAP {
			pcapPolicies := rawData.aclIDToPcapPolices[acl.ID]
			if len(pcapPolicies) > 0 {
				dropletNpbActions := make([]*trident.NpbAction, 0, len(pcapPolicies))
				npbAclGroupID := uint32(0)
				for _, pcapPolicy := range pcapPolicies {
					npbAclGroupID = uint32(pcapPolicy.PolicyACLGroupID)
				}
				npbAction := &trident.NpbAction{
					TunnelType:    &tunnelTypePCAP,
					NpbAclGroupId: &npbAclGroupID,
				}
				dropletNpbActions = append(dropletNpbActions, npbAction)
				dropletProtocol := PROTOCOL_ALL
				if acl.Protocol != nil {
					dropletProtocol = *acl.Protocol
				}
				dropletFlowACL := &trident.FlowAcl{
					Id:          proto.Uint32(uint32(acl.ID)),
					TapType:     proto.Uint32(uint32(acl.TapType)),
					SrcGroupIds: groupIDs.srcGroupIDs,
					DstGroupIds: groupIDs.dstGroupIDs,
					Protocol:    proto.Uint32(uint32(dropletProtocol)),
					SrcPorts:    proto.String(acl.SrcPorts),
					DstPorts:    proto.String(acl.DstPorts),
					Vlan:        proto.Uint32(uint32(acl.Vlan)),
					NpbActions:  dropletNpbActions,
				}
				dropletPolicy.addFlowACL(dropletFlowACL, appInt)
			}
		}
		// generat agent policy
		flowACL := &trident.FlowAcl{
			Id:          proto.Uint32(uint32(acl.ID)),
			Vlan:        proto.Uint32(uint32(acl.Vlan)),
			TapType:     proto.Uint32(uint32(acl.TapType)),
			SrcGroupIds: groupIDs.srcGroupIDs,
			DstGroupIds: groupIDs.dstGroupIDs,
		}
		protocol := op.generateProtoPorts(acl, flowACL, groupIDs)
		vtapIDToNpbActions, allVTapNpbActions := op.generateProtoActions(acl)
		if protocol == PROTOCOL_ALL && (acl.SrcPorts != "" || acl.DstPorts != "") {
			// If the protocol is all and the port is filled in, it means that the protocol is tcp+udp,
			// and if the protocol is empty and the port is empty, it means any
			for vtapID, npbActions := range vtapIDToNpbActions {
				vtapPolicy, ok := vtapIDToPolicy[vtapID]
				if ok == false {
					vtapPolicy = newPolicy(vtapID, op.billingMethod)
					vtapIDToPolicy[vtapID] = vtapPolicy
				}
				tFlowACL := proto.Clone(flowACL).(*trident.FlowAcl)
				tFlowACL.Protocol = proto.Uint32(uint32(TCP))
				tFlowACL.NpbActions = append(tFlowACL.NpbActions, npbActions...)
				vtapPolicy.addFlowACL(tFlowACL, appInt)

				uFlowACL := proto.Clone(flowACL).(*trident.FlowAcl)
				uFlowACL.Protocol = proto.Uint32(uint32(UDP))
				uFlowACL.NpbActions = append(uFlowACL.NpbActions, npbActions...)
				vtapPolicy.addFlowACL(uFlowACL, appInt)
			}
			if len(allVTapNpbActions) > 0 {
				var tFlowACL, uFlowACL *trident.FlowAcl
				tFlowACL = proto.Clone(flowACL).(*trident.FlowAcl)
				tFlowACL.Protocol = proto.Uint32(uint32(TCP))
				tFlowACL.NpbActions = append(tFlowACL.NpbActions, allVTapNpbActions...)
				allVTapSharePolicy.addFlowACL(tFlowACL, appInt)

				uFlowACL = proto.Clone(flowACL).(*trident.FlowAcl)
				uFlowACL.Protocol = proto.Uint32(uint32(UDP))
				uFlowACL.NpbActions = append(uFlowACL.NpbActions, allVTapNpbActions...)
				allVTapSharePolicy.addFlowACL(uFlowACL, appInt)
			}
		} else {
			for vtapID, npbActions := range vtapIDToNpbActions {
				vtapPolicy, ok := vtapIDToPolicy[vtapID]
				if ok == false {
					vtapPolicy = newPolicy(vtapID, op.billingMethod)
					vtapIDToPolicy[vtapID] = vtapPolicy
				}
				aFlowACL := proto.Clone(flowACL).(*trident.FlowAcl)
				aFlowACL.NpbActions = append(aFlowACL.NpbActions, npbActions...)
				aFlowACL.Protocol = proto.Uint32(uint32(protocol))
				vtapPolicy.addFlowACL(aFlowACL, appInt)
			}
			if len(allVTapNpbActions) > 0 {
				aFlowACL := proto.Clone(flowACL).(*trident.FlowAcl)
				aFlowACL.NpbActions = append(aFlowACL.NpbActions, allVTapNpbActions...)
				aFlowACL.Protocol = proto.Uint32(uint32(protocol))
				allVTapSharePolicy.addFlowACL(aFlowACL, appInt)
			}
		}
	}

	op.checkNewPolicies(vtapIDToPolicy, allVTapSharePolicy, dropletPolicy)
}

func getSortKey(vtapIDToPolicy map[int]*Policy) []int {
	vtapIDs := make([]int, 0, len(vtapIDToPolicy))
	for key, _ := range vtapIDToPolicy {
		vtapIDs = append(vtapIDs, 0, key)
	}
	sort.Ints(vtapIDs)
	return vtapIDs
}

func (op *PolicyDataOP) checkNewPolicies(vtapIDToPolicy map[int]*Policy,
	allVTapSharePolicy *Policy, dropletPolicy *Policy) {
	version := uint64(time.Now().Unix())
	allVTapSharePolicy.toSerializeString()
	dropletPolicy.toSerializeString()
	vtapIDs := getSortKey(vtapIDToPolicy)
	if op.init == false {
		for _, vtapID := range vtapIDs {
			vtapPolicy, ok := vtapIDToPolicy[vtapID]
			if ok == false {
				continue
			}
			vtapPolicy.initVersion(version)
			vtapPolicy.merger(allVTapSharePolicy)
			vtapPolicy.toSerializeString()
		}
		allVTapSharePolicy.initVersion(version + ALL_VTAP_SHARE_POLICY_VERSION_OFFSET)
		dropletPolicy.initVersion(version + INGESTER_POLICY_VERSION_OFFSET)
		op.updateVTapIDToPolicy(vtapIDToPolicy)
		op.updateAllVTapSharePolicy(allVTapSharePolicy)
		op.updateDropletPolicy(dropletPolicy)
		op.init = true
		return
	}
	oldVTapIDToPolicy := op.getVTapIDToPolicy()
	oldAllVTapSharePolicy := op.getAllVTapSharePolicy()
	oldDropletPolicy := op.getDropletPolicy()
	for _, vtapID := range vtapIDs {
		vtapPolicy, ok := vtapIDToPolicy[vtapID]
		if ok == false {
			continue
		}
		vtapPolicy.merger(allVTapSharePolicy)
		vtapPolicy.toSerializeString()
		oldPolicy := oldVTapIDToPolicy[vtapID]
		if oldPolicy != nil {
			vtapPolicy.setVersion(oldPolicy)
		} else {
			vtapPolicy.initVersion(version)
		}
	}
	allVTapSharePolicy.setVersion(oldAllVTapSharePolicy)
	dropletPolicy.setVersion(oldDropletPolicy)
	op.updateVTapIDToPolicy(vtapIDToPolicy)
	op.updateAllVTapSharePolicy(allVTapSharePolicy)
	op.updateDropletPolicy(dropletPolicy)
	log.Debug(op)
}

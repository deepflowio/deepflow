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

package agentmetadata

import (
	"fmt"
	"hash/fnv"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"

	mapset "github.com/deckarep/golang-set"
	"github.com/deepflowio/deepflow/message/agent"
	models "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	"github.com/golang/protobuf/proto"

	. "github.com/deepflowio/deepflow/server/controller/common"
	. "github.com/deepflowio/deepflow/server/controller/trisolaris/common"
	. "github.com/deepflowio/deepflow/server/controller/trisolaris/utils"
)

type PolicyRawData struct {
	vtapGroupIDToAgentIDs map[int][]int
	idToNpbTunnel         map[int]*models.NpbTunnel
	idToACL               map[int]*models.ACL
	aclIDToNpbPolices     map[int][]*models.NpbPolicy
	aclIDToPcapPolices    map[int][]*models.PcapPolicy
	idToNpbPolicy         map[int]*models.NpbPolicy
	idToPcapPolicy        map[int]*models.PcapPolicy
}

func newPolicyRawData() *PolicyRawData {
	return &PolicyRawData{
		vtapGroupIDToAgentIDs: make(map[int][]int),
		idToNpbTunnel:         make(map[int]*models.NpbTunnel),
		idToACL:               make(map[int]*models.ACL),
		aclIDToNpbPolices:     make(map[int][]*models.NpbPolicy),
		aclIDToPcapPolices:    make(map[int][]*models.PcapPolicy),
		idToNpbPolicy:         make(map[int]*models.NpbPolicy),
		idToPcapPolicy:        make(map[int]*models.PcapPolicy),
	}
}

type Policy struct {
	agentID             int
	version             uint64
	npbVersion          uint64
	pcapVersion         uint64
	serializeString     []byte
	allDataHash         uint64
	npbSerializeString  []byte
	npbDataHash         uint64
	pcapSerializeString []byte
	pcapDataHash        uint64
	flowACLs            []*agent.FlowAcl
	npbFlowACLs         []*agent.FlowAcl
	pcapFlowACLs        []*agent.FlowAcl
	billingMethod       string
	ORGID
}

func NewPolicy(agentID int, billingMethod string, orgID ORGID) *Policy {
	return &Policy{
		agentID:       agentID,
		billingMethod: billingMethod,
		ORGID:         orgID,
	}
}

func (p *Policy) toSerializeString() {
	var err error
	if len(p.flowACLs) > 0 {
		flowACLsProto := agent.FlowAcls{
			FlowAcl: p.flowACLs,
		}
		p.serializeString, err = flowACLsProto.Marshal()
		if err != nil {
			log.Error(p.Log(err.Error()))
		} else {
			h64 := fnv.New64()
			h64.Write(p.serializeString)
			p.allDataHash = h64.Sum64()
		}
	}
	if len(p.npbFlowACLs) > 0 {
		npbFlowACLsProto := agent.FlowAcls{
			FlowAcl: p.npbFlowACLs,
		}
		p.npbSerializeString, err = npbFlowACLsProto.Marshal()
		if err != nil {
			log.Error(p.Log(err.Error()))
		} else {
			h64 := fnv.New64()
			h64.Write(p.npbSerializeString)
			p.npbDataHash = h64.Sum64()
		}
	}

	if len(p.pcapFlowACLs) > 0 {
		pcapFlowACLsProto := agent.FlowAcls{
			FlowAcl: p.pcapFlowACLs,
		}
		p.pcapSerializeString, err = pcapFlowACLsProto.Marshal()
		if err != nil {
			log.Error(p.Log(err.Error()))
		} else {
			h64 := fnv.New64()
			h64.Write(p.pcapSerializeString)
			p.pcapDataHash = h64.Sum64()
		}
	}
}

func (p *Policy) addFlowACL(flowACL *agent.FlowAcl, aclType int) {
	p.flowACLs = append(p.flowACLs, flowACL)
	if aclType == APPLICATION_NPB {
		p.npbFlowACLs = append(p.npbFlowACLs, flowACL)
	} else if aclType == APPLICATION_PCAP {
		p.pcapFlowACLs = append(p.pcapFlowACLs, flowACL)
	}
}

var tnFunction mapset.Set = mapset.NewSet(
	AGENT_LICENSE_FUNCTION_NET_NPB, AGENT_LICENSE_FUNCTION_DEV_NET_NPB,
	AGENT_LICENSE_FUNCTION_NET_NPMD, AGENT_LICENSE_FUNCTION_DEV_NET_NPMD,
)
var tFunction mapset.Set = mapset.NewSet(AGENT_LICENSE_FUNCTION_NET_NPB, AGENT_LICENSE_FUNCTION_DEV_NET_NPB)
var nFunction mapset.Set = mapset.NewSet(AGENT_LICENSE_FUNCTION_NET_NPMD, AGENT_LICENSE_FUNCTION_DEV_NET_NPMD)

func (p *Policy) getPolicyString(functions mapset.Set) []byte {
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

	return nil
}

func (p *Policy) getPolicyVersion(functions mapset.Set) uint64 {
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

	return 0xFFFFFFFF
}

func (p *Policy) GetAllSerializeString() []byte {
	return p.serializeString
}

func (p *Policy) GetAllVersion() uint64 {
	return p.version
}

func (p *Policy) initVersion(version uint64) {
	p.version = version
	p.npbVersion = version + 100
	p.pcapVersion = version + 200
}

func (p *Policy) setVersion(other *Policy) {
	if p.allDataHash != other.allDataHash {
		log.Infof(p.Logf("agent(agentID = %d) Flow acl version changed to %d", p.agentID, other.version+1))
		p.version = other.version + 1
	} else {
		p.version = other.version
	}
	if p.npbDataHash != other.npbDataHash {
		log.Infof(p.Logf("agent(agentID = %d) Flow acl npb version changed to %d", p.agentID, other.npbVersion+1))
		p.npbVersion = other.npbVersion + 1
	} else {
		p.npbVersion = other.npbVersion
	}
	if p.pcapDataHash != other.pcapDataHash {
		log.Infof(p.Logf("agent(agentID = %d) Flow acl pcap version changed to %d", p.agentID, other.pcapVersion+1))
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

func (p *Policy) MergeIngesterPolicy(other *Policy) {
	if len(other.flowACLs) != 0 {
		p.flowACLs = append(p.flowACLs, other.flowACLs...)
		p.version += other.version
	}
}

func (p *Policy) GenerateIngesterData() {
	var err error
	if len(p.flowACLs) > 0 {
		flowACLsProto := agent.FlowAcls{
			FlowAcl: p.flowACLs,
		}
		p.serializeString, err = flowACLsProto.Marshal()
		if err != nil {
			log.Error(p.Log(err.Error()))
		} else {
			h64 := fnv.New64()
			h64.Write(p.serializeString)
			p.allDataHash = h64.Sum64()
		}
	}
}

func (p *Policy) String() string {
	return fmt.Sprintf("agent_id: %d, version: %d, flow_acls: %d, allDataHash: %d, "+
		"pcapVersion: %d, pcap_flow_acls: %d, pcapDataHash: %d "+
		"npbVersion: %d, npb_flow_acls: %d, npbDataHash: %d",
		p.agentID, p.version, len(p.flowACLs), p.allDataHash,
		p.pcapVersion, len(p.pcapFlowACLs), p.pcapDataHash,
		p.npbVersion, len(p.npbFlowACLs), p.npbDataHash)
}

type PolicyDataOP struct {
	metaData *MetaData
	rawData  *atomic.Value // *FlowAclRawData
	// single agent policy
	agentIDToPolicy *atomic.Value // map[int]*Policy
	// all agent share policy
	allAgentSharePolicy *atomic.Value // *Policy
	//whether the policy initializes the identity
	init          bool
	billingMethod string

	ORGID
}

func newPolicyDaTaOP(metaData *MetaData, billingMethod string) *PolicyDataOP {
	rawData := &atomic.Value{}
	rawData.Store(newPolicyRawData())
	agentIDToPolicy := &atomic.Value{}
	agentIDToPolicy.Store(make(map[int]*Policy))
	allAgentSharePolicy := &atomic.Value{}
	allAgentSharePolicy.Store(NewPolicy(0, billingMethod, metaData.ORGID))
	return &PolicyDataOP{
		rawData:             rawData,
		metaData:            metaData,
		agentIDToPolicy:     agentIDToPolicy,
		allAgentSharePolicy: allAgentSharePolicy,
		init:                false,
		billingMethod:       billingMethod,
		ORGID:               metaData.ORGID,
	}
}

func (op *PolicyDataOP) String() string {
	agentIDToPolicy := op.getAgentIDToPolicy()
	allAgentSharePolicy := op.getAllAgentSharePolicy()
	result := "\n"
	for _, agentPolicy := range agentIDToPolicy {
		result += fmt.Sprintf("%s\n", agentPolicy)
	}
	result += fmt.Sprintf("%s\n", allAgentSharePolicy)
	return result
}

func (op *PolicyDataOP) GetRawData() *PolicyRawData {
	return op.rawData.Load().(*PolicyRawData)
}

func (op *PolicyDataOP) updateRawData(r *PolicyRawData) {
	op.rawData.Store(r)
}

func (op *PolicyDataOP) getAgentIDToPolicy() map[int]*Policy {
	return op.agentIDToPolicy.Load().(map[int]*Policy)
}

func (op *PolicyDataOP) updateAgentIDToPolicy(data map[int]*Policy) {
	op.agentIDToPolicy.Store(data)
}

func (op *PolicyDataOP) getAllAgentSharePolicy() *Policy {
	return op.allAgentSharePolicy.Load().(*Policy)
}

func (op *PolicyDataOP) updateAllAgentSharePolicy(data *Policy) {
	op.allAgentSharePolicy.Store(data)
}

func (op *PolicyDataOP) getAgentPolicyVersion(agentID int, functions mapset.Set) uint64 {
	var version uint64
	agentIDToPolicy := op.getAgentIDToPolicy()
	if policy, ok := agentIDToPolicy[agentID]; ok {
		version = policy.getPolicyVersion(functions)
	} else {
		allAgentSharePolicy := op.getAllAgentSharePolicy()
		version = allAgentSharePolicy.getPolicyVersion(functions)
	}
	return version
}

func (op *PolicyDataOP) getAgentPolicyString(agentID int, functions mapset.Set) []byte {
	var policyStr []byte
	agentIDToPolicy := op.getAgentIDToPolicy()
	if policy, ok := agentIDToPolicy[agentID]; ok {
		policyStr = policy.getPolicyString(functions)
	} else {
		allAgentSharePolicy := op.getAllAgentSharePolicy()
		policyStr = allAgentSharePolicy.getPolicyString(functions)
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
	vtaps := dbDataCache.GetVTapsIDAndName()
	vtapGroups := dbDataCache.GetVTapGroupsIDAndLcuuid()

	rawData := newPolicyRawData()
	vtapGroupLcuuidToID := map[string]int{}
	for _, vtapGroup := range vtapGroups {
		vtapGroupLcuuidToID[vtapGroup.Lcuuid] = vtapGroup.ID
	}
	for _, vtap := range vtaps {
		vtapGroupID, ok := vtapGroupLcuuidToID[vtap.VtapGroupLcuuid]
		if !ok {
			log.Warning(op.Logf("agent(%s) group lcuuid(%s) not found group id", vtap.Name, vtap.VtapGroupLcuuid))
			continue
		}
		rawData.vtapGroupIDToAgentIDs[vtapGroupID] = append(rawData.vtapGroupIDToAgentIDs[vtapGroupID], vtap.ID)
	}

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

func (op *PolicyDataOP) convertGroupIDs(acl *models.ACL) *GroupIDs {
	var srcGroupIDs, dstGroupIDs []int32
	if len(acl.SrcGroupIDs) > 0 {
		groups := strings.Split(acl.SrcGroupIDs, ",")
		srcGroupIDs = make([]int32, 0, len(groups))
		for _, group := range groups {
			groupInt, err := strconv.Atoi(group)
			if err != nil {
				log.Error(op.Logf("%s %s", err, acl.SrcGroupIDs))
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
				log.Error(op.Logf("%s %s", err, acl.DstGroupIDs))
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

func (op *PolicyDataOP) generateProtoPorts(acl *models.ACL, flowACL *agent.FlowAcl, groupIDs *GroupIDs) int {
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
					log.Errorf(op.Logf("pod service (id = %d) not found.", podServiceID))
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
	tapSideSRC  = agent.PacketCaptureSide_SRC
	tapSideDST  = agent.PacketCaptureSide_DST
	tapSideBOTH = agent.PacketCaptureSide_BOTH

	tunnelTypePCAP = agent.TunnelType_PCAP
)

func (op *PolicyDataOP) generateProtoActions(acl *models.ACL) (map[int][]*agent.NpbAction, []*agent.NpbAction) {
	agentIDToNpbActions := make(map[int][]*agent.NpbAction)
	allAgentNpbActions := []*agent.NpbAction{}
	rawData := op.GetRawData()
	appInt, err := strconv.Atoi(acl.Applications)
	if err != nil {
		log.Errorf(op.Logf("err: %s, applications: %s", err, acl.Applications))
		return agentIDToNpbActions, allAgentNpbActions
	}
	switch appInt {
	case APPLICATION_NPB:
		var payloadSlice int
		for _, npbPolicy := range rawData.aclIDToNpbPolices[acl.ID] {
			npbTunnel, ok := rawData.idToNpbTunnel[npbPolicy.NpbTunnelID]
			if ok == false {
				log.Errorf(op.Logf("npb tunnel id (%d) not found", npbPolicy.NpbTunnelID))
				continue
			}

			tunnelType := agent.TunnelType(npbTunnel.Type)
			if npbPolicy.Distribute == NPB_POLICY_FLOW_DROP {
				tunnelType = agent.TunnelType_NPB_DROP
			}
			if npbPolicy.PayloadSlice == nil {
				payloadSlice = MAX_PAYLOAD_SLICE
			} else {
				payloadSlice = *npbPolicy.PayloadSlice
			}
			direction := agent.Direction(npbPolicy.Direction)
			var tunnelID *uint32
			if npbPolicy.Vni != nil {
				tunnelID = proto.Uint32(uint32(*npbPolicy.Vni))
			}
			npbAction := &agent.NpbAction{
				TunnelId:          tunnelID,
				TunnelIp:          proto.String(npbTunnel.IP),
				PacketCaptureSide: &tapSideSRC,
				TunnelType:        &tunnelType,
				PayloadSlice:      proto.Uint32(uint32(payloadSlice)),
				TunnelIpId:        proto.Uint32(uint32(npbTunnel.ID)),
				NpbAclGroupId:     proto.Uint32(uint32(npbPolicy.PolicyACLGroupID)),
				Direction:         &direction,
			}

			if npbPolicy.VtapType == POLICY_VTAP_TYPE_VTAP {
				if len(npbPolicy.VtapIDs) == 0 {
					allAgentNpbActions = append(allAgentNpbActions, npbAction)
				} else {
					for _, agentIDStr := range strings.Split(npbPolicy.VtapIDs, ",") {
						agentIDInt, err := strconv.Atoi(agentIDStr)
						if err != nil {
							log.Errorf(op.Logf("err: %s, agentIDs: %s", err, npbPolicy.VtapIDs))
							continue
						}
						agentIDToNpbActions[agentIDInt] = append(agentIDToNpbActions[agentIDInt], npbAction)
					}
				}
			} else {
				if len(npbPolicy.VtapGroupIDs) == 0 {
					allAgentNpbActions = append(allAgentNpbActions, npbAction)
				} else {
					for _, vtapGroupIDStr := range strings.Split(npbPolicy.VtapGroupIDs, ",") {
						vtapGroupIDInt, err := strconv.Atoi(vtapGroupIDStr)
						if err != nil {
							log.Errorf(op.Logf("err: %s, vtapGroupIDs: %s", err, npbPolicy.VtapGroupIDs))
							continue
						}
						agentIDs, ok := rawData.vtapGroupIDToAgentIDs[vtapGroupIDInt]
						if !ok {
							log.Errorf(op.Logf("not found agent in vtap group id(%d)", vtapGroupIDInt))
							continue
						}
						for agentID := range agentIDs {
							agentIDToNpbActions[agentID] = append(agentIDToNpbActions[agentID], npbAction)
						}
					}
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
			npbAction := &agent.NpbAction{
				PacketCaptureSide: &tapSideSRC,
				TunnelType:        &tunnelTypePCAP,
				PayloadSlice:      proto.Uint32(uint32(payloadSlice)),
				NpbAclGroupId:     proto.Uint32(uint32(pcapPolicy.PolicyACLGroupID)),
			}
			if len(pcapPolicy.VtapIDs) == 0 {
				allAgentNpbActions = append(allAgentNpbActions, npbAction)
			} else {
				for _, agentIDStr := range strings.Split(pcapPolicy.VtapIDs, ",") {
					agentIDInt, err := strconv.Atoi(agentIDStr)
					if err != nil {
						log.Errorf(op.Logf("err: %s, agentIDs: %s", err, pcapPolicy.VtapIDs))
						continue
					}
					agentIDToNpbActions[agentIDInt] = append(agentIDToNpbActions[agentIDInt], npbAction)
				}
			}
		}
	}

	return agentIDToNpbActions, allAgentNpbActions
}

func (op *PolicyDataOP) generatePolicies() {
	agentIDToPolicy := make(map[int]*Policy)
	allAgentSharePolicy := NewPolicy(0, op.billingMethod, op.metaData.ORGID)

	dbDataCache := op.metaData.GetDBDataCache()
	for _, acl := range dbDataCache.GetACLs() {
		appInt, err := strconv.Atoi(acl.Applications)
		if err != nil {
			log.Error(op.Logf("%s %s", err, acl.Applications))
			continue
		}
		if appInt != APPLICATION_NPB && appInt != APPLICATION_PCAP {
			continue
		}
		groupIDs := op.convertGroupIDs(acl)
		// generat agent policy
		flowACL := &agent.FlowAcl{
			Id:                 proto.Uint32(uint32(acl.ID)),
			CaptureNetworkType: proto.Uint32(uint32(acl.TapType)),
			SrcGroupIds:        groupIDs.srcGroupIDs,
			DstGroupIds:        groupIDs.dstGroupIDs,
		}
		protocol := op.generateProtoPorts(acl, flowACL, groupIDs)
		agentIDToNpbActions, allAgentNpbActions := op.generateProtoActions(acl)
		if protocol == PROTOCOL_ALL && (acl.SrcPorts != "" || acl.DstPorts != "") {
			// If the protocol is all and the port is filled in, it means that the protocol is tcp+udp,
			// and if the protocol is empty and the port is empty, it means any
			for agentID, npbActions := range agentIDToNpbActions {
				agentPolicy, ok := agentIDToPolicy[agentID]
				if ok == false {
					agentPolicy = NewPolicy(agentID, op.billingMethod, op.metaData.ORGID)
					agentIDToPolicy[agentID] = agentPolicy
				}
				tFlowACL := proto.Clone(flowACL).(*agent.FlowAcl)
				tFlowACL.Protocol = proto.Uint32(uint32(TCP))
				tFlowACL.NpbActions = append(tFlowACL.NpbActions, npbActions...)
				agentPolicy.addFlowACL(tFlowACL, appInt)

				uFlowACL := proto.Clone(flowACL).(*agent.FlowAcl)
				uFlowACL.Protocol = proto.Uint32(uint32(UDP))
				uFlowACL.NpbActions = append(uFlowACL.NpbActions, npbActions...)
				agentPolicy.addFlowACL(uFlowACL, appInt)
			}
			if len(allAgentNpbActions) > 0 {
				var tFlowACL, uFlowACL *agent.FlowAcl
				tFlowACL = proto.Clone(flowACL).(*agent.FlowAcl)
				tFlowACL.Protocol = proto.Uint32(uint32(TCP))
				tFlowACL.NpbActions = append(tFlowACL.NpbActions, allAgentNpbActions...)
				allAgentSharePolicy.addFlowACL(tFlowACL, appInt)

				uFlowACL = proto.Clone(flowACL).(*agent.FlowAcl)
				uFlowACL.Protocol = proto.Uint32(uint32(UDP))
				uFlowACL.NpbActions = append(uFlowACL.NpbActions, allAgentNpbActions...)
				allAgentSharePolicy.addFlowACL(uFlowACL, appInt)
			}
		} else {
			for agentID, npbActions := range agentIDToNpbActions {
				agentPolicy, ok := agentIDToPolicy[agentID]
				if ok == false {
					agentPolicy = NewPolicy(agentID, op.billingMethod, op.metaData.ORGID)
					agentIDToPolicy[agentID] = agentPolicy
				}
				aFlowACL := proto.Clone(flowACL).(*agent.FlowAcl)
				aFlowACL.NpbActions = append(aFlowACL.NpbActions, npbActions...)
				aFlowACL.Protocol = proto.Uint32(uint32(protocol))
				agentPolicy.addFlowACL(aFlowACL, appInt)
			}
			if len(allAgentNpbActions) > 0 {
				aFlowACL := proto.Clone(flowACL).(*agent.FlowAcl)
				aFlowACL.NpbActions = append(aFlowACL.NpbActions, allAgentNpbActions...)
				aFlowACL.Protocol = proto.Uint32(uint32(protocol))
				allAgentSharePolicy.addFlowACL(aFlowACL, appInt)
			}
		}
	}

	op.checkNewPolicies(agentIDToPolicy, allAgentSharePolicy)
}

func getSortKey(agentIDToPolicy map[int]*Policy) []int {
	agentIDs := make([]int, 0, len(agentIDToPolicy))
	for key, _ := range agentIDToPolicy {
		agentIDs = append(agentIDs, 0, key)
	}
	sort.Ints(agentIDs)
	return agentIDs
}

func (op *PolicyDataOP) checkNewPolicies(agentIDToPolicy map[int]*Policy,
	allAgentSharePolicy *Policy) {
	version := uint64(op.metaData.GetStartTime())
	allAgentSharePolicy.toSerializeString()
	agentIDs := getSortKey(agentIDToPolicy)
	if op.init == false {
		for _, agentID := range agentIDs {
			agentPolicy, ok := agentIDToPolicy[agentID]
			if ok == false {
				continue
			}
			agentPolicy.initVersion(version)
			agentPolicy.merger(allAgentSharePolicy)
			agentPolicy.toSerializeString()
		}
		allAgentSharePolicy.initVersion(version + ALL_VTAP_SHARE_POLICY_VERSION_OFFSET)
		op.updateAgentIDToPolicy(agentIDToPolicy)
		op.updateAllAgentSharePolicy(allAgentSharePolicy)
		op.init = true
		return
	}
	oldAgentIDToPolicy := op.getAgentIDToPolicy()
	oldAllAgentSharePolicy := op.getAllAgentSharePolicy()
	for _, agentID := range agentIDs {
		agentPolicy, ok := agentIDToPolicy[agentID]
		if ok == false {
			continue
		}
		agentPolicy.merger(allAgentSharePolicy)
		agentPolicy.toSerializeString()
		oldPolicy := oldAgentIDToPolicy[agentID]
		if oldPolicy != nil {
			agentPolicy.setVersion(oldPolicy)
		} else {
			agentPolicy.initVersion(version)
		}
	}
	allAgentSharePolicy.setVersion(oldAllAgentSharePolicy)
	op.updateAgentIDToPolicy(agentIDToPolicy)
	op.updateAllAgentSharePolicy(allAgentSharePolicy)
	log.Debug(op.Logf("%s", op))
}

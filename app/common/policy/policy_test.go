package policy

import (
	"testing"

	"gitlab.x.lan/yunshan/droplet-libs/datatype"
)

func TestGroupByActionFlag(t *testing.T) {
	p := &datatype.PolicyData{}
	p.ACLID = datatype.ACLID(2)
	p.ActionFlags = datatype.ACTION_PACKET_COUNTING
	p.Merge([]datatype.AclAction{
		datatype.AclAction(0).AddActionFlags(datatype.ACTION_PACKET_COUNTING).AddTagTemplates(1),
		datatype.AclAction(0).AddActionFlags(datatype.ACTION_PACKET_COUNTING).AddTagTemplates(2),
	}, nil, 1)
	if GetTagTemplateByActionFlags(p, datatype.ACTION_PACKET_COUNTING) != 3 {
		t.Error("合并tag template不正确")
	}
}

func TestGroupByPolicy(t *testing.T) {
	p := &datatype.PolicyData{}
	p.ActionFlags = datatype.ACTION_TCP_FLOW_PERF_COUNTING
	p.Merge([]datatype.AclAction{
		datatype.AclAction(0).SetACLGID(1).AddActionFlags(datatype.ACTION_TCP_FLOW_PERF_COUNTING).AddTagTemplates(3),
		datatype.AclAction(0).SetACLGID(1).AddActionFlags(datatype.ACTION_TCP_FLOW_PERF_COUNT_BROKERING).AddTagTemplates(5),
		datatype.AclAction(0).SetACLGID(2).AddActionFlags(datatype.ACTION_TCP_FLOW_PERF_COUNTING).AddTagTemplates(2),
		datatype.AclAction(0).SetACLGID(2).AddActionFlags(datatype.ACTION_TCP_FLOW_PERF_COUNT_BROKERING).AddTagTemplates(6),
		datatype.AclAction(0).SetACLGID(3).AddActionFlags(datatype.ACTION_TCP_FLOW_PERF_COUNTING).AddTagTemplates(6),
		datatype.AclAction(0).SetACLGID(3).AddActionFlags(datatype.ACTION_TCP_FLOW_PERF_COUNT_BROKERING).AddTagTemplates(2),
		datatype.AclAction(0).SetACLGID(4).AddActionFlags(datatype.ACTION_TCP_FLOW_PERF_COUNTING).AddTagTemplates(2),
		datatype.AclAction(0).SetACLGID(4).AddActionFlags(datatype.ACTION_TCP_FLOW_PERF_COUNT_BROKERING).AddTagTemplates(2),
	}, nil, 1)
	grouped := make([]datatype.AclAction, 0)
	grouped = FillPolicyTagTemplate(p, datatype.ACTION_TCP_FLOW_PERF_COUNTING|datatype.ACTION_TCP_FLOW_PERF_COUNT_BROKERING, grouped)
	if len(grouped) != 8 {
		t.Error("PolicyGroupID长度不正确:", grouped)
	} else {
		if grouped[0].GetTagTemplates() != datatype.TagTemplate(2) {
			t.Error("ACLGID=1的Policy TagTemplate不正确:", grouped)
		}
		if grouped[3].GetTagTemplates() != datatype.TagTemplate(2) {
			t.Error("ACLGID=2的Policy TagTemplate不正确:", grouped)
		}
		if grouped[5].GetTagTemplates() != datatype.TagTemplate(4) {
			t.Error("ACLGID=3的Policy TagTemplate不正确:", grouped)
		}
		if grouped[7].GetTagTemplates() != datatype.TagTemplate(2) {
			t.Error("ACLGID=4的Policy TagTemplate不正确:", grouped)
		}
	}
}
